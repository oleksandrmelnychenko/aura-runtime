#!/usr/bin/env python3

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a local promotion-gate rehearsal and emit a unified evidence bundle."
    )
    parser.add_argument(
        "--target",
        choices=["staging", "release"],
        default="staging",
        help="Promotion target label for the rehearsal bundle.",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/promotion-rehearsal",
        help="Directory where rehearsal artifacts should be written.",
    )
    parser.add_argument(
        "--soak-iterations",
        type=int,
        default=None,
        help="Override FFI soak iterations. Defaults to 3 for staging and 5 for release.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip cargo build during the rehearsal.",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip cargo test during the rehearsal.",
    )
    return parser.parse_args()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def tail_lines(text: str, limit: int = 20) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-limit:]


def run_command(argv: list[str], cwd: Path) -> dict:
    started = time.monotonic()
    result = subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "argv": argv,
        "returncode": result.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout_tail": tail_lines(result.stdout),
        "stderr_tail": tail_lines(result.stderr),
    }


def detect_compiler() -> str | None:
    for candidate in ("cc", "clang", "gcc", "cl"):
        if shutil.which(candidate):
            return candidate
    return None


def compile_ffi_smoke(
    workspace_root: Path,
    output_path: Path,
    object_path: Path,
) -> tuple[dict, dict]:
    compiler = detect_compiler()
    source_path = workspace_root / "ci/ffi_header_smoke.c"
    header_path = workspace_root / "include/aura_ffi.h"

    if compiler is None:
        evidence = {
            "status": "blocked",
            "mode": "local_stub_no_compiler",
            "compiler": "local-stub-no-compiler",
            "compiler_available": False,
            "note": "No local C compiler found; GitHub promotion gate will run a real smoke compile on ubuntu-latest.",
            "header_path": header_path.as_posix(),
            "source_path": source_path.as_posix(),
            "object_path": object_path.as_posix(),
        }
        output_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        return {"status": "stub", "compiler": None, "returncode": 0}, evidence

    if compiler == "cl":
        argv = [
            compiler,
            "/nologo",
            "/W4",
            "/TC",
            "/I.",
            "/c",
            str(source_path),
            f"/Fo{object_path}",
        ]
        version_argv = [compiler]
    else:
        argv = [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-pedantic",
            "-I.",
            "-c",
            str(source_path),
            "-o",
            str(object_path),
        ]
        version_argv = [compiler, "--version"]

    command = run_command(argv, cwd=workspace_root)
    if command["returncode"] != 0:
        return command, {
            "status": "fail",
            "mode": "compile_failed",
            "compiler": compiler,
            "compiler_available": True,
            "header_path": header_path.as_posix(),
            "source_path": source_path.as_posix(),
            "object_path": object_path.as_posix(),
        }

    version = subprocess.run(
        version_argv,
        cwd=workspace_root,
        capture_output=True,
        text=True,
        check=False,
    )
    compiler_text = (version.stdout or version.stderr).splitlines()
    evidence = {
        "status": "pass",
        "mode": "compiled",
        "compiler": compiler_text[0] if compiler_text else compiler,
        "compiler_available": True,
        "header_path": header_path.as_posix(),
        "source_path": source_path.as_posix(),
        "object_path": object_path.as_posix(),
    }
    output_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return command, evidence


def main() -> int:
    args = parse_args()
    workspace_root = Path(__file__).resolve().parents[1]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    soak_iterations = args.soak_iterations or (5 if args.target == "release" else 3)
    label = f"promotion-{args.target}-local"

    paths = {
        "release_report": output_dir / "release-report.json",
        "contract_evidence": output_dir / "contract-evidence.json",
        "dataset_evidence": output_dir / "dataset-evidence.json",
        "audit_evidence": output_dir / "audit-evidence.json",
        "ffi_soak": output_dir / "ffi-state-sync-soak.json",
        "ffi_smoke": output_dir / "ffi-header-smoke.json",
        "ffi_smoke_object": output_dir / "ffi-header-smoke.o",
        "manifest": output_dir / "evidence-manifest.json",
        "summary": output_dir / "promotion-rehearsal-summary.json",
    }

    summary = {
        "status": "pass",
        "target": args.target,
        "label": label,
        "started_at_utc": now_utc(),
        "finished_at_utc": None,
        "workspace_root": workspace_root.as_posix(),
        "output_dir": output_dir.as_posix(),
        "soak_iterations": soak_iterations,
        "commands": [],
        "ffi_smoke_mode": None,
        "manifest_path": paths["manifest"].as_posix(),
        "manifest_evidence_status": None,
    }

    started = time.monotonic()

    def record_and_require(argv: list[str]) -> None:
        result = run_command(argv, cwd=workspace_root)
        summary["commands"].append(result)
        if result["returncode"] != 0:
            summary["status"] = "fail"
            raise RuntimeError(f"command failed: {' '.join(argv)}")

    try:
        if not args.skip_build:
            record_and_require(["cargo", "build", "--verbose"])
        if not args.skip_tests:
            record_and_require(["cargo", "test", "--workspace", "--all-targets", "--all-features"])

        record_and_require(
            [
                sys.executable,
                "ci/run_ffi_soak.py",
                "--output",
                paths["ffi_soak"].as_posix(),
                "--iterations",
                str(soak_iterations),
                "--label",
                label,
            ]
        )
        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--example",
                "release_report",
                "-p",
                "aura-core",
                "--",
                "--output",
                paths["release_report"].as_posix(),
                "--require-pass",
            ]
        )
        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--example",
                "contract_evidence",
                "-p",
                "aura-core",
                "--",
                "--output",
                paths["contract_evidence"].as_posix(),
            ]
        )
        record_and_require(
            [
                sys.executable,
                "ci/generate_dataset_evidence.py",
                "--output",
                paths["dataset_evidence"].as_posix(),
            ]
        )
        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--example",
                "audit_evidence",
                "-p",
                "aura-core",
                "--",
                "--output",
                paths["audit_evidence"].as_posix(),
            ]
        )

        smoke_command, smoke_evidence = compile_ffi_smoke(
            workspace_root=workspace_root,
            output_path=paths["ffi_smoke"],
            object_path=paths["ffi_smoke_object"],
        )
        summary["commands"].append(
            {
                "argv": smoke_command.get("argv", ["ffi-smoke-stub"]),
                "returncode": smoke_command.get("returncode", 0),
                "duration_seconds": smoke_command.get("duration_seconds", 0.0),
                "stdout_tail": smoke_command.get("stdout_tail", []),
                "stderr_tail": smoke_command.get("stderr_tail", []),
            }
        )
        summary["ffi_smoke_mode"] = smoke_evidence["mode"]
        if smoke_evidence["status"] == "fail":
            summary["status"] = "fail"
            raise RuntimeError("ffi smoke compile failed")

        record_and_require(
            [
                sys.executable,
                "ci/generate_evidence_manifest.py",
                "--output",
                paths["manifest"].as_posix(),
                "--label",
                label,
                "--release-report",
                paths["release_report"].as_posix(),
                "--contract-evidence",
                paths["contract_evidence"].as_posix(),
                "--ffi-soak",
                paths["ffi_soak"].as_posix(),
                "--dataset-evidence",
                paths["dataset_evidence"].as_posix(),
                "--audit-evidence",
                paths["audit_evidence"].as_posix(),
                "--ffi-smoke",
                paths["ffi_smoke"].as_posix(),
            ]
        )
        manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
        summary["manifest_evidence_status"] = manifest.get("evidence_status")
    except RuntimeError as error:
        summary["failure"] = str(error)
        return_code = 1
    else:
        return_code = 0
    finally:
        if paths["manifest"].exists():
            try:
                manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
                summary["manifest_evidence_status"] = manifest.get("evidence_status")
            except json.JSONDecodeError:
                summary["manifest_evidence_status"] = "invalid_json"
        summary["finished_at_utc"] = now_utc()
        summary["duration_seconds"] = round(time.monotonic() - started, 3)
        paths["summary"].write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    return return_code


if __name__ == "__main__":
    sys.exit(main())
