#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


class BlockedRehearsal(RuntimeError):
    pass


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
    parser.add_argument(
        "--pilot-review-signoffs",
        default=None,
        help="Optional path to pilot review signoffs JSON. If provided, a pilot gate report will be generated.",
    )
    parser.add_argument(
        "--evidence-signing-private-key",
        default=os.environ.get("AURA_EVIDENCE_SIGNING_PRIVATE_KEY_PATH"),
        help="Optional Ed25519 private key PEM used for detached evidence attestation.",
    )
    parser.add_argument(
        "--evidence-signing-public-key",
        default=os.environ.get("AURA_EVIDENCE_SIGNING_PUBLIC_KEY_PATH"),
        help="Optional trusted Ed25519 public key PEM used to verify the attestation.",
    )
    parser.add_argument(
        "--evidence-signing-key-id",
        default=os.environ.get("AURA_EVIDENCE_SIGNING_KEY_ID"),
        help="Trust-store key identifier for detached evidence attestation.",
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
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    fallback_candidates = []
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        fallback_candidates.append(Path(program_files) / "LLVM" / "bin" / "clang.exe")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        fallback_candidates.extend(
            [
                Path(local_app_data) / "Programs" / "LLVM" / "bin" / "clang.exe",
                Path(local_app_data) / "Microsoft" / "WinGet" / "Links" / "clang.exe",
            ]
        )
    for candidate_path in fallback_candidates:
        if candidate_path.exists():
            return str(candidate_path)
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


def apply_manifest_summary(summary: dict, manifest: dict) -> None:
    manifest_summary = manifest.get("summary", {})
    if not isinstance(manifest_summary, dict):
        manifest_summary = {}

    release_operator_summary = manifest_summary.get("release_operator_summary", [])
    if not isinstance(release_operator_summary, list):
        release_operator_summary = []

    summary["manifest_evidence_status"] = manifest.get("evidence_status")
    summary["ffi_smoke_status"] = manifest_summary.get("ffi_smoke_status")
    summary["ffi_smoke_mode"] = manifest_summary.get("ffi_smoke_mode")
    summary["ffi_smoke_compiler"] = manifest_summary.get("ffi_smoke_compiler")
    summary["ffi_smoke_note"] = manifest_summary.get("ffi_smoke_note")
    summary["release_report_status"] = manifest_summary.get("release_report_status")
    summary["release_operator_summary"] = release_operator_summary
    summary["release_social_context_inference_passed"] = manifest_summary.get(
        "release_social_context_inference_passed"
    )
    summary["release_social_context_inference_total_expectations"] = manifest_summary.get(
        "release_social_context_inference_total_expectations"
    )
    summary["release_social_context_inference_failed_expectations"] = manifest_summary.get(
        "release_social_context_inference_failed_expectations"
    )
    summary["pilot_shadow_status"] = manifest_summary.get("pilot_shadow_status")
    summary["pilot_regression_status"] = manifest_summary.get("pilot_regression_status")
    summary["temporal_shadow_status"] = manifest_summary.get("temporal_shadow_status")
    summary["temporal_shadow_adversarial_variant_count"] = manifest_summary.get(
        "temporal_shadow_adversarial_variant_count"
    )
    summary["temporal_shadow_adversarial_mismatch_count"] = manifest_summary.get(
        "temporal_shadow_adversarial_mismatch_count"
    )
    summary["temporal_shadow_telemetry_validation_status"] = manifest_summary.get(
        "temporal_shadow_telemetry_validation_status"
    )
    summary["temporal_shadow_telemetry_on_prem_inputs"] = manifest_summary.get(
        "temporal_shadow_telemetry_on_prem_inputs"
    )
    summary["temporal_shadow_telemetry_adk_inputs"] = manifest_summary.get(
        "temporal_shadow_telemetry_adk_inputs"
    )
    summary["temporal_policy_activation_readiness"] = manifest_summary.get(
        "temporal_policy_activation_readiness"
    )
    summary["pilot_gate_status"] = manifest_summary.get("pilot_gate_status")
    summary["world_lifecycle_status"] = manifest_summary.get("world_lifecycle_status")
    summary["world_lifecycle_total_worlds"] = manifest_summary.get(
        "world_lifecycle_total_worlds"
    )
    summary["world_lifecycle_total_events"] = manifest_summary.get(
        "world_lifecycle_total_events"
    )
    summary["world_lifecycle_finding_count"] = manifest_summary.get(
        "world_lifecycle_finding_count"
    )


def apply_release_report_summary(summary: dict, release_payload: dict) -> None:
    operator_summary = release_payload.get("operator_summary", [])
    if not isinstance(operator_summary, list):
        operator_summary = []

    summary["release_report_status"] = release_payload.get("overall_status")
    summary["release_operator_summary"] = operator_summary

    suites = release_payload.get("suites", [])
    if not isinstance(suites, list):
        return
    for suite in suites:
        if not isinstance(suite, dict) or suite.get("suite_id") != "social_context":
            continue
        inference = suite.get("social_context_inference")
        if not isinstance(inference, dict):
            return
        summary["release_social_context_inference_passed"] = inference.get("passed")
        summary["release_social_context_inference_total_expectations"] = inference.get(
            "total_expectations"
        )
        summary["release_social_context_inference_failed_expectations"] = inference.get(
            "failed_expectations"
        )
        return


def print_rehearsal_summary(summary: dict, summary_path: Path) -> None:
    status = summary.get("status")
    manifest_status = summary.get("manifest_evidence_status")
    release_status = summary.get("release_report_status")
    print(
        "promotion rehearsal summary written to "
        f"{summary_path.as_posix()} "
        f"(status={status}, manifest={manifest_status}, release={release_status})",
        file=sys.stderr,
    )

    inference_passed = summary.get("release_social_context_inference_passed")
    total_expectations = summary.get("release_social_context_inference_total_expectations")
    failed_expectations = summary.get("release_social_context_inference_failed_expectations")
    if inference_passed is not None:
        print(
            "release social-context inference: "
            f"passed={inference_passed} "
            f"total={total_expectations} "
            f"failed={failed_expectations}",
            file=sys.stderr,
        )

    lifecycle_status = summary.get("world_lifecycle_status")
    if lifecycle_status is not None:
        print(
            "world lifecycle suite: "
            f"status={lifecycle_status} "
            f"worlds={summary.get('world_lifecycle_total_worlds')} "
            f"events={summary.get('world_lifecycle_total_events')} "
            f"findings={summary.get('world_lifecycle_finding_count')}",
            file=sys.stderr,
        )

    for line in summary.get("release_operator_summary", []):
        print(f"release summary: {line}", file=sys.stderr)

    if summary.get("blocker"):
        print(f"blocker: {summary['blocker']}", file=sys.stderr)
    if "failure" in summary:
        print(f"failure: {summary['failure']}", file=sys.stderr)


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
        "world_lifecycle_report": output_dir / "world-lifecycle-suite-report.json",
        "pilot_shadow_bundle": output_dir / "pilot-shadow-bundle.json",
        "pilot_shadow_bundle_2": output_dir / "pilot-shadow-bundle-2.json",
        "pilot_regression_report": output_dir / "pilot-regression-report.json",
        "temporal_shadow_report": output_dir / "temporal-shadow-report.json",
        "temporal_shadow_telemetry_validation": output_dir
        / "temporal-shadow-telemetry-validation.json",
        "kids_memory_health": output_dir / "kids-memory-health.json",
        "kids_preprod_dry_run": output_dir / "kids-preprod-dry-run-matrix.json",
        "pilot_gate_report": output_dir / "pilot-gate-report.json",
        "ffi_soak": output_dir / "ffi-state-sync-soak.json",
        "ffi_smoke": output_dir / "ffi-header-smoke.json",
        "ffi_smoke_object": output_dir / "ffi-header-smoke.o",
        "manifest": output_dir / "evidence-manifest.json",
        "manifest_attestation": output_dir / "evidence-manifest.attestation.json",
        "manifest_attestation_verification": output_dir
        / "evidence-manifest.attestation-verification.json",
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
        "blocker": None,
        "ffi_smoke_mode": None,
        "ffi_smoke_status": None,
        "ffi_smoke_compiler": None,
        "ffi_smoke_note": None,
        "release_report_status": None,
        "release_operator_summary": [],
        "release_social_context_inference_passed": None,
        "release_social_context_inference_total_expectations": None,
        "release_social_context_inference_failed_expectations": None,
        "pilot_shadow_status": None,
        "pilot_regression_status": None,
        "temporal_policy_activation_readiness": None,
        "pilot_gate_status": None,
        "world_lifecycle_status": None,
        "world_lifecycle_total_worlds": None,
        "world_lifecycle_total_events": None,
        "world_lifecycle_finding_count": None,
        "manifest_path": paths["manifest"].as_posix(),
        "manifest_evidence_status": None,
    }

    started = time.monotonic()

    def record_and_require(argv: list[str]) -> dict:
        result = run_command(argv, cwd=workspace_root)
        summary["commands"].append(result)
        if result["returncode"] != 0:
            summary["status"] = "fail"
            raise RuntimeError(f"command failed: {' '.join(argv)}")
        return result

    try:
        if not args.skip_build:
            record_and_require(["cargo", "build", "--verbose"])
        if not args.skip_tests:
            record_and_require(["cargo", "test", "--workspace", "--all-targets", "--all-features"])

        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "-p",
                "aura-military",
                "--features",
                "evaluation",
                "--example",
                "temporal_shadow_eval",
                "--",
                "--output",
                paths["temporal_shadow_report"].as_posix(),
                "--require-pass",
            ]
        )
        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "-p",
                "aura-military",
                "--features",
                "evaluation",
                "--example",
                "temporal_shadow_telemetry_validation",
                "--",
                "--output",
                paths["temporal_shadow_telemetry_validation"].as_posix(),
                "--require-pass",
            ]
        )

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
        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--example",
                "world_sim",
                "-p",
                "aura-core",
                "--",
                "--input",
                "crates/aura-core/data/world_lifecycle_suite",
                "--summary-only",
                "--output",
                paths["world_lifecycle_report"].as_posix(),
                "--redact-text",
                "--require-clean",
            ]
        )
        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--example",
                "world_sim",
                "-p",
                "aura-core",
                "--",
                "--input",
                "crates/aura-core/data/world_sim_2k.json",
                "--summary-only",
                "--shadow-output",
                paths["pilot_shadow_bundle"].as_posix(),
                "--require-clean",
            ]
        )
        if args.pilot_review_signoffs:
            record_and_require(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--example",
                    "world_sim",
                    "-p",
                    "aura-core",
                    "--",
                    "--input",
                    "crates/aura-core/data/world_sim_2k.json",
                    "--summary-only",
                    "--shadow-output",
                    paths["pilot_shadow_bundle_2"].as_posix(),
                    "--require-clean",
                ]
            )
        record_and_require(
            [
                "cargo",
                "run",
                "--quiet",
                "--example",
                "pilot_regression",
                "-p",
                "aura-core",
                "--",
                "--output",
                paths["pilot_regression_report"].as_posix(),
                "--require-pass",
            ]
        )
        if args.pilot_review_signoffs:
            record_and_require(
                [
                    sys.executable,
                    "ci/kids_memory_health_snapshot.py",
                    "--input",
                    paths["pilot_regression_report"].as_posix(),
                    "--input",
                    paths["pilot_shadow_bundle"].as_posix(),
                    "--input",
                    paths["pilot_shadow_bundle_2"].as_posix(),
                    "--output",
                    paths["kids_memory_health"].as_posix(),
                    "--require-mandatory-reasons",
                ]
            )
            record_and_require(
                [
                    sys.executable,
                    "ci/kids_preprod_dry_run_matrix.py",
                    "--policy-expectations",
                    "crates/aura-core/data/action_policy_expectations.json",
                    "--realistic-cases",
                    "crates/aura-core/data/realistic_chat_cases.json",
                    "--kids-memory-health",
                    paths["kids_memory_health"].as_posix(),
                    "--output",
                    paths["kids_preprod_dry_run"].as_posix(),
                ]
            )
            record_and_require(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--example",
                    "pilot_gate",
                    "-p",
                    "aura-core",
                    "--",
                    "--release-report",
                    paths["release_report"].as_posix(),
                    "--pilot-regression-report",
                    paths["pilot_regression_report"].as_posix(),
                    "--shadow-bundle",
                    paths["pilot_shadow_bundle"].as_posix(),
                    "--shadow-bundle",
                    paths["pilot_shadow_bundle_2"].as_posix(),
                    "--review-signoffs",
                    args.pilot_review_signoffs,
                    "--kids-memory-health-report",
                    paths["kids_memory_health"].as_posix(),
                    "--kids-preprod-dry-run-report",
                    paths["kids_preprod_dry_run"].as_posix(),
                    "--output",
                    paths["pilot_gate_report"].as_posix(),
                    "--require-kids-memory-pass",
                    "--require-kids-preprod-dry-run-pass",
                    "--require-pass",
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

        manifest_argv = [
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
            "--pilot-shadow-bundle",
            paths["pilot_shadow_bundle"].as_posix(),
            "--pilot-regression-report",
            paths["pilot_regression_report"].as_posix(),
            "--temporal-shadow-report",
            paths["temporal_shadow_report"].as_posix(),
            "--temporal-shadow-telemetry-validation",
            paths["temporal_shadow_telemetry_validation"].as_posix(),
            "--world-lifecycle-report",
            paths["world_lifecycle_report"].as_posix(),
            *(
                ["--pilot-gate-report", paths["pilot_gate_report"].as_posix()]
                if args.pilot_review_signoffs
                else []
            ),
            *(
                [
                    "--kids-preprod-dry-run-report",
                    paths["kids_preprod_dry_run"].as_posix(),
                ]
                if args.pilot_review_signoffs
                else []
            ),
            "--ffi-smoke",
            paths["ffi_smoke"].as_posix(),
        ]
        manifest_result = run_command(manifest_argv, cwd=workspace_root)
        summary["commands"].append(manifest_result)
        if paths["manifest"].exists():
            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            apply_manifest_summary(summary, manifest)
        if manifest_result["returncode"] != 0:
            if summary.get("manifest_evidence_status") == "blocked":
                summary["status"] = "blocked"
                summary["blocker"] = (
                    "local promotion rehearsal blocked: no local C compiler for ffi_smoke; "
                    "GitHub Actions will run the real compile on ubuntu-latest"
                    if summary.get("ffi_smoke_mode") == "local_stub_no_compiler"
                    else "local promotion rehearsal blocked: evidence manifest is blocked"
                )
                raise BlockedRehearsal(summary["blocker"])
            summary["status"] = "fail"
            raise RuntimeError(f"command failed: {' '.join(manifest_argv)}")

        signing_values = (
            args.evidence_signing_private_key,
            args.evidence_signing_public_key,
            args.evidence_signing_key_id,
        )
        if all(signing_values):
            sign_result = record_and_require(
                [
                    sys.executable,
                    "ci/evidence_attestation.py",
                    "sign",
                    "--manifest",
                    paths["manifest"].as_posix(),
                    "--private-key",
                    str(args.evidence_signing_private_key),
                    "--key-id",
                    str(args.evidence_signing_key_id),
                    "--output",
                    paths["manifest_attestation"].as_posix(),
                ]
            )
            summary["evidence_attestation_sign_returncode"] = sign_result["returncode"]
            verify_result = record_and_require(
                [
                    sys.executable,
                    "ci/evidence_attestation.py",
                    "verify",
                    "--manifest",
                    paths["manifest"].as_posix(),
                    "--attestation",
                    paths["manifest_attestation"].as_posix(),
                    "--public-key",
                    str(args.evidence_signing_public_key),
                    "--expected-key-id",
                    str(args.evidence_signing_key_id),
                    "--output",
                    paths["manifest_attestation_verification"].as_posix(),
                    "--require-pass",
                ]
            )
            summary["evidence_attestation_verify_returncode"] = verify_result[
                "returncode"
            ]
        elif any(signing_values):
            summary["status"] = "blocked"
            summary["blocker"] = "evidence attestation requires private key, public key, and key id"
            raise BlockedRehearsal(summary["blocker"])
        elif args.target == "release":
            summary["status"] = "blocked"
            summary["blocker"] = "release rehearsal requires Ed25519 evidence signing credentials"
            raise BlockedRehearsal(summary["blocker"])
    except BlockedRehearsal:
        return_code = 1
    except RuntimeError as error:
        summary["failure"] = str(error)
        return_code = 1
    else:
        return_code = 0
    finally:
        if paths["release_report"].exists():
            try:
                release_payload = json.loads(paths["release_report"].read_text(encoding="utf-8"))
                apply_release_report_summary(summary, release_payload)
            except json.JSONDecodeError:
                pass
        if paths["manifest"].exists():
            try:
                manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
                apply_manifest_summary(summary, manifest)
            except json.JSONDecodeError:
                summary["manifest_evidence_status"] = "invalid_json"
        summary["finished_at_utc"] = now_utc()
        summary["duration_seconds"] = round(time.monotonic() - started, 3)
        paths["summary"].write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print_rehearsal_summary(summary, paths["summary"])

    return return_code


if __name__ == "__main__":
    sys.exit(main())
