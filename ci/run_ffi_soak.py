#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


TEST_FILTERS = [
    "repeated_import_of_same_state_is_idempotent",
    "repeated_export_import_roundtrips_preserve_growth",
]

FAILURE_POLICY_VERSION = "ffi_soak_failure_policy.v1"
FAILURE_PATTERNS = [
    (
        "timeout",
        "FFI soak command timed out before completion.",
        [r"timed out", r"timeout"],
    ),
    (
        "linker_lock",
        "Toolchain linker could not acquire the test executable or artifact path.",
        [r"LNK1104", r"cannot open file", r"link\.exe failed", r"artifact directory"],
    ),
    (
        "compile_failure",
        "Rust compilation failed before the soak assertions could run.",
        [r"could not compile", r"error\[E\d+\]", r"error: linking with"],
    ),
    (
        "test_panic",
        "An FFI soak test panicked during execution.",
        [r"panicked at", r"thread '.*' panicked"],
    ),
    (
        "assertion_failure",
        "A state-sync assertion failed during soak execution.",
        [r"assertion failed", r"test result: FAILED", r"failures:"],
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run repeated FFI state-sync stress tests and emit JSON evidence."
    )
    parser.add_argument("--output", required=True, help="Path to JSON evidence output.")
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of soak iterations to run for each test.",
    )
    parser.add_argument(
        "--label",
        default="ci",
        help="Short label describing the workflow context.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=180,
        help="Per-command timeout for each cargo test invocation.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_evidence(path: Path, evidence: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def tail_lines(text: str, limit: int = 40) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-limit:]


def highlight_lines(text: str, limit: int = 6) -> list[str]:
    interesting = []
    seen = set()
    patterns = [
        r"LNK1104",
        r"cannot open file",
        r"could not compile",
        r"panicked at",
        r"assertion failed",
        r"test result: FAILED",
        r"error:",
        r"FAILED",
    ]
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(re.search(pattern, stripped, re.IGNORECASE) for pattern in patterns):
            if stripped not in seen:
                seen.add(stripped)
                interesting.append(stripped)
        if len(interesting) >= limit:
            break
    return interesting


def diagnose_failure(text: str, timed_out: bool) -> tuple[str, str, list[str]]:
    if timed_out:
        return (
            "timeout",
            "FFI soak command timed out before completion.",
            highlight_lines(text),
        )

    for category, summary, patterns in FAILURE_PATTERNS:
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
            return category, summary, highlight_lines(text)

    return (
        "unknown_failure",
        "FFI soak command failed without matching a curated failure pattern.",
        highlight_lines(text),
    )


def main() -> int:
    args = parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")

    script_path = Path(__file__).resolve()
    workspace_root = script_path.parents[1]
    output_path = Path(args.output)
    started_at = utc_now()
    started_monotonic = time.monotonic()

    evidence = {
        "status": "pass",
        "label": args.label,
        "failure_policy_version": FAILURE_POLICY_VERSION,
        "started_at_utc": started_at,
        "finished_at_utc": None,
        "duration_seconds": None,
        "workspace_root": str(workspace_root),
        "crate": "aura-ffi",
        "iterations": args.iterations,
        "timeout_seconds": args.timeout_seconds,
        "tests": TEST_FILTERS,
        "attempts_run": 0,
        "failed_test": None,
        "failed_iteration": None,
        "failure_category": None,
        "failure_summary": None,
        "failure_highlights": [],
        "commands": [],
        "failure_tail": [],
    }

    try:
        for iteration in range(1, args.iterations + 1):
            for test_filter in TEST_FILTERS:
                command = [
                    "cargo",
                    "test",
                    "-p",
                    "aura-ffi",
                    test_filter,
                    "--",
                    "--nocapture",
                ]
                evidence["commands"].append(
                    {
                        "iteration": iteration,
                        "test": test_filter,
                        "argv": command,
                    }
                )
                try:
                    result = subprocess.run(
                        command,
                        cwd=workspace_root,
                        capture_output=True,
                        text=True,
                        check=False,
                        env=os.environ.copy(),
                        timeout=args.timeout_seconds,
                    )
                    combined_output = "\n".join([result.stdout, result.stderr]).strip()
                    timed_out = False
                except subprocess.TimeoutExpired as error:
                    combined_output = "\n".join(
                        [
                            (error.stdout or "").strip(),
                            (error.stderr or "").strip(),
                            f"command timed out after {args.timeout_seconds} seconds",
                        ]
                    ).strip()
                    result = None
                    timed_out = True
                evidence["attempts_run"] += 1
                if timed_out or (result is not None and result.returncode != 0):
                    category, summary, highlights = diagnose_failure(
                        combined_output, timed_out=timed_out
                    )
                    evidence["status"] = "fail"
                    evidence["failed_test"] = test_filter
                    evidence["failed_iteration"] = iteration
                    evidence["failure_category"] = category
                    evidence["failure_summary"] = summary
                    evidence["failure_highlights"] = highlights
                    evidence["failure_tail"] = tail_lines(combined_output)
                    return 1
        return 0
    finally:
        evidence["finished_at_utc"] = utc_now()
        evidence["duration_seconds"] = round(time.monotonic() - started_monotonic, 3)
        write_evidence(output_path, evidence)


if __name__ == "__main__":
    sys.exit(main())
