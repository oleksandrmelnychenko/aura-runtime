#!/usr/bin/env python3

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a KIDS memory health snapshot from JSON artifacts by counting "
            "kids.memory.* reason codes."
        )
    )
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Path to a JSON artifact file. Can be passed multiple times.",
    )
    parser.add_argument(
        "--output",
        default="artifacts/kids-memory-health.json",
        help="Output path for the health snapshot JSON.",
    )
    parser.add_argument(
        "--guardian-policy",
        default="crates/aura-kids/src/policy/guardian.rs",
        help="Path to guardian policy source for extracting mandatory reason codes.",
    )
    parser.add_argument(
        "--require-mandatory-reasons",
        action="store_true",
        help=(
            "Exit non-zero when one or more mandatory kids.memory reason codes "
            "are not observed in inputs."
        ),
    )
    return parser.parse_args()


def extract_mandatory_reason_codes(guardian_policy_path: Path) -> list[str]:
    fallback = [
        "kids.memory.grooming_progression",
        "kids.memory.sustained_sextortion",
        "kids.memory.bullying_cascade_selfharm",
        "kids.memory.sender_risk_accumulation",
        "kids.memory.new_sender_fast_escalation",
        "kids.memory.cross_conversation_repeat_offender",
        "kids.memory.victim_vulnerability_targeting",
    ]
    if not guardian_policy_path.exists():
        return fallback

    text = guardian_policy_path.read_text(encoding="utf-8", errors="replace")
    matches = re.findall(r'"(kids\.memory\.[a-z0-9_]+)"', text)
    if not matches:
        return fallback

    deduped = []
    seen = set()
    for code in matches:
        if code in seen:
            continue
        seen.add(code)
        deduped.append(code)
    return deduped


def collect_reason_codes(value: Any, counter: Counter[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "reason_code" and isinstance(item, str) and item.startswith("kids.memory."):
                counter[item] += 1
            elif key == "reason_codes" and isinstance(item, list):
                for reason in item:
                    if isinstance(reason, str):
                        reason = reason.removeprefix("domain.")
                        if reason.startswith("kids.memory."):
                            counter[reason] += 1
            collect_reason_codes(item, counter)
        return

    if isinstance(value, list):
        for item in value:
            collect_reason_codes(item, counter)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    guardian_policy_path = Path(args.guardian_policy)
    mandatory_codes = extract_mandatory_reason_codes(guardian_policy_path)

    inputs = [Path(item) for item in args.input]
    missing_files = [path.as_posix() for path in inputs if not path.exists()]
    if missing_files:
        print("missing input files:", ", ".join(missing_files), file=sys.stderr)
        return 2

    parse_errors: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    scanned_files: list[str] = []
    for path in inputs:
        try:
            payload = read_json(path)
        except Exception as err:  # noqa: BLE001
            parse_errors.append({"path": path.as_posix(), "error": str(err)})
            continue
        collect_reason_codes(payload, counts)
        scanned_files.append(path.as_posix())

    observed = {}
    for code in mandatory_codes:
        observed[code] = counts.get(code, 0)
    missing_mandatory = [code for code, count in observed.items() if count == 0]
    total_memory_hits = sum(observed.values())

    if parse_errors:
        overall_status = "fail"
    elif total_memory_hits == 0:
        overall_status = "warn"
    elif args.require_mandatory_reasons and missing_mandatory:
        overall_status = "fail"
    elif missing_mandatory:
        overall_status = "warn"
    else:
        overall_status = "pass"

    report = {
        "schema_version": "aura.kids_memory_health_snapshot.v1",
        "overall_status": overall_status,
        "inputs": scanned_files,
        "guardian_policy_path": guardian_policy_path.as_posix(),
        "mandatory_reason_codes": mandatory_codes,
        "observed_counts": observed,
        "total_memory_hits": total_memory_hits,
        "missing_mandatory_reason_codes": missing_mandatory,
        "parse_errors": parse_errors,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"kids memory health snapshot written to {output_path.as_posix()}")
    print(f"overall_status={overall_status} total_memory_hits={total_memory_hits}")

    return 1 if overall_status == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
