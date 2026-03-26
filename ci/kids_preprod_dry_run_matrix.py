#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

SCHEMA_VERSION = "aura.kids_preprod_dry_run_matrix.v1"

REQUIRED_HARMFUL_SLICES = [
    "classic_grooming",
    "trusted_adult_grooming",
    "screenshot_blackmail",
    "sustained_sextortion_progression",
    "group_bullying",
    "bullying_selfharm_cascade",
    "acute_selfharm",
    "suicide_coercion",
    "phishing_link",
    "mixed_language_grooming",
    "mixed_language_group_bullying",
    "mixed_language_selfharm_crisis",
    "mixed_language_image_blackmail",
    "noisy_shorthand_grooming",
]

REQUIRED_BENIGN_SLICES = [
    "negative_control_trusted_adult",
    "negative_control_teen_flirting",
    "false_positive_friends",
    "negative_control_multilingual_support",
    "negative_control_multilingual_peer_chat",
    "bystander_rescue",
]

REQUIRED_MEMORY_REASON_CODES = [
    "kids.memory.grooming_progression",
    "kids.memory.sustained_sextortion",
    "kids.memory.bullying_cascade_selfharm",
    "kids.memory.sender_risk_accumulation",
    "kids.memory.new_sender_fast_escalation",
    "kids.memory.cross_conversation_repeat_offender",
    "kids.memory.victim_vulnerability_targeting",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a KIDS pre-prod dry-run matrix report by validating strict "
            "slice coverage and memory-health contract."
        )
    )
    parser.add_argument(
        "--policy-expectations",
        default="crates/aura-core/data/action_policy_expectations.json",
        help="Path to action policy expectations JSON.",
    )
    parser.add_argument(
        "--realistic-cases",
        default="crates/aura-core/data/realistic_chat_cases.json",
        help="Path to realistic chat cases JSON.",
    )
    parser.add_argument(
        "--kids-memory-health",
        default="artifacts/kids-memory-health.json",
        help="Path to strict kids-memory health JSON artifact.",
    )
    parser.add_argument(
        "--output",
        default="artifacts/kids-preprod-dry-run-matrix.json",
        help="Output path for pre-prod matrix report.",
    )
    return parser.parse_args()


def read_json(path: Path) -> tuple[dict | None, str | None]:
    if not path.exists():
        return None, "missing_file"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as err:  # noqa: BLE001
        return None, f"invalid_json: {err}"
    if not isinstance(payload, dict):
        return None, "invalid_json_root"
    return payload, None


def collect_policy_scenarios(payload: dict) -> set[str]:
    items = payload.get("scenarios")
    if not isinstance(items, list):
        return set()
    scenarios = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        scenario_name = item.get("scenario_name")
        if isinstance(scenario_name, str):
            scenarios.add(scenario_name)
    return scenarios


def collect_realistic_policy_cases(payload: dict) -> set[str]:
    items = payload.get("cases")
    if not isinstance(items, list):
        return set()
    scenarios = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        scenario_name = item.get("policy_expectation_case")
        if isinstance(scenario_name, str):
            scenarios.add(scenario_name)
    return scenarios


def list_missing(required: list[str], observed: set[str]) -> list[str]:
    missing = []
    for item in required:
        if item not in observed:
            missing.append(item)
    return missing


def main() -> int:
    args = parse_args()
    policy_path = Path(args.policy_expectations)
    realistic_path = Path(args.realistic_cases)
    health_path = Path(args.kids_memory_health)
    output_path = Path(args.output)

    policy_payload, policy_error = read_json(policy_path)
    realistic_payload, realistic_error = read_json(realistic_path)
    health_payload, health_error = read_json(health_path)

    errors = []
    if policy_error is not None:
        errors.append({"artifact": "policy_expectations", "error": policy_error})
    if realistic_error is not None:
        errors.append({"artifact": "realistic_cases", "error": realistic_error})
    if health_error is not None:
        errors.append({"artifact": "kids_memory_health", "error": health_error})

    policy_scenarios = set()
    if policy_payload is not None:
        policy_scenarios = collect_policy_scenarios(policy_payload)

    realistic_scenarios = set()
    if realistic_payload is not None:
        realistic_scenarios = collect_realistic_policy_cases(realistic_payload)

    missing_policy_harmful = list_missing(REQUIRED_HARMFUL_SLICES, policy_scenarios)
    missing_policy_benign = list_missing(REQUIRED_BENIGN_SLICES, policy_scenarios)
    missing_realistic_harmful = list_missing(REQUIRED_HARMFUL_SLICES, realistic_scenarios)
    missing_realistic_benign = list_missing(REQUIRED_BENIGN_SLICES, realistic_scenarios)

    health_status = None
    total_memory_hits = None
    health_missing_codes = []
    missing_required_memory_codes = []
    if health_payload is not None:
        status_value = health_payload.get("overall_status")
        if isinstance(status_value, str):
            health_status = status_value
        total_hits_value = health_payload.get("total_memory_hits")
        if isinstance(total_hits_value, int):
            total_memory_hits = total_hits_value
        observed_missing = health_payload.get("missing_mandatory_reason_codes", [])
        if isinstance(observed_missing, list):
            for reason_code in observed_missing:
                if isinstance(reason_code, str):
                    health_missing_codes.append(reason_code)
        observed_counts = health_payload.get("observed_counts", {})
        if isinstance(observed_counts, dict):
            for reason_code in REQUIRED_MEMORY_REASON_CODES:
                count = observed_counts.get(reason_code)
                if not isinstance(count, int) or count <= 0:
                    missing_required_memory_codes.append(reason_code)
        else:
            missing_required_memory_codes = list(REQUIRED_MEMORY_REASON_CODES)

    checks = {
        "policy_harmful_slices_complete": len(missing_policy_harmful) == 0,
        "policy_benign_slices_complete": len(missing_policy_benign) == 0,
        "realistic_harmful_slices_complete": len(missing_realistic_harmful) == 0,
        "realistic_benign_slices_complete": len(missing_realistic_benign) == 0,
        "kids_memory_health_is_pass": health_status == "pass",
        "kids_memory_total_hits_positive": (
            isinstance(total_memory_hits, int) and total_memory_hits > 0
        ),
        "kids_memory_missing_codes_empty": len(health_missing_codes) == 0,
        "required_memory_codes_observed": len(missing_required_memory_codes) == 0,
        "artifacts_loaded_without_errors": len(errors) == 0,
    }

    overall_status = "pass"
    for check_value in checks.values():
        if not check_value:
            overall_status = "fail"
            break

    report = {
        "schema_version": SCHEMA_VERSION,
        "overall_status": overall_status,
        "inputs": {
            "policy_expectations": policy_path.as_posix(),
            "realistic_cases": realistic_path.as_posix(),
            "kids_memory_health": health_path.as_posix(),
        },
        "checks": checks,
        "required": {
            "harmful_slices": REQUIRED_HARMFUL_SLICES,
            "benign_slices": REQUIRED_BENIGN_SLICES,
            "memory_reason_codes": REQUIRED_MEMORY_REASON_CODES,
        },
        "missing": {
            "policy_harmful_slices": missing_policy_harmful,
            "policy_benign_slices": missing_policy_benign,
            "realistic_harmful_slices": missing_realistic_harmful,
            "realistic_benign_slices": missing_realistic_benign,
            "health_reported_memory_codes": health_missing_codes,
            "required_memory_codes": missing_required_memory_codes,
        },
        "health_snapshot": {
            "overall_status": health_status,
            "total_memory_hits": total_memory_hits,
        },
        "errors": errors,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"kids preprod dry-run matrix written to {output_path.as_posix()} "
        f"(overall_status={overall_status})"
    )

    if overall_status != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
