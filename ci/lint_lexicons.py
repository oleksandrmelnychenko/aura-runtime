#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path


REPO_LEXICONS = [
    "crates/aura-kids/data/lexicon.json",
    "crates/aura-military/data/lexicon.json",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lint AURA domain lexicon packs for semantic consistency."
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        default=REPO_LEXICONS,
        help="Lexicon JSON paths (repo-relative).",
    )
    return parser.parse_args()


def ensure(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def lint_pack(path: Path, errors: list[str]) -> tuple[set[str], set[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    schema_version = data.get("schema_version")
    ensure(
        schema_version == 1,
        f"{path.as_posix()}: schema_version must be 1, got {schema_version}",
        errors,
    )

    threat_keys: set[str] = set()
    reason_codes: set[str] = set()
    local_threat_keys: set[str] = set()
    local_reason_codes: set[str] = set()

    for section_name, section_rules in data.items():
        if section_name == "schema_version":
            continue
        if section_name == "policy":
            prefix = f"{path.as_posix()}::policy"
            ensure(isinstance(section_rules, dict), f"{prefix}: policy must be an object", errors)
            if not isinstance(section_rules, dict):
                continue
            warn_priority = section_rules.get("warn_priority")
            critical_warn_priority = section_rules.get("critical_warn_priority")
            ensure(
                isinstance(warn_priority, int) and 1 <= warn_priority <= 100,
                f"{prefix}: warn_priority must be integer in [1,100], got {warn_priority}",
                errors,
            )
            ensure(
                isinstance(critical_warn_priority, int)
                and 1 <= critical_warn_priority <= 100,
                (
                    f"{prefix}: critical_warn_priority must be integer in [1,100], "
                    f"got {critical_warn_priority}"
                ),
                errors,
            )
            if isinstance(warn_priority, int) and isinstance(critical_warn_priority, int):
                ensure(
                    critical_warn_priority >= warn_priority,
                    (
                        f"{prefix}: critical_warn_priority ({critical_warn_priority}) must be "
                        f">= warn_priority ({warn_priority})"
                    ),
                    errors,
                )
            guardian_escalation_priority = section_rules.get("guardian_escalation_priority")
            if guardian_escalation_priority is not None:
                ensure(
                    isinstance(guardian_escalation_priority, int)
                    and 1 <= guardian_escalation_priority <= 100,
                    (
                        f"{prefix}: guardian_escalation_priority must be integer in [1,100], "
                        f"got {guardian_escalation_priority}"
                    ),
                    errors,
                )
            priority_escalation_priority = section_rules.get("priority_escalation_priority")
            if priority_escalation_priority is not None:
                ensure(
                    isinstance(priority_escalation_priority, int)
                    and 1 <= priority_escalation_priority <= 100,
                    (
                        f"{prefix}: priority_escalation_priority must be integer in [1,100], "
                        f"got {priority_escalation_priority}"
                    ),
                    errors,
                )
            continue
        if not isinstance(section_rules, list):
            errors.append(f"{path.as_posix()}: section `{section_name}` must be an array")
            continue
        for idx, rule in enumerate(section_rules):
            prefix = f"{path.as_posix()}::{section_name}[{idx}]"
            if not isinstance(rule, dict):
                errors.append(f"{prefix}: rule must be an object")
                continue
            threat_key = str(rule.get("threat_key", "")).strip()
            reason_code = str(rule.get("reason_code", "")).strip()
            score = rule.get("score")
            threat_type = str(rule.get("threat_type", "")).strip()
            severity = str(rule.get("severity", "")).strip()
            priority = rule.get("priority")
            action = str(rule.get("action", "")).strip()
            all_of = rule.get("all_of", [])
            any_of = rule.get("any_of", [])
            any_groups = rule.get("any_groups", [])

            ensure(bool(threat_key), f"{prefix}: empty threat_key", errors)
            ensure(bool(reason_code), f"{prefix}: empty reason_code", errors)
            ensure(
                isinstance(score, (int, float)) and 0.0 <= float(score) <= 1.0,
                f"{prefix}: score must be in [0,1], got {score}",
                errors,
            )
            ensure(
                bool(threat_type),
                f"{prefix}: threat_type must be set",
                errors,
            )
            ensure(
                threat_type
                in {
                    "none",
                    "bullying",
                    "grooming",
                    "explicit",
                    "threat",
                    "self_harm",
                    "spam",
                    "scam",
                    "phishing",
                    "manipulation",
                    "nsfw",
                    "hate_speech",
                    "doxxing",
                    "pii_leakage",
                    "propaganda",
                    "opsec_violation",
                    "psyops",
                    "military_social_eng",
                    "coordinate_leak",
                },
                f"{prefix}: invalid threat_type `{threat_type}`",
                errors,
            )
            ensure(
                severity in {"low", "medium", "high", "critical"},
                f"{prefix}: severity must be one of low/medium/high/critical",
                errors,
            )
            ensure(
                isinstance(priority, int) and 1 <= priority <= 100,
                f"{prefix}: priority must be integer in [1,100], got {priority}",
                errors,
            )
            if action:
                ensure(
                    action in {"allow", "mark", "warn", "block"},
                    f"{prefix}: action must be one of allow/mark/warn/block",
                    errors,
                )

            ensure(isinstance(all_of, list), f"{prefix}: all_of must be an array", errors)
            ensure(isinstance(any_of, list), f"{prefix}: any_of must be an array", errors)
            ensure(
                isinstance(any_groups, list), f"{prefix}: any_groups must be an array", errors
            )

            has_matchers = bool(all_of) or bool(any_of) or bool(any_groups)
            ensure(
                has_matchers,
                f"{prefix}: must define all_of, any_of, or any_groups",
                errors,
            )

            if threat_key:
                if threat_key in local_threat_keys:
                    errors.append(f"{prefix}: duplicate threat_key `{threat_key}` in same pack")
                local_threat_keys.add(threat_key)
                threat_keys.add(threat_key)
            if reason_code:
                if reason_code in local_reason_codes:
                    errors.append(f"{prefix}: duplicate reason_code `{reason_code}` in same pack")
                local_reason_codes.add(reason_code)
                reason_codes.add(reason_code)

    return threat_keys, reason_codes


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    global_threat_keys: dict[str, str] = {}
    global_reason_codes: dict[str, str] = {}

    for rel in args.paths:
        path = root / rel
        if not path.exists():
            errors.append(f"missing lexicon file: {rel}")
            continue
        threat_keys, reason_codes = lint_pack(path, errors)
        for threat_key in threat_keys:
            existing = global_threat_keys.get(threat_key)
            if existing and existing != rel:
                errors.append(
                    f"duplicate threat_key across packs: `{threat_key}` in {existing} and {rel}"
                )
            global_threat_keys[threat_key] = rel
        for reason_code in reason_codes:
            existing = global_reason_codes.get(reason_code)
            if existing and existing != rel:
                errors.append(
                    f"duplicate reason_code across packs: `{reason_code}` in {existing} and {rel}"
                )
            global_reason_codes[reason_code] = rel

    if errors:
        for error in errors:
            print(f"LEXICON_LINT_ERROR: {error}")
        return 1

    print("Lexicon lint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
