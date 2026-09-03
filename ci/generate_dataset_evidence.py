#!/usr/bin/env python3

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


SCHEMA_VERSION = "aura.dataset_evidence.v1"
CHANGELOG_SCHEMA_VERSION = 1
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s\-]{6,}\d)(?!\d)")
SAFE_SENDER_ID_RE = re.compile(r"^[A-Za-z0-9_]+$")
CODE_SWITCH_PROVENANCE = "repository_owned_synthetic_seed"
CODE_SWITCH_REVIEW_STATUS = "developer_reviewed_not_independent_gold"
CODE_SWITCH_LANGUAGES = frozenset({"en", "uk", "ru"})
CODE_SWITCH_CONTEXT_ROLES = frozenset({"quote_report", "refusal", "crisis_support"})
CODE_SWITCH_ORIGINS = frozenset({"lexical", "compositional"})
CODE_SWITCH_EVENT_COMPATIBILITY = {
    "threat": frozenset({"physical_threat"}),
    "grooming": frozenset({"photo_request"}),
    "self_harm": frozenset({"suicidal_ideation"}),
    "manipulation": frozenset({"emotional_blackmail"}),
    "bullying": frozenset({"denigration"}),
    "explicit": frozenset({"sexual_content"}),
    "nsfw": frozenset({"sexual_content"}),
    "phishing": frozenset({"personal_info_request"}),
}
BENIGN_POLICY_EXPECTATION_CASES = frozenset(
    {"false_positive_friends", "negative_control_trusted_adult"}
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate dataset provenance, coverage, and privacy constraints."
    )
    parser.add_argument("--output", required=True, help="Path to dataset evidence JSON.")
    return parser.parse_args()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_digest(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": path.as_posix(),
        "bytes": len(data),
        "sha256": sha256(data).hexdigest(),
    }


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def counter_dict(values) -> dict[str, int]:
    counter = Counter(values)
    return {key: counter[key] for key in sorted(counter)}


def latest_entry(entries: list[dict]) -> dict | None:
    if not entries:
        return None
    return max(entries, key=lambda entry: entry["changed_at_ms"])


def validate_changelog(changelog: dict, errors: list[str]) -> dict[str, list[dict]]:
    ensure(
        changelog.get("schema_version") == CHANGELOG_SCHEMA_VERSION,
        f"dataset changelog schema_version must be {CHANGELOG_SCHEMA_VERSION}",
        errors,
    )
    datasets = changelog.get("datasets")
    ensure(isinstance(datasets, list) and datasets, "dataset changelog must contain datasets", errors)
    by_id: dict[str, list[dict]] = {}
    if not isinstance(datasets, list):
        return by_id

    for dataset in datasets:
        dataset_id = dataset.get("dataset_id", "").strip()
        ensure(bool(dataset_id), "dataset changelog entry has empty dataset_id", errors)
        entries = dataset.get("entries")
        ensure(
            isinstance(entries, list) and entries,
            f"dataset changelog for {dataset_id or '<unknown>'} must contain entries",
            errors,
        )
        if dataset_id and isinstance(entries, list):
            by_id[dataset_id] = entries
            for entry in entries:
                ensure(bool(entry.get("change_id", "").strip()), f"{dataset_id} changelog entry missing change_id", errors)
                ensure(entry.get("changed_at_ms", 0) > 0, f"{dataset_id} changelog entry has invalid changed_at_ms", errors)
                ensure(bool(entry.get("author", "").strip()), f"{dataset_id} changelog entry missing author", errors)
                ensure(bool(entry.get("change_kind", "").strip()), f"{dataset_id} changelog entry missing change_kind", errors)
                ensure(bool(entry.get("summary", "").strip()), f"{dataset_id} changelog entry missing summary", errors)
                slices = entry.get("affected_slices")
                ensure(
                    isinstance(slices, list) and slices,
                    f"{dataset_id} changelog entry must list affected_slices",
                    errors,
                )
                ensure(bool(entry.get("support_impact", "").strip()), f"{dataset_id} changelog entry missing support_impact", errors)
                ensure(bool(entry.get("review_ticket", "").strip()), f"{dataset_id} changelog entry missing review_ticket", errors)
    return by_id


def message_text_privacy_flags(text: str) -> list[str]:
    flags = []
    if EMAIL_RE.search(text):
        flags.append("email_like_text")
    if PHONE_RE.search(text):
        flags.append("phone_like_text")
    return flags


def validate_sender_ids(messages: list[dict], dataset_id: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    sample_ids: list[str] = []
    for message in messages:
        sender_id = message.get("sender_id")
        if sender_id is None:
            continue
        sample_ids.append(sender_id)
        if not SAFE_SENDER_ID_RE.fullmatch(sender_id):
            errors.append(f"{dataset_id} contains non-tokenized sender_id `{sender_id}`")
    return errors, sample_ids


def validate_realistic_dataset(dataset: dict, changelog_entries: list[dict] | None, path: Path) -> dict:
    errors: list[str] = []
    ensure(dataset.get("schema_version") == 1, "realistic dataset schema_version must be 1", errors)
    ensure(bool(dataset.get("dataset_id", "").strip()), "realistic dataset_id must not be empty", errors)
    ensure(bool(dataset.get("dataset_label", "").strip()), "realistic dataset_label must not be empty", errors)
    ensure(bool(dataset.get("maintainer", "").strip()), "realistic maintainer must not be empty", errors)
    ensure(dataset.get("created_at_ms", 0) > 0, "realistic created_at_ms must be non-zero", errors)
    ensure(dataset.get("updated_at_ms", 0) >= dataset.get("created_at_ms", 0), "realistic updated_at_ms must be >= created_at_ms", errors)

    cases = dataset.get("cases", [])
    ensure(isinstance(cases, list) and cases, "realistic dataset must contain cases", errors)
    case_ids = [case.get("id", "").strip() for case in cases if isinstance(case, dict)]
    ensure(len(case_ids) == len(set(case_ids)), "realistic dataset contains duplicate case ids", errors)

    all_messages: list[dict] = []
    for case in cases:
        if not isinstance(case, dict):
            errors.append("realistic dataset case must be an object")
            continue
        case_id = case.get("id", "<unknown>")
        for field in ("default_language", "age_band", "relationship"):
            ensure(bool(case.get(field, "").strip()), f"realistic case {case_id} missing {field}", errors)
        messages = case.get("messages", [])
        ensure(isinstance(messages, list) and messages, f"realistic case {case_id} must contain messages", errors)
        all_messages.extend(message for message in messages if isinstance(message, dict))
        for message in messages:
            if not isinstance(message, dict):
                errors.append(f"realistic case {case_id} contains non-object message")
                continue
            text = message.get("text", "")
            ensure(bool(text.strip()), f"realistic case {case_id} contains empty message text", errors)
            for flag in message_text_privacy_flags(text):
                errors.append(f"realistic case {case_id} contains {flag}")

    sender_errors, sender_ids = validate_sender_ids(all_messages, dataset["dataset_id"])
    errors.extend(sender_errors)

    latest = latest_entry(changelog_entries or [])
    if latest is None:
        errors.append(f"missing changelog entries for {dataset['dataset_id']}")
    else:
        ensure(
            latest["changed_at_ms"] == dataset["updated_at_ms"],
            f"realistic latest changelog timestamp {latest['changed_at_ms']} does not match dataset updated_at_ms {dataset['updated_at_ms']}",
            errors,
        )

    return {
        "dataset_type": "realistic_chat",
        "status": "pass" if not errors else "fail",
        "manifest": {
            "schema_version": dataset["schema_version"],
            "dataset_id": dataset["dataset_id"],
            "dataset_label": dataset["dataset_label"],
            "maintainer": dataset["maintainer"],
            "created_at_ms": dataset["created_at_ms"],
            "updated_at_ms": dataset["updated_at_ms"],
        },
        "files": [file_digest(path)],
        "coverage": {
            "case_count": len(cases),
            "language": counter_dict(case.get("default_language", "") for case in cases),
            "age_band": counter_dict(case.get("age_band", "") for case in cases),
            "relationship": counter_dict(case.get("relationship", "") for case in cases),
        },
        "privacy": {
            "sender_id_scheme": "token_like_only",
            "unique_sender_id_count": len(set(sender_ids)),
            "provided_sender_id_count": len(sender_ids),
        },
        "latest_changelog_entry": latest,
        "errors": errors,
    }


def validate_benign_dataset(dataset: dict, changelog_entries: list[dict] | None, path: Path) -> dict:
    """Benign corpus shares the realistic schema but must stay negatives-only."""
    report = validate_realistic_dataset(dataset, changelog_entries, path)
    errors = report["errors"]
    for case in dataset.get("cases", []):
        if not isinstance(case, dict):
            continue
        case_id = case.get("id", "<unknown>")
        ensure(case.get("primary_threat") is None, f"benign case {case_id} must not declare primary_threat", errors)
        ensure(case.get("onset_step") is None, f"benign case {case_id} must not declare onset_step", errors)
        ensure(
            case.get("policy_expectation_case") in BENIGN_POLICY_EXPECTATION_CASES,
            f"benign case {case_id} must reference a supported negative policy expectation case",
            errors,
        )
        ensure(bool(case.get("tracked_threats")), f"benign case {case_id} must list tracked_threats", errors)
        for message in case.get("messages", []):
            if isinstance(message, dict) and message.get("observed_threats"):
                errors.append(f"benign case {case_id} must not declare observed_threats")
    report["dataset_type"] = "benign_everyday_chat"
    report["status"] = "pass" if not errors else "fail"
    return report


def validate_external_dataset(dataset: dict, changelog_entries: list[dict] | None, path: Path) -> dict:
    errors: list[str] = []
    ensure(dataset.get("schema_version") == 1, "external dataset schema_version must be 1", errors)
    for field in ("dataset_id", "dataset_label", "curation_status", "maintainer"):
        ensure(bool(dataset.get(field, "").strip()), f"external {field} must not be empty", errors)
    ensure(dataset.get("created_at_ms", 0) > 0, "external created_at_ms must be non-zero", errors)
    ensure(dataset.get("updated_at_ms", 0) >= dataset.get("created_at_ms", 0), "external updated_at_ms must be >= created_at_ms", errors)

    cases = dataset.get("cases", [])
    ensure(isinstance(cases, list) and cases, "external dataset must contain cases", errors)
    case_ids = [case.get("id", "").strip() for case in cases if isinstance(case, dict)]
    ensure(len(case_ids) == len(set(case_ids)), "external dataset contains duplicate case ids", errors)

    all_messages: list[dict] = []
    for case in cases:
        if not isinstance(case, dict):
            errors.append("external dataset case must be an object")
            continue
        case_id = case.get("id", "<unknown>")
        for field in ("source_family", "review_status", "default_language", "age_band", "relationship"):
            ensure(bool(case.get(field, "").strip()), f"external case {case_id} missing {field}", errors)
        messages = case.get("messages", [])
        ensure(isinstance(messages, list) and messages, f"external case {case_id} must contain messages", errors)
        all_messages.extend(message for message in messages if isinstance(message, dict))
        for message in messages:
            if not isinstance(message, dict):
                errors.append(f"external case {case_id} contains non-object message")
                continue
            text = message.get("text", "")
            ensure(bool(text.strip()), f"external case {case_id} contains empty message text", errors)
            for flag in message_text_privacy_flags(text):
                errors.append(f"external case {case_id} contains {flag}")

    sender_errors, sender_ids = validate_sender_ids(all_messages, dataset["dataset_id"])
    errors.extend(sender_errors)

    latest = latest_entry(changelog_entries or [])
    if latest is None:
        errors.append(f"missing changelog entries for {dataset['dataset_id']}")
    else:
        ensure(
            latest["changed_at_ms"] == dataset["updated_at_ms"],
            f"external latest changelog timestamp {latest['changed_at_ms']} does not match dataset updated_at_ms {dataset['updated_at_ms']}",
            errors,
        )

    return {
        "dataset_type": "external_curated",
        "status": "pass" if not errors else "fail",
        "manifest": {
            "schema_version": dataset["schema_version"],
            "dataset_id": dataset["dataset_id"],
            "dataset_label": dataset["dataset_label"],
            "curation_status": dataset["curation_status"],
            "maintainer": dataset["maintainer"],
            "created_at_ms": dataset["created_at_ms"],
            "updated_at_ms": dataset["updated_at_ms"],
        },
        "files": [file_digest(path)],
        "coverage": {
            "case_count": len(cases),
            "language": counter_dict(case.get("default_language", "") for case in cases),
            "age_band": counter_dict(case.get("age_band", "") for case in cases),
            "relationship": counter_dict(case.get("relationship", "") for case in cases),
            "review_status": counter_dict(case.get("review_status", "") for case in cases),
            "source_family": counter_dict(case.get("source_family", "") for case in cases),
        },
        "privacy": {
            "sender_id_scheme": "token_like_only",
            "unique_sender_id_count": len(set(sender_ids)),
            "provided_sender_id_count": len(sender_ids),
        },
        "latest_changelog_entry": latest,
        "errors": errors,
    }


def validate_code_switch_dataset(
    dataset: dict, changelog_entries: list[dict] | None, path: Path
) -> dict:
    """Validate paired multilingual attribution boundaries used by core tests."""
    errors: list[str] = []
    ensure(dataset.get("schema_version") == 1, "code-switch schema_version must be 1", errors)
    for field in ("dataset_id", "dataset_label", "maintainer"):
        ensure(bool(dataset.get(field, "").strip()), f"code-switch {field} must not be empty", errors)
    ensure(
        dataset.get("created_at_ms", 0) > 0,
        "code-switch created_at_ms must be non-zero",
        errors,
    )
    ensure(
        dataset.get("updated_at_ms", 0) >= dataset.get("created_at_ms", 0),
        "code-switch updated_at_ms must be >= created_at_ms",
        errors,
    )
    ensure(
        dataset.get("provenance") == CODE_SWITCH_PROVENANCE,
        f"code-switch provenance must be {CODE_SWITCH_PROVENANCE}",
        errors,
    )
    ensure(
        dataset.get("review_status") == CODE_SWITCH_REVIEW_STATUS,
        f"code-switch review_status must be {CODE_SWITCH_REVIEW_STATUS}",
        errors,
    )

    pairs = dataset.get("pairs", [])
    ensure(isinstance(pairs, list) and pairs, "code-switch dataset must contain pairs", errors)
    pair_objects = [case for case in pairs if isinstance(case, dict)] if isinstance(pairs, list) else []
    ensure(
        len(pair_objects) == len(pairs) if isinstance(pairs, list) else False,
        "code-switch dataset pairs must be objects",
        errors,
    )
    case_ids = [case.get("case_id", "").strip() for case in pair_objects]
    ensure(all(case_ids), "code-switch case_id must not be empty", errors)
    ensure(len(case_ids) == len(set(case_ids)), "code-switch dataset contains duplicate case ids", errors)

    privacy_flag_count = 0
    for case in pair_objects:
        case_id = case.get("case_id") or "<unknown>"
        languages = case.get("languages", [])
        ensure(
            isinstance(languages, list)
            and len(languages) == 2
            and len(set(languages)) == 2
            and all(language in CODE_SWITCH_LANGUAGES for language in languages),
            f"code-switch case {case_id} must name two distinct supported languages",
            errors,
        )
        ensure(
            case.get("context_role") in CODE_SWITCH_CONTEXT_ROLES,
            f"code-switch case {case_id} has unsupported context_role",
            errors,
        )
        ensure(
            case.get("detector_origin") in CODE_SWITCH_ORIGINS,
            f"code-switch case {case_id} has unsupported detector_origin",
            errors,
        )

        threat_type = case.get("threat_type")
        event_kind = case.get("event_kind")
        ensure(
            threat_type in CODE_SWITCH_EVENT_COMPATIBILITY,
            f"code-switch case {case_id} has unsupported threat_type",
            errors,
        )
        if threat_type in CODE_SWITCH_EVENT_COMPATIBILITY:
            ensure(
                event_kind in CODE_SWITCH_EVENT_COMPATIBILITY[threat_type],
                f"code-switch case {case_id} has incompatible threat_type/event_kind",
                errors,
            )

        safe_text = case.get("safe_text", "")
        risky_text = case.get("risky_text", "")
        ensure(
            isinstance(safe_text, str) and bool(safe_text.strip()),
            f"code-switch case {case_id} has empty safe_text",
            errors,
        )
        ensure(
            isinstance(risky_text, str) and bool(risky_text.strip()),
            f"code-switch case {case_id} has empty risky_text",
            errors,
        )
        ensure(
            safe_text != risky_text,
            f"code-switch case {case_id} must contain distinct safe/risky counterfactuals",
            errors,
        )
        for polarity, text in (("safe", safe_text), ("risky", risky_text)):
            if not isinstance(text, str):
                continue
            for flag in message_text_privacy_flags(text):
                privacy_flag_count += 1
                errors.append(f"code-switch case {case_id} {polarity}_text contains {flag}")

    latest = latest_entry(changelog_entries or [])
    if latest is None:
        errors.append(f"missing changelog entries for {dataset.get('dataset_id', '<unknown>')}")
    else:
        ensure(
            latest["changed_at_ms"] == dataset.get("updated_at_ms"),
            f"code-switch latest changelog timestamp {latest['changed_at_ms']} does not match dataset updated_at_ms {dataset.get('updated_at_ms')}",
            errors,
        )

    language_pairs = []
    for case in pair_objects:
        languages = case.get("languages", [])
        if isinstance(languages, list) and len(languages) == 2:
            language_pairs.append("-".join(languages))

    return {
        "dataset_type": "code_switch_context_boundaries",
        "status": "pass" if not errors else "fail",
        "manifest": {
            "schema_version": dataset.get("schema_version"),
            "dataset_id": dataset.get("dataset_id"),
            "dataset_label": dataset.get("dataset_label"),
            "maintainer": dataset.get("maintainer"),
            "created_at_ms": dataset.get("created_at_ms"),
            "updated_at_ms": dataset.get("updated_at_ms"),
            "provenance": dataset.get("provenance"),
            "review_status": dataset.get("review_status"),
        },
        "files": [file_digest(path)],
        "coverage": {
            "pair_count": len(pair_objects),
            "language_pair": counter_dict(language_pairs),
            "context_role": counter_dict(case.get("context_role", "") for case in pair_objects),
            "detector_origin": counter_dict(case.get("detector_origin", "") for case in pair_objects),
            "threat_type": counter_dict(case.get("threat_type", "") for case in pair_objects),
            "event_kind": counter_dict(case.get("event_kind", "") for case in pair_objects),
        },
        "privacy": {
            "contains_direct_identifiers": privacy_flag_count > 0,
            "flag_count": privacy_flag_count,
        },
        "latest_changelog_entry": latest,
        "errors": errors,
    }


def main() -> int:
    args = parse_args()
    workspace_root = Path(__file__).resolve().parents[1]
    realistic_path = workspace_root / "crates/aura-core/data/realistic_chat_cases.json"
    external_path = workspace_root / "crates/aura-core/data/external_curated_chat_cases.json"
    benign_path = workspace_root / "crates/aura-core/data/benign_everyday_chat_cases.json"
    code_switch_path = workspace_root / "crates/aura-core/data/code_switch_context_cases.json"
    changelog_path = workspace_root / "crates/aura-core/data/dataset_changelog.json"

    realistic = load_json(realistic_path)
    external = load_json(external_path)
    benign = load_json(benign_path)
    code_switch = load_json(code_switch_path)
    changelog = load_json(changelog_path)

    changelog_errors: list[str] = []
    changelog_by_dataset = validate_changelog(changelog, changelog_errors)

    realistic_report = validate_realistic_dataset(
        realistic,
        changelog_by_dataset.get(realistic.get("dataset_id", "")),
        realistic_path,
    )
    external_report = validate_external_dataset(
        external,
        changelog_by_dataset.get(external.get("dataset_id", "")),
        external_path,
    )
    benign_report = validate_benign_dataset(
        benign,
        changelog_by_dataset.get(benign.get("dataset_id", "")),
        benign_path,
    )
    code_switch_report = validate_code_switch_dataset(
        code_switch,
        changelog_by_dataset.get(code_switch.get("dataset_id", "")),
        code_switch_path,
    )

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "status": "pass",
        "dataset_changelog": {
            "path": changelog_path.as_posix(),
            **file_digest(changelog_path),
            "status": "pass" if not changelog_errors else "fail",
            "errors": changelog_errors,
        },
        "datasets": [realistic_report, external_report, benign_report, code_switch_report],
    }

    if changelog_errors or any(dataset["status"] != "pass" for dataset in evidence["datasets"]):
        evidence["status"] = "fail"

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0 if evidence["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
