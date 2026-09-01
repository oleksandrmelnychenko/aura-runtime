#!/usr/bin/env python3
"""Build and evaluate the AURA internal blinded conversation holdout.

The workflow deliberately separates authoring, annotation, adjudication,
freezing, and detector execution. It never includes message plaintext in an
evaluation report. This is internal blinded evidence, not external validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "aura.internal_blind_holdout_manifest.v1"
FAMILIES = (
    "grooming",
    "manipulation",
    "bullying",
    "self_harm",
    "threat",
    "explicit",
    "nsfw",
    "phishing",
)
ALL_PROBE_FAMILIES = (
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
)
ACTION_SEVERITY = {"allow": 0, "mark": 1, "warn": 2, "blur": 3, "block": 4}
PII_PATTERNS = {
    "email": re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
    "url": re.compile(r"(?i)\b(?:https?://|www\.)\S+"),
    "handle": re.compile(r"(?<!\w)@[A-Za-z0-9_]{2,}"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "phone": re.compile(r"(?<!\w)(?:\+?\d[\s().-]*){7,}(?!\w)"),
}
SAFE_PLACEHOLDERS = ("[LINK]", "[PHONE]", "[HANDLE]", "[LOCATION]")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    assignments = commands.add_parser("assignments")
    assignments.add_argument("--protocol", type=Path, required=True)
    assignments.add_argument("--output", type=Path, required=True)

    authoring_packets = commands.add_parser("authoring-packets")
    authoring_packets.add_argument("--protocol", type=Path, required=True)
    authoring_packets.add_argument("--assignments", type=Path, required=True)
    authoring_packets.add_argument("--output-dir", type=Path, required=True)

    packets = commands.add_parser("packets")
    packets.add_argument("--protocol", type=Path, required=True)
    packets.add_argument("--assignments", type=Path, required=True)
    packets.add_argument("--cases", type=Path, required=True)
    packets.add_argument("--output-dir", type=Path, required=True)
    packets.add_argument("--reference-json", type=Path, action="append", default=[])
    packets.add_argument("--allow-partial", action="store_true")

    adjudicate = commands.add_parser("adjudicate")
    adjudicate.add_argument("--cases", type=Path, required=True)
    adjudicate.add_argument("--review-a", type=Path, nargs="+", required=True)
    adjudicate.add_argument("--review-b", type=Path, nargs="+", required=True)
    adjudicate.add_argument("--review-c", type=Path, nargs="+", default=[])
    adjudicate.add_argument("--gold-output", type=Path, required=True)
    adjudicate.add_argument("--report-output", type=Path, required=True)

    freeze = commands.add_parser("freeze")
    freeze.add_argument("--protocol", type=Path, required=True)
    freeze.add_argument("--assignments", type=Path, required=True)
    freeze.add_argument("--cases", type=Path, required=True)
    freeze.add_argument("--gold", type=Path, required=True)
    freeze.add_argument("--adjudication-report", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)

    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--manifest", type=Path, required=True)
    evaluate.add_argument("--protocol", type=Path, required=True)
    evaluate.add_argument("--assignments", type=Path, required=True)
    evaluate.add_argument("--cases", type=Path, required=True)
    evaluate.add_argument("--gold", type=Path, required=True)
    evaluate.add_argument("--probe", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)

    return root


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def load_jsonl(paths: Path | Iterable[Path]) -> list[dict[str, Any]]:
    if isinstance(paths, Path):
        paths = [paths]
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(f"{path}:{line_number} must be an object")
                rows.append(row)
    return rows


def write_json(path: Path, value: Any) -> None:
    refuse_overwrite(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    refuse_overwrite(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
    )
    path.write_text(payload, encoding="utf-8")


def refuse_overwrite(path: Path) -> None:
    if path.exists():
        raise ValueError(f"refusing to replace existing output: {path}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hex(value: str, length: int = 24) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def validate_protocol(protocol: dict[str, Any]) -> None:
    if protocol.get("schema_version") != "aura.internal_blind_holdout_protocol.v1":
        raise ValueError("unsupported holdout protocol schema")
    if tuple(protocol.get("threat_families", [])) != FAMILIES:
        raise ValueError("protocol threat families drifted from the evaluator contract")
    languages = protocol.get("languages")
    if languages != ["en", "uk", "ru"]:
        raise ValueError("v1 protocol requires canonical en/uk/ru order")
    if int(protocol.get("pairs_per_language_family", 0)) < 10:
        raise ValueError("each language/family slice requires at least 10 pairs")


def assignment_rows(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    risky_roles = protocol["risky_context_roles"]
    safe_roles = protocol["safe_context_roles"]
    obfuscations = protocol["obfuscation_modes"]
    relationships = protocol["allowed_relationships"]
    trust_sources = protocol["allowed_trust_sources"]
    rows = []
    for language in protocol["languages"]:
        for family in protocol["threat_families"]:
            for index in range(protocol["pairs_per_language_family"]):
                pair_id = f"ihv1-{language}-{family}-{index + 1:02d}"
                account_type = "child" if index % 2 == 0 else "teen"
                age = 12 if account_type == "child" else 15
                relationship = relationships[index % len(relationships)]
                trust_source = trust_sources[index % len(trust_sources)]
                code_switch_language = None
                if index in (3, 7):
                    alternatives = [item for item in protocol["languages"] if item != language]
                    code_switch_language = alternatives[(index // 4) % len(alternatives)]
                for polarity, roles in (("risky", risky_roles), ("safe", safe_roles)):
                    assignment_id = f"{pair_id}-{polarity}"
                    rows.append(
                        {
                            "assignment_id": assignment_id,
                            "case_id": f"ihv1-case-{stable_hex(assignment_id)}",
                            "pair_id": pair_id,
                            "language": language,
                            "target_family": family,
                            "target_polarity": polarity,
                            "context_role": roles[index % len(roles)],
                            "obfuscation": obfuscations[index % len(obfuscations)],
                            "code_switch_language": code_switch_language,
                            "account_type": account_type,
                            "account_holder_age": age,
                            "conversation_type": "group" if index in (4, 9) else "direct",
                            "sender_relationship": relationship,
                            "relationship_trust_source": trust_source,
                            "minimum_messages": protocol["messages_per_conversation"]["minimum"],
                            "maximum_messages": protocol["messages_per_conversation"]["maximum"],
                            "author_boundary": (
                                "Write original synthetic dialogue only; use placeholders for "
                                "identifiers; do not inspect AURA rules, outputs, or failed IDs."
                            ),
                        }
                    )
    return rows


def cmd_assignments(args: argparse.Namespace) -> int:
    protocol = load_json(args.protocol)
    validate_protocol(protocol)
    rows = assignment_rows(protocol)
    write_jsonl(args.output, rows)
    summary = {
        "status": "pass",
        "assignments": len(rows),
        "pairs": len(rows) // 2,
        "languages": protocol["languages"],
        "families": protocol["threat_families"],
        "output": str(args.output),
        "sha256": sha256_file(args.output),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


def cmd_authoring_packets(args: argparse.Namespace) -> int:
    protocol = load_json(args.protocol)
    validate_protocol(protocol)
    rows = load_jsonl(args.assignments)
    expected = assignment_rows(protocol)
    if rows != expected:
        raise ValueError("assignment matrix does not match the canonical protocol expansion")
    if args.output_dir.exists():
        raise ValueError(f"refusing to replace existing output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    identities = {}
    for language in protocol["languages"]:
        path = args.output_dir / f"authoring-{language}.jsonl"
        write_jsonl(path, (row for row in rows if row["language"] == language))
        identities[language] = file_identity(path)
    write_json(
        args.output_dir / "authoring-packet-manifest.json",
        {
            "schema_version": "aura.internal_holdout_authoring_packets.v1",
            "status": "ready",
            "assignment_matrix": file_identity(args.assignments),
            "packets": identities,
            "claim_boundary": protocol["claim_boundary"],
        },
    )
    print(
        json.dumps(
            {"status": "ready", "packet_count": 3, "output_dir": str(args.output_dir)},
            sort_keys=True,
        )
    )
    return 0


def index_unique(rows: list[dict[str, Any]], field: str, label: str) -> dict[str, dict]:
    result = {}
    for row in rows:
        key = row.get(field)
        if not isinstance(key, str) or not key:
            raise ValueError(f"{label} has missing {field}")
        if key in result:
            raise ValueError(f"duplicate {label} {field}: {key}")
        result[key] = row
    return result


def stripped_for_pii(text: str) -> str:
    for placeholder in SAFE_PLACEHOLDERS:
        text = text.replace(placeholder, "")
    return text


def normalize_text(text: str) -> str:
    return " ".join(re.findall(r"\w+", text.casefold(), flags=re.UNICODE))


def token_set(text: str) -> set[str]:
    return set(normalize_text(text).split())


def recursive_texts(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "text" and isinstance(nested, str):
                yield nested
            else:
                yield from recursive_texts(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from recursive_texts(nested)


def validate_case(
    case: dict[str, Any], assignment: dict[str, Any], protocol: dict[str, Any]
) -> list[str]:
    errors = []
    exact_fields = (
        "case_id",
        "assignment_id",
        "language",
        "account_type",
        "account_holder_age",
        "conversation_type",
        "sender_relationship",
        "relationship_trust_source",
        "messages",
        "author_certification",
    )
    unknown = sorted(set(case) - set(exact_fields))
    if unknown:
        errors.append(f"unknown fields: {unknown}")
    for field in (
        "case_id",
        "language",
        "account_type",
        "account_holder_age",
        "conversation_type",
        "sender_relationship",
        "relationship_trust_source",
    ):
        expected = assignment[field]
        if case.get(field) != expected:
            errors.append(f"{field} must equal assignment value {expected!r}")
    messages = case.get("messages")
    if not isinstance(messages, list):
        return errors + ["messages must be an array"]
    minimum = protocol["messages_per_conversation"]["minimum"]
    maximum = protocol["messages_per_conversation"]["maximum"]
    if not minimum <= len(messages) <= maximum:
        errors.append(f"messages must contain {minimum}..={maximum} turns")
    total_bytes = 0
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            errors.append(f"message {index} must be an object")
            continue
        if set(message) - {"speaker", "text", "language"}:
            errors.append(f"message {index} has unknown fields")
        if message.get("speaker") not in ("protected", "other"):
            errors.append(f"message {index} has invalid speaker")
        text = message.get("text")
        if not isinstance(text, str) or not text.strip():
            errors.append(f"message {index} text must be non-empty")
            continue
        size = len(text.encode("utf-8"))
        total_bytes += size
        if size > protocol["maximum_message_bytes"]:
            errors.append(f"message {index} exceeds maximum bytes")
        inspected = stripped_for_pii(text)
        for label, pattern in PII_PATTERNS.items():
            if pattern.search(inspected):
                errors.append(f"message {index} contains possible {label}; use placeholder")
        if message.get("language", case.get("language")) not in protocol["languages"]:
            errors.append(f"message {index} has unsupported language")
    if total_bytes > protocol["maximum_conversation_bytes"]:
        errors.append("conversation exceeds maximum bytes")
    certification = case.get("author_certification")
    required_certifications = (
        "original_synthetic_text",
        "no_real_child_data",
        "no_direct_identifiers",
        "no_detector_access",
    )
    if not isinstance(certification, dict) or any(
        certification.get(name) is not True for name in required_certifications
    ):
        errors.append("all author certifications must be true")
    if case.get("account_type") == "child" and not 9 <= case.get("account_holder_age", 0) <= 12:
        errors.append("child age must be 9..=12")
    if case.get("account_type") == "teen" and not 13 <= case.get("account_holder_age", 0) <= 17:
        errors.append("teen age must be 13..=17")
    return errors


def validate_cases(
    protocol: dict[str, Any],
    assignments: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    reference_paths: list[Path],
    allow_partial: bool,
) -> dict[str, Any]:
    assignment_index = index_unique(assignments, "assignment_id", "assignment")
    case_index = index_unique(cases, "case_id", "case")
    errors = []
    seen_assignments = set()
    normalized_owner: dict[str, str] = {}
    reference_sets = []
    reference_hashes = {}
    for path in reference_paths:
        reference_hashes[str(path)] = sha256_file(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        reference_sets.extend(
            (normalize_text(text), token_set(text)) for text in recursive_texts(data)
        )
    for case_id, case in case_index.items():
        assignment_id = case.get("assignment_id")
        assignment = assignment_index.get(assignment_id)
        if assignment is None:
            errors.append(f"{case_id}: unknown assignment_id {assignment_id!r}")
            continue
        if assignment_id in seen_assignments:
            errors.append(f"{case_id}: assignment reused: {assignment_id}")
        seen_assignments.add(assignment_id)
        for error in validate_case(case, assignment, protocol):
            errors.append(f"{case_id}: {error}")
        for message in case.get("messages", []):
            text = message.get("text")
            if not isinstance(text, str):
                continue
            normalized = normalize_text(text)
            if normalized in normalized_owner:
                errors.append(
                    f"{case_id}: exact normalized duplicate of {normalized_owner[normalized]}"
                )
            normalized_owner[normalized] = case_id
            tokens = token_set(text)
            if len(tokens) >= 8:
                for reference_text, reference_tokens in reference_sets:
                    if normalized == reference_text:
                        errors.append(f"{case_id}: exact match to governed reference corpus")
                        break
                    union = len(tokens | reference_tokens)
                    if union and len(tokens & reference_tokens) / union >= 0.90:
                        errors.append(f"{case_id}: near-duplicate of governed reference corpus")
                        break
    missing = sorted(set(assignment_index) - seen_assignments)
    if missing and not allow_partial:
        errors.append(f"missing {len(missing)} assignment cases")
    return {
        "status": "pass" if not errors else "fail",
        "assignment_count": len(assignments),
        "case_count": len(cases),
        "missing_assignment_count": len(missing),
        "errors": errors,
        "reference_sha256": reference_hashes,
    }


def annotation_packet_row(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case["case_id"],
        "language": case["language"],
        "account_type": case["account_type"],
        "account_holder_age": case["account_holder_age"],
        "conversation_type": case["conversation_type"],
        "sender_relationship": case["sender_relationship"],
        "relationship_trust_source": case["relationship_trust_source"],
        "messages": case["messages"],
        "annotation": {
            "case_id": case["case_id"],
            "reviewer_id": None,
            "included": None,
            "primary_threat": None,
            "onset_turn": None,
            "minimum_action": None,
            "naturalness": None,
            "confidence": None,
            "contains_pii": None,
            "exclusion_reason": None,
            "notes": None,
        },
    }


def cmd_packets(args: argparse.Namespace) -> int:
    protocol = load_json(args.protocol)
    validate_protocol(protocol)
    assignments = load_jsonl(args.assignments)
    cases = load_jsonl(args.cases)
    report = validate_cases(
        protocol, assignments, cases, args.reference_json, args.allow_partial
    )
    if report["status"] != "pass":
        print(json.dumps(report, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1
    if args.output_dir.exists():
        raise ValueError(f"refusing to replace existing output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    for language in protocol["languages"]:
        language_cases = [case for case in cases if case["language"] == language]
        for reviewer in ("a", "b"):
            ordered = sorted(
                language_cases,
                key=lambda case: stable_hex(f"{reviewer}\0{case['case_id']}", 64),
            )
            write_jsonl(
                args.output_dir / f"annotation-{language}-{reviewer}.jsonl",
                (annotation_packet_row(case) for case in ordered),
            )
    write_json(args.output_dir / "validation-report.json", report)
    print(
        json.dumps(
            {
                "status": "pass",
                "case_count": len(cases),
                "packet_count": 6,
                "output_dir": str(args.output_dir),
            },
            sort_keys=True,
        )
    )
    return 0


def extract_annotation(row: dict[str, Any]) -> dict[str, Any]:
    annotation = row.get("annotation", row)
    if not isinstance(annotation, dict):
        raise ValueError("annotation must be an object")
    return annotation


def validate_annotation(annotation: dict[str, Any], case: dict[str, Any]) -> None:
    if annotation.get("case_id") != case["case_id"]:
        raise ValueError(f"annotation case_id mismatch for {case['case_id']}")
    reviewer = annotation.get("reviewer_id")
    if not isinstance(reviewer, str) or not re.fullmatch(r"[a-z0-9_-]{3,32}", reviewer):
        raise ValueError(f"invalid reviewer_id for {case['case_id']}")
    if not isinstance(annotation.get("included"), bool):
        raise ValueError(f"included must be boolean for {case['case_id']}")
    threat = annotation.get("primary_threat")
    if threat not in ("none", *FAMILIES):
        raise ValueError(f"invalid primary_threat for {case['case_id']}")
    onset = annotation.get("onset_turn")
    if threat == "none" and onset is not None:
        raise ValueError(f"safe annotation must have null onset for {case['case_id']}")
    if threat != "none" and (not isinstance(onset, int) or not 0 <= onset < len(case["messages"])):
        raise ValueError(f"risky annotation requires valid onset for {case['case_id']}")
    if annotation.get("minimum_action") not in ("allow", "warn", "block"):
        raise ValueError(f"invalid minimum_action for {case['case_id']}")
    if not isinstance(annotation.get("naturalness"), int) or not 1 <= annotation["naturalness"] <= 5:
        raise ValueError(f"invalid naturalness for {case['case_id']}")
    if not isinstance(annotation.get("confidence"), int) or not 1 <= annotation["confidence"] <= 5:
        raise ValueError(f"invalid confidence for {case['case_id']}")
    if not isinstance(annotation.get("contains_pii"), bool):
        raise ValueError(f"contains_pii must be boolean for {case['case_id']}")
    if annotation["included"] and annotation["contains_pii"]:
        raise ValueError(f"included case cannot contain PII: {case['case_id']}")


def annotation_index(paths: list[Path], cases: dict[str, dict]) -> dict[str, dict]:
    result = {}
    for row in load_jsonl(paths):
        annotation = extract_annotation(row)
        case_id = annotation.get("case_id")
        if case_id not in cases:
            raise ValueError(f"annotation references unknown case: {case_id}")
        if case_id in result:
            raise ValueError(f"duplicate annotation: {case_id}")
        validate_annotation(annotation, cases[case_id])
        result[case_id] = annotation
    return result


def cohen_kappa(left: list[str], right: list[str]) -> float:
    if not left:
        return 0.0
    observed = sum(a == b for a, b in zip(left, right, strict=True)) / len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    labels = set(left_counts) | set(right_counts)
    expected = sum(
        (left_counts[label] / len(left)) * (right_counts[label] / len(right))
        for label in labels
    )
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1.0 - expected)


def annotations_agree(left: dict[str, Any], right: dict[str, Any]) -> bool:
    fields = ("included", "primary_threat", "onset_turn", "minimum_action")
    return all(left.get(field) == right.get(field) for field in fields)


def gold_row(annotation: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "case_id": annotation["case_id"],
        "included": annotation["included"],
        "primary_threat": annotation["primary_threat"],
        "onset_turn": annotation["onset_turn"],
        "minimum_action": annotation["minimum_action"],
        "naturalness": annotation["naturalness"],
        "confidence": annotation["confidence"],
        "adjudication_source": source,
    }


def cmd_adjudicate(args: argparse.Namespace) -> int:
    cases = index_unique(load_jsonl(args.cases), "case_id", "case")
    review_a = annotation_index(args.review_a, cases)
    review_b = annotation_index(args.review_b, cases)
    if set(review_a) != set(cases) or set(review_b) != set(cases):
        raise ValueError("review A and B must each cover every case exactly once")
    review_c = annotation_index(args.review_c, cases) if args.review_c else {}
    labels_a = []
    labels_b = []
    disagreements = []
    gold = []
    for case_id in sorted(cases):
        left = review_a[case_id]
        right = review_b[case_id]
        if left["reviewer_id"] == right["reviewer_id"]:
            raise ValueError(f"case {case_id} was not independently double-reviewed")
        labels_a.append(left["primary_threat"])
        labels_b.append(right["primary_threat"])
        if annotations_agree(left, right):
            gold.append(gold_row(left, "reviewer_agreement"))
        else:
            disagreements.append(case_id)
            adjudicated = review_c.get(case_id)
            if adjudicated is not None:
                gold.append(gold_row(adjudicated, "third_reviewer"))
    primary_agreements = sum(a == b for a, b in zip(labels_a, labels_b, strict=True))
    report = {
        "schema_version": "aura.internal_holdout_adjudication.v1",
        "status": "pass" if len(gold) == len(cases) else "blocked",
        "case_count": len(cases),
        "primary_label_agreement": primary_agreements / len(cases) if cases else 0.0,
        "primary_label_cohen_kappa": cohen_kappa(labels_a, labels_b),
        "full_annotation_agreement_count": len(cases) - len(disagreements),
        "disagreement_count": len(disagreements),
        "unresolved_case_ids": sorted(set(disagreements) - set(review_c)),
        "gold_case_count": len(gold),
    }
    write_json(args.report_output, report)
    if report["status"] != "pass":
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 1
    write_jsonl(args.gold_output, gold)
    print(json.dumps(report, sort_keys=True))
    return 0


def cmd_freeze(args: argparse.Namespace) -> int:
    protocol = load_json(args.protocol)
    validate_protocol(protocol)
    assignments = load_jsonl(args.assignments)
    cases = load_jsonl(args.cases)
    gold = load_jsonl(args.gold)
    adjudication = load_json(args.adjudication_report)
    validation = validate_cases(protocol, assignments, cases, [], False)
    if validation["status"] != "pass":
        raise ValueError(f"case validation failed: {validation['errors']}")
    assignment_index = index_unique(assignments, "assignment_id", "assignment")
    case_index = index_unique(cases, "case_id", "case")
    gold_index = index_unique(gold, "case_id", "gold label")
    if set(case_index) != set(gold_index):
        raise ValueError("gold labels must cover every case exactly once")
    support = Counter()
    mismatches = []
    for case_id, case in case_index.items():
        assignment = assignment_index[case["assignment_id"]]
        label = gold_index[case_id]
        if label.get("included") is not True:
            mismatches.append(f"{case_id}: excluded cases must be replaced before freeze")
            continue
        expected = assignment["target_family"] if assignment["target_polarity"] == "risky" else "none"
        if label.get("primary_threat") != expected:
            mismatches.append(
                f"{case_id}: adjudicated {label.get('primary_threat')} but assignment requires {expected}"
            )
        support[(assignment["language"], assignment["target_family"], assignment["target_polarity"])] += 1
    minimum = protocol["release_gates"]["minimum_cases_per_language_family_polarity"]
    thin = [
        {"language": language, "family": family, "polarity": polarity, "support": support[(language, family, polarity)]}
        for language in protocol["languages"]
        for family in protocol["threat_families"]
        for polarity in ("risky", "safe")
        if support[(language, family, polarity)] < minimum
    ]
    if adjudication.get("status") != "pass":
        mismatches.append("adjudication report is not pass")
    agreement = float(adjudication.get("primary_label_agreement", 0.0))
    if agreement < protocol["release_gates"]["minimum_primary_label_agreement"]:
        mismatches.append("primary label agreement is below the prespecified gate")
    if mismatches or thin:
        raise ValueError(json.dumps({"mismatches": mismatches, "thin_slices": thin}, indent=2))
    manifest = {
        "schema_version": SCHEMA,
        "status": "frozen",
        "evidence_class": protocol["evidence_class"],
        "dataset_id": protocol["dataset_id"],
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_revision": git_revision(args.protocol.parent),
        "inputs": {
            "protocol": file_identity(args.protocol),
            "assignments": file_identity(args.assignments),
            "cases": file_identity(args.cases),
            "gold": file_identity(args.gold),
            "adjudication_report": file_identity(args.adjudication_report),
        },
        "counts": {
            "pairs": len(cases) // 2,
            "cases": len(cases),
            "messages": sum(len(case["messages"]) for case in cases),
        },
        "adjudication": {
            "primary_label_agreement": agreement,
            "primary_label_cohen_kappa": adjudication.get("primary_label_cohen_kappa"),
            "disagreement_count": adjudication.get("disagreement_count"),
        },
        "claim_boundary": protocol["claim_boundary"],
    }
    write_json(args.output, manifest)
    print(json.dumps({"status": "frozen", "output": str(args.output)}, sort_keys=True))
    return 0


def git_revision(path: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def file_identity(path: Path) -> dict[str, Any]:
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256_file(path)}


def verify_manifest_input(manifest: dict[str, Any], name: str, path: Path) -> None:
    expected = manifest["inputs"][name]
    if sha256_file(path) != expected["sha256"] or path.stat().st_size != expected["bytes"]:
        raise ValueError(f"frozen {name} identity mismatch")


def probe_payload(cases: list[dict[str, Any]]) -> str:
    rows = []
    for case in cases:
        rows.append(
            {
                "id": case["case_id"],
                "default_language": case["language"],
                "account_type": case["account_type"],
                "account_holder_age": case["account_holder_age"],
                "conversation_type": case["conversation_type"],
                "sender_relationship": case["sender_relationship"],
                "relationship_trust_source": case["relationship_trust_source"],
                "messages": case["messages"],
            }
        )
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


def run_probe(probe: Path, cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    completed = subprocess.run(
        [str(probe)],
        input=probe_payload(cases),
        text=True,
        capture_output=True,
        check=True,
    )
    outputs = {}
    for line in completed.stdout.splitlines():
        output = json.loads(line)
        outputs[output["id"]] = output
    if len(outputs) != len(cases):
        raise ValueError(f"probe returned {len(outputs)} outputs for {len(cases)} cases")
    return outputs


def wilson(numerator: int, denominator: int) -> dict[str, float | int]:
    if denominator == 0:
        return {"numerator": numerator, "denominator": 0, "value": 0.0, "wilson_95_low": 0.0, "wilson_95_high": 1.0}
    p = numerator / denominator
    z = 1.959963984540054
    z2 = z * z
    scale = 1 + z2 / denominator
    center = (p + z2 / (2 * denominator)) / scale
    half = z * math.sqrt(p * (1 - p) / denominator + z2 / (4 * denominator * denominator)) / scale
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": p,
        "wilson_95_low": max(0.0, center - half),
        "wilson_95_high": min(1.0, center + half),
    }


def action_name(value: Any) -> str:
    return str(value).casefold().replace("_", "")


def max_action(turns: list[dict[str, Any]]) -> str:
    actions = (action_name(turn.get("action")) for turn in turns)
    return max(actions, key=lambda action: ACTION_SEVERITY.get(action, -1), default="allow")


def threshold_for(protocol: dict[str, Any], family: str) -> float:
    return float(protocol["thresholds"].get(family, protocol["thresholds"]["default_other_family"]))


def any_alert(protocol: dict[str, Any], turns: list[dict[str, Any]]) -> bool:
    return any(
        float(turn.get("scores", {}).get(family, 0.0)) >= threshold_for(protocol, family)
        for turn in turns
        for family in ALL_PROBE_FAMILIES
    )


def family_hit(protocol: dict[str, Any], family: str, turns: list[dict[str, Any]]) -> bool:
    return any(
        float(turn.get("scores", {}).get(family, 0.0)) >= threshold_for(protocol, family)
        for turn in turns
    )


def top_family(protocol: dict[str, Any], turns: list[dict[str, Any]]) -> str:
    maxima = {
        family: max((float(turn.get("scores", {}).get(family, 0.0)) for turn in turns), default=0.0)
        for family in ALL_PROBE_FAMILIES
    }
    candidates = [
        (score, family)
        for family, score in maxima.items()
        if score >= threshold_for(protocol, family)
    ]
    return max(candidates, default=(0.0, "none"))[1]


def case_result(
    protocol: dict[str, Any], assignment: dict[str, Any], gold: dict[str, Any], output: dict[str, Any]
) -> dict[str, Any]:
    turns = output["turns"]
    expected = gold["primary_threat"]
    relevant = turns if expected == "none" else turns[int(gold["onset_turn"]):]
    if expected == "none":
        alert = any_alert(protocol, relevant)
        block_error = max_action(relevant) == "block"
        return {
            "correct": not alert and not block_error,
            "specific": not alert,
            "family_correct": None,
            "action_error": block_error,
            "prediction": top_family(protocol, relevant),
        }
    detected = family_hit(protocol, expected, relevant)
    prediction = top_family(protocol, relevant)
    allow_error = max_action(relevant) == "allow"
    return {
        "correct": detected and not allow_error,
        "specific": detected,
        "family_correct": detected and prediction == expected,
        "action_error": allow_error,
        "prediction": prediction,
    }


def cmd_evaluate(args: argparse.Namespace) -> int:
    manifest = load_json(args.manifest)
    if manifest.get("schema_version") != SCHEMA or manifest.get("status") != "frozen":
        raise ValueError("evaluation requires a frozen v1 manifest")
    for name, path in (
        ("protocol", args.protocol),
        ("assignments", args.assignments),
        ("cases", args.cases),
        ("gold", args.gold),
    ):
        verify_manifest_input(manifest, name, path)
    protocol = load_json(args.protocol)
    assignments = index_unique(load_jsonl(args.assignments), "assignment_id", "assignment")
    cases = load_jsonl(args.cases)
    gold = index_unique(load_jsonl(args.gold), "case_id", "gold label")
    outputs = run_probe(args.probe, cases)
    results = {}
    risky_hits = safe_hits = risky_total = safe_total = 0
    family_hits = detected_positives = 0
    risky_allow_errors = safe_block_errors = 0
    slice_counts: dict[tuple[str, str], Counter] = defaultdict(Counter)
    pair_members: dict[str, list[bool]] = defaultdict(list)
    failures = []
    backends = set()
    latency = []
    for case in cases:
        case_id = case["case_id"]
        assignment = assignments[case["assignment_id"]]
        label = gold[case_id]
        output = outputs[case_id]
        backends.update(turn["backend"] for turn in output["turns"])
        latency.extend(int(turn["analysis_time_us"]) for turn in output["turns"])
        result = case_result(protocol, assignment, label, output)
        results[case_id] = result
        pair_members[assignment["pair_id"]].append(result["correct"])
        key = (assignment["language"], assignment["target_family"])
        polarity = assignment["target_polarity"]
        slice_counts[key][f"{polarity}_total"] += 1
        slice_counts[key][f"{polarity}_correct"] += int(result["specific"])
        if polarity == "risky":
            risky_total += 1
            risky_hits += int(result["specific"])
            risky_allow_errors += int(result["action_error"])
            if result["specific"]:
                detected_positives += 1
                family_hits += int(result["family_correct"])
        else:
            safe_total += 1
            safe_hits += int(result["specific"])
            safe_block_errors += int(result["action_error"])
        if not result["correct"]:
            failures.append(case_id)
    pair_correct = sum(len(values) == 2 and all(values) for values in pair_members.values())
    slices = {}
    gates = protocol["release_gates"]
    slice_failures = []
    for (language, family), counts in sorted(slice_counts.items()):
        risky_metric = wilson(counts["risky_correct"], counts["risky_total"])
        safe_metric = wilson(counts["safe_correct"], counts["safe_total"])
        slice_id = f"{language}:{family}"
        slices[slice_id] = {
            "expected_family_recall": risky_metric,
            "safe_specificity": safe_metric,
        }
        if counts["risky_total"] < gates["minimum_cases_per_language_family_polarity"]:
            slice_failures.append(f"{slice_id}:risky_support")
        if counts["safe_total"] < gates["minimum_cases_per_language_family_polarity"]:
            slice_failures.append(f"{slice_id}:safe_support")
        if risky_metric["value"] < gates["minimum_slice_expected_family_recall"]:
            slice_failures.append(f"{slice_id}:recall")
        if safe_metric["value"] < gates["minimum_slice_safe_specificity"]:
            slice_failures.append(f"{slice_id}:specificity")
    overall_recall = wilson(risky_hits, risky_total)
    overall_specificity = wilson(safe_hits, safe_total)
    family_accuracy = wilson(family_hits, detected_positives)
    pair_accuracy = wilson(pair_correct, len(pair_members))
    gate_checks = {
        "overall_expected_family_recall": overall_recall["value"] >= gates["minimum_overall_expected_family_recall"],
        "overall_safe_specificity": overall_specificity["value"] >= gates["minimum_overall_safe_specificity"],
        "detected_family_accuracy": family_accuracy["value"] >= gates["minimum_detected_family_accuracy"],
        "risky_allow_errors": risky_allow_errors <= gates["maximum_risky_allow_errors"],
        "safe_block_errors": safe_block_errors <= gates["maximum_safe_block_errors"],
        "pair_accuracy": pair_accuracy["value"] >= gates["minimum_pair_accuracy"],
        "all_language_family_slices": not slice_failures,
    }
    latency.sort()
    report = {
        "schema_version": "aura.internal_blind_holdout_result.v1",
        "status": "pass" if all(gate_checks.values()) else "fail",
        "evidence_class": manifest["evidence_class"],
        "dataset_id": manifest["dataset_id"],
        "frozen_manifest_sha256": sha256_file(args.manifest),
        "probe": file_identity(args.probe),
        "runtime_backends": sorted(backends),
        "overall": {
            "expected_family_recall": overall_recall,
            "safe_specificity": overall_specificity,
            "detected_family_accuracy": family_accuracy,
            "pair_accuracy": pair_accuracy,
            "risky_allow_errors": risky_allow_errors,
            "safe_block_errors": safe_block_errors,
        },
        "by_language_family": slices,
        "gate_checks": gate_checks,
        "slice_failures": slice_failures,
        "failed_case_ids": failures,
        "latency_us": {
            "count": len(latency),
            "median": percentile(latency, 0.50),
            "p95": percentile(latency, 0.95),
            "maximum": max(latency, default=0),
        },
        "claim_boundary": manifest["claim_boundary"],
    }
    write_json(args.output, report)
    print(json.dumps({"status": report["status"], "output": str(args.output)}, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    index = math.ceil((len(values) - 1) * fraction)
    return values[index]


def main() -> int:
    args = parser().parse_args()
    commands = {
        "assignments": cmd_assignments,
        "authoring-packets": cmd_authoring_packets,
        "packets": cmd_packets,
        "adjudicate": cmd_adjudicate,
        "freeze": cmd_freeze,
        "evaluate": cmd_evaluate,
    }
    try:
        return commands[args.command](args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"internal holdout error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
