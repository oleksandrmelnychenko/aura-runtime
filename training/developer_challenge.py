#!/usr/bin/env python3
"""Build, freeze, and evaluate the AURA developer-authored challenge.

This corpus is diagnostic-only. It intentionally does not share the authoring,
review, adjudication, or release semantics of the internal blinded holdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from training import internal_holdout as shared


MANIFEST_SCHEMA = "aura.developer_challenge_manifest.v1"
RESULT_SCHEMA = "aura.developer_challenge_result.v1"

OPENERS = {
    "en": (
        "Can you explain what you mean?",
        "I am listening. What did you want to say?",
        "What is this message about?",
        "Please say clearly what you want.",
        "I saw your last message. Continue.",
        "What are you asking me to do?",
        "I do not understand yet. Explain it.",
        "Tell me what you meant by that.",
        "What did you want to discuss?",
        "I am here. What is going on?",
    ),
    "uk": (
        "Можеш пояснити, що ти маєш на увазі?",
        "Я слухаю. Що ти хотів сказати?",
        "Про що це повідомлення?",
        "Скажи чітко, чого ти хочеш.",
        "Я бачив твоє попереднє повідомлення. Продовжуй.",
        "Що ти просиш мене зробити?",
        "Я поки не розумію. Поясни.",
        "Розкажи, що ти цим мав на увазі.",
        "Що ти хотів обговорити?",
        "Я тут. Що відбувається?",
    ),
    "ru": (
        "Можешь объяснить, что ты имеешь в виду?",
        "Я слушаю. Что ты хотел сказать?",
        "О чём это сообщение?",
        "Скажи ясно, чего ты хочешь.",
        "Я видел твоё предыдущее сообщение. Продолжай.",
        "Что ты просишь меня сделать?",
        "Я пока не понимаю. Объясни.",
        "Расскажи, что ты имел в виду.",
        "Что ты хотел обсудить?",
        "Я здесь. Что происходит?",
    ),
}

SAFE_STANCES = {
    "en": (
        "I am reporting this harmful message, not agreeing with it.",
        "I refuse this request and will show it to a trusted adult.",
        "This is an example of unsafe language that people should not use.",
        "I copied this sentence only to ask for help reporting it.",
        "That quoted message is unacceptable, and I will not follow it.",
        "A friend received this message; we are asking an adult for help.",
        "I reject the quoted instruction and want it documented safely.",
        "This quotation is from a safety lesson about warning signs.",
        "I am sharing the quote with support staff so they can protect someone.",
        "The sentence in quotation marks is evidence for a report, not my intent.",
    ),
    "uk": (
        "Я повідомляю про це шкідливе повідомлення, а не погоджуюся з ним.",
        "Я відмовляюся від цієї вимоги й покажу її дорослому, якому довіряю.",
        "Це приклад небезпечних слів, які не можна використовувати.",
        "Я скопіював це речення лише для того, щоб попросити допомоги зі скаргою.",
        "Процитоване повідомлення неприйнятне, і я не виконуватиму його.",
        "Друг отримав це повідомлення, і ми звертаємося по допомогу до дорослого.",
        "Я відкидаю процитовану вказівку й хочу безпечно її задокументувати.",
        "Ця цитата взята з уроку безпеки про тривожні ознаки.",
        "Я передаю цитату службі підтримки, щоб вони могли когось захистити.",
        "Речення в лапках є доказом для скарги, а не моїм наміром.",
    ),
    "ru": (
        "Я сообщаю об этом вредном сообщении, а не соглашаюсь с ним.",
        "Я отказываюсь от этого требования и покажу его взрослому, которому доверяю.",
        "Это пример опасных слов, которые нельзя использовать.",
        "Я скопировал это предложение только для того, чтобы попросить помощи с жалобой.",
        "Процитированное сообщение неприемлемо, и я не буду его выполнять.",
        "Друг получил это сообщение, и мы обращаемся за помощью к взрослому.",
        "Я отвергаю процитированное указание и хочу безопасно его задокументировать.",
        "Эта цитата взята из урока безопасности о тревожных признаках.",
        "Я передаю цитату службе поддержки, чтобы они могли кого-то защитить.",
        "Предложение в кавычках является доказательством для жалобы, а не моим намерением.",
    ),
}

RELATIONSHIPS = (
    "unknown_adult",
    "unknown_peer",
    "peer",
    "teacher",
    "coach",
    "service",
)
TRUST_SOURCES = (
    "unknown",
    "self_declared",
    "local_heuristic",
    "server_reputation",
    "school_directory",
)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--protocol", type=Path, required=True)
    build.add_argument("--scenario-bank", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--manifest", type=Path, required=True)
    evaluate.add_argument("--protocol", type=Path, required=True)
    evaluate.add_argument("--scenario-bank", type=Path, required=True)
    evaluate.add_argument("--cases", type=Path, required=True)
    evaluate.add_argument("--gold", type=Path, required=True)
    evaluate.add_argument("--probe", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    return root


def validate_inputs(protocol: dict[str, Any], bank: dict[str, Any]) -> None:
    if protocol.get("schema_version") != "aura.developer_challenge_protocol.v1":
        raise ValueError("unsupported developer challenge protocol")
    if protocol.get("evidence_class") != "developer_authored_challenge":
        raise ValueError("developer challenge evidence class drifted")
    if protocol.get("release_eligible") is not False:
        raise ValueError("developer challenge must never be release eligible")
    if protocol.get("languages") != ["en", "uk", "ru"]:
        raise ValueError("v1 requires canonical en/uk/ru order")
    if tuple(protocol.get("threat_families", [])) != shared.FAMILIES:
        raise ValueError("threat family matrix drifted")
    if protocol.get("pairs_per_language_family") != 10:
        raise ValueError("v1 requires ten pairs per language/family slice")
    if protocol.get("messages_per_conversation") != 2:
        raise ValueError("v1 requires exactly two messages per conversation")
    if bank.get("schema_version") != "aura.developer_challenge_scenario_bank.v1":
        raise ValueError("unsupported scenario bank")
    scenarios = bank.get("scenarios")
    if not isinstance(scenarios, dict) or set(scenarios) != set(shared.FAMILIES):
        raise ValueError("scenario bank must cover each canonical threat family")
    seen: set[tuple[str, str]] = set()
    for family in shared.FAMILIES:
        rows = scenarios[family]
        if not isinstance(rows, list) or len(rows) != 10:
            raise ValueError(f"{family} must contain exactly ten scenarios")
        for index, row in enumerate(rows):
            if not isinstance(row, dict) or set(row) != {"en", "uk", "ru"}:
                raise ValueError(f"{family}:{index + 1} must contain en/uk/ru text")
            for language, text in row.items():
                if not isinstance(text, str) or not text.strip():
                    raise ValueError(f"{family}:{index + 1}:{language} is empty")
                if len(text.encode("utf-8")) > protocol["maximum_message_bytes"]:
                    raise ValueError(f"{family}:{index + 1}:{language} is too large")
                normalized = shared.normalize_text(text)
                key = (language, normalized)
                if key in seen:
                    raise ValueError(f"duplicate target phrase: {family}:{index + 1}:{language}")
                seen.add(key)
                inspected = shared.stripped_for_pii(text)
                for label, pattern in shared.PII_PATTERNS.items():
                    if pattern.search(inspected):
                        raise ValueError(f"possible {label}: {family}:{index + 1}:{language}")
    if any(len(OPENERS[language]) != 10 for language in protocol["languages"]):
        raise ValueError("opener matrix drifted")
    if any(len(SAFE_STANCES[language]) != 10 for language in protocol["languages"]):
        raise ValueError("safe stance matrix drifted")


def quote(language: str, text: str) -> str:
    opening, closing = ("“", "”") if language == "en" else ("«", "»")
    return f"{opening}{text}{closing}"


def build_rows(
    protocol: dict[str, Any], bank: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases: list[dict[str, Any]] = []
    gold: list[dict[str, Any]] = []
    for language in protocol["languages"]:
        for family in protocol["threat_families"]:
            for index, scenario in enumerate(bank["scenarios"][family]):
                pair_id = f"dev1-{language}-{family}-{index + 1:02d}"
                account_type = "child" if index % 2 == 0 else "teen"
                target_speaker = "protected" if family == "self_harm" else "other"
                opener_speaker = "other" if target_speaker == "protected" else "protected"
                metadata = {
                    "pair_id": pair_id,
                    "language": language,
                    "target_family": family,
                    "account_type": account_type,
                    "account_holder_age": 12 if account_type == "child" else 15,
                    "conversation_type": "group" if index in (4, 9) else "direct",
                    "sender_relationship": RELATIONSHIPS[index % len(RELATIONSHIPS)],
                    "relationship_trust_source": TRUST_SOURCES[index % len(TRUST_SOURCES)],
                }
                target = scenario[language]
                for polarity in ("risky", "safe"):
                    case_id = f"{pair_id}-{polarity}"
                    target_text = (
                        target
                        if polarity == "risky"
                        else f"{quote(language, target)} — {SAFE_STANCES[language][index]}"
                    )
                    cases.append(
                        {
                            "case_id": case_id,
                            **metadata,
                            "target_polarity": polarity,
                            "messages": [
                                {"speaker": opener_speaker, "text": OPENERS[language][index]},
                                {"speaker": target_speaker, "text": target_text},
                            ],
                        }
                    )
                    gold.append(
                        {
                            "case_id": case_id,
                            "primary_threat": family if polarity == "risky" else "none",
                            "onset_turn": 1 if polarity == "risky" else None,
                            "minimum_action": "warn" if polarity == "risky" else "allow",
                            "label_source": "developer_authored_counterfactual",
                        }
                    )
    validate_rows(protocol, cases, gold)
    return cases, gold


def validate_rows(
    protocol: dict[str, Any], cases: list[dict[str, Any]], gold: list[dict[str, Any]]
) -> None:
    expected_cases = (
        len(protocol["languages"])
        * len(protocol["threat_families"])
        * protocol["pairs_per_language_family"]
        * 2
    )
    if len(cases) != expected_cases or len(gold) != expected_cases:
        raise ValueError("generated challenge has the wrong size")
    case_ids = [case["case_id"] for case in cases]
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("duplicate case IDs")
    if {row["case_id"] for row in gold} != set(case_ids):
        raise ValueError("gold labels do not cover the generated cases")
    pairs: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    support = Counter()
    for case in cases:
        if len(case["messages"]) != 2:
            raise ValueError(f"{case['case_id']} must have two messages")
        for message in case["messages"]:
            text = message["text"]
            if not text.strip() or len(text.encode("utf-8")) > protocol["maximum_message_bytes"]:
                raise ValueError(f"invalid message size in {case['case_id']}")
            inspected = shared.stripped_for_pii(text)
            for label, pattern in shared.PII_PATTERNS.items():
                if pattern.search(inspected):
                    raise ValueError(f"possible {label} in {case['case_id']}")
        pairs[case["pair_id"]][case["target_polarity"]] = case
        support[(case["language"], case["target_family"], case["target_polarity"])] += 1
    if set(support.values()) != {10} or len(support) != 48:
        raise ValueError("language/family/polarity support drifted")
    for pair_id, members in pairs.items():
        if set(members) != {"risky", "safe"}:
            raise ValueError(f"incomplete pair: {pair_id}")
        risky = members["risky"]
        safe = members["safe"]
        controlled = (
            "language",
            "target_family",
            "account_type",
            "account_holder_age",
            "conversation_type",
            "sender_relationship",
            "relationship_trust_source",
        )
        if any(risky[field] != safe[field] for field in controlled):
            raise ValueError(f"controlled metadata mismatch: {pair_id}")
        target = risky["messages"][1]["text"]
        safe_text = safe["messages"][1]["text"]
        if target not in safe_text or safe_text.count(target) != 1:
            raise ValueError(f"safe counterfactual lost exact target phrase: {pair_id}")
        if not (("“" in safe_text and "”" in safe_text) or ("«" in safe_text and "»" in safe_text)):
            raise ValueError(f"safe counterfactual must close its quotation: {pair_id}")


def cmd_build(args: argparse.Namespace) -> int:
    protocol = shared.load_json(args.protocol)
    bank = shared.load_json(args.scenario_bank)
    validate_inputs(protocol, bank)
    cases, gold = build_rows(protocol, bank)
    if args.output_dir.exists():
        raise ValueError(f"refusing to replace existing output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    cases_path = args.output_dir / "cases.jsonl"
    gold_path = args.output_dir / "gold.jsonl"
    shared.write_jsonl(cases_path, cases)
    shared.write_jsonl(gold_path, gold)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "status": "frozen_before_first_run",
        "dataset_id": protocol["dataset_id"],
        "evidence_class": protocol["evidence_class"],
        "release_eligible": False,
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_revision": shared.git_revision(args.protocol.parent),
        "inputs": {
            "protocol": shared.file_identity(args.protocol),
            "scenario_bank": shared.file_identity(args.scenario_bank),
            "cases": shared.file_identity(cases_path),
            "gold": shared.file_identity(gold_path),
        },
        "counts": {
            "pairs": len(cases) // 2,
            "cases": len(cases),
            "messages": sum(len(case["messages"]) for case in cases),
        },
        "claim_boundary": protocol["claim_boundary"],
    }
    manifest_path = args.output_dir / "manifest.json"
    shared.write_json(manifest_path, manifest)
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "cases": len(cases),
                "pairs": len(cases) // 2,
                "manifest": str(manifest_path),
                "manifest_sha256": shared.sha256_file(manifest_path),
            },
            sort_keys=True,
        )
    )
    return 0


def metric_protocol(protocol: dict[str, Any]) -> dict[str, Any]:
    return {
        "thresholds": protocol["thresholds"],
        "release_gates": protocol["diagnostic_targets"],
    }


def timing_distribution(values: list[int]) -> dict[str, int]:
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "total": sum(ordered),
        "median": shared.percentile(ordered, 0.50),
        "p95": shared.percentile(ordered, 0.95),
        "maximum": max(ordered, default=0),
    }


def aggregate_probe_timing(
    outputs: dict[str, dict[str, Any]], probe_wall_us: int
) -> dict[str, Any]:
    analyzer_init: list[int] = []
    runtime_reset: list[int] = []
    conversation_wall: list[int] = []
    detector_reported: list[int] = []
    for output in outputs.values():
        for field, destination in (
            ("analyzer_init_us", analyzer_init),
            ("runtime_reset_us", runtime_reset),
            ("probe_wall_us", conversation_wall),
        ):
            value = output.get(field)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"probe returned invalid {field}")
            destination.append(value)
        for turn in output.get("turns", []):
            value = turn.get("analysis_time_us")
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("probe returned invalid analysis_time_us")
            detector_reported.append(value)
    return {
        "analyzer_init_us": timing_distribution(analyzer_init),
        "runtime_reset_us": timing_distribution(runtime_reset),
        "probe_wall_us": probe_wall_us,
        "probe_reported_conversation_wall_us": timing_distribution(conversation_wall),
        "detector_reported_turn_latency_us": timing_distribution(detector_reported),
    }


def cmd_evaluate(args: argparse.Namespace) -> int:
    manifest = shared.load_json(args.manifest)
    if (
        manifest.get("schema_version") != MANIFEST_SCHEMA
        or manifest.get("status") != "frozen_before_first_run"
        or manifest.get("release_eligible") is not False
    ):
        raise ValueError("evaluation requires a frozen diagnostic-only manifest")
    for name, path in (
        ("protocol", args.protocol),
        ("scenario_bank", args.scenario_bank),
        ("cases", args.cases),
        ("gold", args.gold),
    ):
        shared.verify_manifest_input(manifest, name, path)
    protocol = shared.load_json(args.protocol)
    bank = shared.load_json(args.scenario_bank)
    validate_inputs(protocol, bank)
    cases = shared.load_jsonl(args.cases)
    gold = shared.index_unique(shared.load_jsonl(args.gold), "case_id", "gold label")
    validate_rows(protocol, cases, list(gold.values()))
    probe_started_ns = perf_counter_ns()
    outputs = shared.run_probe(args.probe, cases)
    probe_wall_us = (perf_counter_ns() - probe_started_ns) // 1_000
    timing = aggregate_probe_timing(outputs, probe_wall_us)
    scoring = metric_protocol(protocol)
    risky_hits = safe_hits = risky_total = safe_total = 0
    family_hits = detected_positives = 0
    risky_allow_errors = safe_block_errors = 0
    slice_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    pair_members: dict[str, list[bool]] = defaultdict(list)
    failures: list[str] = []
    failure_modes: Counter[str] = Counter()
    confusions: Counter[str] = Counter()
    backends: set[str] = set()
    latency: list[int] = []
    for case in cases:
        case_id = case["case_id"]
        output = outputs[case_id]
        backends.update(turn["backend"] for turn in output["turns"])
        latency.extend(int(turn["analysis_time_us"]) for turn in output["turns"])
        result = shared.case_result(scoring, case, gold[case_id], output)
        pair_members[case["pair_id"]].append(result["correct"])
        polarity = case["target_polarity"]
        key = (case["language"], case["target_family"])
        slice_counts[key][f"{polarity}_total"] += 1
        slice_counts[key][f"{polarity}_correct"] += int(result["specific"])
        if polarity == "risky":
            risky_total += 1
            risky_hits += int(result["specific"])
            risky_allow_errors += int(result["action_error"])
            if result["specific"]:
                detected_positives += 1
                family_hits += int(result["family_correct"])
            if not result["specific"]:
                failure_modes["risky_expected_family_miss"] += 1
            elif not result["family_correct"]:
                failure_modes["risky_family_confusion"] += 1
                confusions[f"{case['target_family']}->{result['prediction']}"] += 1
            if result["action_error"]:
                failure_modes["risky_allow"] += 1
        else:
            safe_total += 1
            safe_hits += int(result["specific"])
            safe_block_errors += int(result["action_error"])
            if not result["specific"]:
                failure_modes["safe_alert"] += 1
                confusions[f"none->{result['prediction']}"] += 1
            if result["action_error"]:
                failure_modes["safe_block"] += 1
        if not result["correct"]:
            failures.append(case_id)
    targets = protocol["diagnostic_targets"]
    slices: dict[str, Any] = {}
    slice_failures: list[str] = []
    for (language, family), counts in sorted(slice_counts.items()):
        recall = shared.wilson(counts["risky_correct"], counts["risky_total"])
        specificity = shared.wilson(counts["safe_correct"], counts["safe_total"])
        slice_id = f"{language}:{family}"
        slices[slice_id] = {
            "expected_family_recall": recall,
            "safe_specificity": specificity,
        }
        if counts["risky_total"] < targets["minimum_cases_per_language_family_polarity"]:
            slice_failures.append(f"{slice_id}:risky_support")
        if counts["safe_total"] < targets["minimum_cases_per_language_family_polarity"]:
            slice_failures.append(f"{slice_id}:safe_support")
        if recall["value"] < targets["minimum_slice_expected_family_recall"]:
            slice_failures.append(f"{slice_id}:recall")
        if specificity["value"] < targets["minimum_slice_safe_specificity"]:
            slice_failures.append(f"{slice_id}:specificity")
    overall_recall = shared.wilson(risky_hits, risky_total)
    overall_specificity = shared.wilson(safe_hits, safe_total)
    family_accuracy = shared.wilson(family_hits, detected_positives)
    pair_correct = sum(len(values) == 2 and all(values) for values in pair_members.values())
    pair_accuracy = shared.wilson(pair_correct, len(pair_members))
    gate_checks = {
        "overall_expected_family_recall": overall_recall["value"]
        >= targets["minimum_overall_expected_family_recall"],
        "overall_safe_specificity": overall_specificity["value"]
        >= targets["minimum_overall_safe_specificity"],
        "detected_family_accuracy": family_accuracy["value"]
        >= targets["minimum_detected_family_accuracy"],
        "risky_allow_errors": risky_allow_errors <= targets["maximum_risky_allow_errors"],
        "safe_block_errors": safe_block_errors <= targets["maximum_safe_block_errors"],
        "pair_accuracy": pair_accuracy["value"] >= targets["minimum_pair_accuracy"],
        "all_language_family_slices": not slice_failures,
    }
    latency.sort()
    passed = all(gate_checks.values())
    report = {
        "schema_version": RESULT_SCHEMA,
        "status": "diagnostic_pass" if passed else "diagnostic_fail",
        "release_eligible": False,
        "evidence_class": manifest["evidence_class"],
        "dataset_id": manifest["dataset_id"],
        "frozen_manifest_sha256": shared.sha256_file(args.manifest),
        "probe": shared.file_identity(args.probe),
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
        "diagnostic_target_checks": gate_checks,
        "slice_failures": slice_failures,
        "failure_mode_counts": dict(sorted(failure_modes.items())),
        "confusion_counts": dict(sorted(confusions.items())),
        "failed_case_ids": failures,
        "latency_us": {
            "count": len(latency),
            "median": shared.percentile(latency, 0.50),
            "p95": shared.percentile(latency, 0.95),
            "maximum": max(latency, default=0),
        },
        "timing": timing,
        "claim_boundary": manifest["claim_boundary"],
    }
    shared.write_json(args.output, report)
    print(json.dumps({"status": report["status"], "output": str(args.output)}, sort_keys=True))
    return 0 if passed else 1


def main() -> int:
    args = parser().parse_args()
    try:
        return {"build": cmd_build, "evaluate": cmd_evaluate}[args.command](args)
    except (OSError, ValueError, KeyError) as error:
        print(f"developer challenge error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
