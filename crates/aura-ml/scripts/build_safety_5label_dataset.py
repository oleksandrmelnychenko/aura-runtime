#!/usr/bin/env python3
"""Build safety 5-label train/eval JSONL files from curated Wave1 chat cases."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

THREATS = ("grooming", "bullying", "self_harm", "manipulation")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate safety_train.jsonl and safety_eval.jsonl from curated Wave1 cases"
    )
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Path to curated case JSON file (repeatable)",
    )
    parser.add_argument("--train-out", required=True, help="Output JSONL for train split")
    parser.add_argument("--eval-out", required=True, help="Output JSONL for eval split")
    parser.add_argument(
        "--eval-ratio",
        type=float,
        default=0.2,
        help="Fraction of case IDs assigned to eval split (default: 0.2)",
    )
    parser.add_argument(
        "--seed",
        default="aura-safety-5label-wave1-v1",
        help="Salt for deterministic split hashing",
    )
    return parser.parse_args()


def _normalize_threat(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _case_threat_set(case: Dict) -> set[str]:
    result: set[str] = set()
    primary = case.get("primary_threat")
    if isinstance(primary, str):
        normalized = _normalize_threat(primary)
        if normalized in THREATS:
            result.add(normalized)

    for threat in case.get("tracked_threats", []):
        if not isinstance(threat, str):
            continue
        normalized = _normalize_threat(threat)
        if normalized in THREATS:
            result.add(normalized)
    return result


def _case_is_in_safety_scope(case: Dict) -> bool:
    raw_threats: set[str] = set()
    primary = case.get("primary_threat")
    if isinstance(primary, str):
        raw_threats.add(_normalize_threat(primary))
    for threat in case.get("tracked_threats", []):
        if isinstance(threat, str):
            raw_threats.add(_normalize_threat(threat))

    if not raw_threats:
        return True
    return any(threat in THREATS for threat in raw_threats)


def _message_threat_set(message: Dict) -> set[str]:
    result: set[str] = set()
    for threat in message.get("observed_threats", []):
        if not isinstance(threat, str):
            continue
        normalized = _normalize_threat(threat)
        if normalized in THREATS:
            result.add(normalized)
    return result


def _labels_from_message(
    case: Dict,
    message: Dict,
    message_index: int,
) -> Dict[str, int]:
    labels = {threat: 0 for threat in THREATS}
    observed = _message_threat_set(message)
    for threat in observed:
        labels[threat] = 1

    # Fallback for older curated rows where observed_threats are sparse.
    if not observed:
        onset = case.get("onset_step")
        if isinstance(onset, int) and message_index >= onset:
            for threat in _case_threat_set(case):
                labels[threat] = 1

    labels["safe"] = int(sum(labels.values()) == 0)
    return labels


def _extract_records(source_path: Path) -> List[Tuple[str, Dict]]:
    data = json.loads(source_path.read_text(encoding="utf-8"))
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"{source_path} has no top-level 'cases' array")

    rows: List[Tuple[str, Dict]] = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        if not _case_is_in_safety_scope(case):
            continue
        case_id = str(case.get("id", "unknown_case"))
        messages = case.get("messages", [])
        if not isinstance(messages, list):
            continue

        default_lang = str(case.get("default_language") or case.get("language") or "und")
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                continue
            text = str(message.get("text", "")).strip()
            if not text:
                continue
            labels = _labels_from_message(case, message, index)
            row = {
                "text": text,
                "language": str(message.get("language") or default_lang),
                **labels,
            }
            rows.append((case_id, row))
    return rows


def _split_for_case_id(case_id: str, eval_ratio: float, seed: str) -> str:
    digest = hashlib.sha256(f"{seed}:{case_id}".encode("utf-8")).hexdigest()
    bucket = int(digest[:8], 16) / 0xFFFFFFFF
    return "eval" if bucket < eval_ratio else "train"


def _write_jsonl(path: Path, records: Sequence[Dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in records:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _label_stats(records: Sequence[Dict]) -> Dict[str, int]:
    stats = {threat: 0 for threat in THREATS}
    stats["safe"] = 0
    for row in records:
        for key in stats:
            stats[key] += int(row.get(key, 0))
    return stats


def _ensure_eval_coverage(train_rows: List[Dict], eval_rows: List[Dict]) -> None:
    """Move a minimum set of rows from train->eval so each risk label appears in eval."""
    eval_stats = _label_stats(eval_rows)
    for label in THREATS:
        if eval_stats[label] > 0:
            continue
        candidate_idx = None
        for idx, row in enumerate(train_rows):
            if int(row.get(label, 0)) == 1:
                candidate_idx = idx
                break
        if candidate_idx is None:
            continue
        row = train_rows.pop(candidate_idx)
        eval_rows.append(row)
        eval_stats[label] += 1


def main() -> int:
    args = parse_args()
    if not (0.0 < args.eval_ratio < 1.0):
        raise ValueError("--eval-ratio must be between 0 and 1")

    extracted: List[Tuple[str, Dict]] = []
    for path_str in args.input:
        path = Path(path_str)
        extracted.extend(_extract_records(path))

    dedupe: Dict[Tuple[str, int, int, int, int], Tuple[str, Dict]] = {}
    for case_id, row in extracted:
        key = (
            row["text"].strip().lower(),
            row["grooming"],
            row["bullying"],
            row["self_harm"],
            row["manipulation"],
        )
        dedupe[key] = (case_id, row)

    train_rows: List[Dict] = []
    eval_rows: List[Dict] = []
    for case_id, row in dedupe.values():
        split = _split_for_case_id(case_id, args.eval_ratio, args.seed)
        if split == "eval":
            eval_rows.append(row)
        else:
            train_rows.append(row)

    _ensure_eval_coverage(train_rows, eval_rows)

    train_rows.sort(key=lambda r: (r["language"], r["text"]))
    eval_rows.sort(key=lambda r: (r["language"], r["text"]))

    _write_jsonl(Path(args.train_out), train_rows)
    _write_jsonl(Path(args.eval_out), eval_rows)

    print(f"Built train rows: {len(train_rows)} | labels: {_label_stats(train_rows)}")
    print(f"Built eval rows:  {len(eval_rows)} | labels: {_label_stats(eval_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
