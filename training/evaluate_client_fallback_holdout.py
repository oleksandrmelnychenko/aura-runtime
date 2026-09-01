#!/usr/bin/env python3
"""Evaluate the Rust client fallback on a frozen broad-label validation sample.

This is an auxiliary experiment. KoalaAI labels are content-moderation labels,
not AURA conversation-level child-safety labels, so the report intentionally
uses broad family mappings and carries that limitation in its output.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq


LABEL_COLUMNS = ("S", "H", "V", "HR", "SH", "S3", "H2", "V2")
SAMPLE_PER_COHORT = 200
MAPPED_FAMILIES = {
    "self_harm": ("self_harm",),
    "harassment": ("bullying", "hate_speech", "threat", "manipulation"),
    "violence": ("threat", "bullying"),
}
THRESHOLDS = defaultdict(
    lambda: 0.55,
    {
        "self_harm": 0.70,
        "threat": 0.60,
    },
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parquet", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument(
        "--language-scope",
        choices=("all", "english_ascii_heuristic"),
        default="all",
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def cohort_for(row: dict[str, object]) -> str | None:
    labels = {name: int(row[name] or 0) for name in LABEL_COLUMNS}
    if labels["SH"] == 1:
        return "self_harm"
    if labels["HR"] == 1:
        return "harassment"
    if labels["V"] == 1 or labels["V2"] == 1:
        return "violence"
    if not any(labels.values()):
        return "safe"
    return None


ENGLISH_FUNCTION_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "but",
    "by",
    "for",
    "from",
    "has",
    "have",
    "he",
    "her",
    "his",
    "i",
    "if",
    "in",
    "is",
    "it",
    "me",
    "my",
    "not",
    "of",
    "on",
    "or",
    "our",
    "she",
    "that",
    "the",
    "their",
    "they",
    "this",
    "to",
    "was",
    "we",
    "were",
    "with",
    "you",
    "your",
}


def in_language_scope(text: str, language_scope: str) -> bool:
    if language_scope == "all":
        return True
    if not text.isascii():
        return False
    words = re.findall(r"[A-Za-z']+", text.lower())
    if len(words) < 5:
        return False
    return sum(word in ENGLISH_FUNCTION_WORDS for word in words) >= 2


def stable_sample(
    parquet_path: Path, language_scope: str = "all"
) -> tuple[dict[str, list[dict]], Counter, Counter]:
    columns = ("prompt", *LABEL_COLUMNS)
    heaps: dict[str, list[tuple[int, str, dict]]] = defaultdict(list)
    raw_support = Counter()
    scoped_support = Counter()
    seen_prompts: dict[str, set[str]] = defaultdict(set)

    parquet = pq.ParquetFile(parquet_path)
    for batch in parquet.iter_batches(batch_size=8_192, columns=columns):
        for row in batch.to_pylist():
            text = str(row["prompt"] or "").strip()
            if not text:
                continue
            cohort = cohort_for(row)
            if cohort is None:
                continue
            raw_support[cohort] += 1
            if not in_language_scope(text, language_scope):
                continue
            scoped_support[cohort] += 1
            if text in seen_prompts[cohort]:
                continue
            seen_prompts[cohort].add(text)
            digest = hashlib.sha256(f"{cohort}\0{text}".encode()).digest()
            rank = int.from_bytes(digest[:8], "big")
            record_id = hashlib.sha256(text.encode()).hexdigest()[:24]
            item = (-rank, record_id, {"id": record_id, "text": text})
            heap = heaps[cohort]
            if len(heap) < SAMPLE_PER_COHORT:
                heapq.heappush(heap, item)
            elif item > heap[0]:
                heapq.heapreplace(heap, item)

    samples = {}
    for cohort in ("self_harm", "harassment", "violence", "safe"):
        selected = sorted(heaps[cohort], key=lambda item: (-item[0], item[1]))
        samples[cohort] = [item[2] for item in selected]
    return samples, raw_support, scoped_support


def run_probe(probe: Path, samples: dict[str, list[dict]]) -> dict[str, dict]:
    rows = []
    for cohort, cohort_rows in samples.items():
        for row in cohort_rows:
            rows.append(
                {
                    "id": f"{cohort}:{row['id']}",
                    "text": row["text"],
                    "language": None,
                }
            )
    payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    completed = subprocess.run(
        [str(probe)],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
    )
    outputs = {}
    for line in completed.stdout.splitlines():
        output = json.loads(line)
        outputs[output["id"]] = output
    if len(outputs) != len(rows):
        raise RuntimeError(f"probe returned {len(outputs)} rows for {len(rows)} inputs")
    return outputs


def any_alert(output: dict) -> bool:
    return any(
        score >= THRESHOLDS[family]
        for family, score in output["scores"].items()
    )


def positive_hit(cohort: str, output: dict) -> bool:
    return any(
        output["scores"].get(family, 0.0) >= THRESHOLDS[family]
        for family in MAPPED_FAMILIES[cohort]
    )


def top_prediction(output: dict) -> str:
    candidates = [
        (score, family)
        for family, score in output["scores"].items()
        if score >= THRESHOLDS[family]
    ]
    if not candidates:
        return "none"
    return max(candidates)[1]


def wilson(numerator: int, denominator: int) -> dict[str, float | int]:
    if denominator == 0:
        return {
            "numerator": numerator,
            "denominator": denominator,
            "value": 0.0,
            "wilson_95_low": 0.0,
            "wilson_95_high": 1.0,
        }
    p = numerator / denominator
    z = 1.959963984540054
    z2 = z * z
    scale = 1 + z2 / denominator
    center = (p + z2 / (2 * denominator)) / scale
    half = z * math.sqrt(
        p * (1 - p) / denominator + z2 / (4 * denominator * denominator)
    ) / scale
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": p,
        "wilson_95_low": max(0.0, center - half),
        "wilson_95_high": min(1.0, center + half),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    values = sorted(values)
    index = math.ceil((len(values) - 1) * fraction)
    return values[index]


def main() -> int:
    args = parse_args()
    samples, raw_source_support, scoped_source_support = stable_sample(
        args.parquet, args.language_scope
    )
    outputs = run_probe(args.probe, samples)

    by_cohort = {}
    confusion = defaultdict(Counter)
    failed_ids = defaultdict(list)
    action_errors = defaultdict(Counter)
    reason_counts = defaultdict(Counter)
    latency = []
    slowest_cases = []
    backends = set()

    for cohort, rows in samples.items():
        passed = 0
        for row in rows:
            probe_id = f"{cohort}:{row['id']}"
            output = outputs[probe_id]
            backends.add(output["backend"])
            latency.append(int(output["analysis_time_us"]))
            slowest_cases.append(
                {
                    "id": probe_id,
                    "cohort": cohort,
                    "analysis_time_us": int(output["analysis_time_us"]),
                    "input_chars": len(row["text"]),
                    "input_bytes": len(row["text"].encode()),
                }
            )
            prediction = top_prediction(output)
            confusion[cohort][prediction] += 1
            reason_counts[cohort].update(output["reason_codes"])

            if cohort == "safe":
                correct = not any_alert(output)
                if output["action"] == "block":
                    action_errors[cohort]["block"] += 1
            else:
                correct = positive_hit(cohort, output)
                if output["action"] == "allow":
                    action_errors[cohort]["allow"] += 1
            passed += int(correct)
            if not correct:
                failed_ids[cohort].append(probe_id)

        metric_name = "specificity" if cohort == "safe" else "broad_recall"
        by_cohort[cohort] = {
            "raw_source_support": raw_source_support[cohort],
            "scoped_source_support": scoped_source_support[cohort],
            "sample_support": len(rows),
            metric_name: wilson(passed, len(rows)),
            "action_errors": dict(action_errors[cohort]),
            "failed_case_ids": failed_ids[cohort],
            "top_reason_codes": reason_counts[cohort].most_common(20),
        }

    report = {
        "schema_version": "aura.client_fallback_broad_holdout.v1",
        "dataset": {
            "path": str(args.parquet),
            "sha256": sha256_file(args.parquet),
            "sample_rule": "smallest sha256(cohort + NUL + prompt), exact-prompt deduplicated",
            "sample_per_cohort": SAMPLE_PER_COHORT,
            "language_scope": args.language_scope,
        },
        "runtime_backends": sorted(backends),
        "thresholds": dict(THRESHOLDS),
        "label_mapping": MAPPED_FAMILIES,
        "by_cohort": by_cohort,
        "confusion_matrix": {key: dict(value) for key, value in confusion.items()},
        "latency": {
            "count": len(latency),
            "median_us": percentile(latency, 0.50),
            "p95_us": percentile(latency, 0.95),
            "max_us": max(latency, default=0),
            "slowest_cases": sorted(
                slowest_cases,
                key=lambda case: case["analysis_time_us"],
                reverse=True,
            )[:10],
        },
        "interpretation_limits": [
            "KoalaAI broad moderation labels are not AURA conversation-level child-safety labels.",
            "The validation split may overlap historical model-training sources and is not an independent release holdout.",
            "Language is absent from the rows, so the client probe uses multilingual pattern scanning and no language slices are claimed.",
            "Sexual labels are intentionally excluded from grooming evaluation because the semantic mapping is invalid.",
        ],
    }
    if args.language_scope == "english_ascii_heuristic":
        report["interpretation_limits"].append(
            "The English ASCII heuristic was introduced after the all-language run exposed an unsupported-language confound; this slice is exploratory, not confirmatory."
        )
    if args.output is None:
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        if args.output.exists():
            raise SystemExit(f"refusing to replace existing output: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "status": "written",
                    "output": str(args.output),
                    "sample_count": sum(
                        cohort["sample_support"] for cohort in by_cohort.values()
                    ),
                    "runtime_backends": sorted(backends),
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
