#!/usr/bin/env python3
"""Train the deterministic hashed character n-gram abstention model."""

from __future__ import annotations

import argparse
import array
import csv
import hashlib
import json
import math
import struct
import sys
import unicodedata
from collections import Counter
from pathlib import Path


MAGIC = b"AURALID1"
SCHEMA_VERSION = 1
LABELS = ("en", "uk", "ru", "tt")
GOVERNED_LABELS = frozenset(("en", "uk", "ru"))
BUCKET_COUNT = 16_384
MINIMUM_NGRAM = 2
MAXIMUM_NGRAM = 5
ALPHA = 0.05
DEVELOPMENT_MARGIN = 0.20


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-model", type=Path, required=True)
    parser.add_argument("--output-metrics", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_text(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(
        "".join(character if character.isalpha() else " " for character in folded)
        .split()
    )


def fnv1a64(value: bytes) -> int:
    result = 14_695_981_039_346_656_037
    for byte in value:
        result = ((result ^ byte) * 1_099_511_628_211) & 0xFFFF_FFFF_FFFF_FFFF
    return result


def bucket_counts(text: str) -> Counter[int]:
    bounded = f"^{normalized_text(text)}$"
    result: Counter[int] = Counter()
    for width in range(MINIMUM_NGRAM, MAXIMUM_NGRAM + 1):
        for start in range(max(0, len(bounded) - width + 1)):
            ngram = bounded[start : start + width].encode("utf-8")
            result[fnv1a64(ngram) % BUCKET_COUNT] += 1
    return result


def read_rows(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["text", "label"]:
            raise SystemExit(f"unexpected CSV columns in {path}: {reader.fieldnames}")
        for row in reader:
            text = row.get("text")
            label = row.get("label")
            if not text or label not in LABELS:
                raise SystemExit(f"invalid row in {path}")
            rows.append((text, label))
    return rows


def train(rows: list[tuple[str, str]]) -> tuple[dict[str, list[float]], dict[str, int]]:
    counts = {label: [0] * BUCKET_COUNT for label in LABELS}
    totals = {label: 0 for label in LABELS}
    for text, label in rows:
        for bucket, count in bucket_counts(text).items():
            counts[label][bucket] += count
            totals[label] += count

    log_probabilities: dict[str, list[float]] = {}
    for label in LABELS:
        denominator = totals[label] + ALPHA * BUCKET_COUNT
        log_probabilities[label] = [
            math.log((count + ALPHA) / denominator) for count in counts[label]
        ]
    return log_probabilities, totals


def predict(text: str, weights: dict[str, list[float]]) -> tuple[str, float]:
    features = bucket_counts(text)
    total = max(1, sum(features.values()))
    scores = {
        label: sum(count * weights[label][bucket] for bucket, count in features.items())
        / total
        for label in LABELS
    }
    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return ordered[0][0], ordered[0][1] - ordered[1][1]


def evaluate(
    rows: list[tuple[str, str]], weights: dict[str, list[float]]
) -> dict[str, object]:
    confusion: Counter[str] = Counter()
    emitted = 0
    emitted_correct = 0
    supported_total = 0
    supported_emitted = 0
    unsupported_as_supported = 0
    for text, expected in rows:
        predicted, margin = predict(text, weights)
        confusion[f"{expected}>{predicted}"] += 1
        if expected in GOVERNED_LABELS:
            supported_total += 1
        if margin < DEVELOPMENT_MARGIN or predicted not in GOVERNED_LABELS:
            continue
        emitted += 1
        if expected in GOVERNED_LABELS:
            supported_emitted += 1
        else:
            unsupported_as_supported += 1
        if predicted == expected:
            emitted_correct += 1

    return {
        "rows": len(rows),
        "top1_accuracy": sum(
            count for key, count in confusion.items() if key.split(">", 1)[0] == key.split(">", 1)[1]
        )
        / max(1, len(rows)),
        "confusion": dict(sorted(confusion.items())),
        "policy": {
            "minimum_margin": DEVELOPMENT_MARGIN,
            "supported_coverage": supported_emitted / max(1, supported_total),
            "precision_when_emitted": emitted_correct / max(1, emitted),
            "unsupported_as_supported_count": unsupported_as_supported,
        },
    }


def write_model(
    path: Path,
    weights: dict[str, list[float]],
    totals: dict[str, int],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        output.write(MAGIC)
        output.write(
            struct.pack(
                "<IIIIdI",
                SCHEMA_VERSION,
                BUCKET_COUNT,
                MINIMUM_NGRAM,
                MAXIMUM_NGRAM,
                ALPHA,
                len(LABELS),
            )
        )
        for label in LABELS:
            encoded_label = label.encode("ascii")
            output.write(struct.pack("<B", len(encoded_label)))
            output.write(encoded_label)
            output.write(struct.pack("<Q", totals[label]))
            values = array.array("f", weights[label])
            if sys.byteorder != "little":
                values.byteswap()
            values.tofile(output)


def main() -> None:
    arguments = parse_arguments()
    train_rows = read_rows(arguments.input_dir / "train.csv")
    calibration_rows = read_rows(arguments.input_dir / "calibration.csv")
    test_rows = read_rows(arguments.input_dir / "test.csv")
    weights, totals = train(train_rows)
    write_model(arguments.output_model, weights, totals)

    metrics = {
        "schema_version": 1,
        "algorithm": "hashed multinomial character n-gram naive Bayes",
        "labels": list(LABELS),
        "bucket_count": BUCKET_COUNT,
        "ngram_widths": [MINIMUM_NGRAM, MAXIMUM_NGRAM],
        "alpha": ALPHA,
        "training_rows": len(train_rows),
        "training_csv_sha256": sha256_file(arguments.input_dir / "train.csv"),
        "model_sha256": sha256_file(arguments.output_model),
        "calibration": evaluate(calibration_rows, weights),
        "test": evaluate(test_rows, weights),
        "release_eligible": False,
    }
    arguments.output_metrics.parent.mkdir(parents=True, exist_ok=True)
    arguments.output_metrics.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"model: {arguments.output_model}")
    print(f"metrics: {arguments.output_metrics}")


if __name__ == "__main__":
    main()
