#!/usr/bin/env python3
"""Prepare deterministic language-ID development splits from local Arrow data.

The output is development evidence only. It does not create an independent
release holdout and deliberately keeps Tatar as an unsupported Cyrillic control.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import unicodedata
from pathlib import Path

try:
    import pyarrow.ipc as arrow_ipc
except ImportError as error:  # pragma: no cover - exercised by operator setup
    raise SystemExit(
        "pyarrow is required; install training/language_id/requirements.txt"
    ) from error


LABELS = ("en", "uk", "ru", "tt")
SPLIT_NAMES = ("train", "calibration", "test")
MINIMUM_ALPHABETIC_SCALARS = 20
MAXIMUM_ALPHABETIC_SCALARS = 500


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_text(raw_text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", raw_text).split())


def split_name(label: str, text: str) -> str:
    digest = hashlib.sha256(f"{label}\0{text}".encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:8], "big") % 100
    if bucket < 70:
        return "train"
    if bucket < 85:
        return "calibration"
    return "test"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Path to data/raw/hf/textdetox_multilingual",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    arguments.output_dir.mkdir(parents=True, exist_ok=True)

    output_paths = {
        split: arguments.output_dir / f"{split}.csv" for split in SPLIT_NAMES
    }
    handles = {
        split: path.open("w", encoding="utf-8", newline="")
        for split, path in output_paths.items()
    }
    writers = {
        split: csv.DictWriter(
            handle,
            fieldnames=["text", "label"],
            lineterminator="\n",
        )
        for split, handle in handles.items()
    }
    for writer in writers.values():
        writer.writeheader()

    counts = {split: {label: 0 for label in LABELS} for split in SPLIT_NAMES}
    discarded = {label: 0 for label in LABELS}
    source_artifacts: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    try:
        for label in LABELS:
            source_path = (
                arguments.source_root
                / label
                / "data-00000-of-00001.arrow"
            )
            if not source_path.is_file():
                raise SystemExit(f"missing source artifact: {source_path}")

            with source_path.open("rb") as source:
                table = arrow_ipc.open_stream(source).read_all()
            if "text" not in table.column_names:
                raise SystemExit(f"source has no text column: {source_path}")

            source_artifacts.append(
                {
                    "label": label,
                    "path": str(source_path),
                    "rows": table.num_rows,
                    "sha256": sha256_file(source_path),
                }
            )

            for raw_text in table["text"].to_pylist():
                if not isinstance(raw_text, str):
                    discarded[label] += 1
                    continue
                text = normalized_text(raw_text)
                alphabetic_count = sum(character.isalpha() for character in text)
                if not (
                    MINIMUM_ALPHABETIC_SCALARS
                    <= alphabetic_count
                    <= MAXIMUM_ALPHABETIC_SCALARS
                ):
                    discarded[label] += 1
                    continue

                deduplication_key = (label, text.casefold())
                if deduplication_key in seen:
                    discarded[label] += 1
                    continue
                seen.add(deduplication_key)

                split = split_name(label, text)
                writers[split].writerow({"text": text, "label": label})
                counts[split][label] += 1
    finally:
        for handle in handles.values():
            handle.close()

    summary = {
        "schema_version": 1,
        "source_dataset": "textdetox/multilingual_toxicity_dataset-local-snapshot",
        "labels": list(LABELS),
        "governed_labels": ["en", "ru", "uk"],
        "unsupported_control_labels": ["tt"],
        "normalization": "NFKC plus collapsed Unicode whitespace",
        "filter": {
            "minimum_alphabetic_scalars": MINIMUM_ALPHABETIC_SCALARS,
            "maximum_alphabetic_scalars": MAXIMUM_ALPHABETIC_SCALARS,
        },
        "split": {
            "algorithm": "sha256(label + NUL + normalized_text) first-u64 mod 100",
            "train_buckets": "0..69",
            "calibration_buckets": "70..84",
            "test_buckets": "85..99",
        },
        "counts": counts,
        "discarded_or_duplicate_rows": discarded,
        "source_artifacts": source_artifacts,
        "release_eligible": False,
        "release_blockers": [
            "not an independently collected holdout",
            "no native-speaker adjudication",
            "source-label noise has not been independently reviewed",
            "source-license chain has not been approved for redistribution",
        ],
    }
    summary_path = arguments.output_dir / "dataset-summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    for split, path in output_paths.items():
        print(f"{split}: {sum(counts[split].values())} rows -> {path}")
    print(f"summary: {summary_path}")


if __name__ == "__main__":
    main()
