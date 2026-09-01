#!/usr/bin/env python3
"""Compile and assemble the independently pinned Swift shadow model bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coreml-model", type=Path, required=True)
    parser.add_argument("--ngram-model", type=Path, required=True)
    parser.add_argument("--dataset-summary", type=Path, required=True)
    parser.add_argument("--coreml-metrics", type=Path, required=True)
    parser.add_argument("--ngram-metrics", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    arguments = parse_arguments()
    inputs = (
        arguments.coreml_model,
        arguments.ngram_model,
        arguments.dataset_summary,
        arguments.coreml_metrics,
        arguments.ngram_metrics,
    )
    for path in inputs:
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")
    if arguments.output_dir.exists():
        raise SystemExit(f"refusing to replace existing output: {arguments.output_dir}")

    arguments.output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aura-language-id-coreml-") as temporary:
        temporary_path = Path(temporary)
        subprocess.run(
            [
                "xcrun",
                "coremlcompiler",
                "compile",
                str(arguments.coreml_model),
                str(temporary_path),
            ],
            check=True,
        )
        compiled_model = temporary_path / "AuraAbstainingLanguageID.mlmodelc"
        if not compiled_model.is_dir():
            raise SystemExit("coremlcompiler did not produce the expected model directory")
        arguments.output_dir.mkdir()
        shutil.copytree(
            compiled_model,
            arguments.output_dir / compiled_model.name,
        )

    ngram_name = "AuraLanguageIDNGramV1.bin"
    shutil.copyfile(arguments.ngram_model, arguments.output_dir / ngram_name)

    artifact_paths = sorted(
        path.relative_to(arguments.output_dir).as_posix()
        for path in arguments.output_dir.rglob("*")
        if path.is_file()
    )
    artifacts = [
        {
            "path": relative_path,
            "sha256": sha256_file(arguments.output_dir / relative_path),
        }
        for relative_path in artifact_paths
    ]
    xcode_version = subprocess.run(
        ["xcodebuild", "-version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip().replace("\n", " / ")

    manifest = {
        "schema_version": 1,
        "identifier": "aura-language-id-shadow-maxent-ngram-v1",
        "release_state": "shadow_only",
        "production_span_emission_enabled": False,
        "model_directory": "AuraAbstainingLanguageID.mlmodelc",
        "ngram_filename": ngram_name,
        "labels": ["en", "ru", "tt", "uk"],
        "governed_labels": ["en", "ru", "uk"],
        "unsupported_labels": ["tt"],
        "policy": {
            "minimum_alphabetic_scalars": 20,
            "maximum_utf8_bytes": 10_000,
            "minimum_coreml_probability": 0.50,
            "minimum_coreml_margin": 0.20,
            "minimum_ngram_margin": 0.20,
            "require_apple_language_agreement": True,
            "allowed_cyrillic_scalars": "абвгґдеёєжзиіїйклмнопрстуфхцчшщъыьэюя",
        },
        "artifacts": artifacts,
        "provenance": {
            "source_dataset": "textdetox/multilingual_toxicity_dataset-local-snapshot",
            "source_model_sha256": sha256_file(arguments.coreml_model),
            "source_summary_sha256": sha256_file(arguments.dataset_summary),
            "coreml_training_metrics_sha256": sha256_file(arguments.coreml_metrics),
            "ngram_training_metrics_sha256": sha256_file(arguments.ngram_metrics),
            "xcode": xcode_version,
            "release_eligible": False,
        },
    }
    manifest_path = arguments.output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"bundle: {arguments.output_dir}")
    print(f"manifest_sha256: {sha256_file(manifest_path)}")


if __name__ == "__main__":
    main()
