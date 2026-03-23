#!/usr/bin/env python3
"""Download and export ONNX models for AURA ML pipeline.

Usage:
    python scripts/download_models.py [--output-dir models] [--quantize] [--force]

Requirements:
    pip install transformers optimum[onnxruntime] onnxruntime torch
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def export_toxicity_model(output_dir: Path, quantize: bool) -> dict:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    model_id = "unitary/multilingual-toxic-xlm-roberta"
    print(f"Exporting toxicity model: {model_id}")

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()

    dummy = tokenizer(
        "test input", return_tensors="pt", padding="max_length", max_length=128
    )

    onnx_path = output_dir / "toxicity.onnx"
    with torch.no_grad():
        torch.onnx.export(
            model,
            (dummy["input_ids"], dummy["attention_mask"]),
            str(onnx_path),
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "seq"},
                "attention_mask": {0: "batch", 1: "seq"},
                "logits": {0: "batch"},
            },
            opset_version=14,
        )

    if quantize:
        quantize_model(onnx_path, output_dir / "toxicity_int8.onnx")

    return {
        "filename": "toxicity.onnx",
        "sha256": sha256_file(onnx_path),
        "num_outputs": 6,
        "max_seq_length": 128,
    }


def export_sentiment_model(output_dir: Path, quantize: bool) -> dict:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    model_id = "cardiffnlp/twitter-xlm-roberta-base-sentiment-multilingual"
    print(f"Exporting sentiment model: {model_id}")

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()

    dummy = tokenizer(
        "test input", return_tensors="pt", padding="max_length", max_length=128
    )

    onnx_path = output_dir / "sentiment.onnx"
    with torch.no_grad():
        torch.onnx.export(
            model,
            (dummy["input_ids"], dummy["attention_mask"]),
            str(onnx_path),
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "seq"},
                "attention_mask": {0: "batch", 1: "seq"},
                "logits": {0: "batch"},
            },
            opset_version=14,
        )

    if quantize:
        quantize_model(onnx_path, output_dir / "sentiment_int8.onnx")

    return {
        "filename": "sentiment.onnx",
        "sha256": sha256_file(onnx_path),
        "num_outputs": 3,
        "max_seq_length": 128,
    }


def export_vocab(output_dir: Path) -> dict:
    from transformers import AutoTokenizer

    model_id = "bert-base-multilingual-cased"
    print(f"Downloading vocab from: {model_id}")

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    vocab_path = output_dir / "vocab.txt"
    vocab = tokenizer.get_vocab()
    sorted_vocab = sorted(vocab.items(), key=lambda x: x[1])

    with open(vocab_path, "w", encoding="utf-8") as f:
        for token, _ in sorted_vocab:
            f.write(f"{token}\n")

    return {
        "filename": "vocab.txt",
        "sha256": sha256_file(vocab_path),
    }


def quantize_model(input_path: Path, output_path: Path):
    try:
        from onnxruntime.quantization import QuantType, quantize_dynamic

        print(f"Quantizing {input_path.name} -> {output_path.name} (INT8)")
        quantize_dynamic(str(input_path), str(output_path), weight_type=QuantType.QInt8)
        original_mb = input_path.stat().st_size / (1024 * 1024)
        quantized_mb = output_path.stat().st_size / (1024 * 1024)
        ratio = quantized_mb / original_mb * 100 if original_mb > 0 else 0
        print(f"  {original_mb:.1f}MB -> {quantized_mb:.1f}MB ({ratio:.0f}%)")
    except ImportError:
        print("  onnxruntime.quantization not available, skipping")


def main():
    parser = argparse.ArgumentParser(description="Download ONNX models for AURA")
    parser.add_argument("--output-dir", default="models", help="Output directory")
    parser.add_argument(
        "--quantize", action="store_true", help="Produce INT8 quantized models"
    )
    parser.add_argument(
        "--force", action="store_true", help="Re-download even if files exist"
    )
    parser.add_argument(
        "--vocab-only", action="store_true", help="Only download vocab.txt"
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"version": 1, "models": {}}

    if args.vocab_only:
        manifest["models"]["vocab"] = export_vocab(output_dir)
    else:
        for name, path, export_fn in [
            ("toxicity", "toxicity.onnx", lambda: export_toxicity_model(output_dir, args.quantize)),
            ("sentiment", "sentiment.onnx", lambda: export_sentiment_model(output_dir, args.quantize)),
        ]:
            full_path = output_dir / path
            if args.force or not full_path.exists():
                manifest["models"][name] = export_fn()
            else:
                print(f"{name} model exists at {full_path}, skipping (--force to re-download)")
                manifest["models"][name] = {
                    "filename": path,
                    "sha256": sha256_file(full_path),
                }

        vocab_path = output_dir / "vocab.txt"
        if args.force or not vocab_path.exists():
            manifest["models"]["vocab"] = export_vocab(output_dir)
        else:
            print(f"Vocab exists at {vocab_path}, skipping")
            manifest["models"]["vocab"] = {
                "filename": "vocab.txt",
                "sha256": sha256_file(vocab_path),
            }

    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nManifest written to {manifest_path}")
    print("Done!")


if __name__ == "__main__":
    main()
