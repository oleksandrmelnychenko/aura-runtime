#!/usr/bin/env python3
"""Download and export ONNX models for AURA ML pipeline.

Usage:
    python scripts/download_models.py [--output-dir models] [--quantize] [--force]
    python scripts/download_models.py --include-safety --safety-model-id <hf-or-local-id>
    python scripts/download_models.py --include-intent --intent-model-id <hf-or-local-id>

Requirements:
    pip install transformers optimum[onnxruntime] onnxruntime torch
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

os.environ.setdefault("PYTHONIOENCODING", "utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def attach_external_data_hashes(entry: dict, model_path: Path, key_prefix: str = "") -> None:
    data_path = model_path.with_name(f"{model_path.name}.data")
    if not data_path.exists():
        return
    filename_key = f"{key_prefix}data_filename"
    sha_key = f"{key_prefix}data_sha256"
    entry[filename_key] = data_path.name
    entry[sha_key] = sha256_file(data_path)


def export_sequence_classifier_model(
    model_id: str,
    output_path: Path,
    num_outputs: int,
    quantize: bool,
    max_seq_length: int = 128,
) -> dict:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    print(f"Exporting model: {model_id} -> {output_path.name}")

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
    except Exception:
        tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=False)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()
    model_num_labels = int(getattr(model.config, "num_labels", -1))
    if model_num_labels != num_outputs:
        raise ValueError(
            f"Model {model_id} has num_labels={model_num_labels}, expected {num_outputs}"
        )

    dummy = tokenizer(
        "test input", return_tensors="pt", padding="max_length", max_length=max_seq_length
    )

    with torch.no_grad():
        token_type_ids = dummy.get("token_type_ids")
        if token_type_ids is None:
            token_type_ids = torch.zeros_like(dummy["input_ids"])
        export_inputs = (dummy["input_ids"], dummy["attention_mask"], token_type_ids)
        input_names = ["input_ids", "attention_mask", "token_type_ids"]

        torch.onnx.export(
            model,
            export_inputs,
            str(output_path),
            input_names=input_names,
            output_names=["logits"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "seq"},
                "attention_mask": {0: "batch", 1: "seq"},
                "token_type_ids": {0: "batch", 1: "seq"},
                "logits": {0: "batch"},
            },
            opset_version=18,
        )

    quantized_path = None
    if quantize:
        quantized_path = output_path.with_name(f"{output_path.stem}_int8.onnx")
        quantize_model(output_path, quantized_path)

    manifest_entry = {
        "filename": output_path.name,
        "sha256": sha256_file(output_path),
        "num_outputs": num_outputs,
        "max_seq_length": max_seq_length,
    }
    attach_external_data_hashes(manifest_entry, output_path)
    if quantized_path and quantized_path.exists():
        manifest_entry["quantized_filename"] = quantized_path.name
        manifest_entry["quantized_sha256"] = sha256_file(quantized_path)
        attach_external_data_hashes(manifest_entry, quantized_path, key_prefix="quantized_")
    return manifest_entry


def export_ifmain_safety_remap_model(
    model_id: str,
    output_path: Path,
    quantize: bool,
    max_seq_length: int = 128,
) -> dict:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    print(f"Exporting safety model with ifmain remap: {model_id} -> {output_path.name}")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
    except Exception:
        tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=False)
    base_model = AutoModelForSequenceClassification.from_pretrained(model_id)
    base_model.eval()
    model_num_labels = int(getattr(base_model.config, "num_labels", -1))
    if model_num_labels != 18:
        raise ValueError(
            f"ifmain safety remap expects 18 labels, got {model_num_labels} for {model_id}"
        )

    # Category order from model card:
    # 0 harassment, 1 harassment_threatening, 2 hate, 3 hate_threatening,
    # 4 self_harm, 5 self_harm_instructions, 6 self_harm_intent, 7 sexual,
    # 8 sexual_minors, 9 violence, 10 violence_graphic, 11 self-harm,
    # 12 sexual/minors, 13 hate/threatening, 14 violence/graphic,
    # 15 self-harm/intent, 16 self-harm/instructions, 17 harassment/threatening
    class IfmainSafetyRemapWrapper(torch.nn.Module):
        def __init__(self, model):
            super().__init__()
            self.model = model

        def forward(self, input_ids, attention_mask, token_type_ids):
            logits18 = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
            ).logits
            probs18 = torch.sigmoid(logits18)

            grooming = torch.max(
                torch.max(probs18[:, 8], probs18[:, 12]),
                probs18[:, 7],
            )
            bullying = torch.max(
                torch.max(probs18[:, 0], probs18[:, 2]),
                torch.max(probs18[:, 1], probs18[:, 17]),
            )
            self_harm = torch.max(
                torch.max(probs18[:, 4], probs18[:, 11]),
                torch.max(
                    torch.max(probs18[:, 5], probs18[:, 6]),
                    torch.max(probs18[:, 15], probs18[:, 16]),
                ),
            )
            manipulation = torch.max(
                torch.max(probs18[:, 1], probs18[:, 17]),
                torch.max(probs18[:, 9], probs18[:, 10]),
            )
            max_risk = torch.max(
                torch.max(grooming, bullying),
                torch.max(self_harm, manipulation),
            )
            safe = 1.0 - max_risk

            out = torch.stack([grooming, bullying, self_harm, manipulation, safe], dim=1)
            tie = token_type_ids[:, :1].to(out.dtype) * 0.0
            return out + tie

    export_model = IfmainSafetyRemapWrapper(base_model)
    dummy = tokenizer(
        "test input", return_tensors="pt", padding="max_length", max_length=max_seq_length
    )
    with torch.no_grad():
        token_type_ids = dummy.get("token_type_ids")
        if token_type_ids is None:
            token_type_ids = torch.zeros_like(dummy["input_ids"])
        export_inputs = (dummy["input_ids"], dummy["attention_mask"], token_type_ids)
        torch.onnx.export(
            export_model,
            export_inputs,
            str(output_path),
            input_names=["input_ids", "attention_mask", "token_type_ids"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "seq"},
                "attention_mask": {0: "batch", 1: "seq"},
                "token_type_ids": {0: "batch", 1: "seq"},
                "logits": {0: "batch"},
            },
            opset_version=18,
        )

    quantized_path = None
    if quantize:
        quantized_path = output_path.with_name(f"{output_path.stem}_int8.onnx")
        quantize_model(output_path, quantized_path)

    manifest_entry = {
        "filename": output_path.name,
        "sha256": sha256_file(output_path),
        "num_outputs": 5,
        "max_seq_length": max_seq_length,
        "source_model_id": model_id,
        "safety_label_mapping": "ifmain_moderation18_to_aura5_v1",
    }
    attach_external_data_hashes(manifest_entry, output_path)
    if quantized_path and quantized_path.exists():
        manifest_entry["quantized_filename"] = quantized_path.name
        manifest_entry["quantized_sha256"] = sha256_file(quantized_path)
        attach_external_data_hashes(manifest_entry, quantized_path, key_prefix="quantized_")
    return manifest_entry


def export_toxicity_model(output_dir: Path, quantize: bool) -> dict:
    return export_sequence_classifier_model(
        model_id="unitary/multilingual-toxic-xlm-roberta",
        output_path=output_dir / "toxicity.onnx",
        num_outputs=6,
        quantize=quantize,
        max_seq_length=128,
    )


def export_sentiment_model(output_dir: Path, quantize: bool) -> dict:
    return export_sequence_classifier_model(
        model_id="cardiffnlp/twitter-xlm-roberta-base-sentiment-multilingual",
        output_path=output_dir / "sentiment.onnx",
        num_outputs=3,
        quantize=quantize,
        max_seq_length=128,
    )


def export_safety_model(output_dir: Path, quantize: bool, model_id: str) -> dict:
    if model_id == "ifmain/ModerationBERT-En-02":
        return export_ifmain_safety_remap_model(
            model_id=model_id,
            output_path=output_dir / "safety.onnx",
            quantize=quantize,
            max_seq_length=128,
        )
    return export_sequence_classifier_model(
        model_id=model_id,
        output_path=output_dir / "safety.onnx",
        num_outputs=5,
        quantize=quantize,
        max_seq_length=128,
    )


def export_intent_model(output_dir: Path, quantize: bool, model_id: str) -> dict:
    return export_sequence_classifier_model(
        model_id=model_id,
        output_path=output_dir / "intent.onnx",
        num_outputs=4,
        quantize=quantize,
        max_seq_length=128,
    )


def register_existing_onnx_model(
    source_path: Path,
    output_path: Path,
    num_outputs: int,
    source_model_id: str | None = None,
) -> dict:
    if not source_path.exists():
        raise FileNotFoundError(f"ONNX file not found: {source_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if source_path.resolve() != output_path.resolve():
        shutil.copy2(source_path, output_path)
    source_data_path = source_path.with_name(f"{source_path.name}.data")
    output_data_path = output_path.with_name(f"{output_path.name}.data")
    if source_data_path.exists() and source_data_path.resolve() != output_data_path.resolve():
        shutil.copy2(source_data_path, output_data_path)

    entry = {
        "filename": output_path.name,
        "sha256": sha256_file(output_path),
        "num_outputs": num_outputs,
        "max_seq_length": 128,
    }
    attach_external_data_hashes(entry, output_path)
    if source_model_id:
        entry["source_model_id"] = source_model_id
    return entry


def existing_model_manifest_entry(
    model_path: Path,
    num_outputs: int | None = None,
    max_seq_length: int | None = None,
    source_model_id: str | None = None,
) -> dict:
    entry = {
        "filename": model_path.name,
        "sha256": sha256_file(model_path),
    }
    if num_outputs is not None:
        entry["num_outputs"] = num_outputs
    if max_seq_length is not None:
        entry["max_seq_length"] = max_seq_length
    attach_external_data_hashes(entry, model_path)
    if source_model_id:
        entry["source_model_id"] = source_model_id
    return entry


def export_vocab(output_dir: Path) -> dict:
    from transformers import AutoTokenizer

    model_id = "bert-base-multilingual-cased"
    print(f"Downloading vocab from: {model_id}")

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
    except Exception:
        tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=False)
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
        try:
            quantize_dynamic(str(input_path), str(output_path), weight_type=QuantType.QInt8)
            original_mb = input_path.stat().st_size / (1024 * 1024)
            quantized_mb = output_path.stat().st_size / (1024 * 1024)
            ratio = quantized_mb / original_mb * 100 if original_mb > 0 else 0
            print(f"  {original_mb:.1f}MB -> {quantized_mb:.1f}MB ({ratio:.0f}%)")
        except Exception as err:
            print(f"  quantization skipped due to error: {err}")
    except ImportError:
        print("  onnxruntime.quantization not available, skipping")


def main() -> int:
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
    parser.add_argument(
        "--skip-toxicity",
        action="store_true",
        help="Skip exporting toxicity.onnx",
    )
    parser.add_argument(
        "--skip-sentiment",
        action="store_true",
        help="Skip exporting sentiment.onnx",
    )
    parser.add_argument(
        "--include-safety",
        action="store_true",
        help="Export safety head model to safety.onnx",
    )
    parser.add_argument(
        "--include-intent",
        action="store_true",
        help="Export intent head model to intent.onnx",
    )
    parser.add_argument(
        "--safety-model-id",
        default=None,
        help="HF model id (or local path) with 5 output logits for safety head",
    )
    parser.add_argument(
        "--safety-onnx-path",
        default=None,
        help="Path to prebuilt native safety.onnx (preferred for production)",
    )
    parser.add_argument(
        "--safety-source-id",
        default=None,
        help="Metadata source id for prebuilt safety.onnx (optional)",
    )
    parser.add_argument(
        "--intent-model-id",
        default=None,
        help="HF model id (or local path) with 4 output logits for intent head",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"version": 1, "models": {}}

    if args.vocab_only:
        manifest["models"]["vocab"] = export_vocab(output_dir)
    else:
        model_exports = []
        if not args.skip_toxicity:
            model_exports.append(
                ("toxicity", "toxicity.onnx", lambda: export_toxicity_model(output_dir, args.quantize))
            )
        if not args.skip_sentiment:
            model_exports.append(
                ("sentiment", "sentiment.onnx", lambda: export_sentiment_model(output_dir, args.quantize))
            )

        for name, path, export_fn in model_exports:
            full_path = output_dir / path
            if args.force or not full_path.exists():
                manifest["models"][name] = export_fn()
            else:
                print(f"{name} model exists at {full_path}, skipping (--force to re-download)")
                manifest["models"][name] = existing_model_manifest_entry(full_path)

        if args.include_safety:
            if not args.safety_model_id and not args.safety_onnx_path:
                print(
                    "ERROR: --include-safety requires --safety-model-id or --safety-onnx-path",
                    file=sys.stderr,
                )
                return 2
            safety_path = output_dir / "safety.onnx"
            if args.force or not safety_path.exists():
                if args.safety_onnx_path:
                    manifest["models"]["safety"] = register_existing_onnx_model(
                        source_path=Path(args.safety_onnx_path),
                        output_path=safety_path,
                        num_outputs=5,
                        source_model_id=args.safety_source_id,
                    )
                else:
                    manifest["models"]["safety"] = export_safety_model(
                        output_dir, args.quantize, args.safety_model_id
                    )
            else:
                print(f"safety model exists at {safety_path}, skipping (--force to re-download)")
                safety_entry = existing_model_manifest_entry(
                    safety_path,
                    num_outputs=5,
                    max_seq_length=128,
                )
                if args.safety_source_id:
                    safety_entry["source_model_id"] = args.safety_source_id
                manifest["models"]["safety"] = safety_entry

        if args.include_intent:
            if not args.intent_model_id:
                print("ERROR: --include-intent requires --intent-model-id", file=sys.stderr)
                return 2
            intent_path = output_dir / "intent.onnx"
            if args.force or not intent_path.exists():
                manifest["models"]["intent"] = export_intent_model(
                    output_dir, args.quantize, args.intent_model_id
                )
            else:
                print(f"intent model exists at {intent_path}, skipping (--force to re-download)")
                manifest["models"]["intent"] = existing_model_manifest_entry(
                    intent_path,
                    num_outputs=4,
                    max_seq_length=128,
                )

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
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print(f"\nManifest written to {manifest_path}")
    print("Done!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
