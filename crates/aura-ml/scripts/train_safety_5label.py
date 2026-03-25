#!/usr/bin/env python3
"""Train a native 5-label safety model for AURA.

Expected input columns (JSONL or CSV):
  - text (str)
  - grooming (0/1)
  - bullying (0/1)
  - self_harm (0/1)
  - manipulation (0/1)
  - safe (0/1, optional; auto-derived if omitted)

Usage example:
  python crates/aura-ml/scripts/train_safety_5label.py \
    --train-file data/safety_train.jsonl \
    --eval-file data/safety_eval.jsonl \
    --output-dir artifacts/safety-5label \
    --base-model bert-base-multilingual-cased \
    --export-onnx --onnx-output models/safety.onnx --quantize
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np
import torch
from datasets import load_dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

LABELS = ["grooming", "bullying", "self_harm", "manipulation", "safe"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train native AURA safety 5-label model")
    parser.add_argument("--train-file", required=True, help="Path to training JSONL/CSV file")
    parser.add_argument("--eval-file", required=True, help="Path to eval JSONL/CSV file")
    parser.add_argument("--output-dir", required=True, help="Where to save trained model")
    parser.add_argument(
        "--base-model",
        default="bert-base-multilingual-cased",
        help="HF base model id",
    )
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--export-onnx", action="store_true")
    parser.add_argument("--onnx-output", default="models/safety.onnx")
    parser.add_argument("--quantize", action="store_true")
    parser.add_argument("--push-to-hub", default=None, help="HF repo id to push model")
    parser.add_argument("--hub-private", action="store_true")
    return parser.parse_args()


def file_format(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in [".jsonl", ".json"]:
        return "json"
    if suffix == ".csv":
        return "csv"
    raise ValueError(f"Unsupported file format for {path}")


def ensure_columns(record: Dict) -> Dict:
    if "text" not in record:
        raise ValueError("Dataset record missing 'text' field")
    for key in LABELS[:-1]:
        if key not in record:
            raise ValueError(f"Dataset record missing '{key}' field")

    cleaned = dict(record)
    for key in LABELS[:-1]:
        cleaned[key] = int(float(cleaned[key]) > 0.0)

    if "safe" not in cleaned:
        cleaned["safe"] = int(
            (cleaned["grooming"] + cleaned["bullying"] + cleaned["self_harm"] + cleaned["manipulation"]) == 0
        )
    else:
        cleaned["safe"] = int(float(cleaned["safe"]) > 0.0)
    return cleaned


def build_label_vector(record: Dict) -> List[float]:
    return [float(record[label]) for label in LABELS]


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    probs = 1.0 / (1.0 + np.exp(-logits))
    preds = (probs >= 0.5).astype(np.float32)
    labels = labels.astype(np.float32)
    micro_acc = float((preds == labels).mean())
    return {"multi_label_accuracy": micro_acc}


def export_onnx(
    model_dir: Path,
    base_model_id: str,
    onnx_output: Path,
    max_length: int,
    quantize: bool,
) -> None:
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
    tokenizer = AutoTokenizer.from_pretrained(base_model_id)
    model.eval()

    dummy = tokenizer(
        "test input", return_tensors="pt", padding="max_length", max_length=max_length
    )
    token_type_ids = dummy.get("token_type_ids")
    if token_type_ids is None:
        token_type_ids = torch.zeros_like(dummy["input_ids"])

    onnx_output.parent.mkdir(parents=True, exist_ok=True)
    with torch.no_grad():
        torch.onnx.export(
            model,
            (dummy["input_ids"], dummy["attention_mask"], token_type_ids),
            str(onnx_output),
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

    if quantize:
        try:
            from onnxruntime.quantization import QuantType, quantize_dynamic

            quantized = onnx_output.with_name(f"{onnx_output.stem}_int8.onnx")
            quantize_dynamic(str(onnx_output), str(quantized), weight_type=QuantType.QInt8)
            print(f"Quantized ONNX saved: {quantized}")
        except Exception as err:
            print(f"Quantization skipped: {err}")


def main() -> int:
    args = parse_args()
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    train_fmt = file_format(args.train_file)
    eval_fmt = file_format(args.eval_file)
    if train_fmt != eval_fmt:
        raise ValueError("Train/eval files must use the same format")

    data_files = {"train": args.train_file, "validation": args.eval_file}
    ds = load_dataset(train_fmt, data_files=data_files)
    ds = ds.map(ensure_columns)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)

    def preprocess(batch):
        encoded = tokenizer(
            batch["text"],
            truncation=True,
            max_length=args.max_length,
        )
        encoded["labels"] = [build_label_vector(rec) for rec in zip_records(batch)]
        return encoded

    def zip_records(batch):
        size = len(batch["text"])
        for i in range(size):
            yield {label: batch[label][i] for label in ["text", *LABELS]}

    tokenized = ds.map(preprocess, batched=True, remove_columns=ds["train"].column_names)

    id2label = {idx: label for idx, label in enumerate(LABELS)}
    label2id = {label: idx for idx, label in enumerate(LABELS)}
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=len(LABELS),
        id2label=id2label,
        label2id=label2id,
        problem_type="multi_label_classification",
    )

    output_dir = Path(args.output_dir)
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        learning_rate=args.learning_rate,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs=args.epochs,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_steps=50,
        load_best_model_at_end=True,
        metric_for_best_model="multi_label_accuracy",
        greater_is_better=True,
        seed=args.seed,
        report_to=[],
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()
    print("Eval metrics:", json.dumps(metrics, indent=2))

    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    if args.push_to_hub:
        trainer.push_to_hub(
            repo_id=args.push_to_hub,
            private=args.hub_private,
            commit_message="Train AURA native safety 5-label model",
        )

    if args.export_onnx:
        export_onnx(
            model_dir=output_dir,
            base_model_id=args.base_model,
            onnx_output=Path(args.onnx_output),
            max_length=args.max_length,
            quantize=args.quantize,
        )

    print("Training pipeline complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
