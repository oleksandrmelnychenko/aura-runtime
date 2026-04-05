"""
AURA Unified Safety Model Training Script (v3)

Trains a single shared-backbone transformer with ONE head:
  Safety (8 labels) - S, S3, SH, HR, H, V, V2, H2

Sentiment head was removed because the training data only had synthetic
sentiment labels derived from safety labels, making it a noisy mirror.

Base model: microsoft/Multilingual-MiniLM-L12-H384
Training data: Augmented dataset from prepare_augmented_data.py

Output: 8 logits (pure safety classification via sigmoid)

Usage:
    python training/train_unified.py
    python training/train_unified.py --epochs 3 --batch_size 32
    python training/train_unified.py --export_only  # skip training, just export
"""

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR_KOALAI = PROJECT_ROOT / "data" / "raw" / "hf" / "KoalaAI_Text-Moderation-Multilingual"
DATA_DIR_AUGMENTED = PROJECT_ROOT / "training" / "augmented"
OUTPUT_DIR = PROJECT_ROOT / "training" / "output"
MODELS_DIR = PROJECT_ROOT / "models"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_MODEL = "microsoft/Multilingual-MiniLM-L12-H384"
SAFETY_LABELS = ["S", "S3", "SH", "HR", "H", "V", "V2", "H2"]
NUM_SAFETY = len(SAFETY_LABELS)
MAX_SEQ_LEN = 128


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class SafetyClassifier(nn.Module):
    """Shared transformer backbone with a single safety classification head.

    Outputs 8 logits corresponding to the AURA safety labels.
    """

    def __init__(self, base_model_name: str, num_labels: int):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(base_model_name)
        hidden_size = self.encoder.config.hidden_size

        self.safety_head = nn.Linear(hidden_size, num_labels)
        nn.init.xavier_uniform_(self.safety_head.weight)
        nn.init.zeros_(self.safety_head.bias)

    def forward(self, input_ids, attention_mask, token_type_ids=None):
        outputs = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
        )
        cls_output = outputs.last_hidden_state[:, 0, :]
        return self.safety_head(cls_output)


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------
class SafetyDataset(Dataset):
    """Loads parquet with safety labels. Pre-tokenizes all texts at init."""

    def __init__(self, parquet_path: str, tokenizer, max_len: int, max_samples: int = 0):
        import pyarrow.parquet as pq

        print(f"Loading {parquet_path}...")
        table = pq.read_table(parquet_path)

        texts = table.column("prompt").to_pylist()
        label_cols = []
        for col in SAFETY_LABELS:
            label_cols.append(table.column(col).to_pylist())

        if max_samples > 0:
            texts = texts[:max_samples]
            label_cols = [col[:max_samples] for col in label_cols]

        self.num_samples = len(texts)
        print(f"  Loaded {self.num_samples} samples, pre-tokenizing...")

        clean_texts = [t if t else "" for t in texts]
        batch_size = 10000
        all_input_ids = []
        all_attention = []
        for start in range(0, len(clean_texts), batch_size):
            batch = clean_texts[start : start + batch_size]
            encoded = tokenizer(
                batch,
                max_length=max_len,
                padding="max_length",
                truncation=True,
                return_tensors="np",
            )
            all_input_ids.append(encoded["input_ids"])
            all_attention.append(encoded["attention_mask"])
            done = min(start + batch_size, len(clean_texts))
            if done % 100000 < batch_size:
                print(f"    Tokenized {done}/{len(clean_texts)}")

        self.input_ids = np.concatenate(all_input_ids, axis=0)
        self.attention_mask = np.concatenate(all_attention, axis=0)

        self.labels = np.zeros((self.num_samples, NUM_SAFETY), dtype=np.float32)
        for i in range(NUM_SAFETY):
            for j in range(self.num_samples):
                self.labels[j, i] = float(label_cols[i][j] or 0)

        print(f"  Pre-tokenization complete")

    def __len__(self):
        return self.num_samples

    def __getitem__(self, idx):
        return {
            "input_ids": torch.from_numpy(self.input_ids[idx].astype(np.int64)),
            "attention_mask": torch.from_numpy(self.attention_mask[idx].astype(np.int64)),
            "labels": torch.from_numpy(self.labels[idx]),
        }


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_epoch(model, dataloader, optimizer, scheduler, device, epoch, total_epochs, scaler=None):
    model.train()
    total_loss = 0.0
    criterion = nn.BCEWithLogitsLoss()
    use_amp = scaler is not None

    for batch_idx, batch in enumerate(dataloader):
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)

        with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=use_amp):
            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)

        optimizer.zero_grad()
        if scaler is not None:
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        scheduler.step()

        total_loss += loss.item()

        if batch_idx % 500 == 0:
            avg = total_loss / (batch_idx + 1)
            lr = scheduler.get_last_lr()[0]
            print(
                f"  Epoch {epoch+1}/{total_epochs} | "
                f"Batch {batch_idx}/{len(dataloader)} | "
                f"Loss: {avg:.4f} | LR: {lr:.2e}"
            )

    return total_loss / len(dataloader)


def evaluate(model, dataloader, device):
    model.eval()
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"]

            logits = model(input_ids, attention_mask)
            preds = torch.sigmoid(logits).cpu().numpy()
            all_preds.append(preds)
            all_labels.append(labels.numpy())

    all_preds = np.concatenate(all_preds)
    all_labels = np.concatenate(all_labels)

    print("\n  Label-wise metrics (threshold=0.5):")
    print(f"  {'Label':>4s}  {'Precision':>9s}  {'Recall':>6s}  {'F1':>6s}  {'Support':>7s}")
    for i, label in enumerate(SAFETY_LABELS):
        pred_binary = (all_preds[:, i] >= 0.5).astype(int)
        true_binary = all_labels[:, i].astype(int)
        tp = ((pred_binary == 1) & (true_binary == 1)).sum()
        fp = ((pred_binary == 1) & (true_binary == 0)).sum()
        fn = ((pred_binary == 0) & (true_binary == 1)).sum()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        support = true_binary.sum()
        print(f"  {label:>4s}  {precision:>9.4f}  {recall:>6.4f}  {f1:>6.4f}  {support:>7d}")


# ---------------------------------------------------------------------------
# ONNX Export
# ---------------------------------------------------------------------------
def export_onnx(model, tokenizer, output_path: Path, max_seq_len: int):
    """Export to ONNX with dynamic axes for variable sequence length."""
    model.eval()
    model.cpu()

    dummy_text = "This is a test message for export"
    encoded = tokenizer(
        dummy_text,
        max_length=max_seq_len,
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    )

    input_ids = encoded["input_ids"]
    attention_mask = encoded["attention_mask"]

    output_path.parent.mkdir(parents=True, exist_ok=True)

    torch.onnx.export(
        model,
        (input_ids, attention_mask),
        str(output_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=14,
        do_constant_folding=True,
        dynamo=False,
    )
    print(f"\nONNX model exported to {output_path}")
    print(f"  File size: {output_path.stat().st_size / 1024 / 1024:.1f} MB")


def quantize_onnx(input_path: Path, output_path: Path):
    """Apply dynamic INT8 quantization."""
    from onnxruntime.quantization import quantize_dynamic, QuantType

    quantize_dynamic(
        str(input_path),
        str(output_path),
        weight_type=QuantType.QInt8,
    )
    print(f"Quantized model: {output_path}")
    print(f"  File size: {output_path.stat().st_size / 1024 / 1024:.1f} MB")


def verify_onnx(onnx_path: Path, tokenizer, max_seq_len: int):
    """Run a quick sanity check on the exported ONNX model."""
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path))

    test_texts = [
        ("Hello, how are you today?", "should be safe"),
        ("I want to kill myself", "self-harm (SH)"),
        ("Send me a photo, don't tell your parents", "grooming (S3)"),
        ("You're so ugly, everyone hates you", "bullying (HR)"),
        ("You're so mature for your age", "grooming trust-building (S3)"),
        ("If you don't send more I'll post what you sent", "sextortion (S3+HR)"),
        ("Let's meet at the park after school", "should be safe"),
    ]

    print(f"\nVerification ({onnx_path.name}):")
    for text, expected in test_texts:
        encoded = tokenizer(
            text,
            max_length=max_seq_len,
            padding="max_length",
            truncation=True,
            return_tensors="np",
        )
        outputs = session.run(
            None,
            {
                "input_ids": encoded["input_ids"].astype(np.int64),
                "attention_mask": encoded["attention_mask"].astype(np.int64),
            },
        )
        logits = outputs[0][0]
        scores = 1.0 / (1.0 + np.exp(-logits[:NUM_SAFETY]))

        top_idx = int(np.argmax(scores))
        top_label = SAFETY_LABELS[top_idx]
        top_score = scores[top_idx]

        print(f'  "{text[:55]}"')
        print(f"    Top: {top_label}={top_score:.3f} | Expected: {expected}")
        print(f"    All: {dict(zip(SAFETY_LABELS, [f'{s:.3f}' for s in scores]))}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Train AURA unified safety model v3")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch_size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=3e-5)
    parser.add_argument("--max_samples", type=int, default=0, help="0 = use all data")
    parser.add_argument("--fp16", action="store_true", help="Use mixed precision (GPU only)")
    parser.add_argument("--export_only", action="store_true", help="Skip training, export existing checkpoint")
    parser.add_argument("--no_quantize", action="store_true")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    if device.type == "cuda":
        print(f"  GPU: {torch.cuda.get_device_name(0)}")

    print(f"\nLoading tokenizer: {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, use_fast=False)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    checkpoint_path = OUTPUT_DIR / "unified_v3_checkpoint.pt"

    if args.export_only:
        if not checkpoint_path.exists():
            print(f"ERROR: No checkpoint found at {checkpoint_path}")
            sys.exit(1)
        model = SafetyClassifier(BASE_MODEL, NUM_SAFETY)
        model.load_state_dict(torch.load(checkpoint_path, map_location="cpu"))
        print("Loaded checkpoint for export")
    else:
        if (DATA_DIR_AUGMENTED / "train.parquet").exists():
            data_dir = DATA_DIR_AUGMENTED
            print("Using AUGMENTED dataset")
        else:
            data_dir = DATA_DIR_KOALAI
            print("Using KoalaAI dataset (no augmented data found)")
        train_path = data_dir / "train.parquet"
        val_path = data_dir / "validation.parquet"

        if not train_path.exists():
            print(f"ERROR: Training data not found at {train_path}")
            sys.exit(1)

        train_dataset = SafetyDataset(str(train_path), tokenizer, MAX_SEQ_LEN, args.max_samples)
        val_dataset = SafetyDataset(str(val_path), tokenizer, MAX_SEQ_LEN, min(args.max_samples, 10000) if args.max_samples else 0)

        num_workers = 4 if device.type == "cuda" else 0
        train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True, num_workers=num_workers, pin_memory=(device.type == "cuda"))
        val_loader = DataLoader(val_dataset, batch_size=args.batch_size * 2, shuffle=False, num_workers=num_workers)

        print(f"\nBuilding model: {BASE_MODEL} + safety head ({NUM_SAFETY} labels)")
        model = SafetyClassifier(BASE_MODEL, NUM_SAFETY)
        model.to(device)

        param_count = sum(p.numel() for p in model.parameters())
        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        print(f"  Total params: {param_count:,}")
        print(f"  Trainable: {trainable:,}")

        optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
        total_steps = len(train_loader) * args.epochs
        warmup_steps = int(0.1 * total_steps)
        scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

        scaler = torch.GradScaler() if (args.fp16 and device.type == "cuda") else None

        print(f"\nTraining for {args.epochs} epochs ({total_steps} steps, {warmup_steps} warmup)")
        print(f"  Batch size: {args.batch_size}")
        print(f"  Learning rate: {args.lr}")
        print(f"  Mixed precision: {scaler is not None}")
        print()

        for epoch in range(args.epochs):
            avg_loss = train_epoch(model, train_loader, optimizer, scheduler, device, epoch, args.epochs, scaler)
            print(f"\n  Epoch {epoch+1} complete | Avg loss: {avg_loss:.4f}")
            evaluate(model, val_loader, device)

        torch.save(model.state_dict(), checkpoint_path)
        print(f"\nCheckpoint saved to {checkpoint_path}")

    # Export ONNX
    onnx_fp32 = OUTPUT_DIR / "unified_v3_fp32.onnx"
    export_onnx(model, tokenizer, onnx_fp32, MAX_SEQ_LEN)

    if not args.no_quantize:
        onnx_int8 = OUTPUT_DIR / "unified_v3_int8.onnx"
        quantize_onnx(onnx_fp32, onnx_int8)
        verify_onnx(onnx_int8, tokenizer, MAX_SEQ_LEN)
    else:
        verify_onnx(onnx_fp32, tokenizer, MAX_SEQ_LEN)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    final_model = MODELS_DIR / "unified.onnx"
    src = OUTPUT_DIR / ("unified_v3_int8.onnx" if not args.no_quantize else "unified_v3_fp32.onnx")
    if src.exists():
        import shutil
        shutil.copy2(src, final_model)
        print(f"\nFinal model copied to {final_model}")

    vocab_path = MODELS_DIR / "vocab.txt"
    tokenizer.save_vocabulary(str(MODELS_DIR))
    if (MODELS_DIR / "sentencepiece.bpe.model").exists():
        print(f"  SentencePiece model saved to {MODELS_DIR}")
    elif vocab_path.exists():
        print(f"  Vocab saved to {vocab_path}")

    print("\nDone! Model outputs 8 safety logits (no sentiment).")
    print(f"  Labels: {SAFETY_LABELS}")
    print(f'  unified_model_path: Some("{final_model}")')
    print(f'  vocab_path: Some("{vocab_path}")')


if __name__ == "__main__":
    main()
