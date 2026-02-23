#!/usr/bin/env python3
"""
Download and export ONNX models for AURA ML pipeline.

Requirements:
    pip install transformers optimum[onnxruntime] onnx onnxruntime

Models:
    1. Toxicity: unitary/toxic-bert (Jigsaw 6-label: toxic, severe_toxic, obscene, threat, insult, identity_hate)
    2. Sentiment: textattack/bert-base-uncased-SST-2 (binary: negative, positive — same BERT vocab)

Output:
    models/toxicity.onnx    — toxicity classifier
    models/sentiment.onnx   — sentiment analyzer
    models/vocab.txt        — BERT WordPiece vocabulary (from toxic-bert)
"""

import os
import sys
import shutil
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent / "models"


def download_toxicity():
    """Download and export toxic-bert to ONNX."""
    from optimum.onnxruntime import ORTModelForSequenceClassification
    from transformers import AutoTokenizer

    model_name = "unitary/toxic-bert"
    output_dir = MODELS_DIR / "toxicity_tmp"

    print(f"[1/4] Downloading {model_name}...")
    model = ORTModelForSequenceClassification.from_pretrained(
        model_name, export=True
    )
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    print(f"[2/4] Saving ONNX model to {output_dir}...")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    # Move the ONNX file to models/
    onnx_path = output_dir / "model.onnx"
    target = MODELS_DIR / "toxicity.onnx"
    if onnx_path.exists():
        shutil.move(str(onnx_path), str(target))
        print(f"  -> {target}")
    else:
        # optimum may output differently
        for f in output_dir.glob("*.onnx"):
            shutil.move(str(f), str(target))
            print(f"  -> {target}")
            break

    # Copy vocab.txt
    vocab_src = output_dir / "vocab.txt"
    vocab_dst = MODELS_DIR / "vocab.txt"
    if vocab_src.exists():
        shutil.copy2(str(vocab_src), str(vocab_dst))
        print(f"  -> {vocab_dst}")
    else:
        # Try tokenizer.json fallback
        print("  WARNING: vocab.txt not found, checking tokenizer files...")
        for f in output_dir.iterdir():
            print(f"    {f.name}")

    # Cleanup temp dir
    shutil.rmtree(str(output_dir), ignore_errors=True)

    return target.exists()


def download_sentiment():
    """Download and export sentiment model to ONNX."""
    from optimum.onnxruntime import ORTModelForSequenceClassification
    from transformers import AutoTokenizer

    # Use BERT-based model (same WordPiece vocab as toxic-bert).
    # SST-2 binary: LABEL_0=negative, LABEL_1=positive
    model_name = "textattack/bert-base-uncased-SST-2"
    output_dir = MODELS_DIR / "sentiment_tmp"

    print(f"[3/4] Downloading {model_name}...")
    model = ORTModelForSequenceClassification.from_pretrained(
        model_name, export=True
    )
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    print(f"[4/4] Saving ONNX model to {output_dir}...")
    model.save_pretrained(output_dir)

    # Move the ONNX file
    onnx_path = output_dir / "model.onnx"
    target = MODELS_DIR / "sentiment.onnx"
    if onnx_path.exists():
        shutil.move(str(onnx_path), str(target))
        print(f"  -> {target}")
    else:
        for f in output_dir.glob("*.onnx"):
            shutil.move(str(f), str(target))
            print(f"  -> {target}")
            break

    # Cleanup
    shutil.rmtree(str(output_dir), ignore_errors=True)

    return target.exists()


def verify_models():
    """Quick verification that models load and produce output."""
    import onnxruntime as ort
    import numpy as np

    print("\nVerifying models...")

    # Test toxicity
    tox_path = str(MODELS_DIR / "toxicity.onnx")
    if os.path.exists(tox_path):
        session = ort.InferenceSession(tox_path)
        inputs = session.get_inputs()
        print(f"  Toxicity model inputs: {[i.name for i in inputs]}")
        print(f"  Toxicity model outputs: {[o.name for o in session.get_outputs()]}")

        # Test inference
        dummy = {
            "input_ids": np.zeros((1, 128), dtype=np.int64),
            "attention_mask": np.ones((1, 128), dtype=np.int64),
            "token_type_ids": np.zeros((1, 128), dtype=np.int64),
        }
        # Filter to only use inputs the model expects
        model_input_names = {i.name for i in inputs}
        dummy = {k: v for k, v in dummy.items() if k in model_input_names}
        result = session.run(None, dummy)
        print(f"  Toxicity output shape: {result[0].shape}")
        print(f"  OK: toxicity model works")
    else:
        print(f"  SKIP: {tox_path} not found")

    # Test sentiment
    sent_path = str(MODELS_DIR / "sentiment.onnx")
    if os.path.exists(sent_path):
        session = ort.InferenceSession(sent_path)
        inputs = session.get_inputs()
        print(f"  Sentiment model inputs: {[i.name for i in inputs]}")
        print(f"  Sentiment model outputs: {[o.name for o in session.get_outputs()]}")

        dummy = {
            "input_ids": np.zeros((1, 128), dtype=np.int64),
            "attention_mask": np.ones((1, 128), dtype=np.int64),
        }
        model_input_names = {i.name for i in inputs}
        dummy = {k: v for k, v in dummy.items() if k in model_input_names}
        result = session.run(None, dummy)
        print(f"  Sentiment output shape: {result[0].shape}")
        print(f"  OK: sentiment model works")
    else:
        print(f"  SKIP: {sent_path} not found")


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("=" * 60)
    print("AURA ML Model Download & Export")
    print("=" * 60)
    print(f"Output directory: {MODELS_DIR}")
    print()

    tox_ok = download_toxicity()
    sent_ok = download_sentiment()

    print()
    print("=" * 60)
    print("Results:")
    print(f"  Toxicity model:  {'OK' if tox_ok else 'FAILED'}")
    print(f"  Sentiment model: {'OK' if sent_ok else 'FAILED'}")

    vocab_ok = (MODELS_DIR / "vocab.txt").exists()
    print(f"  Vocabulary:      {'OK' if vocab_ok else 'MISSING'}")
    print("=" * 60)

    if tox_ok or sent_ok:
        verify_models()

    if tox_ok and sent_ok and vocab_ok:
        print("\nAll models ready! You can now run:")
        print("  cargo test --features=onnx -p aura-ml")
        return 0
    else:
        print("\nSome models failed to download. Check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
