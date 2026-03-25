# Safety 5-Label Training (Native)

This guide creates a native AURA safety model with 5 outputs:

- `grooming`
- `bullying`
- `self_harm`
- `manipulation`
- `safe`

## 1) Prepare data

Use JSONL or CSV with columns:

- `text`
- `grooming`
- `bullying`
- `self_harm`
- `manipulation`
- `safe` (optional, auto-derived if omitted)

Reference schema:

- `crates/aura-ml/scripts/safety_5label_schema.example.jsonl`

Or auto-generate from curated Wave1 cases in this repo:

```bash
python crates/aura-ml/scripts/build_safety_5label_dataset.py \
  --input crates/aura-core/data/corpus_curated_cases.json \
  --input crates/aura-core/data/external_curated_chat_cases.json \
  --train-out data/safety_train.jsonl \
  --eval-out data/safety_eval.jsonl
```

## 2) Train model

```bash
python crates/aura-ml/scripts/train_safety_5label.py \
  --train-file data/safety_train.jsonl \
  --eval-file data/safety_eval.jsonl \
  --output-dir artifacts/safety-5label \
  --base-model bert-base-multilingual-cased \
  --epochs 2 \
  --batch-size 16
```

## 3) Export ONNX

```bash
python crates/aura-ml/scripts/train_safety_5label.py \
  --train-file data/safety_train.jsonl \
  --eval-file data/safety_eval.jsonl \
  --output-dir artifacts/safety-5label \
  --base-model bert-base-multilingual-cased \
  --export-onnx \
  --onnx-output models/safety.onnx \
  --quantize
```

## 4) Optional: push to HF Hub

```bash
python crates/aura-ml/scripts/train_safety_5label.py \
  --train-file data/safety_train.jsonl \
  --eval-file data/safety_eval.jsonl \
  --output-dir artifacts/safety-5label \
  --push-to-hub your-org/aura-safety-5label \
  --hub-private
```

Then use the produced model id with:

```bash
python crates/aura-ml/scripts/download_models.py \
  --output-dir models \
  --skip-toxicity --skip-sentiment \
  --include-safety --safety-model-id your-org/aura-safety-5label \
  --include-intent --intent-model-id Unggi/intent_search_dialog_counseling_v1
```

Or, for a locally trained native model already exported to `models/safety.onnx`:

```bash
python crates/aura-ml/scripts/download_models.py \
  --output-dir models \
  --skip-toxicity --skip-sentiment \
  --include-safety --safety-onnx-path models/safety.onnx \
  --safety-source-id aura-native-5label-bert-base-multilingual-cased-wave1 \
  --include-intent --intent-model-id Unggi/intent_search_dialog_counseling_v1 --force
```

## 5) Validate runtime

```bash
cargo test -p aura-ml --features onnx pipeline_onnx_initializes
cargo test -p aura-core --features onnx analyzer::tests::high_uncertainty_high_risk_downgrades_block_to_guardian_warn
```

## 6) Production handoff checklist

```bash
cargo run --quiet --example release_report -p aura-core -- --require-pass
cargo run --quiet --example pilot_regression -p aura-core -- --require-pass
```

Notes:

- Native safety ONNX readiness is necessary but not sufficient; release promotion is controlled by `release_report`.
- INT8 quantization can be skipped by ONNX Runtime for some exports; keep FP32 `models/safety.onnx` as canonical production artifact unless INT8 passes shape/inference validation.
