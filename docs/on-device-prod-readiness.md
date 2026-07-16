# On-Device Production Readiness

Date: 2026-03-25

## Referenced Model Set

The manifest references the following files, but the current checkout does not
contain the ONNX graphs, external tensor data, or `vocab.txt`. This document
records a prior validation run; it is not evidence that the current Apple
artifact contains or activates those models.

- `models/safety.onnx`
  - Source model: `aura-native-5label-bert-base-multilingual-cased-wave1`
  - Mapping: native 5-label (no remap)
  - Output shape: `(1, 5)`
- `models/intent.onnx`
  - Source model: `Unggi/intent_search_dialog_counseling_v1`
  - Output shape: `(1, 4)`
- `models/vocab.txt`
- `models/manifest.json` updated with SHA256 hashes.

## Validation Performed

- ONNX runtime load check:
  - `safety.onnx` inputs: `input_ids`, `attention_mask`, `token_type_ids`
  - `intent.onnx` inputs: `input_ids`, `attention_mask`, `token_type_ids`
  - Output names: `logits`
- Tensor shape smoke checks:
  - `safety.onnx` -> `(1, 5)`
  - `intent.onnx` -> `(1, 4)`
- Rust ONNX smoke:
  - `cargo test -p aura-ml --features onnx pipeline_onnx_initializes`
  - Optional safety/intent ONNX integration check:
    - `AURA_RUN_SAFETY_INTENT_ONNX=1 cargo test -p aura-ml --features onnx --test onnx_integration`
  - `cargo test -p aura-core --features onnx analyzer::tests::high_uncertainty_high_risk_downgrades_block_to_guardian_warn`
- Pre-release and pilot gates:
  - `cargo run --quiet --example release_report -p aura-core -- --require-pass`
  - `cargo run --quiet --example pilot_regression -p aura-core -- --require-pass`

## Production Notes

- Intent model is native 4-label (no truncation path used).
- Safety model is now native 5-label (grooming, bullying, self_harm, manipulation, safe).
- `download_models.py` supports a production path for prebuilt native safety ONNX via `--safety-onnx-path`.
- Current production manifest stores:
  - `models.safety.source_model_id = aura-native-5label-bert-base-multilingual-cased-wave1`
- Safety/intent ONNX load tests are gated behind `AURA_RUN_SAFETY_INTENT_ONNX=1` to prevent platform-specific hangs during default CI/local runs.

## Recorded Gate Snapshot

- The 2026-03-25 run recorded `release_report`: **Pass**.
- The 2026-03-25 run recorded `pilot_regression`: **Pass**.
- Current checkout rollout decision: **Blocked** until the referenced model
  files are restored from a governed artifact, their hashes match the manifest,
  the Apple FFI is built with the `onnx` feature, and the app supplies a valid
  `models_path`.

`MlPipeline::is_active()` may also be true for a rules/lexicon fallback. Product
diagnostics and release evidence must identify the actual backend and model
hash rather than treating `ml_active` as proof that ONNX is running.

## Next Hardening Steps

- Materialize the governed model bundle and verify every manifest hash.
- Build the Apple XCFramework with `AURA_AGENT_ONNX=1` and record enabled Cargo
  features in the release artifact manifest.
- Bundle or securely provision the models and pass their path in `AuraConfig`.
- Expose backend identity, model identifier, and model hash in runtime
  capabilities and diagnostics.
- Run focused regression slices for:
  - `self_harm`, `grooming`, `manipulation` recall
  - safe-cohort false-positive budget
- Keep `high_recall` profile for KIDS/TEEN rollout and monitor guardian-review rate.
