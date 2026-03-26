# Wave 1 Release Hardening

This document captures rollback criteria and regression-report expectations for Wave 1 dataset integration.

## Rollback Criteria

Rollback is required when any of the following are true:

- `overall_status` in `PreReleaseReport` is not `pass`.
- A suite has `status != pass`.
- Any release-blocking slice fails, especially:
  - `relationship:group_peer`
  - `relationship:supportive_peer`
  - `relationship:trusted_adult`
  - `language:ru`
  - `language:uk`
- Any drift check reports non-pass status for blocking-ready comparisons.

Runtime helper: use `evaluate_wave1_rollback_criteria()` in `crates/aura-core/src/eval_release.rs`.

## Regression Reporting Contract

For each merge touching eval/rules/ML integration:

1. Run:
   - `cargo test -p aura-core eval_external::tests::external_curated_suite_passes_pre_release_gates`
   - `cargo test -p aura-core eval_social_context::tests::social_context_pre_release_gates_pass`
   - `cargo test -p aura-ml`
   - Optional (safety/intent ONNX load checks): `AURA_RUN_SAFETY_INTENT_ONNX=1 cargo test -p aura-ml --features onnx --test onnx_integration`
2. Generate pre-release report via `run_pre_release_report()`.
3. Store report artifacts with:
   - suite statuses
   - required slice coverage
   - drift status and failed checks
   - `wave1_on_device_checks` for:
     - `wave1.on_device.high_risk_slice_coverage`
     - `wave1.on_device.safe_cohort_slice_coverage`
     - `wave1.on_device.high_risk_recall`
     - `wave1.on_device.safe_cohort_fp_budget`
   - `wave1_model_profile_drift` notes
   - `wave1_rollback_decision.reasons`
4. If rollback criteria trigger, revert the last Wave 1 change set and re-open in report-only mode.

Recommended production check sequence (runs both reports even if release gate fails):

- `cargo run --quiet --example release_report -p aura-core -- --require-pass; cargo run --quiet --example pilot_regression -p aura-core -- --require-pass`

## Stabilization Notes

- Keep transitional gates as default (`pre_release_*` functions).
- Move to target gates only after two consecutive green runs without forbidden-policy regressions.
- Do not promote rule/ML updates if support drops below release-blocking thresholds for the three Wave 1 source families.
- For production `models_path`, require `manifest.json` under that directory when strict manifest validation is enabled.
- A partial ONNX set (`safety.onnx` + `intent.onnx`) is acceptable with fallback enabled for missing heads.
- Include and validate SHA-256 for ONNX sidecar tensors (`*.onnx.data`) in `manifest.json`.
- `onnx_integration` safety/intent load tests are opt-in to avoid long-running hangs on some Windows environments.
  Enable explicitly with `AURA_RUN_SAFETY_INTENT_ONNX=1`.
- KIDS memory-level guardian escalation reasons are mandatory regardless of
  priority drift; keep regression checks aligned with
  `docs/kids-memory-escalation-matrix.md`.

## Current Snapshot (2026-03-25)

- `release_report`: `pass`.
- `pilot_regression`: `pass`.
- Native safety model integration is validated at runtime and no longer blocked by release-report criteria.
