# Wave 1 Release Hardening

This document captures rollback criteria and regression-report expectations for Wave 1 dataset integration.

## Rollback Criteria

Rollback is required when any of the following are true:

- `overall_status` in `PreReleaseReport` is not `pass`.
- A suite has `status != pass`.
- Any release-blocking slice fails, especially:
  - `source_family:bluff`
  - `source_family:mumin`
  - `source_family:ua_news`
- Any drift check reports non-pass status for blocking-ready comparisons.

Runtime helper: use `evaluate_wave1_rollback_criteria()` in `crates/aura-core/src/eval_release.rs`.

## Regression Reporting Contract

For each merge touching eval/rules/ML integration:

1. Run:
   - `cargo test -p aura-core eval_external::tests::external_curated_suite_passes_pre_release_gates`
   - `cargo test -p aura-core eval_social_context::tests::social_context_pre_release_gates_pass`
   - `cargo test -p aura-ml`
2. Generate pre-release report via `run_pre_release_report()`.
3. Store report artifacts with:
   - suite statuses
   - required slice coverage
   - drift status and failed checks
4. If rollback criteria trigger, revert the last Wave 1 change set and re-open in report-only mode.

## Stabilization Notes

- Keep transitional gates as default (`pre_release_*` functions).
- Move to target gates only after two consecutive green runs without forbidden-policy regressions.
- Do not promote rule/ML updates if support drops below release-blocking thresholds for the three Wave 1 source families.
