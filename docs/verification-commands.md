# Verification Commands

Date: 2026-03-25

Single place for the most used verification commands during release and pilot work.

## Quick Aliases (`just`)

```bash
just verify
just verify-full
just verify-onnx
just kids-memory-health
```

## Core Release Gates

```bash
cargo run --quiet --example release_report -p aura-core -- --require-pass
cargo run --quiet --example pilot_regression -p aura-core -- --require-pass
```

## Focused Gate Smoke Tests

```bash
cargo test -p aura-core eval_external::tests::external_curated_suite_passes_pre_release_gates
cargo test -p aura-core eval_social_context::tests::social_context_pre_release_gates_pass
cargo test -p aura-ml
```

## Full Workspace Validation

```bash
cargo test --workspace --all-features --all-targets
```

## ONNX-Specific Checks

Default runs include baseline ONNX coverage. Safety/intent ONNX load checks are opt-in.

```bash
AURA_RUN_SAFETY_INTENT_ONNX=1 cargo test -p aura-ml --features onnx --test onnx_integration
```

If missing ONNX models must fail the run (instead of skipping):

```bash
AURA_REQUIRE_ONNX_MODELS=1 cargo test -p aura-ml --features onnx --test onnx_integration
```

## Pilot Gate Artifact Decision

```bash
cargo run --example pilot_gate -p aura-core -- \
  --release-report artifacts/release-report.json \
  --pilot-regression-report artifacts/pilot-regression-report.json \
  --shadow-bundle artifacts/pilot-shadow-run-a.json \
  --shadow-bundle artifacts/pilot-shadow-run-b.json \
  --review-signoffs docs/pilot-review-signoffs.json \
  --output artifacts/pilot-gate-report.json \
  --require-pass
```

## KIDS Memory Daily Health Snapshot

Build a compact daily snapshot for `kids.memory.*` incidents from existing artifacts:

```bash
python ci/kids_memory_health_snapshot.py \
  --input artifacts/pilot-regression-report.json \
  --input artifacts/pilot-shadow-run-a.json \
  --input artifacts/pilot-shadow-run-b.json \
  --output artifacts/kids-memory-health.json
```

Fail the command when not all mandatory `kids.memory.*` reasons are observed:

```bash
python ci/kids_memory_health_snapshot.py \
  --input artifacts/pilot-regression-report.json \
  --input artifacts/pilot-shadow-run-a.json \
  --input artifacts/pilot-shadow-run-b.json \
  --output artifacts/kids-memory-health.json \
  --require-mandatory-reasons
```

Run the scheduled CI workflow manually (strict mode):

```bash
gh workflow run kids-memory-health.yml -f require_mandatory_reasons=true
```
