# Verification Commands

Date: 2026-03-25

Single place for the most used verification commands during release and pilot work.

## Quick Aliases (`just`)

```bash
just verify
just verify-full
just verify-onnx
just kids-memory-health
just kids-preprod-dry-run
just kids-memory-health-strict
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

## Safety World v2 Smoke Gate

```bash
bash ci/safety_world_v2_smoke.sh
```

Expanded commands:

```bash
cargo test -p aura-core --example safety_world_v2_project
cargo run -p aura-core --example safety_world_v2_validate -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json
cargo run -p aura-core --example safety_world_v2_project -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json \
  --output /tmp/safety_world_v2_projected_world_sim.json
cargo run -p aura-core --example world_sim -- \
  --input /tmp/safety_world_v2_projected_world_sim.json \
  --summary-only \
  --require-clean
cargo test -p aura-core --example safety_world_v2_platform_seed
cargo run -p aura-core --example safety_world_v2_platform_seed -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json \
  --output /tmp/safety_world_v2_platform_seed.json
```

## World Lifecycle Gate

```bash
bash ci/world_lifecycle_gate.sh
```

This writes redacted reports to `artifacts/world-lifecycle-dense-2y-report.json`
and `artifacts/world-lifecycle-suite-report.json`. For nightly scale, raise
`AURA_LIFECYCLE_REPEAT_MULTIPLIER` without changing the fixture files.

## Release Report With World Metrics

```bash
cargo run --quiet --example release_report -p aura-core -- \
  --world-lifecycle-report artifacts/world-lifecycle-suite-report.json \
  --output artifacts/release-report.json \
  --require-pass
```

The release report embeds the compact world-simulation metric section by
relationship, surface, language, and expected threat. CI also picks up
`AURA_WORLD_LIFECYCLE_REPORT_PATH` when the lifecycle report is present.

## FFI World Replay Gate

```bash
bash ci/ffi_world_replay_gate.sh
```

This runs the long ignored `aura-agent-ffi` world replay tests for the
six-month fixture and dense two-year fixture through the protobuf FFI boundary.

## Client Boundary Replay Gate

```bash
bash ci/client_boundary_replay_gate.sh
```

This runs the same long world fixtures while periodically exporting context,
destroying the FFI handle, initializing a new handle, importing context, and
continuing replay. It simulates app restarts and verifies analyzer memory
survives client lifecycle boundaries.

## World Performance Gate

```bash
bash ci/world_performance_gate.sh
```

By default this runs release-built `world_sim` at the `10k`, `50k`, and `100k`
tiers using repeat multipliers over the dense two-year lifecycle fixture. Use
`AURA_PERF_TIERS=10k` for a local smoke run, or override per-tier runtime/RSS
limits with `AURA_PERF_10K_MAX_SECONDS`, `AURA_PERF_50K_MAX_SECONDS`, and
`AURA_PERF_100K_MAX_SECONDS`.

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
  --kids-memory-health-report artifacts/kids-memory-health.json \
  --kids-preprod-dry-run-report artifacts/kids-preprod-dry-run-matrix.json \
  --output artifacts/pilot-gate-report.json \
  --require-kids-memory-pass \
  --require-kids-preprod-dry-run-pass \
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

Reference strict readiness contracts:

- `docs/kids-strict-scenario-matrix.md`
- `docs/kids-memory-operational-targets.md`
- `docs/kids-preprod-dry-run-matrix.md`

## KIDS Pre-Prod Dry-Run Matrix

Build strict pre-prod readiness matrix from policy/corpus + memory-health:

```bash
python ci/kids_preprod_dry_run_matrix.py \
  --policy-expectations crates/aura-core/data/action_policy_expectations.json \
  --realistic-cases crates/aura-core/data/realistic_chat_cases.json \
  --kids-memory-health artifacts/kids-memory-health.json \
  --output artifacts/kids-preprod-dry-run-matrix.json
```

End-to-end strict stress rehearsal (recommended before promotion windows):

```bash
just kids-memory-health-strict
```
