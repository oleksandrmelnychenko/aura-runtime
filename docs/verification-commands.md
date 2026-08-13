# Verification Commands

Date: 2026-07-24

Single place for the most used verification commands during release and pilot work.

## Quick Aliases (`just`)

```bash
just verify
just verify-full
just verify-onnx
just swift-proto-check
just kids-memory-health
just kids-preprod-dry-run
just kids-memory-health-strict
just refactor-baseline-gate
```

## Core Release Gates

```bash
cargo run --locked --quiet --example release_report -p aura-core -- --require-pass
cargo run --locked --quiet --example pilot_regression -p aura-core -- --require-pass
```

## CI and Supply-Chain Contract

```bash
python3 -m unittest ci.test_ci_supply_chain
python3 -m unittest discover -s ci -p 'test_*.py'
```

The repository fixes Rust to the exact version in `rust-toolchain.toml`, pins
every external GitHub Action to a full commit SHA, prevents checkout from
retaining credentials, grants jobs read-only repository access, and requires
all CI Cargo resolution to use `Cargo.lock`. The discovery command is the
canonical Python helper gate so newly added evidence tests cannot be omitted by
an outdated hand-maintained module list.

## Top-Level Release Decision

The exact GO/NO-GO creation and Ed25519 operator-signature commands are in
`docs/release-decision.md`. Run its focused contract tests with:

```bash
python3 -m unittest ci.test_release_decision
```

The current repository must remain `no-go` until the external Apple client
acceptance and four real pilot signoffs exist for the same candidate.

## AURA Core Refactor Differential Gate

```bash
just refactor-baseline-gate
```

This captures current contract, release, pilot, lifecycle, and 10k performance
evidence, then compares it with
`crates/aura-core/data/refactor_baseline_v1.json`. Unapproved differences,
stale approvals, and performance envelope violations fail the command. See
`docs/refactor-baseline.md` for the exact approval contract.

## Focused Gate Smoke Tests

```bash
cargo test --locked -p aura-core eval_external::tests::external_curated_suite_passes_pre_release_gates
cargo test --locked -p aura-core eval_social_context::tests::social_context_pre_release_gates_pass
cargo test --locked -p aura-ml
```

## Independent Recomputation Contract

Run the Rust end-to-end chain, negative outcomes, resource/chronology bounds,
and Python/OpenSSL adapter tests with:

```bash
cargo test --locked -p aura-domain recomputation
python3 -m unittest \
  ci.test_domain_recomputation_signer \
  ci.test_domain_recomputation_timestamp_adapter
```

The full CI discovery and workspace commands remain authoritative. These
focused commands are a fast local check for
`aura.domain.independent_recomputation_evidence.v1`; they do not perform a real
independent run or replace the external append-only run registry described in
`docs/domain-independent-recomputation-evidence.md`.

## Safety World v2 Smoke Gate

```bash
bash ci/safety_world_v2_smoke.sh
```

Expanded commands:

```bash
cargo test --locked -p aura-core --example safety_world_v2_project
cargo run --locked -p aura-core --example safety_world_v2_validate -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json
cargo run --locked -p aura-core --example safety_world_v2_project -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json \
  --output /tmp/safety_world_v2_projected_world_sim.json
cargo run --locked -p aura-core --example world_sim -- \
  --input /tmp/safety_world_v2_projected_world_sim.json \
  --summary-only \
  --require-clean
cargo test --locked -p aura-core --example safety_world_v2_platform_seed
cargo run --locked -p aura-core --example safety_world_v2_platform_seed -- \
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
cargo run --locked --quiet --example release_report -p aura-core -- \
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

This runs the same long world fixtures while periodically exporting both
Safety Case and context state, destroying the FFI handle, initializing a new
handle, importing both states, reapplying the execution policy, and continuing
replay. Terminal clean sources are checkpointed through the same explicit
native-to-host ownership transfer required by clients. It simulates app
restarts and verifies bounded analyzer memory across client lifecycle
boundaries.

## Analyzer Microbenchmark Gate

Run the analyzer latency smoke test in isolation so the strict wall-clock
threshold is not distorted by concurrent corpus tests:

```bash
bash ci/analyzer_microbenchmark_gate.sh
```

The script fails closed if the ignored microbenchmark is missing or renamed,
then runs exactly that test in the optimized release profile and enforces the
existing sub-millisecond bound.

## World Performance Gate

```bash
bash ci/world_performance_gate.sh
```

By default this runs release-built `world_sim` at the `10k`, `50k`, and `100k`
tiers using repeat multipliers over the dense two-year lifecycle fixture. Use
`AURA_PERF_TIERS=10k` for a local smoke run, or override per-tier runtime/RSS
limits with `AURA_PERF_10K_MAX_SECONDS`, `AURA_PERF_50K_MAX_SECONDS`, and
`AURA_PERF_100K_MAX_SECONDS`.

## Apple Artifact Provenance

Before building the Swift package or Apple artifact, verify that the checked-in
typed protobuf source matches `messenger.proto` and the exactly pinned
`protoc-gen-swift` 1.38.1 generator:

```bash
just swift-proto-check
```

Regenerate it after an intentional schema change with
`just swift-proto-generate`.

Build and verify a local release-profile artifact without overwriting
`dist/apple`:

```bash
just apple-artifact-build-local
```

The local artifact is marked `shippable=false` whenever reviewable source is
dirty. For a clean reviewed checkout, build and verify the shippable artifact:

```bash
just apple-artifact-build-release
```

Verify an already packaged clean artifact independently:

```bash
python3 ci/apple_artifact.py verify \
  --root . \
  --dist-dir dist/apple \
  --output artifacts/apple-release-verification.json \
  --require-clean-source
```

The verifier checks source revision/digest, runtime/wire/state/FFI versions,
Cargo feature identity, three XCFramework slices, Mach-O architectures,
embedded headers, trust keyring, descriptor identities, binary hashes, and the
exact Aura export allowlist.

## Full Workspace Validation

```bash
cargo test --locked --workspace --all-features --all-targets
```

## ONNX-Specific Checks

Default runs include baseline ONNX coverage. Safety/intent ONNX load checks are opt-in.

```bash
AURA_RUN_SAFETY_INTENT_ONNX=1 cargo test --locked -p aura-ml --features onnx --test onnx_integration
```

If missing ONNX models must fail the run (instead of skipping):

```bash
AURA_REQUIRE_ONNX_MODELS=1 cargo test --locked -p aura-ml --features onnx --test onnx_integration
```

## Pilot Gate Artifact Decision

```bash
cargo run --locked --example pilot_gate -p aura-core -- \
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
python3 ci/kids_memory_health_snapshot.py \
  --input artifacts/pilot-regression-report.json \
  --input artifacts/pilot-shadow-run-a.json \
  --input artifacts/pilot-shadow-run-b.json \
  --output artifacts/kids-memory-health.json
```

Fail the command when not all mandatory `kids.memory.*` reasons are observed:

```bash
python3 ci/kids_memory_health_snapshot.py \
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
python3 ci/kids_preprod_dry_run_matrix.py \
  --policy-expectations crates/aura-core/data/action_policy_expectations.json \
  --realistic-cases crates/aura-core/data/realistic_chat_cases.json \
  --kids-memory-health artifacts/kids-memory-health.json \
  --output artifacts/kids-preprod-dry-run-matrix.json
```

End-to-end strict stress rehearsal (recommended before promotion windows):

```bash
just kids-memory-health-strict
```
