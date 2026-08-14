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
an outdated hand-maintained module list. The strict Apple provenance job also
requires full Git history and materialized Git LFS objects; it pins Xcode
`26.2` and Rust `1.96.1` and fails if the resolved versions differ.

## Top-Level Release Decision

The exact GO/NO-GO creation and Ed25519 operator-signature commands are in
`docs/release-decision.md`. Run its focused contract tests with:

```bash
python3 -m unittest ci.test_release_decision ci.test_release_dossier
python3 -m unittest ci.test_pilot_signoff_verification ci.test_release_artifact_ingest ci.test_ci_supply_chain
```

The current repository must remain `no-go` until the external Apple client
acceptance and four real pilot signoffs exist for the same candidate.
`docs/release-candidate-dossier.md` contains the exact assemble/finalize/verify
commands for the terminal fixed-layout bundle. The hosted
`Release Evidence Freeze` workflow creates only its exact unsigned evidence
input; external evidence signing and release-operator authorization remain
separate and it cannot authorize a release.

## Pilot Signoff Verification and Hosted Intake

At policy enrollment, a separate reviewed governance process computes and
records the canonical policy identity. Ordinary verification must retrieve
that pinned digest independently; never derive the expected digest from the
candidate policy file in the same verification invocation.

Verify an externally signed four-role bundle locally with that independent
pin:

```bash
EXPECTED_POLICY_SHA256='<governance-pinned canonical policy digest>'

python3 ci/pilot_signoff_verification.py verify \
  --bundle /external/pilot-review-signoff-bundle.json \
  --trust-policy /trusted/pilot-signoff-policy.json \
  --expected-trust-policy-sha256 "$EXPECTED_POLICY_SHA256" \
  --release-revision '<R>' \
  --output artifacts/pilot-signoff-verification.json \
  --signoffs-output artifacts/pilot-review-signoffs.json \
  --require-pass
```

`Pilot Signoff Ingest` takes exact `R`, standard base64 of the original bundle
bytes, their lowercase SHA-256, and byte count (maximum 32768). A successful
first-attempt run ID is then supplied to the release `Promotion Gate`; Freeze
accepts only a successful Promotion artifact and re-verifies the pilot leaf.
No hosted step receives a private key or signs anything.
Promotion is manual-only. Tag pushes do not trigger or authorize it; a release
dispatch must name the exact ingest run ID and attempt `1`.

Hosted use is intentionally unavailable until administrators provision and
govern the repository variables
`AURA_PILOT_SIGNOFF_TRUST_POLICY_B64`,
`AURA_PILOT_SIGNOFF_TRUST_POLICY_SHA256`, and
`AURA_PILOT_SIGNOFF_WORKFLOW_ID`. The workflow ID is provisioned, but the two
policy variables remain absent, so the three hosted stages fail closed. They
also require protected `main` and approval through the `release` environment,
which forbids self-review and admin bypass. Repository variables are externally
mutable configuration and are not intrinsically protected; administrators must
appoint an independent release reviewer and maintain reviewed change/rotation
controls. The policy digest above is canonical and domain-separated; do not
replace it with SHA-256 of arbitrary JSON bytes.

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
  ci.test_domain_recomputation_timestamp_adapter \
  ci.test_domain_recomputation_registry_signer \
  ci.test_domain_recomputation_registry_timestamp_adapter
```

The full CI discovery and workspace commands remain authoritative. These
focused commands are a fast local check for
`aura.domain.independent_recomputation_evidence.v1` and its witnessed
recomputation-registry overlay; they do not perform a real independent run,
publish a checkpoint to externally controlled WORM storage, detect an
off-ledger attempt, or rule out split views. See
`docs/domain-recomputation-attempt-registry.md`.

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
dirty. For a clean reviewed source commit `H`, build the shippable artifact
candidate:

```bash
just apple-artifact-build-release
```

Commit only the permitted generated `dist/apple` outputs as the direct child
`A` of `H`. Record any artifact approval or accepted differential baseline in a
linear suffix that changes only the two excluded governance files, and call the
resulting exact release revision `R` (`R` may equal `A`). Then, on exact revision
`R`, verify the checked-in artifact before running any build:

```bash
python3 ci/apple_artifact.py verify \
  --root . \
  --dist-dir dist/apple \
  --output artifacts/apple-release-verification.json \
  --require-clean-source
```

The strict caller must provide full history and materialize all required Git
LFS objects before either command. The verifier does not silently repair a
shallow checkout or download missing LFS content. It validates the exact
stage-zero LFS pointer object identifier and size against materialized working
bytes. With source digest `aura.build-source-tree.v2`, all materialized
build-relevant LFS content currently participates in the digest (about 5.5 GiB,
or 5.9 GB); selecting only part of that content would require a `v3` digest
contract.

After the checked-in verification passes, run the strict two-build gate:

```bash
python3 ci/apple_artifact_reproducibility.py verify \
  --root . \
  --output artifacts/apple-reproducibility.json
```

The gate requires `A` to have exactly one parent `H`, requires the manifest to
name full revision `H`, and permits only the contract's generated artifact
paths in the `H..A` diff. Every optional `A..R` commit must be single-parent and
may modify only `docs/refactor-diff-approvals.json` and/or
`crates/aura-core/data/refactor_baseline_v1.json`. The report separately binds
`H`, `A`, and `R`; version 1 permits `A` plus at most 15 governance commits. It
verifies the exact checked-in 11-file inventory, then
performs two sequential fresh builds from `H` into distinct external
directories. It requires byte-identical path, type, executable-bit, size, and
SHA-256 inventories for:

```text
checked-in dist/apple == build 1 == build 2
```

The artifact verifier also checks runtime/wire/state/FFI versions, Cargo
feature identity, three XCFramework slices, Mach-O architectures, embedded
headers, trust keyring, descriptor identities, binary hashes, and the exact
Aura export allowlist.

A passing run demonstrates deterministic repeatability and path independence
on the pinned Xcode `26.2` / Rust `1.96.1` runner. It is not independent
reproduction and does not prove that the compiler, runner image, or build
service is trustworthy. The source and build scripts are trusted inputs, and
the linked worktrees do not prove candidate-blind or hermetic execution.
Pull-request merge revisions are validation inputs, not release evidence
commits.

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
  --review-signoffs artifacts/pilot-review-signoffs.json \
  --release-revision "$(git rev-parse HEAD)" \
  --kids-memory-health-report artifacts/kids-memory-health.json \
  --kids-preprod-dry-run-report artifacts/kids-preprod-dry-run-matrix.json \
  --output artifacts/pilot-gate-report.json \
  --require-kids-memory-pass \
  --require-kids-preprod-dry-run-pass \
  --require-pass
```

The untracked signoff input must use `aura.pilot_review_signoffs.v2`; its
top-level `release_revision` and all four signoff-level revisions must equal
the command's exact `--release-revision`. The v2 pilot report preserves that
binding for the release-decision evaluator. Hosted workflows do not yet own an
authenticated ingestion step for this external human input, so absence remains
an intentional no-go condition.

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
