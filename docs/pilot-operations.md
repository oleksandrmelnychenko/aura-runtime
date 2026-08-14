# Pilot Operations

This document defines the operator-facing process for running AURA in shadow
mode or controlled pilot rollout.

Status: synchronized with current pilot/runtime behavior on August 14, 2026.

## Pilot-Ready Contract

A pilot is considered ready only when all of the following are true:

- Phase 2 `release_report` is `pass`
- `pilot_regression_report` is `pass`
- at least two clean shadow bundles are available
- strict `kids-memory-health` snapshot is `pass` with zero missing mandatory reasons
- strict `kids-preprod-dry-run-matrix` is `pass` with zero failed checks
- shadow bundles contain no plaintext and no findings
- required human signoffs are present and approved
- rollback triggers are known before rollout starts

The machine-readable decision artifact is produced by:

```bash
cargo run --example pilot_gate -p aura-core -- \
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

## Required Signoff Areas

Every pilot gate requires exactly one signoff for each area:

- `false_positive_hotspots`
- `self_harm_boundary_cases`
- `trusted_adult_scenarios`
- `reputation_image_abuse`

`pilot_gate` enforces these four areas. Military/propaganda/opsec/psyops review
remains required as a parallel operator checklist, but it is not part of the
current `pilot_gate` enum contract.

Statuses:

- `approved`
- `pending`
- `needs_changes`

`approved` is required for pilot-ready status.

## Signed Signoff Source

The Rust gate consumes the strict `aura.pilot_review_signoffs.v2` projection
from:

- [`pilot_gate.rs`](../crates/aura-core/src/pilot_gate.rs)

Use the template only to plan review content:

- [`pilot-review-signoffs.template.json`](./pilot-review-signoffs.template.json)

Production projection bytes must be derived by
`ci/pilot_signoff_verification.py` from an external
`aura.pilot_review_signoff_bundle.v1`. The bundle contains exactly four
detached `aura.pilot_review_signoff_attestation.v1` values. Each claim binds
the policy ID/epoch, canonical trust-policy digest, area, reviewer, status,
review time, notes, and exact lowercase 40-character `R`. The external
`aura.pilot_signoff_trust_policy.v1` fixes one distinct reviewer, key ID, and
raw Ed25519 public key per required area. The policy is a caller trust root and
must never be copied into the release artifact.

Create signatures only after immutable candidate `R` exists, outside the
repository and hosted workflows. The bundle and every one of its exactly four
claims must repeat the same `R`. Verify locally without any private key:

```bash
python3 ci/pilot_signoff_verification.py verify \
  --bundle /external/pilot-review-signoff-bundle.json \
  --trust-policy /trusted/pilot-signoff-policy.json \
  --expected-trust-policy-sha256 '<64 lowercase canonical policy digest>' \
  --release-revision '<R>' \
  --output artifacts/pilot-signoff-verification.json \
  --signoffs-output artifacts/pilot-review-signoffs.json \
  --require-pass
```

The resulting `aura.pilot_gate_report.v2` repeats that `R`, and the terminal
release-decision evaluator compares the report and every signoff with its own
candidate revision. A v1 array, a stale revision, a mixed-revision set, a
duplicate area, reused signing identity, small-order/non-prime-order Ed25519
point, invalid signature, or incomplete set fails closed. Cryptographically
valid `pending` is `blocked`; valid `needs_changes` is `fail`; only four
`approved` claims produce `pass`.

`H`, `A`, and `source_tree_sha256` remain bound by the separate verified Apple
artifact and reproducibility evidence. They are deliberately not copied into
the human signoff document: requiring them in tracked source would make the
release candidate self-referential, while repeating them in unsigned operator
input would add no independent trust.

Do not commit fake approved signoffs just to satisfy automation. Approved
signoffs must represent real operator review. Reviewer strings are recorded
labels, not authenticated identities; candidate binding prevents stale replay
but does not replace an external identity/authentication process.

## Shadow-Mode Review Checklist

Reviewers should confirm:

- no plaintext appears in shadow bundles
- no raw sender or conversation identifiers appear in artifacts
- child-facing interventions match expected rollout mode
- guardian-facing alerts are appropriate for the slice
- mandatory `kids.memory.*` escalation reasons are preserved as guardian-review
  class findings (no downgrade during pilot triage)
- trusted-adult supportive traffic is not over-escalated
- supportive self-harm replies are not treated as crisis-originating content
- reputation/image-abuse cases open review with the expected urgency
- propaganda counter-narrative/citation messages are not escalated as hostile
  propaganda
- coordinate leaks are not duplicated as both generic and Ukraine-specific
  signals for the same message
- military phishing and psyops subtypes in signals are present and coherent for
  review tooling

## Operator Cadence

Recommended cadence:

- daily for the first 7 pilot days
- every 3 days after stability is established
- immediate re-review after any regression, rollback, or policy retune
- weekly strict KIDS memory trend review before promotion windows

Minimum owners:

- one policy reviewer
- one safety/product reviewer
- one runtime/operator owner

## Daily KIDS Memory Health Automation

Daily monitoring is automated in GitHub Actions via:

- `.github/workflows/kids-memory-health.yml`

What it produces:

- `artifacts/kids-memory-health.json`
- `artifacts/pilot-regression-report.json`
- `artifacts/pilot-shadow-run-a.json`
- `artifacts/pilot-shadow-run-b.json`

Manual run (with strict fail if mandatory reason codes are missing):

```bash
gh workflow run kids-memory-health.yml -f require_mandatory_reasons=true
```

If strict mode is not enabled, missing mandatory reason codes are reported as
`warn` in the health snapshot and the job still completes.

Strict baseline and rollback thresholds:

- [KIDS Strict Scenario Matrix](./kids-strict-scenario-matrix.md)
- [KIDS Memory Operational Targets](./kids-memory-operational-targets.md)
- [KIDS Pre-Prod Dry-Run Matrix](./kids-preprod-dry-run-matrix.md)

## Rollback Triggers

Current pilot rollback triggers are encoded in:

- [`pilot_gate.rs`](../crates/aura-core/src/pilot_gate.rs)

High-signal triggers:

- any shadow artifact contains plaintext or raw identifiers
- self-harm boundary review finds supportive replies escalated as crisis origin
- trusted-adult educational/supportive traffic accumulates repeated high-severity interventions
- pilot regression or repeated shadow bundles regress below the approved baseline

## Workflow Support

Local rehearsal can verify the signed bundle and derive the projection before
running the Rust gate:

```bash
python3 ci/run_promotion_rehearsal.py \
  --target release \
  --pilot-signoff-bundle /external/pilot-review-signoff-bundle.json \
  --pilot-signoff-trust-policy /trusted/pilot-signoff-policy.json \
  --expected-pilot-signoff-trust-policy-sha256 '<canonical policy digest>'
```

For hosted release use `Pilot Signoff Ingest` at exact `R`. Supply base64 of
the bundle plus its exact raw SHA-256 and byte count; decoded input is capped at
32 KiB. The workflow has no signing operation or private key. It verifies
offline and uploads exactly the bundle, verification report, and Rust
projection. A signed negative decision is retained for diagnosis through an
unsuccessful run; malformed signatures emit no report. `Promotion Gate` accepts
only a successful first-attempt ingest run for the same `R`, resolves its sole
immutable artifact ID/digest/length, downloads using a token only for metadata
and transport, then repeats offline verification before invoking Rust. Release
Evidence Freeze repeats verification again and carries only the verification
leaf.

`Promotion Gate` is manual-only. A tag push is not promotion authorization and
cannot select an ingest artifact. For `target=release`, the exact successful
ingest run ID and attempt `1` are mandatory inputs; staging may run without
pilot signoffs and remains non-release evidence.

Required repository variables are
`AURA_PILOT_SIGNOFF_TRUST_POLICY_B64`,
`AURA_PILOT_SIGNOFF_TRUST_POLICY_SHA256`, and
`AURA_PILOT_SIGNOFF_WORKFLOW_ID`. They are externally configured governance
inputs, not proof that change control is already protected. The workflow ID is
provisioned, while both trust-policy variables remain absent. Hosted intake,
release Promotion, and Freeze therefore fail closed until an independent
release reviewer is appointed and the reviewed policy pair is provisioned.
All three stages bind execution to protected `main`; the `release` environment
disallows self-review and admin bypass. The digest is the helper's
domain-separated canonical policy identity, not a raw-file digest. Committing a
policy, private key, signoff bundle, or generated projection is not a substitute.

When pilot gate runs with `--require-kids-memory-pass`, missing mandatory
`kids.memory.*` reasons are treated as a blocking/failing condition instead of a
report-only warning.

## ONNX Test Mode Notes

For pilot/release verification on Windows, keep default ONNX checks lightweight
and deterministic:

- baseline ONNX coverage is included in default `cargo test` runs
- safety/intent ONNX load tests are opt-in because some environments may hold
  file locks and stall those binaries
- enable explicitly when needed:

```bash
AURA_RUN_SAFETY_INTENT_ONNX=1 cargo test -p aura-ml --features onnx --test onnx_integration
```

If you need missing-model behavior to fail hard, set:

```bash
AURA_REQUIRE_ONNX_MODELS=1
```

## KIDS Memory Escalation Trail

For KIDS-domain pilot review, use the mandatory reason-code matrix:

- [KIDS Memory Escalation Matrix](./kids-memory-escalation-matrix.md)
- [KIDS Memory Incident Runbook](./kids-memory-incident-runbook.md)

This matrix is the required explainability baseline when evaluating guardian
escalations originating from memory-level KIDS signals.
