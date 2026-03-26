# Pilot Operations

This document defines the operator-facing process for running AURA in shadow
mode or controlled pilot rollout.

Status: synchronized with current pilot/runtime behavior on March 25, 2026.

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
  --review-signoffs docs/pilot-review-signoffs.json \
  --kids-memory-health-report artifacts/kids-memory-health.json \
  --kids-preprod-dry-run-report artifacts/kids-preprod-dry-run-matrix.json \
  --output artifacts/pilot-gate-report.json \
  --require-kids-memory-pass \
  --require-kids-preprod-dry-run-pass \
  --require-pass
```

## Required Signoff Areas

Every pilot gate requires one latest signoff for each area:

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

## Signoff Source

The current expected format is JSON and matches
`Vec<PilotReviewSignoff>` from:

- [pilot_gate.rs](/c:/Users/123/ecliptix-aura/crates/aura-core/src/pilot_gate.rs)

Use the template:

- [pilot-review-signoffs.template.json](/c:/Users/123/ecliptix-aura/docs/pilot-review-signoffs.template.json)

Do not commit fake approved signoffs just to satisfy automation. Approved
signoffs must represent real operator review.

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

- [pilot_gate.rs](/c:/Users/123/ecliptix-aura/crates/aura-core/src/pilot_gate.rs)

High-signal triggers:

- any shadow artifact contains plaintext or raw identifiers
- self-harm boundary review finds supportive replies escalated as crisis origin
- trusted-adult educational/supportive traffic accumulates repeated high-severity interventions
- pilot regression or repeated shadow bundles regress below the approved baseline

## Workflow Support

Local rehearsal already understands optional pilot signoffs:

```bash
python ci/run_promotion_rehearsal.py \
  --target staging \
  --pilot-review-signoffs docs/pilot-review-signoffs.json
```

CI and `Promotion Gate` also understand optional pilot gate artifacts if a real
signoff file is present at the configured path.

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
