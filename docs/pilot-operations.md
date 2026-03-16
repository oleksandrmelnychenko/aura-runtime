# Pilot Operations

This document defines the operator-facing process for running AURA in shadow
mode or controlled pilot rollout.

## Pilot-Ready Contract

A pilot is considered ready only when all of the following are true:

- Phase 2 `release_report` is `pass`
- `pilot_regression_report` is `pass`
- at least two clean shadow bundles are available
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
  --output artifacts/pilot-gate-report.json \
  --require-pass
```

## Required Signoff Areas

Every pilot gate requires one latest signoff for each area:

- `false_positive_hotspots`
- `self_harm_boundary_cases`
- `trusted_adult_scenarios`
- `reputation_image_abuse`

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
- trusted-adult supportive traffic is not over-escalated
- supportive self-harm replies are not treated as crisis-originating content
- reputation/image-abuse cases open review with the expected urgency

## Operator Cadence

Recommended cadence:

- daily for the first 7 pilot days
- every 3 days after stability is established
- immediate re-review after any regression, rollback, or policy retune

Minimum owners:

- one policy reviewer
- one safety/product reviewer
- one runtime/operator owner

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
