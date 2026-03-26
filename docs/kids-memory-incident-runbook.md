# KIDS Memory Incident Runbook

This runbook defines the incident response workflow for `kids.memory.*`
findings in production and pilot operations.

Status: synchronized with runtime behavior on March 26, 2026.

## Scope

Use this runbook when any of the following reason codes appear in incident
reports, pilot bundles, or operator escalations:

- `kids.memory.grooming_progression`
- `kids.memory.sustained_sextortion`
- `kids.memory.bullying_cascade_selfharm`
- `kids.memory.sender_risk_accumulation`
- `kids.memory.new_sender_fast_escalation`
- `kids.memory.cross_conversation_repeat_offender`
- `kids.memory.victim_vulnerability_targeting`

## Severity and Response Targets

- `P0` immediate-risk (`selfharm` + active coercion/targeting):
  - acknowledge in 15 minutes
  - containment decision in 30 minutes
  - rollback/forward-fix decision in 2 hours
- `P1` high-risk persistent abuse patterns:
  - acknowledge in 30 minutes
  - containment decision in 2 hours
  - rollback/forward-fix decision in 4 hours
- `P2` elevated false-positive or drift concern:
  - acknowledge in 4 hours
  - mitigation plan in 1 business day

## Triage Checklist

1. Confirm reason code and count by conversation/sender slices.
2. Confirm whether guardian escalation was emitted.
3. Confirm whether signal came from:
   - single-conversation memory
   - cross-conversation sender memory
4. Check for simultaneous self-harm vulnerability indicators.
5. Compare to previous known-good artifact set and drift deltas.

## Containment Actions

- Preserve current release artifact and pilot bundle evidence.
- If `P0`/`P1` with suspected false negatives:
  - keep strict behavior and increase review cadence immediately.
- If `P1`/`P2` with suspected false positives:
  - do not remove mandatory guardian reasons;
  - isolate by profile/context threshold adjustments only.
- If behavior regression is broad:
  - rollback to previous known-good runtime + pattern/model set.

## Evidence Package

Each incident record must include:

- commit SHA
- release report and pilot regression report identifiers
- affected reason codes and frequency table
- conversation type split (`direct` vs `group`)
- sender repeat/conversation-repeat metrics
- decision outcome (`rollback`, `forward_fix`, `threshold_tune`)

## Post-Incident Guardrails

- Add or update one regression test per root-cause pattern.
- Update `docs/kids-memory-escalation-matrix.md` if semantics changed.
- Re-run KIDS gate checks before promotion:
  - `cargo test -p aura-kids`
  - `cargo run --quiet --example release_report -p aura-core -- --require-pass`
  - `cargo run --quiet --example pilot_regression -p aura-core -- --require-pass`
