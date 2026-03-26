# KIDS Memory Operational Targets

This document defines strict operational targets for `kids.memory.*` monitoring,
pilot hold decisions, and release rollback decisions.

Status: active baseline for strict-profile operations on March 26, 2026.

## Daily SLO Targets

Evaluate using `artifacts/kids-memory-health.json`:

- `overall_status` must be `pass` for scheduled strict checks.
- `missing_mandatory_reason_codes` must be empty (`0`).
- `total_memory_hits` must stay greater than `0` on daily simulation runs.

## Hold and Rollback Thresholds

Use these thresholds for pilot/release decisions:

- `P0 rollback trigger`:
  - strict run reports `overall_status = fail` because mandatory reasons are
    missing on two consecutive daily runs.
- `P1 hold trigger`:
  - strict run fails once, or `total_memory_hits = 0` once.
  - action: hold promotion and run same-day rerun after artifact sanity check.
- `P2 drift trigger`:
  - strict run passes but shows persistent week-over-week drop of
    `total_memory_hits` by at least `30%` for 7 days.
  - action: open threshold review and scenario-corpus review before next
    promotion.

## Ownership and Escalation

- Primary owner: runtime/operator owner
- Secondary owner: policy reviewer
- Tertiary owner: safety/product reviewer

Escalation policy:

- `P0`: page all three owners immediately, decision within 2 hours
- `P1`: runtime/operator + policy within 4 hours
- `P2`: weekly review queue with explicit action item owner

## Review Cadence

- Daily: review strict `kids-memory-health` artifacts
- Weekly: review trend deltas and scenario coverage drift
- Release week: run strict check as a required pre-promotion gate
- Release week: run strict pre-prod dry-run matrix and attach JSON to signoff

## Required Commands

Local strict snapshot:

```bash
python ci/kids_memory_health_snapshot.py \
  --input artifacts/pilot-regression-report.json \
  --input artifacts/pilot-shadow-run-a.json \
  --input artifacts/pilot-shadow-run-b.json \
  --output artifacts/kids-memory-health.json \
  --require-mandatory-reasons
```

CI strict run:

```bash
gh workflow run kids-memory-health.yml -f require_mandatory_reasons=true
```

Pre-prod dry-run matrix:

```bash
python ci/kids_preprod_dry_run_matrix.py \
  --policy-expectations crates/aura-core/data/action_policy_expectations.json \
  --realistic-cases crates/aura-core/data/realistic_chat_cases.json \
  --kids-memory-health artifacts/kids-memory-health.json \
  --output artifacts/kids-preprod-dry-run-matrix.json
```
