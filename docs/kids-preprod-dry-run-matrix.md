# KIDS Pre-Prod Dry-Run Matrix

This contract defines the minimum dry-run checks before expanding KIDS pilot
traffic or promoting a release with strict KIDS protections enabled.

Status: active baseline on March 26, 2026.

## Goal

Provide one compact artifact that confirms:

- strict KIDS harmful and benign slices are present in policy expectations
- strict KIDS harmful and benign slices are present in realistic corpus anchors
- strict `kids-memory-health` is `pass`
- mandatory `kids.memory.*` reason codes are observed

## Artifact

Default output:

- `artifacts/kids-preprod-dry-run-matrix.json`

Schema:

- `aura.kids_preprod_dry_run_matrix.v1`

## Command

Run after generating `artifacts/kids-memory-health.json`:

```bash
python ci/kids_preprod_dry_run_matrix.py \
  --policy-expectations crates/aura-core/data/action_policy_expectations.json \
  --realistic-cases crates/aura-core/data/realistic_chat_cases.json \
  --kids-memory-health artifacts/kids-memory-health.json \
  --output artifacts/kids-preprod-dry-run-matrix.json
```

## Pass Criteria

Dry-run matrix passes only when:

- no required harmful slices are missing in policy expectations
- no required benign slices are missing in policy expectations
- no required harmful slices are missing in realistic corpus anchors
- no required benign slices are missing in realistic corpus anchors
- `kids-memory-health.overall_status == pass`
- `kids-memory-health.total_memory_hits > 0`
- `kids-memory-health.missing_mandatory_reason_codes` is empty
- all required mandatory `kids.memory.*` reason codes have positive observed counts

## Operational Usage

- Run this matrix before production-like scenario rehearsals.
- Treat `overall_status = fail` as hold condition for KIDS promotion.
- Attach matrix JSON artifact to pilot/release review tickets.
