# AURA Core Refactor Baseline

Status: refreshed after the reviewed confirmed-memory domain differential on August 11, 2026.

## Purpose

The checked-in
`crates/aura-core/data/refactor_baseline_v1.json` freezes the observable
behavior and boundary contracts at the exact revision stored in its
`source.revision` field.

It records:

- the 21-crate workspace graph;
- runtime, protobuf wire, persisted state, C ABI, and request-size contracts;
- protobuf compatibility fixture hashes;
- the reviewed schema-5 Apple artifact manifest, exact export allowlist, and
  clean source provenance;
- governed detector and evaluation input hashes;
- normalized release, pilot, and 16-world lifecycle results;
- a release-built 10k performance snapshot and bounded comparison envelope;
- the additive canonical local-decision and terminal-source checkpoint ABI;
- the additive content-free local-decision temporal context contract;
- the governed Military temporal-fusion rules and adversarial Shadow corpus.

Timestamps, source-tree dirtiness, raw world event logs, and absolute artifact
paths are not behavioral comparison inputs.

## Local Gate

Run:

```bash
just refactor-baseline-gate
```

or:

```bash
bash ci/refactor_baseline_gate.sh
```

The gate writes a candidate snapshot and
`artifacts/refactor/refactor-diff-report.json`. It fails when any observed
change is unapproved, when an approval is stale, or when an approval does not
exactly match both sides of the observed JSON-pointer diff.

CI and the promotion workflow run the same comparison with the 10k performance
tier. The unified `aura.evidence_manifest.v1` includes both the performance
report and refactor diff report.

## Change Classification

Unapproved differences are always classified as `regression`.

The only reviewable exceptions are:

- `structural_only`: observable structure changed but reviewed safety behavior
  did not;
- `approved_safety_improvement`: an intentional safety behavior change with
  reviewed evidence.

Approvals live in `docs/refactor-diff-approvals.json`. Every approval must
contain:

```json
{
  "path": "/behavior/pilot_regression/...",
  "classification": "approved_safety_improvement",
  "baseline": "exact old JSON value",
  "candidate": "exact new JSON value",
  "reason": "Review decision and evidence reference."
}
```

Wildcards are unsupported. Unused approvals fail the gate, so approvals cannot
silently remain after the underlying diff disappears.

An approval does not authorize a protobuf v1, C ABI, or persisted-state
breaking change. Those still require the separately versioned migration
process in `docs/proto-abi-stability.md`.

## Updating the Baseline

Do not update the baseline merely to make a failing diff green.

Update it only after:

1. the diff is reviewed and classified;
2. all Rust, release, pilot, lifecycle, FFI replay, and performance gates pass;
3. any safety change has explicit evidence and approval;
4. boundary changes follow the versioning rules;
5. the accepted candidate becomes the new reviewed reference revision.

After accepting a new baseline, clear obsolete entries from
`docs/refactor-diff-approvals.json`; the empty state is the normal state.
The baseline and exact-approval JSON files are deliberately excluded from the
Apple build-source digest because they review hashes stored in the Apple
artifact itself. This exact two-file exclusion prevents a cryptographic
self-reference; it does not exclude governed fixtures or executable CI code.
