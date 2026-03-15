# Release Criteria

## Purpose

This document defines what "green" means for AURA Core as a safety-critical
messenger runtime. A release is acceptable only when quality, support,
contract stability, and privacy constraints all pass together.

Current automation enforces this through:

- `cargo run --quiet --example release_report -p aura-core -- --output ... --require-pass`
- `python ci/generate_evidence_manifest.py --output ...`
- `.github/workflows/rust.yml`
- `.github/workflows/promotion-gate.yml`

## Release Statuses

The release system exposes four explicit statuses:

- `PASS`: all blocking gates passed and all required slices had enough support
- `FAIL`: at least one blocking gate failed
- `INSUFFICIENT_SUPPORT`: no blocking metric failed, but one or more required
  slices were under-supported and therefore cannot claim a real pass
- `BLOCKED`: required evidence is missing, such as no compatibility result, no
  release artifact, or no dataset provenance for a changed corpus

`INSUFFICIENT_SUPPORT` is not a soft success. It is a signal that the release
cannot be called stable yet.

## Blocking Suite Set

The production release report should include, at minimum:

- canonical scenario suite
- manipulation suite
- multilingual suite
- noisy/slang suite
- robustness suite
- corpus-style suite
- social-context suite
- realistic chat suite
- external curated mixed suite
- external curated gold-only suite
- policy-action gates for realistic, social-context, and external curated

## Blocking Dimensions

The following views are required in the release report:

- overall per-suite metrics
- per-threat calibration where the suite carries enough support
- per-language metrics for multilingual, realistic, and external curated suites
- per-age-band metrics for realistic and external curated suites
- per-relationship metrics for realistic and external curated suites
- per-review-status and per-source-family metrics for external curated suites
- per-cohort metrics for social-context evaluation

## Minimum Support Policy

Two support tiers should exist:

### Reportable

Use this tier to show a slice in the report:

- at least 12 calibration examples, or
- at least 8 onset cases for lead-time claims

If a slice does not meet this tier, it should still appear in the report, but
only as `INSUFFICIENT_SUPPORT`.

### Release-Blocking Target

This is the target support bar before a slice becomes a true release blocker:

- at least 24 calibration examples
- at least 8 positive scenarios
- at least 8 negative scenarios
- at least 8 onset cases for any pre-onset gate

Until a slice reaches this bar, it can inform review and drift monitoring, but
it should not be misrepresented as hard production evidence.

## Metric Families

Every blocking suite should report:

- calibration count
- Brier score
- Expected Calibration Error
- positive detection rate
- negative false positive rate
- pre-onset detection rate when onset applies

Policy suites should also report:

- scenario pass rate
- required-any coverage
- required-by-onset coverage
- forbidden violation rate

## Existing Threshold Sources

Current baseline threshold families already live in code:

- [`crates/aura-core/src/eval.rs`](../crates/aura-core/src/eval.rs)
- [`crates/aura-core/src/eval_realistic.rs`](../crates/aura-core/src/eval_realistic.rs)
- [`crates/aura-core/src/eval_external.rs`](../crates/aura-core/src/eval_external.rs)
- [`crates/aura-core/src/eval_social_context.rs`](../crates/aura-core/src/eval_social_context.rs)

The current release framework wraps these gates with support-aware statuses.
Threshold tightening should still happen only after slice support and corpus
quality improve together.

## Mixed vs Gold External Rule

External curated release discipline must include both mixed and derived
gold-only views.

The minimum rule set is:

- mixed must pass its own gates
- gold-only must pass stricter gates
- if mixed passes but gold-only fails, the release fails
- if mixed and gold diverge materially, the release requires review even if both
  pass

Recommended initial review tolerances until the first structured release reports
are stable:

- Brier delta greater than 0.05
- ECE delta greater than 0.05
- positive detection delta greater than 0.10
- negative false positive delta greater than 0.03

These are review triggers, not permanent final thresholds. They should be
revisited after several stable report snapshots.

## Contract and Operational Blockers

A release is `BLOCKED` if any of the following are missing:

- protobuf compatibility evidence
- FFI compatibility evidence
- context import/export compatibility evidence
- FFI request-size limit evidence
- FFI state-sync soak evidence
- structured release artifact for the current commit
- dataset provenance for changed external curated corpora
- privacy-safe audit behavior for any new telemetry or debug path
- machine-readable dataset evidence for the current corpus snapshot
- machine-readable audit evidence proving raw identifiers and transcript fields are absent

## Required Release Artifact

Each release candidate should produce one machine-readable artifact containing:

- git commit
- runtime version
- protobuf package version or wire version
- context schema version
- FFI boundary request-size limits
- FFI state-sync soak result
- curated soak failure diagnosis when the soak result is not `PASS`
- suite summaries
- slice summaries
- gate results
- support-status results
- drift comparisons
- mixed-vs-gold comparison

The current entrypoint is a unified evidence manifest that points to the
release report, contract evidence, dataset evidence, audit evidence, FFI smoke
evidence, and FFI state-sync soak evidence for the same commit or tag.

Current manifest contract:

- schema: `aura.evidence_manifest.v1`
- release report schema: `3`
- audit schema: `aura.audit_record.v1`

## Release Checklist

- All blocking suites are present in the report
- No blocking suite is `FAIL`
- No required slice is `INSUFFICIENT_SUPPORT`
- No required artifact is missing
- Mixed and gold external results are both reviewed
- Compatibility checks are green
- Dataset evidence is green
- Privacy and audit constraints are unchanged or explicitly approved
- Audit evidence proves forbidden fields are absent
- Local promotion rehearsal is not treated as green if the FFI smoke compile is
  only a stub due to a missing local compiler

## What Does Not Count As Release Readiness

- one-off good console output from examples
- good overall metrics with thin critical slices
- synthetic-only confidence without realistic and curated support
- undocumented protobuf or FFI changes
- raw message logging used as a debugging crutch
