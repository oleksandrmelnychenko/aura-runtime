# Phase 2 Production Roadmap

Status: Closeout snapshot as of March 15, 2026. Milestones 1 through 3 are
operational, and this document now serves as both the record of what was
delivered and the handoff into the next major phase.

## Purpose

Phase 2 is not only about "better calibration." For AURA Core, Phase 2 is the
bridge from a strong evaluation stack to a production-ready safety runtime with:

- stable release signals
- stable protobuf and C ABI contracts
- slice-aware quality discipline
- privacy-safe auditability
- repeatable rollback and incident handling

The goal is still one strong v1. The roadmap below is intentionally narrow and
does not add unrelated product layers.

## Closeout Snapshot

Phase 2 now has the following production-facing outputs in place:

- structured release report with support-aware and blocker-aware statuses
- unified evidence manifest consumed by CI and promotion workflows
- contract evidence for protobuf, ABI, state schema, and FFI request limits
- dataset evidence with coverage snapshots and changelog linkage
- audit evidence with forbidden-field checks and declared identifier tokenization
- FFI smoke compile and repeated state-sync soak evidence
- all-targets/all-features build and test path in default automation
- release-critical realistic and external slices expanded to hard-gating support

What this does not mean: policy modeling is finished. It means the release and
boundary discipline for the current v1 track is now in place.

## Non-Negotiable Constraints

- Messenger-native safety runtime only
- Protobuf-only wire contract
- Rust domain model inside the core
- C ABI only at the boundary
- Evaluation-first release discipline
- Privacy and explainability treated as product requirements

## Baseline Snapshot

Snapshot date: March 13, 2026.

These values come from the current example suites and should be treated as the
starting baseline for Phase 2 reporting and drift checks.

| Suite | Calibration Count | Brier | ECE | Positive Detect | Negative FP | Pre-Onset Detect |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Canonical | 74 | 0.0833 | 0.0949 | 1.00 | 0.00 | 0.8750 |
| Multilingual | 35 | 0.0893 | 0.1092 | 1.00 | 0.00 | 0.7500 |
| Realistic | 75 | 0.0803 | 0.1133 | 1.00 | 0.00 | 0.2500 |
| External Curated Mixed | 38 | 0.0794 | 0.0861 | 1.00 | 0.00 | 0.6667 |
| External Curated Gold | 17 | 0.0970 | 0.0818 | 1.00 | 0.00 | 1.0000 |
| Social Context | 385 | 0.0963 | 0.0900 | 0.9574 | 0.00 | 0.7021 |

Current weak spots already visible in slice outputs:

- multilingual `ru` ECE is materially weaker than `en` and `uk`
- realistic `trusted_adult` and `group_peer` slices have high ECE
- external curated slices are still too thin to act as hard release blockers
- social-context `child_stranger_direct` and `school_group_social_pressure`
  are materially harder than the overall suite

## Target End State For Phase 2

At the end of Phase 2, AURA should have:

- one aggregated release report across all critical suites
- explicit `PASS`, `FAIL`, `INSUFFICIENT_SUPPORT`, and `BLOCKED` statuses
- per-language, per-age-band, per-threat, and critical-slice calibration views
- drift checks between canonical, realistic, external mixed, and external gold
- mixed-vs-gold comparison used as a release signal, not only a diagnostic
- stable protobuf and FFI change rules
- privacy-safe audit rules that do not depend on raw message logging
- dataset governance and coverage targets for release-critical slices

## Milestone 1: Evaluation Contract and Release Artifacts

### Why This Comes First

Before tightening any gates, the project needs a stable evaluation contract that
CI and future release tooling can consume without scraping human-readable
example output.

### Core Work

1. Extend shared evaluation primitives in
   [`crates/aura-core/src/eval.rs`](../crates/aura-core/src/eval.rs).
   Add a stable release-status model, slice support metadata, and suite
   comparison outputs.
2. Unify suite reporting across
   [`crates/aura-core/src/eval_realistic.rs`](../crates/aura-core/src/eval_realistic.rs),
   [`crates/aura-core/src/eval_external.rs`](../crates/aura-core/src/eval_external.rs),
   [`crates/aura-core/src/eval_social_context.rs`](../crates/aura-core/src/eval_social_context.rs),
   and the scenario-based suites so they can emit one shared machine-readable
   result shape.
3. Introduce an aggregated release entrypoint in `aura-core` examples or a
   dedicated release-report module that runs the critical suites together.
4. Separate "passing because good" from "passing because under-sampled".
   Small slices must resolve to `INSUFFICIENT_SUPPORT`, not a misleading `PASS`.
5. Add drift comparison between:
   - canonical and realistic
   - canonical and external mixed
   - realistic and external mixed
   - external mixed and external gold
6. Preserve human-readable console reports, but make them secondary views over
   the structured report.

### File Targets

- [`crates/aura-core/src/eval.rs`](../crates/aura-core/src/eval.rs)
- [`crates/aura-core/src/eval_realistic.rs`](../crates/aura-core/src/eval_realistic.rs)
- [`crates/aura-core/src/eval_external.rs`](../crates/aura-core/src/eval_external.rs)
- [`crates/aura-core/src/eval_social_context.rs`](../crates/aura-core/src/eval_social_context.rs)
- [`crates/aura-core/examples/realistic_eval.rs`](../crates/aura-core/examples/realistic_eval.rs)
- [`crates/aura-core/examples/external_curated_eval.rs`](../crates/aura-core/examples/external_curated_eval.rs)

### Deliverables

- Structured release report format
- Shared release-status enum
- Critical-slice support thresholds
- Drift report format
- Aggregated release example or CLI entrypoint
- Tests covering status transitions and slice support behavior

### Exit Criteria

- A single command can produce one release report for all critical suites
- Release statuses no longer depend on manual interpretation of stdout
- Critical slices can be distinguished from under-sampled slices
- Mixed-vs-gold comparison exists in machine-readable form

Status: complete.

## Milestone 2: Contract and Boundary Hardening

### Why This Comes Second

Once release signals are formalized, the next production risk is contract drift.
If protobuf, persisted context state, or the C ABI change without hard rules,
evaluation green status will not be enough.

### Core Work

1. Freeze explicit wire-compatibility rules for
   [`proto/aura/messenger/v1/messenger.proto`](../proto/aura/messenger/v1/messenger.proto).
2. Freeze ABI rules for
   [`include/aura_ffi.h`](../include/aura_ffi.h) and the functions exported by
   [`crates/aura-ffi`](../crates/aura-ffi).
3. Define three separate version tracks:
   - protobuf wire version
   - persisted tracker state schema version
   - runtime release version
4. Add compatibility tests for:
   - protobuf encode/decode stability
   - context export/import across schema revisions
   - invalid and truncated input at the FFI boundary
   - null handle and buffer behavior
5. Define panic-free FFI behavior and stable error semantics.
6. Define safe-degradation rules for missing models, missing pattern data, or
   malformed import payloads.

### File Targets

- [`proto/aura/messenger/v1/messenger.proto`](../proto/aura/messenger/v1/messenger.proto)
- [`include/aura_ffi.h`](../include/aura_ffi.h)
- [`crates/aura-proto`](../crates/aura-proto)
- [`crates/aura-ffi`](../crates/aura-ffi)

### Deliverables

- Contract stability policy
- ABI compatibility matrix
- Context schema migration rules
- FFI robustness tests
- Safe-degradation expectations

### Exit Criteria

- Breaking protobuf changes require a new major wire version instead of silent
  in-place mutation
- Breaking context-state changes require an explicit schema migration story
- FFI edge cases have tests and documented semantics
- A release cannot be cut without compatibility evidence

Status: complete.

## Milestone 3: Dataset and Slice Stabilization

### Why This Comes Third

The current overall metrics are good, but several release-critical slices still
lack enough support to carry hard production confidence.

### Core Work

1. Expand realistic and external curated corpora where support is currently too
   thin.
2. Promote release-critical dimensions from "report-only" to "release-blocking"
   once support thresholds are met.
3. Add explicit coverage targets for:
   - `language`
   - `age_band`
   - `relationship`
   - `review_status`
   - `source_family`
4. Tighten gold-only external gates only after support is high enough to make
   them meaningful.
5. Turn mixed-vs-gold delta review into a real release rule.
6. Maintain provenance, review history, and corpus changelog discipline.

### Highest-Priority Data Gaps Addressed In This Milestone

- external curated `ru` language support
- external curated `uk` language support
- external curated `child`, `trusted_adult`, `supportive_peer`, and
  `group_peer` coverage
- realistic `child`, `trusted_adult`, `self`, and `stranger` coverage
- harder trusted-adult boundary and support-boundary cases that preserve
  protective-signal reasoning

These gaps drove the corpus expansions that closed the current release-critical
slice set.

### File Targets

- [`crates/aura-core/data/realistic_chat_cases.json`](../crates/aura-core/data/realistic_chat_cases.json)
- [`crates/aura-core/data/external_curated_chat_cases.json`](../crates/aura-core/data/external_curated_chat_cases.json)
- [`crates/aura-core/data/social_context_cohorts.json`](../crates/aura-core/data/social_context_cohorts.json)

### Deliverables

- Coverage target table
- Corpus promotion rules
- Mixed-vs-gold release comparator
- Dataset changelog discipline
- Tests for schema, provenance, and slice coverage assumptions

### Exit Criteria

- Every release-critical slice has enough support to justify hard gating
- Mixed and gold suites are both green and interpretable
- Dataset changes become reviewable and reproducible artifacts

Status: complete for the current release-critical slice set. Thin report-only
views still exist, but they are no longer misrepresented as hard release proof.

## Work Sequencing

### Now

- Preserve the current release gates and artifact contracts
- Review promotion bundles instead of manually inspecting console output
- Keep the evidence manifest stable for downstream automation

### Next

- Extend Phase 3 policy and psychological modeling on top of the locked release
  discipline
- Add new evaluation slices only together with support targets and governance
- Keep privacy, ABI, and dataset evidence green while expanding behavior

### Then

- Consider stricter thresholds only after several consecutive stable promotion
  bundles
- Expand non-blocking thin slices if they become release-relevant
- Add deeper mathematical upgrades only after policy pathways mature

## What Is Explicitly Out Of Scope Here

- broadening AURA into a generic moderation SDK
- adding unrelated AI companion or engagement features
- replacing the current messenger-native contract with a more generic API shape
- major mathematical upgrades before evaluation and contract discipline are
  stable

## Definition Of Done

Phase 2 is done only when all of the following are true:

- release reports are structured and reproducible
- critical slices have support-aware statuses
- drift between corpora is tracked and reviewable
- external mixed vs gold comparison affects release decisions
- protobuf, persisted state, and C ABI changes follow explicit rules
- privacy-safe audit behavior is documented and enforceable
- dataset changes are governed, versioned, and attributable

Current status: satisfied for the current release-hardening track.
