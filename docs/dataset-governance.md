# Dataset Governance

## Purpose

The evaluation stack is one of AURA Core's main differentiators. That means the
corpora themselves are production assets and need governance, not ad hoc case
editing.

## Corpus Inventory

Current data artifacts include:

- [`crates/aura-core/data/corpus_curated_cases.json`](../crates/aura-core/data/corpus_curated_cases.json)
- [`crates/aura-core/data/corpus_style_profiles.json`](../crates/aura-core/data/corpus_style_profiles.json)
- [`crates/aura-core/data/social_context_cohorts.json`](../crates/aura-core/data/social_context_cohorts.json)
- [`crates/aura-core/data/realistic_chat_cases.json`](../crates/aura-core/data/realistic_chat_cases.json)
- [`crates/aura-core/data/external_curated_chat_cases.json`](../crates/aura-core/data/external_curated_chat_cases.json)
- [`crates/aura-core/data/dataset_changelog.json`](../crates/aura-core/data/dataset_changelog.json)

## Governance Principles

- every corpus change should be attributable
- provenance matters more than volume
- review tier must be explicit
- slice coverage should be deliberate, not accidental
- changing a corpus is equivalent to changing a release input

## Review Tiers

For external curated data, the tier model is already present:

- `seed_reviewed`
- `gold_reviewed`
- `mixed_review_tiers`

Promotion should follow a documented path:

1. case drafted or imported
2. provenance and metadata attached
3. seed review completed
4. gold review completed where needed
5. promoted into release-critical evaluation

## Required Metadata

External curated corpora must carry:

- `schema_version`
- `dataset_id`
- `dataset_label`
- `curation_status`
- `maintainer`
- `created_at_ms`
- `updated_at_ms`

Each case must carry:

- unique ID
- source family
- review status
- default language
- age band
- relationship
- threat labeling and onset assumptions
- policy expectation linkage where required

## Current Coverage Snapshot

Snapshot date: March 15, 2026.

### Realistic Chat Corpus

- total cases: 71
- languages: `en=47`, `uk=19`, `ru=5`
- age bands: `child=39`, `teen=32`
- relationships:
  - `group_peer=16`
  - `peer=5`
  - `self=16`
  - `stranger=16`
  - `supportive_peer=2`
  - `trusted_adult=16`

### External Curated Corpus

- total cases: 57
- review status: `gold_reviewed=50`, `seed_reviewed=7`
- languages: `en=13`, `uk=22`, `ru=22`
- age bands: `child=29`, `teen=28`
- relationships:
  - `group_peer=17`
  - `peer=2`
  - `self=1`
  - `stranger=2`
  - `supportive_peer=18`
  - `trusted_adult=17`
- source families:
  - `moderation_seed=2`
  - `research_seed=18`
  - `school_context_seed=17`
  - `support_boundary_seed=20`

## Release-Critical Slices Brought To Hard-Gating Support

The following release-critical slices were expanded during the Phase 2
hardening track and are now part of the governed support baseline:

- realistic `age_band:child`
- realistic `relationship:trusted_adult`
- realistic `relationship:stranger`
- realistic `relationship:group_peer`
- realistic `relationship:self`
- external curated `language:ru`
- external curated `language:uk`
- external curated `age_band:child`
- external curated `relationship:trusted_adult`
- external curated `relationship:supportive_peer`
- external curated `relationship:group_peer`
- external curated `review_status:gold_reviewed`

## Current Non-Blocking Thin Slices

The following slices remain intentionally monitored as thin or report-only
views rather than hard release blockers:

- realistic `relationship:supportive_peer`
- realistic `relationship:peer`
- external curated `relationship:self`
- external curated `relationship:peer`
- external curated `relationship:stranger`

## Coverage Targets

### Reportable Target

Enough support to include a slice as a meaningful monitored view:

- at least 4 cases per critical slice
- balanced positive and negative examples where the slice semantics require both

### Release-Blocking Target

Enough support to treat the slice as true release evidence:

- at least 8 cases per critical slice
- at least 3 positive and 3 negative scenarios where applicable
- at least 2 onset-bearing positive scenarios when pre-onset behavior matters

These are initial governance targets, not final end-state limits. They should
increase as the corpus matures.

## Change Management

Every corpus-affecting change should include:

- what changed
- why the change was needed
- which slices were affected
- whether the change increased, decreased, or rebalanced support
- expected metric impact if known

At a minimum, dataset updates should be visible in commit history and reflected
in release-report metadata.

Current automation also requires:

- a machine-readable dataset evidence artifact for the exact corpus files used
  by CI or promotion
- a lightweight dataset changelog in
  [`crates/aura-core/data/dataset_changelog.json`](../crates/aura-core/data/dataset_changelog.json)
- changelog linkage between the corpus snapshot and the latest governance entry

## Promotion Rules

A case should not move into release-critical status unless:

- the metadata is complete
- provenance is recorded
- labeling assumptions are internally consistent
- policy expectation linkage exists where policy quality is being gated
- the change does not silently collapse a critical slice into under-support

## Privacy Expectations

Dataset realism must not come from exposing real child identities. Messenger
behavioral realism is valuable; private identifying content is not.

## Current Enforcement Expectations

- surface corpus metadata in release artifacts
- flag slice coverage regressions automatically
- make mixed-vs-gold comparison part of corpus promotion review
- keep a lightweight dataset changelog for external curated updates
- emit dataset evidence for the exact corpus files used by CI and promotion gates
