# Documentation Map

This folder holds the planning and operating documents that turn AURA Core from
an evaluation-heavy prototype into a production-grade safety runtime.

## Active Operating Set

- [Phase 2 Production Roadmap](./phase-2-production-roadmap.md)
- [Release Criteria](./release-criteria.md)
- [Proto and ABI Stability](./proto-abi-stability.md)
- [Privacy and Audit Policy](./privacy-audit-policy.md)
- [Dataset Governance](./dataset-governance.md)
- [Incidents and Rollbacks](./incidents-and-rollbacks.md)

## Historical and Research Docs

- [Messenger Psychology Research Spec](./messenger-psychology-research-spec.md)
- [Pig Butchering Scam Research](./pig-butchering-scam-research.md)

## How To Use These Docs

- Start with the roadmap to understand what was delivered in the Phase 2
  release-hardening track and what remains for the next phase.
- Use the release criteria as the source of truth for gating and CI status.
- Use the proto and ABI document before changing protobuf schemas, FFI exports,
  or persisted context state.
- Use the privacy and audit policy before adding logs, telemetry, or any
  debugging hooks.
- Use the dataset governance document before changing realistic or external
  curated corpora.
- Use the incident runbook when planning operational safeguards, kill switches,
  and rollback behavior.
- Use [`../CHANGELOG.md`](../CHANGELOG.md) for the high-level change record
  when preparing a release note or promotion review.
