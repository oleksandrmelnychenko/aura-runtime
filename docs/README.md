# Documentation Map

This folder holds the planning and operating documents that turn AURA Core from
an evaluation-heavy prototype into a production-grade safety runtime.

Status: synchronized with runtime and policy behavior on March 23, 2026.

## Active Operating Set

- [Phase 2 Production Roadmap](./phase-2-production-roadmap.md)
- [Phase 3 Pilot Readiness Roadmap](./phase-3-pilot-readiness-roadmap.md)
- [Product Integration Contract](./product-integration-contract.md)
- [Pilot Operations](./pilot-operations.md)
- [Release Criteria](./release-criteria.md)
- [Proto and ABI Stability](./proto-abi-stability.md)
- [Privacy and Audit Policy](./privacy-audit-policy.md)
- [Dataset Governance](./dataset-governance.md)
- [Incidents and Rollbacks](./incidents-and-rollbacks.md)

## Product and Scenario Docs

- [How AURA Protects Olena (Ukrainian)](./olena-scenarios-uk.md)

## Historical and Research Docs

- [Messenger Psychology Research Spec](./messenger-psychology-research-spec.md)
- [Pig Butchering Scam Research](./pig-butchering-scam-research.md)
- [Russian Propaganda and Disinformation Research](./russian-propaganda-detection-research.md)

## Current Implementation Notes

- Military anti-propaganda flow now applies runtime false-positive filtering for
  propaganda pattern matches before signal emission.
- Coordinate handling now enforces a runtime Ukraine DD gate for generic
  coordinate rules and suppresses duplicate generic coordinate signals when
  Ukraine-specific coordinate rules match the same message.
- `DetectionSignal.threat_subtype` is part of the stable product-facing payload
  and is now populated for heuristic URL detections (`doppelganger`,
  `homoglyph`, `heuristic`) and broader military/psyops subtype paths.
- Current `patterns_mvp.json` size is 322 rules.

## How To Use These Docs

- Start with the roadmap to understand what was delivered in the Phase 2
  release-hardening track and what remains for the next phase.
- Use the Phase 3 roadmap when planning pilot-readiness work, shadow mode,
  product integration, or simulation-to-regression promotion.
- Use the product integration contract when building Swift/iOS, Android, or
  desktop clients on top of `AnalysisResult.product_surface`.
- Use the pilot operations doc when preparing signoffs, running pilot gates,
  or defining rollback actions for a staged rollout.
- Use the release criteria as the source of truth for gating and CI status.
- Use the proto and ABI document before changing protobuf schemas, FFI exports,
  or persisted context state.
- Use the privacy and audit policy before adding logs, telemetry, or any
  debugging hooks.
- Use the dataset governance document before changing realistic or external
  curated corpora.
- Use the incident runbook when planning operational safeguards, kill switches,
  and rollback behavior.
- Use the Olena scenarios doc when preparing product demos, guardian-facing
  explanations, or copy that must stay aligned with current policy semantics.
- Use [`../CHANGELOG.md`](../CHANGELOG.md) for the high-level change record
  when preparing a release note or promotion review.
