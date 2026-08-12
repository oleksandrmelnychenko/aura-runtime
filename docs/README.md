# Documentation Map

This folder holds the planning and operating documents that turn AURA Core from
an evaluation-heavy prototype into a production-grade safety runtime.

Status: synchronized with runtime and policy behavior on August 1, 2026.

## Active Operating Set

- [Master Production Release Plan](./production-release-master-plan.md)
- [Release Decision Contract](./release-decision.md)
- [AURA Core Refactor Completion Plan](./aura-core-refactor-completion-plan.md)
- [AURA Core Research Evidence Roadmap](./research-evidence-roadmap.md)
- [Independent Domain Result Evidence](./domain-independent-result-evidence.md)
- [Domain Result Trusted Timestamp Adapter](./domain-result-trusted-timestamp-adapter.md)
- [Apple Artifact Integration Contract](./apple-artifact-integration.md)
- [Canonical Local Decision ADR](./adr/0001-canonical-local-decision-api.md)
- [AURA Core Refactor Baseline](./refactor-baseline.md)
- [Phase 2 Production Roadmap](./phase-2-production-roadmap.md)
- [Phase 3 Pilot Readiness Roadmap](./phase-3-pilot-readiness-roadmap.md)
- [Server, Client, and Feature Backlog](./server-client-feature-backlog.md)
- [Product Integration Contract](./product-integration-contract.md)
- [Pilot Operations](./pilot-operations.md)
- [Release Criteria](./release-criteria.md)
- [Proto and ABI Stability](./proto-abi-stability.md)
- [Privacy and Audit Policy](./privacy-audit-policy.md)
- [Dataset Governance](./dataset-governance.md)
- [Incidents and Rollbacks](./incidents-and-rollbacks.md)
- [Wave 1 Release Hardening](./wave1-release-hardening.md)
- [On-Device Production Readiness](./on-device-prod-readiness.md)
- [Safety 5-Label Training](./safety-5label-training.md)
- [Verification Commands](./verification-commands.md)
- [Continuation Handoff](./continuation-handoff.md)
- [KIDS Memory Escalation Matrix](./kids-memory-escalation-matrix.md)
- [KIDS Memory Incident Runbook](./kids-memory-incident-runbook.md)
- [KIDS Strict Scenario Matrix](./kids-strict-scenario-matrix.md)
- [KIDS Memory Operational Targets](./kids-memory-operational-targets.md)
- [KIDS Pre-Prod Dry-Run Matrix](./kids-preprod-dry-run-matrix.md)

## Product and Scenario Docs

- [Safety World v2](./safety-world-v2.md)
- [How AURA Protects Olena (Ukrainian)](./olena-scenarios-uk.md)

## Historical and Research Docs

- [AURA Core Research Evidence Roadmap](./research-evidence-roadmap.md)
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
- Current `patterns_mvp.json` size is 533 rules.
- `aura-ml` ONNX safety/intent integration tests are opt-in via
  `AURA_RUN_SAFETY_INTENT_ONNX=1`; default runs keep core ONNX coverage but
  skip these heavy load checks on platforms where they can hang.

## How To Use These Docs

- Start with the master production release plan for the authoritative release
  scope, blockers, execution order, evidence gates, signoffs, rollout, and
  rollback rules.
- Use the Phase 2 roadmap to understand what was delivered in the earlier
  release-hardening track and what remains for the next phase.
- Use the Phase 3 roadmap when planning pilot-readiness work, shadow mode,
  product integration, or simulation-to-regression promotion.
- Use the product integration contract when building Swift/iOS clients on the
  typed local-decision protobuf or Rust/desktop clients on `AnalysisResult`.
- Use the pilot operations doc when preparing signoffs, running pilot gates,
  or defining rollback actions for a staged rollout.
- Use the release criteria as the source of truth for gating and CI status.
- Use the proto and ABI document before changing protobuf schemas, FFI exports,
  or persisted context state.
- Use the privacy and audit policy before adding logs, telemetry, or any
  debugging hooks.
- Use the dataset governance document before changing realistic or external
  curated corpora.
- Use the research evidence roadmap before turning production or pilot results
  into a scientific hypothesis, experiment, or doctoral claim.
- Use the incident runbook when planning operational safeguards, kill switches,
  and rollback behavior.
- Use the Olena scenarios doc when preparing product demos, guardian-facing
  explanations, or copy that must stay aligned with current policy semantics.
- Use [`../CHANGELOG.md`](../CHANGELOG.md) for the high-level change record
  when preparing a release note or promotion review.
