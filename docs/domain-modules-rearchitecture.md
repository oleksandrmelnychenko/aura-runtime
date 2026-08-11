# AURA Domain Modules Rearchitecture

## Target Architecture

The runtime architecture is organized around a central `AURA` core and two
domain modules:

- `AURA` (central core)
- `AURA.KIDS`
- `AURA.MILITARY`

The repository now contains dedicated crates for this model:

- `crates/aura-domain`
- `crates/aura-kids`
- `crates/aura-military`

## File/Folder Grouping

### Shared Contract

- `crates/aura-domain/src/module.rs`
- `crates/aura-domain/src/input.rs`
- `crates/aura-domain/src/output.rs`
- `crates/aura-domain/src/registry.rs`

### AURA.KIDS

- `crates/aura-kids/src/detectors/grooming.rs`
- `crates/aura-kids/src/detectors/bullying.rs`
- `crates/aura-kids/src/detectors/selfharm.rs`
- `crates/aura-kids/src/detectors/manipulation.rs`
- `crates/aura-kids/src/policy/guardian.rs`
- `crates/aura-kids/src/policy/intervention.rs`
- `crates/aura-kids/src/hooks.rs`

### AURA.MILITARY

- `crates/aura-military/src/detectors/opsec.rs`
- `crates/aura-military/src/detectors/coordinate_leak.rs`
- `crates/aura-military/src/detectors/psyops.rs`
- `crates/aura-military/src/detectors/social_eng.rs`
- `crates/aura-military/src/policy/escalation.rs`
- `crates/aura-military/src/policy/response.rs`
- `crates/aura-military/src/hooks.rs`

### AURA Core Runtime Bridge

- `crates/aura-core/src/domain_runtime.rs`

### Structural Runtime Owners

- `crates/aura-core/src/analyzer.rs` — stable public façade
- `crates/aura-core/src/analyzer/orchestrator.rs` — runtime orchestration
- `crates/aura-core/src/analyzer/orchestrator/stages.rs` — interpretation and
  memory stage sequencing
- `crates/aura-core/src/analyzer/orchestrator/stages/observations.rs` —
  observation collectors and bounded normalization helpers
- `crates/aura-core/src/analyzer/orchestrator/inference.rs` — inference and
  result-building helpers
- `crates/aura-core/src/context/contact.rs` — stable contact-memory façade
- `crates/aura-core/src/context/contact/relationship/model.rs` — exported
  contact and trajectory model
- `crates/aura-core/src/context/contact/relationship/state.rs` — bounded
  profiler state and import/export lifecycle

## Migration Map (Logical Ownership)

- Kids detectors: from `crates/aura-core/src/context/*` into
  `crates/aura-kids/src/detectors/*`
- Military detectors: from `crates/aura-core/src/context/*` into
  `crates/aura-military/src/detectors/*`
- Domain selection contract: kept in `crates/aura-core/src/types.rs` and
  `crates/aura-core/src/config.rs`
- Wire enum: `proto/aura/messenger/v1/messenger.proto`

## Rollout Status

- Structural rearchitecture: complete
- Workspace wiring for new crates: complete
- Domain runtime bridge in core: complete and active in analyzer flow
- Domain signals now enter core scoring/context pipeline (not only metadata)
- Baseline domain lexical heuristics migrated into kids/military detector crates
- Domain lexical rules are file-based (`data/lexicon.json`) with schema validation
- Rule packs are versioned (`schema_version`) and guarded by tests in CI
- Domain rule records now include `threat_type`, `severity`, and `priority` metadata
- Domain action policy is now resolved via shared `aura-domain` policy engine
- Legacy military context detectors in core tracker are fully disabled (military signals come from domain runtime)
- `AURA.MILITARY` runtime no longer executes legacy kids context detectors in core tracker
- Core analyzer now resolves domain `ThreatType` from rule metadata (`threat_type`) without `threat_key` fallback mapping
- Core tracker no longer stores/rebuilds legacy military detector state (`opsec_detector`/`psyops_detector`)
- Legacy kids context detectors are no longer executed by the core tracker
- Legacy kids and military context detector modules were removed from `aura-core/context` source tree
- Coordinate validation for military leaks moved from core context helpers into `aura-patterns`
- Tracker no longer carries domain-module selection in core context config
- Core contact anomaly escalation for predator-pattern heuristics is now restricted to minor accounts
- Core `EventKind` no longer exposes military-specific classifier helper methods (`is_opsec_indicator`, `is_psyops_indicator`)
- Military rule/threat to `EventKind` mapping for domain output is now routed via `domain_runtime` adapter (not hardcoded inside analyzer)
- Military subtype mapping (`psyops`/`opsec`/`coordinate`/`military_social_eng`) is now routed via `domain_runtime` adapter too
- Domain-specific match guard for generic military coordinates (`opsec_coordinates_001`) is now routed via `domain_runtime` adapter
- Propaganda subtype/source mapping is also routed via `domain_runtime` adapter (removed from analyzer-local mapping helpers)
- Propaganda false-positive context guard is now routed via `domain_runtime` adapter (removed from analyzer-local skip logic)
- Analyzer pattern pass is consolidated into a shared helper for `analyze`/`analyze_with_context` to reduce duplication and keep adapter routing consistent
- Domain rule-prefix `EventKind` mapping for propaganda sources (`propaganda_domain_*`, `propaganda_telegram_channel_*`) is now routed via `domain_runtime` adapter
- Domain override suppression for generic-vs-specific coordinate rules is now routed via `domain_runtime` adapter
- Domain-signal to `EventKind` mapping for context event emission is now routed via `domain_runtime` adapter
- Analyzer no longer uses sentinel `"domain_signal"` for domain event mapping; it delegates to `domain_runtime::map_domain_signal_to_event_kind`
- Kids/teen rule-prefix `EventKind` mappings (`grooming_*`, `selfharm*`, `platform_switch_teen`, `gaming_bribery`, `emotional_withdrawal`) are now routed via `domain_runtime` adapter
- Manipulation/coercion rule-prefix `EventKind` mappings (`manipulation_*`, `substance_*`, `coercion_*`, `false_consensus`, `debt_creation`, `reputation_threat`, `identity_erosion`, `network_poisoning`, `fake_vulnerability`) are now routed via `domain_runtime` adapter
- Additional safety prefix/keyword `EventKind` mappings (`bullying` keyword family, `doxxing*`, `screenshot_threat*`, `hate_*`, `pii_*`, `meeting_casual*`, `dare_*`, `dangerous_*`) are now routed via `domain_runtime` adapter
- Analyzer `match_to_event_kind` now delegates fallback `ThreatType -> EventKind` mapping through `domain_runtime::map_threat_to_event_kind`
- Analyzer `infer_threat_subtype` now fully delegates to `domain_runtime::map_domain_threat_subtype` (no local threat-type branching)
- Analyzer ML event conversion now delegates to `domain_runtime::map_ml_signal_to_event_kind` (removing another local `ThreatType` mapping branch)
- Analyzer threat classification guards were normalized to compact `matches!(...)` predicates, removing repeated explicit domain-threat fallback branches from core orchestration paths
- Analyzer `is_detection_enabled` now delegates domain toggles (`propaganda` / `opsec` / `psyops`) through `domain_runtime::domain_detection_enabled`
- Additional domain-specific analyzer decisions were moved behind adapter helpers (`is_propaganda_threat`, `is_link_family_threat`, `parse_domain_threat_type`, `domain_threat_priority`) to further reduce direct domain branching in `aura-core/analyzer`
- Domain threat classification helper `is_domain_threat` was added and wired into analyzer gating/priority paths to centralize domain family membership checks
- Analyzer now delegates full threat tables (`is_detection_enabled`, `parse_threat_type`, `threat_priority`) through `domain_runtime` helpers (`detection_enabled_for_threat`, `parse_threat_type_label`, `threat_priority_for_sort`)
- Analyzer proxy helpers for threat parsing/priority were removed; call sites now use `domain_runtime` helpers directly
- Domain-signal normalization in analyzer now uses adapter helpers (`domain_signal_threat_type`, `domain_signal_confidence`, `core_action_from_domain_action`) instead of local conversion helpers
- Analyzer wrapper helpers for subtype inference, context skip checks, and event mapping were removed; call sites now invoke `domain_runtime` mapping/skip APIs directly
- Rule/threat to `EventKind` resolution was deduplicated into `domain_runtime::map_rule_or_threat_to_event_kind`, and analyzer now uses this helper directly
- Domain reason-code merge behavior was extracted to `domain_runtime` (`push_domain_reason_codes`, `domain_action_reason_marker`), reducing merge logic in analyzer
- Domain output -> detection signal conversion now delegates to `domain_runtime::build_domain_detection_signals` (removing local transformation helper from analyzer)
- Domain output merge side-effects now delegate to `domain_runtime::merge_domain_output_effects`, leaving analyzer with orchestration-only update wiring
- Domain `DetectionSignal -> ContextEvent` conversion now delegates to `domain_runtime::build_domain_context_events`, removing another local adapter loop from analyzer
- Local analyzer wrapper `merge_domain_output` was removed; both analysis paths now call `domain_runtime::merge_domain_output_effects` directly
- Blocked URL signal construction now delegates to `domain_runtime::build_blocked_url_signal` (reason-code, subtype, and link-family mapping no longer live in analyzer helper code)
- Action selection with propaganda override now delegates through `domain_runtime::decide_action_with_domain_overrides`, removing direct domain-specific action branching from analyzer
- Analyzer no longer keeps a local score-to-confidence helper; it aliases `domain_runtime::confidence_from_score` directly
- Lexicon rules now support optional `action` hints (`allow|mark|warn|block`) consumed by shared domain policy engine
- Domain packs now include a top-level `policy` profile (`warn_priority`, `critical_warn_priority`) used by hooks/runtime
- Domain packs now also drive escalation thresholds (`guardian_escalation_priority` for kids, `priority_escalation_priority` for military)
- Hooks now promote low-severity actions to `warn` when escalation threshold is reached
- CI now runs `ci/lint_lexicons.py` for semantic checks and duplicate detection
- Production packs no longer include synthetic `probe` rules
- Domain outputs carry typed signal-to-event routes owned by `aura-kids` and
  `aura-military`; core no longer derives domain events from rule-name prefixes
- Legacy shared Layer 1 rule routing and military subtype compatibility are
  owned by `aura-patterns`, without adding a dependency on domain crates
- Full detector logic migration and differential parity validation: complete
- Shared action aggregation is monotonic: an `allow`/`mark` hint cannot suppress
  a threshold-derived warning, and a weaker high-priority hint cannot replace a
  stronger `block` hint.
- Non-finite or out-of-range ML score channels are neutralized by the shared
  contract without discarding other valid channels; duplicate lexical
  threat/reason identities are rejected during pack loading.
- Temporal registry execution is gated by `temporal_enabled`, and Military
  temporal fusion requires both event confidence and interpreted-context
  confidence to meet the configured floor.
- `aura-domain` now forbids unsafe code, denies missing public documentation,
  and passes strict pedantic, nursery, and performance Clippy review.
