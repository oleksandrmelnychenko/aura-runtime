# Context Architecture Blueprint

## Purpose

This document freezes the target architecture for AURA's context-aware messenger pipeline.

The system is no longer missing context entirely. The repo already has:

- a universal interpreter in [`context/interpretation.rs`](../crates/aura-core/src/context/interpretation.rs)
- persisted event context in [`context/events.rs`](../crates/aura-core/src/context/events.rs)
- behavior tracking in [`context/tracker.rs`](../crates/aura-core/src/context/tracker.rs)
- context-aware policy softening in [`action.rs`](../crates/aura-core/src/action.rs)
- product surfaces in [`product.rs`](../crates/aura-core/src/product.rs)
- social-context eval and release gates in [`eval_social_context.rs`](../crates/aura-core/src/eval_social_context.rs), [`eval_release.rs`](../crates/aura-core/src/eval_release.rs), and [`pilot_gate.rs`](../crates/aura-core/src/pilot_gate.rs)

The remaining problem is architectural: semantics are still split across typed context, string markers, and a few post-interpretation patches.

The goal of this blueprint is to make one layer authoritative for each decision.

## Current State

Today the effective runtime flow in [`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs) is:

`pattern + enricher + ML + domain -> raw signals/context events -> interpretation -> tracker -> context/timing signals -> combine -> inference -> policy -> product`

That is already directionally correct.

The main gaps are:

- raw detections still become `ContextEvent`s too early in several places
- post-interpretation logic still mutates semantics in analyzer/policy using string `context_markers`
- some threat families still carry local heuristics that should eventually become interpretation or policy-table logic

## Canonical Pipeline

The target pipeline should be treated as canonical:

`RawObservation -> ThreatContextFrame -> ConfirmedEvent -> Memory -> Inference -> Policy -> Product Surface`

Each stage answers a different question:

1. `RawObservation`: what did detectors find in this message?
2. `ThreatContextFrame`: what is the sender doing with that content here?
3. `ConfirmedEvent`: what behavior is affirmed after contextual interpretation?
4. `Memory`: how does affirmed behavior accumulate over time?
5. `Inference`: what does the accumulated pattern imply about trajectory and latent risk?
6. `Policy`: what response is justified?
7. `Product Surface`: how is that policy exposed to child, guardian, and review systems?

## Canonical Entities

### 1. RawObservation

This should become the only canonical output of detector layers.

It does not mean "real behavior". It means "detector X saw signal Y with confidence Z".

Target properties:

- `threat_type`
- `subtype`
- `source_layer`
- `score/confidence`
- `reason_code`
- optional payload such as content hash or detector metadata

Ownership:

- pattern layer
- ML layer
- domain adapters
- enricher hint adapters

Non-goal:

- detector layers should not decide stance, directionality, reciprocity, or whether a behavior is affirmed

### 2. ThreatContextFrame

This is already implemented in [`context/interpretation.rs`](../crates/aura-core/src/context/interpretation.rs) and should become the only authoritative semantic interpretation of the current message.

Canonical axes:

- `speech_act`
- `stance`
- `directionality`
- `reciprocity`
- `relationship`
- `trajectory`
- `confidence`

Ownership:

- only the interpreter may assign these fields

Non-goal:

- no downstream module should infer its own substitute for these fields from raw text

### 3. ConfirmedEvent

In the current codebase this is `ContextEvent + EventContextFrame` in [`context/events.rs`](../crates/aura-core/src/context/events.rs).

A confirmed event means:

- the message contained some signal
- the interpreter decided it represents affirmed behavior worth persisting

Examples:

- direct threat
- coercive screenshot blackmail
- grooming escalation
- neutral report of propaganda

The key difference is that the last example may still become a persisted event, but only with context that prevents it from being treated as hostile promotion in memory or policy.

### 4. Memory

Memory is owned by [`context/tracker.rs`](../crates/aura-core/src/context/tracker.rs) and the modules it drives:

- [`context/contact.rs`](../crates/aura-core/src/context/contact.rs)
- [`context/coercion.rs`](../crates/aura-core/src/context/coercion.rs)
- [`context/raid.rs`](../crates/aura-core/src/context/raid.rs)
- [`context/propaganda.rs`](../crates/aura-core/src/context/propaganda.rs)
- timing and conversation-profile logic

Memory should only consume confirmed events.

It should never recompute raw semantics from message text.

### 5. Inference

Inference lives in [`analyzer.rs`](../crates/aura-core/src/analyzer.rs).

It should consume:

- combined signals
- contact snapshot
- context-aware memory outputs
- typed context summary

It should not own first-pass context interpretation.

### 6. Policy and Product

Policy currently spans:

- [`action.rs`](../crates/aura-core/src/action.rs)
- [`product.rs`](../crates/aura-core/src/product.rs)

Policy decides what should happen.

Product decides how that policy is expressed to:

- child surface
- guardian surface
- review surface

These layers should consume typed context outcomes, not reconstruct them.

## Ownership Rules

The table below should be treated as a hard contract.

| Layer | Canonical output | Owns semantics? | Allowed to persist? |
| --- | --- | --- | --- |
| Pattern / ML / Domain detectors | `RawObservation` | No | No |
| Interpreter | `ThreatContextFrame`, `ConfirmedEvent`, adjusted observations | Yes | No |
| Tracker / Memory | timelines, contact state, derived context signals | No new message semantics | Yes |
| Inference | `InferenceSummary` | No first-pass semantics | No |
| Policy | `ActionRecommendation` | No first-pass semantics | No |
| Product | `ProductDecisionSurface` | No first-pass semantics | No |
| Eval / Release / Pilot | evidence and gates | No | Yes, reports only |

## Hard Invariants

These should remain true even as new threat families are added.

1. Detector layers may not create persistent memory by themselves.
2. Only the interpreter may assign `speech_act`, `stance`, `directionality`, or `reciprocity`.
3. Tracker receives only affirmed behavior.
4. Long-window detectors operate on persisted event context, not raw message text.
5. Policy does not reinterpret the message; it consumes typed outcomes.
6. `context_markers` are explainability, not the source of truth.
7. Eval and release gates must exercise the same semantics that production policy uses.

## Current Drift Hotspots

These are the places where the architecture is still mixed.

### 1. Early `ContextEvent` creation before interpretation

In [`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs), pattern, ML, enricher, and domain flows still materialize `ContextEvent`s before the interpreter runs.

That is workable, but not ideal.

Target:

- detector layers emit `RawObservation`
- a single adapter converts `RawObservation -> ConfirmedEvent` only inside interpretation

### 2. Stringly-typed `context_markers`

`context_markers` are useful and should stay for explainability and audit:

- [`types.rs`](../crates/aura-core/src/types.rs)
- [`audit.rs`](../crates/aura-core/src/audit.rs)
- [`pilot.rs`](../crates/aura-core/src/pilot.rs)

But today they also drive behavior in:

- [`action.rs`](../crates/aura-core/src/action.rs)
- [`product.rs`](../crates/aura-core/src/product.rs)
- parts of [`analyzer.rs`](../crates/aura-core/src/analyzer.rs)
- post-interpretation filters in [`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs)

Target:

- typed context becomes canonical
- `context_markers` are derived from typed context for explainability only

### 3. Post-interpretation semantic mutation in analyzer

[`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs) still contains:

- `apply_context_marker_signal_filters(...)`
- `apply_contextual_corroboration_boost(...)`

These are currently useful regression guards, but architecturally they are semantic logic after the interpreter.

Target:

- either move them into the interpreter
- or replace them with data-driven policy tables evaluated from typed context

### 4. Threat-local heuristics

Some threat families still keep local fast-path semantics:

- [`domain_runtime.rs`](../crates/aura-core/src/domain_runtime.rs)
- [`context/propaganda.rs`](../crates/aura-core/src/context/propaganda.rs)
- parts of coercion/manipulation handling

This is acceptable for precision guards, but not as the long-term home of stance and context semantics.

Target:

- fast guards may remain
- canonical meaning must still be resolved by the interpreter contract

## Target Refactor Program

### Phase 1. Freeze current architecture

Status:

- mostly done

Actions:

- treat [`context/interpretation.rs`](../crates/aura-core/src/context/interpretation.rs) as the only authority on first-pass message semantics
- treat [`context/events.rs`](../crates/aura-core/src/context/events.rs) predicates as the only authority on event eligibility for memory consumers
- keep release/pilot/social-context gating aligned with these semantics

Exit criteria:

- no new threat family adds raw semantic logic directly to policy or tracker

### Phase 2. Introduce explicit `RawObservation`

Status:

- not done

Actions:

- add a dedicated internal observation type and batch container
- stop constructing normal/hostile/supportive `ContextEvent`s in detector adapters
- move detector-to-event mapping into interpretation

Primary file targets:

- [`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs)
- [`domain_runtime.rs`](../crates/aura-core/src/domain_runtime.rs)
- pattern/ML mapping helpers

Exit criteria:

- detector layers only emit observations
- interpreter is the only place that turns observations into confirmed events

### Phase 3. Replace string marker control flow with typed context

Status:

- partially done

Actions:

- introduce a compact typed context summary on `AnalysisResult`
- keep `context_markers` as derived explainability only
- refactor policy softening and inference softening to consume typed context rather than marker strings

Primary file targets:

- [`types.rs`](../crates/aura-core/src/types.rs)
- [`action.rs`](../crates/aura-core/src/action.rs)
- [`product.rs`](../crates/aura-core/src/product.rs)
- [`analyzer.rs`](../crates/aura-core/src/analyzer.rs)
- [`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs)

Exit criteria:

- no business-critical decision depends on parsing string markers

### Phase 4. Move interpretation and policy exceptions into data

Status:

- not done

Actions:

- define a data-driven rule matrix for safe contexts, risky contexts, and escalation modifiers
- separate:
  - interpretation rules
  - memory eligibility rules
  - policy softening/escalation rules

Suggested future files:

- `crates/aura-core/data/context_interpretation_rules.json`
- `crates/aura-core/data/context_policy_rules.json`

Exit criteria:

- most contextual edge-case tuning is declarative rather than hand-written `if` chains

### Phase 5. Expand long-horizon eval around the same contract

Status:

- partially done

Actions:

- keep [`eval_social_context.rs`](../crates/aura-core/src/eval_social_context.rs) as the contract suite
- add more multi-turn and boundary-heavy cases
- explicitly validate:
  - context interpretation
  - memory accumulation
  - inference trajectory
  - policy surface

Exit criteria:

- every major context rule has a declarative boundary case in eval corpora or cohort specs

## What Not To Do

These shortcuts will recreate the original problem.

- Do not add new threat-family-specific context skips directly in policy.
- Do not let tracker modules infer meaning from raw text independently.
- Do not add more `context_markers` and treat them as the canonical state model.
- Do not let release/pilot gating drift away from the production semantics path.

## Immediate Next Work

If work starts now, the highest-value sequence is:

1. Add explicit `RawObservation` and route detector outputs through it.
2. Add a typed context summary to `AnalysisResult`.
3. Refactor `action.rs`, `product.rs`, and inference softening to use typed context instead of marker strings.
4. Move post-interpretation analyzer patches into interpreter or rule tables.
5. Only then expand coverage into more threat families.

## Decision Rule

When choosing where a new rule belongs, use this test:

- If it answers "what was detected?", it belongs to detectors.
- If it answers "what is the sender doing here?", it belongs to the interpreter.
- If it answers "should this pattern persist over time?", it belongs to memory eligibility.
- If it answers "what should the system do now?", it belongs to policy.
- If it answers "how should this appear to child/guardian/review?", it belongs to product.

If a rule seems to fit multiple places, the architecture is drifting and should be simplified before more features are added.
