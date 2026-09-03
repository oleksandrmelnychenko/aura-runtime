# Context Architecture Blueprint

## Purpose

This document freezes the target architecture for AURA's context-aware messenger pipeline.

This document covers the offline client runtime only. Context detection,
interpretation, memory, inference and policy execute in-process; this pipeline
does not own HTTP, endpoints, transport or server synchronization.
The `offline-runtime-gate` also rejects HTTP/TLS client packages and socket
transport APIs from the resolved all-features client graph. ONNX support loads
a locally supplied dynamic runtime and does not enable `ort` binary downloads.

The system is no longer missing context entirely. The repo already has:

- a universal interpreter in [`context/interpretation.rs`](../crates/aura-core/src/context/interpretation.rs)
- persisted event context in [`context/events.rs`](../crates/aura-core/src/context/events.rs)
- behavior tracking in [`context/tracker.rs`](../crates/aura-core/src/context/tracker.rs)
- context-aware policy softening in [`action.rs`](../crates/aura-core/src/action.rs)
- product surfaces in [`product.rs`](../crates/aura-core/src/product.rs)
- social-context eval and release gates in [`eval_social_context.rs`](../crates/aura-core/src/eval_social_context.rs), [`eval_release.rs`](../crates/aura-core/src/eval_release.rs), and [`pilot_gate.rs`](../crates/aura-core/src/pilot_gate.rs)

The current hardening branch has one typed interpretation boundary. Legacy
string markers remain only as derived explainability and compatibility output;
new tracker-derived signals are routed back through the interpreter before
they join the final signal set.

The goal of this blueprint is to make one layer authoritative for each decision.

## Current State

Today the effective runtime flow in [`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs) is:

`pattern + enricher + ML + domain -> raw signals/context events -> interpretation -> tracker -> context/timing signals -> combine -> inference -> policy -> product`

That is already directionally correct.

The main gaps are:

- a few compatibility APIs still accept `context_markers`, then immediately
  convert them into `AnalysisContextSummary`
- some threat families still carry local precision heuristics that should
  eventually become interpretation or policy-table logic
- multilingual held-out and native-speaker validation remains a release gate,
  distinct from the repository-owned engineering corpus

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
- typed `evidence_origin` (`lexical`, `compositional`, or `derived`)
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

### 2a. Attribution

Implemented in [`context/attribution.rs`](../crates/aura-core/src/context/attribution.rs).
Context suppression (reports, lessons, refusals, protective negation, crisis
support) is not a phrase-list decision over the whole message. Before the
interpreter may suppress a signal or an event it separates the normalized
message into:

- **attributed spans**: outermost closed quotations, reported-speech clauses
  introduced by an explicit cue (`he said`, `мені написали`, `quote:`,
  `my friend texted`), and protective negations that quote the abusive claim
  in order to deny it (`you are not worthless`);
- **stance cues**: the author's own reporting, educational, refusing,
  protective, counter-speech, supportive or crisis wording, detected on the
  unattributed text only and blanked before rescanning;
- **unattributed text**: everything else.

Both fragments are rescanned by the same detectors through an
`ActiveRiskProbe` (the routed pattern matchers plus the kids composition
probe) and a small phrase floor. Suppression of a family is permitted only
when:

1. the family is not active in the unattributed text, and
2. for pattern and composition signals, the same detector finds the family
   inside the attributed content; derived/ML evidence also requires
   same-family evidence from the independent attribution probe. A substantive
   span by itself is never sufficient to suppress a family.

Support and crisis-support suppression use the intent-bearing subset of the
author's activity (composition and phrase floor) so a supporter may repeat a
victim's words, while a compliance directive over a quoted request
(`... so do it now`) makes the quoted request the author's own.

Fail-closed rules: unclosed or mismatched quotes, nested-ambiguous quotes and
semantic capacity errors produce no spans and mark every family active. A
bare quotation over live risk without a protective stance keeps the
`Assert` speech act and the `DirectedAtUser` directionality. Cue-free
messages skip the probe entirely and pay only for the phrase floor.

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
8. Suppression is attribution-gated: a family may only be treated as reported, taught, refused or supported when it is absent from the author's own text and present in an attributed span.

## Current Drift Hotspots

These are the places where the architecture is still mixed.

### 1. Detector-to-event boundary

Status: resolved on the current hardening branch.

Pattern, ML, enricher and domain adapters emit `RawObservation`. Event hints
become tracker-eligible `ConfirmedEvent`s only inside interpretation.

### 2. Stringly-typed `context_markers`

`context_markers` are useful and should stay for explainability and audit:

- [`types.rs`](../crates/aura-core/src/types.rs)
- [`audit.rs`](../crates/aura-core/src/audit.rs)
- [`pilot.rs`](../crates/aura-core/src/pilot.rs)

Typed `AnalysisContextSummary` is canonical. Compatibility entry points in
[`action.rs`](../crates/aura-core/src/action.rs) may accept markers, but they
convert once at the boundary; production orchestration and product policy use
the typed summary directly.

### 3. Derived-signal interpretation

Status: resolved on the current hardening branch.

The tracker and temporal detectors necessarily run after confirmed events are
recorded. Their newly derived signals are interpreted as one separate typed
batch by `interpret_derived_signals_with_probe` before they are combined with
the already-interpreted detector signals. Existing signals are not re-mutated,
and derived provenance is explicit rather than reconstructed from reason-code
text.

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

- implemented

Actions:

- dedicated observations carry typed signal/event provenance
- detector adapters no longer construct tracker-ready events
- detector-to-event confirmation is owned by interpretation

Primary file targets:

- [`analyzer/stages.rs`](../crates/aura-core/src/analyzer/stages.rs)
- [`domain_runtime.rs`](../crates/aura-core/src/domain_runtime.rs)
- pattern/ML mapping helpers

Exit criteria:

- detector layers only emit observations
- interpreter is the only place that turns observations into confirmed events

### Phase 3. Replace string marker control flow with typed context

Status:

- implemented for the production orchestration and policy path; legacy marker
  adapters remain for source compatibility

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

- implemented for the governed interpretation, memory and policy rule packs;
  local detector precision predicates remain code-owned

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

- engineering coverage implemented; independent held-out/native-speaker review
  remains external evidence

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

The highest-value continuation is:

1. Keep expanding risky/safe multilingual and code-switch counterfactuals.
2. Add independently adjudicated held-out conversations per language pair.
3. Profile only after correctness gates are frozen; accept no safety regression
   in exchange for latency.
4. Onboard another language only through the complete governed language matrix.

## Decision Rule

When choosing where a new rule belongs, use this test:

- If it answers "what was detected?", it belongs to detectors.
- If it answers "what is the sender doing here?", it belongs to the interpreter.
- If it answers "should this pattern persist over time?", it belongs to memory eligibility.
- If it answers "what should the system do now?", it belongs to policy.
- If it answers "how should this appear to child/guardian/review?", it belongs to product.

If a rule seems to fit multiple places, the architecture is drifting and should be simplified before more features are added.
