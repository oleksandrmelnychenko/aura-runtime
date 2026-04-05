# Universal Context Interpretation Plan

Detailed architecture contract:

- [Context Architecture Blueprint](./context-architecture-blueprint.md)

## Goal

AURA already has strong message-level detection and stateful context tracking, but it still
conflates three different questions:

1. What did the model or rules detect in the message?
2. What is the sender doing with that content in this conversation?
3. How risky is that behavior in this social context?

The missing layer is a universal interpretation step between raw detection and persistent
behavior tracking.

This is not only a propaganda problem. The same gap exists across:

- self-harm: disclosure vs support vs coercion
- bullying: quote vs banter vs directed abuse
- grooming: routine logistics vs exploitative probing
- manipulation: support vs guilt pressure vs control
- hate speech: condemnation vs endorsement
- propaganda/psyops: reporting vs counter-speech vs promotion
- opsec: warning about a leak vs actually leaking

## Core Design

Introduce a new internal pipeline stage:

`raw observation -> context interpretation -> confirmed event + adjusted signal`

The key rule is:

- detection finds content
- interpretation decides role and direction
- tracker stores only affirmed behavior, not every mention

## New Internal Types

These types should be internal to `aura-core` first. They do not need FFI/protobuf exposure in
phase 1.

```rust
pub enum SpeechAct {
    Assert,
    Ask,
    Quote,
    Report,
    Counter,
    Support,
    Joke,
    Coordinate,
    Solicit,
    Threaten,
}

pub enum Stance {
    Endorse,
    Oppose,
    Neutral,
    Ambiguous,
}

pub enum Directionality {
    DirectedAtUser,
    SelfReferential,
    ThirdParty,
    Broadcast,
    Unknown,
}

pub enum Reciprocity {
    OneSided,
    Mutual,
    Unknown,
}

pub struct RelationshipContext {
    pub is_new_contact: bool,
    pub is_trusted: bool,
    pub circle_tier: CircleTier,
    pub trust_level: f32,
    pub prior_conversation_count: usize,
}

pub struct TrajectoryContext {
    pub repeated_by_sender: bool,
    pub escalating: bool,
    pub cross_conversation: bool,
    pub bursty: bool,
}

pub struct ThreatContextFrame {
    pub speech_act: SpeechAct,
    pub stance: Stance,
    pub directionality: Directionality,
    pub reciprocity: Reciprocity,
    pub relationship: RelationshipContext,
    pub trajectory: TrajectoryContext,
    pub confidence: f32,
}

pub struct Observation {
    pub threat_type: ThreatType,
    pub subtype: Option<String>,
    pub score: f32,
    pub source_layer: DetectionLayer,
    pub reason_code: String,
}

pub struct ContextInterpretation {
    pub frame: ThreatContextFrame,
    pub adjusted_signals: Vec<DetectionSignal>,
    pub confirmed_events: Vec<ContextEvent>,
    pub suppressed_reason_codes: Vec<String>,
}
```

## File-Level Refactor Plan

### 1. Add new interpretation module

Create:

- [context/interpretation.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/interpretation.rs)

Responsibilities:

- derive `ThreatContextFrame` from message text, sender history, conversation type, and raw hits
- convert raw observations into confirmed behavior events
- downweight or suppress false-positive signal paths
- centralize threat-specific context rules

This module should be pure and testable. It should not mutate tracker state directly.

### 2. Insert interpretation into analyzer pipeline

Update:

- [analyzer.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/analyzer.rs)

Current problem:

- pattern/domain/ML output quickly becomes signals and context events
- filters are applied later via ad hoc heuristics
- tracker can still accumulate semantically wrong events

Target flow:

1. collect raw pattern/domain/url signals
2. run ML layer
3. run enricher and gather context hints
4. build `Observation` list from raw signals
5. call `ContextInterpreter::interpret(...)`
6. use `adjusted_signals` for scoring and policy
7. send only `confirmed_events` into `ConversationTracker`

Concretely, the interpretation call should sit between:

- raw signal collection
- `apply_contextual_false_positive_filters(...)`
- tracker `record_event(s)`

Longer term, `apply_contextual_false_positive_filters(...)` should shrink or be absorbed into
the interpretation module.

### 3. Keep tracker behavior-only

Update:

- [tracker.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/tracker.rs)

Rule:

- tracker stores behavior that has been affirmed by interpretation
- tracker should not store raw mentions that are quote/report/counter/support contexts

This matters because the tracker currently drives:

- conversation detectors
- contact risk accumulation
- behavioral trends
- escalation logic

If raw mentions keep entering timelines, long-window detectors will learn the wrong behavior.

### 4. Tighten contact profiling semantics

Update:

- [contact.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/contact.rs)
- [events.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/events.rs)

Rule:

- rating and trust should react to confirmed hostile/coercive/promotional behavior
- neutral reference or counter-speech should not count as hostility

Important examples:

- quoted insult should not reduce contact rating as `Insult`
- fact-checking a propaganda claim should not count as `PropagandaNarrative`
- a supportive self-harm response should not count as `SelfHarm`
- warning about leaked coordinates should not count as `CoordinateLeak`

### 5. Expand enricher into a universal context-hint source

Update:

- [enricher.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/enricher.rs)

Add categories for:

- quote/report markers
- counter-speech markers
- support/reassurance markers
- uncertainty/questioning markers
- routine logistics markers
- explicit forwarding/share/subscribe markers

These should not all become threat events. Many should stay interpretation hints only.

### 6. Reduce propaganda-specific special casing

Update:

- [domain_runtime.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/domain_runtime.rs)
- [propaganda.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/propaganda.rs)

The current propaganda false-positive skip is useful, but too local.

Phase 1:

- keep the current fast skip as a cheap precision guard
- add interpretation after it for generalized stance resolution

Phase 2:

- move stance logic out of propaganda-only code
- let propaganda reuse the same universal interpretation framework as all other threats

## Threat-Family Interpretation Matrix

This is the minimum behavior policy the interpretation layer should apply.

### Self-Harm

- `SelfReferential + Assert` -> likely genuine self-harm disclosure
- `DirectedAtUser + Support` -> supportive response, suppress self-harm threat
- `DirectedAtUser + Threaten/Coerce` -> manipulation or harm encouragement
- `Quote/Report` -> downweight unless accompanied by acute concern markers

### Bullying / Hate

- `DirectedAtUser + Assert/Threaten` -> direct abuse
- `Mutual + Joke` -> possible banter, downweight unless severity or asymmetry is high
- `Quote/Counter/Report` -> suppress direct abuse event creation
- repeated one-sided attacks -> strong upweight

### Grooming / Manipulation

- `Ask + new contact + personal probe` -> risky
- `Ask + trusted adult + routine logistics` -> downweight
- `Support` alone should never become grooming
- secrecy + platform shift + asymmetry + persistence -> strong upweight

### Propaganda / Psyops

- `Endorse + Assert` -> promote narrative
- `Solicit/Coordinate` -> stronger than mere endorsement
- `Quote/Report` -> neutral mention
- `Counter/Oppose` -> counter-speech, do not accumulate as propaganda behavior

### OPSEC / Coordinate Leak

- `Assert + content disclosure` -> real leak
- `Counter/Report/Warning` -> suppress leak event
- repeated sharing + media/link evidence -> strong upweight

## Minimal-Invasive Phase 1

The first implementation should avoid public contract churn.

Phase 1 rules:

- keep protobuf/FFI unchanged
- keep `DetectionSignal` public shape unchanged if possible
- keep tracker schema changes minimal
- add interpretation as an internal analyzer step
- record only confirmed events
- expose effect mainly through better scores, cleaner reason codes, and safer tracker state

That gets most of the value without forcing a full ABI migration.

## Structural Phase 2

Once phase 1 is stable:

- introduce `Observation` formally as a first-class internal analyzer output
- stop mapping raw pattern hits directly to `ContextEvent`
- move most special-case filters into the interpretation module
- optionally expose debug-friendly context metadata in internal reports or audit outputs

## Concrete Analyzer Changes

### Current choke points

Relevant files:

- [analyzer.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/analyzer.rs)
- [domain_runtime.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/domain_runtime.rs)
- [events.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/events.rs)

Current issues:

- `collect_pattern_layer(...)` can emit both signals and events too early
- domain threat mapping often implies behavior before context is resolved
- filters happen after detection but before long-term semantics are fully resolved

Recommended refactor:

```rust
let pattern = self.collect_pattern_layer(...);
let ml = self.run_ml_layer(text);
let hints = self.signal_enricher.enrich_full_with_hash(...);
let observations = build_observations(&pattern.signals, &ml);
let interpretation = self.context_interpreter.interpret(
    input,
    text,
    timestamp_ms,
    &observations,
    &hints.events,
    self.context_tracker.timeline(&input.conversation_id),
    self.context_tracker.contact_profiler().snapshot(&input.sender_id),
);
let mut signals = interpretation.adjusted_signals;
let confirmed_events = interpretation.confirmed_events;
```

Then:

- score only `signals`
- persist only `confirmed_events`

## Evaluation Plan

Update:

- [eval_social_context.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/eval_social_context.rs)
- [social_context_cohorts.json](C:/Users/123/ecliptix-aura/crates/aura-core/data/social_context_cohorts.json)

Add new cohorts:

- `propaganda_discussion_boundary`
- `selfharm_support_boundary`
- `peer_banter_boundary`
- `trusted_adult_logistics_boundary`
- `opsec_warning_boundary`
- `hate_counter_speech_boundary`

Each cohort should contain both:

- risky positives where context confirms threat behavior
- safe negatives where the same surface language appears in quote/report/support/counter contexts

This is critical. Without evaluation cohorts, the interpretation layer will drift back into
per-threat hacks.

## Recommended Implementation Order

1. Add `context/interpretation.rs` with types and unit tests.
2. Wire it into [analyzer.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/analyzer.rs) without changing FFI/proto.
3. Make tracker persist confirmed events only.
4. Extend [enricher.rs](C:/Users/123/ecliptix-aura/crates/aura-core/src/context/enricher.rs) with generalized context hints.
5. Add social-context evaluation cohorts for safe-vs-risky boundaries.
6. After metrics stabilize, clean up propaganda-only special casing and other one-off filters.

## Non-Goals

This plan should not become:

- one giant universal score with no interpretable axes
- a full rewrite of all detectors before phase 1 ships
- a logic dump inside `analyzer.rs`
- a public API break before internal semantics are stable

## Success Criteria

The work is successful when the system consistently does all of the following:

- detects risky content when the sender is actually endorsing, directing, coercing, or spreading it
- suppresses the same surface text when it is quoted, opposed, supported, or reported
- avoids polluting timelines and contact profiles with semantically false events
- improves cross-threat precision without weakening truly dangerous repeated behavior
