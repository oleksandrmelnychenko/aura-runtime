# Messenger Psychology Research Spec

## Scope

This document defines the post-stabilization research roadmap for AURA as a
messenger-native trust and safety runtime. The goal is not to add more generic
"AI moderation", but to deepen the existing event-driven psychology engine with:

- richer latent constructs from psychology and trust-and-safety research
- stronger temporal mathematics for escalation and state change
- more realistic scenario coverage
- evaluation that measures early detection and calibration, not only final labels

The current codebase already has the right substrate:

- event vocabulary in [events.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/events.rs)
- staged grooming analysis in [grooming.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/grooming.rs)
- coercion and manipulation detectors in [coercion.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/coercion.rs) and [manipulation.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/manipulation.rs)
- self-harm temporal logic in [selfharm.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/selfharm.rs)
- contact longitudinal state in [contact.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/contact.rs)
- structured messenger output in [types.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/types.rs), [action.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/action.rs), and [analyzer.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/analyzer.rs)
- scenario harness in [simulations.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/examples/simulations.rs)

The next leap should turn this from a heuristic event scorer into a calibrated,
stateful psychological inference engine.

## Core Thesis

AURA should evolve toward four explicit layers:

1. `Observed Events`
   Current `EventKind`, message metadata, timing, participant structure, link
   behavior, contact history.
2. `Latent Constructs`
   Psychological variables inferred from events over time.
3. `Risk Processes`
   Temporal models for escalation, change points, contagion, and onset risk.
4. `Policy Actions`
   Messenger-native decisions and UI actions calibrated to risk and uncertainty.

The biggest mistake would be to skip layer 2 and pile more rules directly onto
layer 1. Research across grooming, coercive control, self-harm, and bullying
points to latent states, progression, and interaction effects rather than simple
event counts.

## Research-Backed Extensions

### 1. Grooming

Current strength:

- staged progression already exists in [grooming.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/grooming.rs)
- speed and ordering already affect score
- contact freshness and minor-target breadth already modulate severity

Gaps to add:

- `risk_assessment`
  Signals that the offender is probing supervision, device access, secrecy
  tolerance, or general vulnerability.
- `authority_or_status_claim`
  Coach, mentor, "industry helper", older trusted expert, social proof.
- `fantasy_or_roleplay_pathway`
  Sexualized or dependency-building fantasy without immediate direct asks.
- `media_progression`
  Text -> disappearing media -> voice/video -> out-of-band channel -> meet.
- `deception_masking`
  False vulnerability, false peer similarity, false consensus, fake emergency.
- `target_suitability`
  A context multiplier only. Never a standalone trigger.

Recommended modeling shift:

- Replace pure stage counts with a `Hidden Semi-Markov Model` or a simpler
  Bayesian state tracker.
- Preserve the current stages, but allow parallel pathway priors:
  `relationship_building`, `authority grooming`, `financial grooming`,
  `fantasy grooming`, `secrecy/control`.

Why:

- Grooming research consistently reports multiple pathways, risk assessment,
  deception, and media progression. AURA already has a stage skeleton that can
  absorb this cleanly.

### 2. Coercive Control and Digital Dating Abuse

Current strength:

- multi-vector coercion already exists in [coercion.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/coercion.rs)
- manipulation cycles and DARVO already exist in [manipulation.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/manipulation.rs)

Gaps to add:

- `surveillance_control`
  Password requests, location sharing demands, read-receipt pressure,
  availability pressure, monitoring framed as care.
- `image_based_control`
  Threats around screenshots, saved media, non-consensual redistribution.
- `omnipresence`
  Excessive check-ins, response-time control, sleep disruption, "prove where you are".
- `post_breakup_persistence`
  Continued control or intimidation after the relationship frame is broken.
- `jealousy_as_normative_care`
  "If you loved me, you'd share your password."

Recommended modeling shift:

- Split current `Manipulation` into subfamilies internally:
  `coercive_control`, `reality_manipulation`, `dependency_manipulation`,
  `reputation_blackmail`, `image_based_abuse`.
- Add a control graph:
  `dependency -> monitoring -> isolation -> threat -> compliance demand`.

Why:

- Research on adolescent cyber-dating abuse shows that monitoring and control
  behaviors are often normalized by young users, so they need explicit
  representation rather than hiding inside a generic manipulation score.

### 3. Self-Harm and Crisis

Current strength:

- [selfharm.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/selfharm.rs) already models accumulation, farewell sequences, acute vs chronic, and protective factors

Gaps to add:

- `burdensomeness`
- `belongingness_loss`
- `defeat`
- `entrapment`
- `action_proximity`
  Planning, finality, logistics, giving away valuables, irreversible framing.
- `capability_signals`
  Exposure, desensitization, or persistent self-harm talk distinct from despair.

Recommended modeling shift:

- Separate `ideation risk` from `attempt proximity`.
- Use an internal two-layer model:
  `motivational risk` and `volitional risk`.
- Do not collapse both into one score.

Why:

- Ideation-to-action theories consistently show that the drivers of suicidal
  thinking differ from the drivers of imminent attempt risk.

### 4. Bullying, Harassment, and Group Abuse

Current strength:

- group and pile-on logic already exists in bullying and raid detection
- contact trend logic already supports long-term deterioration

Gaps to add:

- `audience_amplification`
  Public humiliation, visible group watching, reaction cascades.
- `identity_targeting`
  Appearance, sexuality, ethnicity, disability, social status.
- `private_space_invasion`
  Persistent intrusion into DMs, message requests, late-night harassment.
- `bystander_support_vs_silence`
  Supportive intervention should reduce risk; silence should not be neutral.
- `humor_masking`
  Abuse reframed as jokes or banter.

Recommended modeling shift:

- Treat group abuse as a separate process family, not just a stronger version of
  one-to-one bullying.
- Maintain a group-level short-horizon model for burst dynamics.

Why:

- Cyberbullying severity is driven by persistence, audience, context collapse,
  and group amplification, not only by insult count.

## Mathematical Roadmap

### A. Calibration First

Before any major model expansion, calibrate existing risk outputs.

Required metrics:

- Expected Calibration Error
- Brier score
- reliability diagrams by threat family
- calibration by age band and surface

Why:

- Messenger actions depend on calibrated probabilities, not only ranking.

### B. Bayesian Online Changepoint Detection

Apply BOCPD to:

- contact `rating`
- `trust_level`
- weekly hostility/support ratios
- sender timing anomalies
- response-latency changes

Best targets:

- `RoleReversal`
- `RapidWorsening`
- abrupt shift from trusted to coercive
- sudden relapse after apparent recovery

Natural home:

- [contact.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/contact.rs)
- [tracker.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/tracker.rs)

### C. Hidden Semi-Markov Models

Best targets:

- grooming progression
- coercive control progression
- self-harm motivational -> volitional transition

Why semi-Markov:

- durations matter; some states are brief escalation pivots, others are slow-burn.

Natural home:

- new sequential layer inside `context/`
- outputs still collapse into `DetectionSignal` and `RiskBreakdown`

### D. Hazard Models

Predict time-to-next-severe event:

- secrecy -> sexualization
- photo exchange -> image blackmail
- hopelessness -> acute crisis
- repeated monitoring -> coercive threat

Use case:

- short-horizon policy decisions, especially messenger warnings and contact review.

### E. Hawkes or Other Self-Exciting Processes

Best targets:

- group raid cascades
- pile-on dynamics
- self-harm contagion
- repeated hostile pinging from multiple accounts

Natural home:

- [raid.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/src/context/raid.rs)
- future group-abuse layer

### F. Conformal Abstention

When classification is uncertain:

- return a valid risk set or abstain to a safer action family
- preserve policy safety even under label ambiguity

Best use:

- self-harm vs manipulation ambiguity
- consensual sexuality vs coercive sexualization
- rough joking vs real group humiliation

## Event Ontology Expansion

Add these event candidates after ontology freeze:

- `AuthorityClaim`
- `PasswordRequest`
- `LocationSharingDemand`
- `AvailabilityDemand`
- `ReadReceiptPressure`
- `MediaMigration`
- `DisappearingMediaRequest`
- `ImageRedistributionThreat`
- `PostBreakupContact`
- `EntrapmentExpression`
- `BurdensomenessExpression`
- `BelongingnessLoss`
- `GivingAwayPossessions`
- `PublicHumiliation`
- `HumorMasking`
- `StatusThreat`
- `PeerNormPressure`
- `BystanderDefense`
- `BystanderSilence`

Do not add them all at once. Start with the ones that unlock the biggest new
risk families:

- coercive control
- action-proximate self-harm
- authority grooming
- public humiliation

## Scenario Pack Expansion

The current [simulations.rs](/Users/oleksandrmelnychenko/Aura%20Core/crates/aura-core/examples/simulations.rs) already gives a strong base. Add a second wave focused on under-covered but high-value cases.

### High-value new scenarios

- authority grooming through coach/mentor/expert framing
- fantasy-first grooming without immediate explicit sexual language
- platform migration ladder with disappearing-media pressure
- consensual teen sexting that later turns into image-based abuse
- password sharing framed as love or loyalty
- post-breakup digital omnipresence
- group humiliation disguised as jokes
- bystander rescue that should reduce risk
- burdensomeness/entrapment self-harm pathway without explicit suicide words
- contagion after another user's crisis disclosure
- friend-of-friend triangulation
- false positive controls for intense but healthy teen intimacy

### Evaluation scenarios that matter most

- lead-time before severe event
- ambiguity handling
- protective factor recovery
- trusted-contact betrayal
- multi-contact serial offender behavior
- low-grade manipulation that never becomes explicit

## Evaluation Framework

Do not optimize on final-message F1 alone.

Primary metrics:

- `lead_time_to_escalation_detection`
- `false_positive_rate_on_normative_teen_chats`
- `calibration_by_family`
- `action_appropriateness`
- `protective_factor_recovery_accuracy`
- `group_burst_detection_latency`

Dataset structure:

- event-level labels
- onset-point labels
- stage-transition labels
- severity and uncertainty labels
- negative controls that look superficially risky but are contextually normal

Review discipline:

- red-team by child-safety specialists
- clinician review for self-harm pathways
- abuse dynamics review for coercive control
- multilingual review for slang and indirect phrasing

## Product and Policy Implications

Research does not support building this as pure surveillance.

Messenger policy should prefer:

- contextual warnings
- friction at high-risk transitions
- collaborative guardian escalation where appropriate
- explanations tied to concrete signals
- softer interventions under uncertainty

Avoid:

- one global risk score for all families
- victim-vulnerability features as standalone triggers
- hard blocking under major uncertainty
- invisible policy decisions without explanation

## Sequencing

### Phase 1: Stabilize and Measure

- freeze event ontology
- freeze reason-code taxonomy
- scenario pack expansion
- calibration baselines
- lead-time metrics

### Phase 2: Add Latent Constructs

- authority grooming
- surveillance control
- burdensomeness / entrapment
- audience amplification
- bystander support

### Phase 3: Add Sequential Math

- changepoints
- hazard models
- semi-Markov progression models
- self-exciting group dynamics

### Phase 4: Policy Refinement

- uncertainty-aware actioning
- age-band calibration
- surface-aware interventions
- guardian and crisis escalation tuning

## References

- Child sexual grooming strategies scoping review:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC10914399/
- Online grooming offender pathways:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC6428127/
- Preventive intervention against online grooming of adolescents:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC10877864/
- Integrated Motivational-Volitional model review:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC6053985/
- Systematic review of online communication and self-harm/suicidality:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC12245553/
- Cyber-dating abuse in adolescents scoping review:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC12040757/
- Survival analysis of electronic coercion onset:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC7772591/
- Cyberbullying systematic map:
  https://pmc.ncbi.nlm.nih.gov/articles/PMC9996762/
- Temporal cyberbullying detection with hierarchical session modeling:
  https://dl.acm.org/doi/10.1145/3583780.3615234
- Bayesian Online Changepoint Detection:
  https://arxiv.org/abs/0710.3742
- Calibration in predictive analytics:
  https://bmcmedicine.biomedcentral.com/articles/10.1186/s12916-019-1466-7
- Privacy and autonomy in adolescence:
  https://www.nap.edu/read/5120/chapter/6
