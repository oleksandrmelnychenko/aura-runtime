# AURA System Dataflow

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Ecliptix App (Kotlin/Swift)                  │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ analyze  │  │ analyze  │  │ guardian  │  │ export / import   │  │
│  │ _context │  │ _batch   │  │ _feedback │  │ _context          │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬──────────┘  │
└───────┼──────────────┼─────────────┼─────────────────┼──────────────┘
        │ protobuf     │ protobuf    │ protobuf        │ protobuf
════════╪══════════════╪═════════════╪═════════════════╪══════════════
        ▼              ▼             ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          aura-ffi (C FFI)                           │
│                                                                     │
│  Proto decode ──► Core types ──► Analyzer ──► Proto encode          │
│                                                                     │
│  MessageInput ──────────────────► AnalysisResult                    │
│  GuardianFeedbackRequest ───────► GuardianFeedbackResponse          │
│  (empty) ───────────────────────► ExportContextResponse             │
│  ImportContextRequest ──────────► StatusResponse                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      aura-core (Analyzer)                           │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  analyze_with_context_staged()               │   │
│  │                                                             │   │
│  │  1. Rate Limiter ──────────────────────────────────── skip? │   │
│  │         │                                                   │   │
│  │         ▼                                                   │   │
│  │  2. Pattern Layer ─────────────────────────► signals[]      │   │
│  │         │                              context_events[]     │   │
│  │         ▼                                                   │   │
│  │  3. Signal Enricher ──────────────────► context_events[]    │   │
│  │         │                              (age extraction)     │   │
│  │         ▼                                                   │   │
│  │  4. ML Pipeline ──────────────────────► signals[]           │   │
│  │         │                              MlSafetyHint         │   │
│  │         │                              context_events[]     │   │
│  │         ▼                                                   │   │
│  │  5. Domain Module (Kids) ─────────────► signals[]           │   │
│  │         │  receives: MlSafetyHint      domain_action        │   │
│  │         │           server_risk_hint   context_events[]     │   │
│  │         ▼                                                   │   │
│  │  6. Context Tracker ──────────────────► context_signals[]   │   │
│  │         │  records events                                   │   │
│  │         │  updates contact profiles                         │   │
│  │         ▼                                                   │   │
│  │  7. Timing Analyzer ─────────────────► timing_signals[]     │   │
│  │         │                                                   │   │
│  │         ▼                                                   │   │
│  │  8. Contact Risk Boost ──────────────► boosted signals[]    │   │
│  │         │                                                   │   │
│  │         ▼                                                   │   │
│  │  9. Combine Signals ─────────────────► AnalysisResult       │   │
│  │         │  anchored vs context priority                     │   │
│  │         │  domain action override (upgrade only)            │   │
│  │         │  contact history escalation                       │   │
│  │         ▼                                                   │   │
│  │  10. Build Output ───────────────────► AnalysisResult       │   │
│  │         inference summary                                   │   │
│  │         product decision surface                            │   │
│  │         kids memory explainability                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## ML Pipeline Detail

```
┌─────────────────────────────────────────────────────────────────┐
│                     aura-ml (MlPipeline)                        │
│                                                                 │
│  text ──► normalize_for_ml()                                    │
│              │                                                  │
│              ▼                                                  │
│           cache.get(hash) ──── hit? ──► return cached result    │
│              │ miss                                              │
│              ▼                                                  │
│           LexiconGate                                           │
│           (Aho-Corasick)                                        │
│              │                                                  │
│              ▼ gate_score                                       │
│           CascadePolicy.decide()                                │
│              │                                                  │
│     ┌────────┴────────┐                                         │
│     │ run_deep=false  │ run_deep=true                           │
│     │ (Gate tier)     │                                         │
│     ▼                 ▼                                         │
│  gate_only()     ┌─────────────────────────┐                    │
│  (empty result)  │ Unified Model?          │                    │
│                  │  ┌─────┐    ┌────────┐  │                    │
│                  │  │ YES │    │   NO   │  │                    │
│                  │  └──┬──┘    └───┬────┘  │                    │
│                  │     ▼           ▼       │                    │
│                  │  unified     individual  │                    │
│                  │  .predict()  models:     │                    │
│                  │  ┌────────┐  toxicity    │                    │
│                  │  │8 safety│  sentiment   │                    │
│                  │  │logits  │  safety      │                    │
│                  │  └────────┘  intent      │                    │
│                  └──────┬──────────┬───────┘                    │
│                         └─────┬────┘                            │
│                               ▼                                 │
│                    ┌──────────────────────┐                     │
│                    │ apply_calibration()  │                     │
│                    │ (per-language)       │                     │
│                    └──────────┬───────────┘                     │
│                               ▼                                 │
│                    ┌──────────────────────┐                     │
│                    │ uncertainty_decision │                     │
│                    │ Low / Medium / High  │                     │
│                    │ abstain_to_guardian? │                     │
│                    └──────────┬───────────┘                     │
│                               ▼                                 │
│                          cache.insert()                         │
│                               │                                 │
│                               ▼                                 │
│                           MlResult {                            │
│                             toxicity, sentiment,                │
│                             safety, intent,                     │
│                             uncertainty, tier                   │
│                           }                                     │
└─────────────────────────────────────────────────────────────────┘

  * Kids mode: cascade BYPASSED (every message → deep inference)
  * Non-Kids: cascade gate filters ~60-70% of benign messages
```

## Kids Domain Pipeline Detail

```
┌───────────────────────────────────────────────────────────────────┐
│                  aura-kids (run_kids_pipeline)                     │
│                                                                   │
│  DomainInput { text, sender_id, conversation_id,                  │
│                ml_safety_hint, server_sender_risk_hint }          │
│      │                                                            │
│      ▼                                                            │
│  ┌─────────────────────────────────────────────┐                  │
│  │          Lexicon Detectors (×4)             │                  │
│  │  grooming ──► [lexicon.json rules]          │                  │
│  │  bullying ──► [lexicon.json rules]          │                  │
│  │  selfharm ──► [lexicon.json rules]          │                  │
│  │  manipulation ► [lexicon.json rules]        │                  │
│  │                                             │                  │
│  │  compact_for_lexical_match() handles:       │                  │
│  │    leetspeak (0→o, 3→e, @→a, $→s)          │                  │
│  │    character insertion (d.o.n.t → dont)      │                  │
│  │    case normalization                        │                  │
│  └──────────────────────┬──────────────────────┘                  │
│                         ▼                                         │
│  ┌─────────────────────────────────────────────┐                  │
│  │        Risk Amplifiers (compound)           │                  │
│  │  selfharm + manipulation + coercion → 0.98  │                  │
│  │  grooming + manipulation → 0.93             │                  │
│  │  grooming + blackmail → 0.97 (Warn)         │                  │
│  │  bullying + selfharm → 0.96 (Warn)          │                  │
│  └──────────────────────┬──────────────────────┘                  │
│                         ▼                                         │
│  ┌─────────────────────────────────────────────┐                  │
│  │     Conversation Memory Amplifiers          │                  │
│  │                                             │                  │
│  │  MessageRiskSnapshot built from:            │                  │
│  │    ├── lexicon hits (has_grooming, etc.)     │                  │
│  │    ├── ML hints ≥ 0.3 threshold             │                  │
│  │    └── ML raw scores (ml_grooming, etc.)    │                  │
│  │                                             │                  │
│  │  ┌──────────────────────────────┐           │                  │
│  │  │ Per-Conversation Memory      │           │                  │
│  │  │ (OnceLock<Mutex<HashMap>>)   │           │                  │
│  │  │ MAX: 2000 conversations      │           │                  │
│  │  │ LRU eviction by activity     │           │                  │
│  │  │                              │           │                  │
│  │  │ Detects:                     │           │                  │
│  │  │ • grooming_progression       │           │                  │
│  │  │ • sustained_sextortion       │           │                  │
│  │  │ • bullying_cascade_selfharm  │           │                  │
│  │  │ • sender_risk_accumulation   │           │                  │
│  │  │ • new_sender_fast_escalation │           │                  │
│  │  │ • victim_vulnerability       │           │                  │
│  │  └──────────────────────────────┘           │                  │
│  │                                             │                  │
│  │  ┌──────────────────────────────┐           │                  │
│  │  │ Cross-Conversation Sender    │           │                  │
│  │  │ (OnceLock<Mutex<HashMap>>)   │           │                  │
│  │  │ MAX: 4000 senders            │           │                  │
│  │  │ LRU eviction by activity     │           │                  │
│  │  │                              │           │                  │
│  │  │ Detects:                     │           │                  │
│  │  │ • repeat_offender            │           │                  │
│  │  └──────────────────────────────┘           │                  │
│  │                                             │                  │
│  │  Sender risk += ML scores * weight          │                  │
│  │  Sender risk += server_hint * 2.0           │                  │
│  └──────────────────────┬──────────────────────┘                  │
│                         ▼                                         │
│  ┌─────────────────────────────────────────────┐                  │
│  │     Guardian Escalation Check               │                  │
│  │  7 mandatory reason codes → escalate to Warn│                  │
│  └──────────────────────┬──────────────────────┘                  │
│                         ▼                                         │
│  DomainOutput { signals[], action: Option<DomainAction> }         │
└───────────────────────────────────────────────────────────────────┘
```

## Signal Priority & Merging

```
┌──────────────────────────────────────────────────────────────────┐
│                    Signal Combination                             │
│                                                                  │
│  Input: all signals from Pattern + ML + Domain + Context layers  │
│                                                                  │
│  1. Noise factor by conversation type:                           │
│     Direct: 1.0x  │  Group: 0.85x                              │
│     (Grooming/SelfHarm: min 0.93x, Threat/Doxxing: min 0.90x)   │
│                                                                  │
│  2. Layer priority:                                              │
│     ┌──────────────────────┐   ┌──────────────────┐             │
│     │ ANCHORED (trusted)   │   │ CONTEXT (lower)  │             │
│     │ • PatternMatching    │   │ • ContextAnalysis │             │
│     │ • MlClassification   │   │   (domain module) │             │
│     └──────────┬───────────┘   └────────┬─────────┘             │
│                │                         │                       │
│                ▼                         ▼                       │
│     Anchored wins UNLESS context is dramatically                 │
│     higher priority (priority + 4 > anchored)                   │
│                                                                  │
│  3. Action determination:                                        │
│     primary signal → decide_action_v2(threat, score, protection) │
│     domain override → upgrade only (never downgrade)             │
│     uncertainty → may downgrade Block → Warn                     │
│                                                                  │
│  4. Action ranks:                                                │
│     Allow(0) < Mark(1) < Blur(2) < Warn(3) < Block(4)           │
└──────────────────────────────────────────────────────────────────┘
```

## Proto Output Structure

```
AnalysisResult
├── threat_type: ThreatType
├── confidence: Low | Medium | High
├── action: Allow | Mark | Blur | Warn | Block
├── score: f32
├── explanation: String
├── detected_threats: [(ThreatType, score)]
├── signals: [DetectionSignal]
│   ├── threat_type, score, confidence
│   ├── layer: PatternMatching | MlClassification | ContextAnalysis
│   ├── family: Content | Conversation | Link | Abuse
│   └── reason_code, explanation
├── recommended_action: ActionRecommendation
│   ├── parent_alert: AlertPriority
│   ├── follow_ups: [FollowUpAction]
│   ├── crisis_resources: bool
│   └── ui_actions: [UiAction]
├── risk_breakdown: { content, conversation, link, abuse }
├── contact_snapshot: ContactSnapshot
│   ├── sender_id, rating, trust_level
│   ├── circle_tier, trend
│   └── is_trusted, is_new_contact
├── inference: InferenceSummary
│   ├── uncertainty: Low | Medium | High
│   ├── risk_horizon: Immediate | ShortTerm | Sustained
│   ├── escalation_likelihood_24h: f32
│   └── latent_states: [LatentStateEvidence]
├── product_surface: ProductDecisionSurface
│   ├── child:    { delivery_mode, visible, intervention, ui_actions }
│   ├── guardian: { delivery_mode, notify, priority, follow_ups }
│   └── review:   { delivery_mode, open_review, urgency }
└── kids_memory: KidsMemoryExplainability
    ├── reason_codes: [String]
    ├── mandatory_guardian_escalation: bool
    ├── conversation_risk_score: f32
    ├── sender_risk_score: f32
    └── escalation_message_count: u32
```

## Guardian Feedback Flow

```
App ──► aura_guardian_feedback(GuardianFeedbackRequest)
          │
          ├── TRUSTED ──► remove sender from sender_memory
          │                remove sender entries from conversation_memory
          │
          ├── BLOCK ────► inject 5 synthetic high-risk conversation markers
          │                → repeat-offender fires immediately on next message
          │
          ├── MONITOR ──► no memory change (app-layer behavior)
          │
          └── FALSE_POSITIVE ► remove conversation from conversation_memory
```

## Export / Import Flow

```
EXPORT:
  aura_export_context()
    ├── context_tracker.export_wire_state()
    │   ├── conversation timelines (events per conversation)
    │   └── contact profiler (per-sender profiles)
    └── aura_kids::export_kids_memory()
        ├── conversation memory (risk snapshots + ML scores)
        └── sender memory (cross-conversation risk)

IMPORT:
  aura_import_context(TrackerState)
    ├── kids_memory_state_from_proto()
    │   └── aura_kids::import_kids_memory()
    │       ├── restore conversation memory (LRU indices preserved)
    │       └── restore sender memory (activity indices preserved)
    └── context_tracker.import_wire_state()
        ├── merge conversation timelines
        └── merge contact profiles
```
