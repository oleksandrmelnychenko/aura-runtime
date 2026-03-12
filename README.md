# AURA Core

AURA Core is a messenger-native trust and safety runtime for child and teen protection. It combines per-message moderation with stateful conversation analysis, contact profiling, policy actions, and evidence-driven evaluation.

Current product direction is narrow on purpose:

- Messenger-only safety runtime
- Protobuf-only wire contract
- Rust domain model inside the core
- C ABI at the boundary
- Evaluation-first stabilization before any broader product expansion

## Current State

- **Messenger-native runtime**: content, conversation, link, and abuse signals are combined into one analysis result
- **Stateful context engine**: timelines, contact profiles, trust decay, weekly snapshots, and behavioral trend detection
- **Messenger policy layer**: `UiAction` outputs such as warn, blur, report, block, crisis support, guardian escalation
- **3 languages**: English, Ukrainian, Russian, including slang, shorthand, and noisy chat normalization
- **Protobuf-only FFI**: stable C ABI over encoded bytes via `AuraBuffer`
- **Evaluation stack**: canonical scenarios, manipulation track, multilingual, noisy/slang, robustness, corpus-style, social-context, realistic curated, and external curated suites
- **679 Rust tests** across the workspace, all green

## Key Capabilities

- **3-layer analysis pipeline**: pattern matching, ML classification, context analysis
- **46 event types** across grooming, bullying, manipulation, self-harm, coercion, abuse, and protective signals
- **7 context detectors**: grooming, bullying, manipulation, self-harm, coercion, raid, timing
- **20 enricher categories**: PII, probing, screenshot blackmail, suicide coercion, false consensus, debt leverage, platform migration, identity erosion, network poisoning, and more
- **Contact intelligence**: rating, trust level, circle tier, behavioral trend, shift signals
- **Messenger policy actions**: `WarnBeforeSend`, `WarnBeforeDisplay`, `BlurUntilTap`, `ConfirmBeforeOpenLink`, `SuggestBlockContact`, `SuggestReport`, `RestrictUnknownContact`, `SlowDownConversation`, `ShowCrisisSupport`, `EscalateToGuardian`
- **Robustness layers**: mixed-language chats, slang, typos, shorthand, social-context slices, realistic curated corpora

## Architecture

```text
aura-core       Analyzer, action engine, context engine, evaluation stack
aura-patterns   Pattern matching, boundary-safe matcher, normalizer, URL checker, emoji signals
aura-ml         Toxicity + sentiment (rule-based fallback, optional ONNX)
aura-proto      Protobuf contracts for messenger runtime and FFI
aura-ffi        Protobuf-only C ABI for mobile and desktop clients
```

### Runtime Flow

```text
Message / Event
    │
    ├─ Layer 1: Pattern matching
    │   ├─ keyword + phrase matcher
    │   ├─ URL safety
    │   ├─ text normalization
    │   └─ emoji threat signals
    │
    ├─ Layer 2: ML classification
    │   └─ toxicity + sentiment
    │
    └─ Layer 3: Context analysis
        ├─ signal enricher
        ├─ grooming
        ├─ bullying
        ├─ manipulation
        ├─ self-harm
        ├─ coercion
        ├─ raid
        ├─ timing
        └─ contact profiler
```

### Core Runtime Outputs

`AnalysisResult` is messenger-oriented rather than model-oriented. It includes:

- primary threat summary
- detected threats and scores
- `risk_breakdown` across `content`, `conversation`, `link`, `abuse`
- `contact_snapshot`
- `reason_codes`
- `ui_actions`
- inference summary for uncertainty, horizon, escalation likelihood, latent states

## Context and Psychology

### Context Detectors

| Detector | What it catches |
| --- | --- |
| Grooming | trust building, secrecy, platform migration, dependency, staged escalation |
| Bullying | sustained harassment, isolation, pile-on, bystander silence |
| Manipulation | gaslighting, DARVO, love-bomb/devalue, emotional blackmail, screenshot/reputation threats |
| Self-Harm | hopelessness, ideation, farewell, contagion, protective signals |
| Coercion | suicide coercion, debt leverage, reputation blackmail, combined tactics |
| Raid | many hostile senders in a short window |
| Timing | late-night contact, response asymmetry, message bombing, rapid attachment |

### Contact Profiling

Per-contact state includes:

- rating `0..100`
- trust `0.0..1.0`
- circle tier
- weekly snapshots
- behavioral trend
- shift signals such as `RoleReversal` and `RapidWorsening`

This is one of the main differentiators of AURA: it reasons over contact behavior over time, not only over isolated messages.

## Evaluation Stack

AURA now has multiple evaluation layers, each targeting a different failure mode.

### Scenario Suites

- **Canonical messenger pack**: baseline child-safety scenarios
- **Manipulation pack**: gaslighting, coercive control, blackmail, DARVO
- **Multilingual pack**: EN/UK/RU and mixed-language transitions
- **Noisy/slang pack**: shorthand, typos, teen chat noise

### Robustness and Corpus Layers

- **Robustness profiles**: teen shorthand profiles by language
- **Corpus-style suite**: style-mutated variants from data banks
- **Social-context suite**: cohorts such as trusted adult, peer intimacy, group pressure, support boundary
- **Realistic curated suite**: more natural messenger-like chats with support-aware slice gates
- **External curated suite**: provenance-aware dataset contract with manifest metadata and reviewer-oriented ingestion

### Policy Evaluation

Detection is not enough. AURA also gates policy quality:

- required actions must appear for risky cases
- forbidden actions must not appear for safe or mismatched cases
- onset-aware policy checks verify that critical actions happen by escalation time

### Examples

You can run the evaluation layers directly:

```bash
cargo run --example scenario_eval -p aura-core
cargo run --example manipulation_eval -p aura-core
cargo run --example multilingual_eval -p aura-core
cargo run --example noisy_eval -p aura-core
cargo run --example robustness_eval -p aura-core
cargo run --example corpus_eval -p aura-core
cargo run --example social_context_eval -p aura-core
cargo run --example realistic_eval -p aura-core
cargo run --example external_curated_eval -p aura-core
```

## Test Coverage

**679 Rust tests** across the workspace:

| Crate | Tests | Focus |
| --- | ---: | --- |
| `aura-core` | 481 | detectors, analyzer, contact profiler, tracker, evaluation, scenarios, policy |
| `aura-ffi` | 19 | protobuf-only C ABI, errors, context import/export, batch processing |
| `aura-ml` | 113 | toxicity, sentiment, tokenization, boundary logic |
| `aura-patterns` | 66 | matcher, normalizer, URL checker, emoji signals |
| `aura-proto` | 0 | generated protobuf contract crate |

Coverage areas include:

- unit tests for each detector and event family
- integration tests for end-to-end analyzer behavior
- property/stress tests for contact rating and tracker behavior
- multilingual and noisy-language regressions
- policy-action gates
- realistic and external curated evaluation suites

## Build

```bash
cargo build
cargo test --workspace
```

Optional ONNX path:

```bash
brew install onnxruntime
cargo test --all-features --workspace
```

## Usage (Rust)

```rust
use aura_core::{Analyzer, AuraConfig, ContentType, MessageInput};
use aura_patterns::PatternDatabase;

let config = AuraConfig::default();
let patterns = PatternDatabase::default_mvp();
let analyzer = Analyzer::new(config, &patterns);

let input = MessageInput {
    content_type: ContentType::Text,
    text: Some("Hello".into()),
    image_data: None,
    sender_id: "user_1".into(),
    conversation_id: "conv_1".into(),
    language: None,
    conversation_type: Default::default(),
    member_count: None,
};

let result = analyzer.analyze(&input);
```

## FFI (C ABI)

Public header: `include/aura_ffi.h`

- Wire format is **protobuf only**
- Requests and responses are encoded byte buffers
- `AuraBuffer` is the output transport type
- `aura_last_error()` is the only string-based error channel

Main functions:

- `aura_init`
- `aura_analyze`
- `aura_analyze_context`
- `aura_analyze_batch`
- `aura_update_config`
- `aura_reload_patterns`
- `aura_export_context`
- `aura_import_context`
- `aura_cleanup_context`
- `aura_get_contacts_by_risk`
- `aura_get_contact_profile`
- `aura_mark_contact_trusted`
- `aura_get_conversation_summary`
- `aura_free`
- `aura_free_buffer`
- `aura_free_string`

Context export/import now uses native protobuf tracker/contact state end-to-end.

## Data Artifacts

The evaluation stack is data-driven. Important artifacts currently include:

- `crates/aura-patterns/data/patterns_mvp.json`
- `crates/aura-core/data/corpus_style_profiles.json`
- `crates/aura-core/data/corpus_curated_cases.json`
- `crates/aura-core/data/social_context_cohorts.json`
- `crates/aura-core/data/realistic_chat_cases.json`
- `crates/aura-core/data/external_curated_chat_cases.json`

The external curated corpus now carries manifest metadata:

- `schema_version`
- `dataset_id`
- `dataset_label`
- `curation_status`
- `maintainer`
- `created_at_ms`
- `updated_at_ms`

This is the contract intended for future reviewer-curated external datasets.

## How To Move Forward

The next steps should stay focused on stabilizing **one strong v1**, not adding unrelated product layers.

### Phase 1: Gold-Reviewed Corpus

- Add a second external corpus tier: `gold_reviewed` / `human_curated`
- Keep the current external manifest contract, but feed it real reviewer-curated excerpts
- Introduce stronger gates for `gold_reviewed` than for `seed_reviewed`

### Phase 2: Calibration Discipline

- Add per-language, per-age-band, and per-threat calibration reports
- Split stronger gates for `child`, `trusted_adult`, `support boundary`, and `group pressure`
- Track calibration drift between canonical, realistic, and external corpora

### Phase 3: Psychological Modeling

- Expand latent psychological state tracking
- Separate self-harm ideation from attempt-proximity logic more explicitly
- Improve coercive-control and reputation/image-abuse pathways
- Preserve protective-factor reasoning, not only threat accumulation

### Phase 4: Mathematical Upgrades

After the corpus and evaluation base is strong enough:

- changepoint detection over contact time series
- better uncertainty and abstention handling
- escalation / hazard modeling
- stronger family-specific calibration instead of global tuning

### Phase 5: Release Discipline

Before calling anything stable:

- protobuf contract stable
- policy gates stable
- realistic and external curated suites green
- regression packs green across EN/UK/RU
- no reliance on synthetic-only confidence

## Boundaries

What AURA Core is:

- contextual safety runtime
- messenger policy engine
- evidence-driven safety infrastructure

What AURA Core is not:

- generic moderation SDK for the whole internet
- AI friend / companion runtime
- engagement product

If an AI companion ever exists, it should be a separate layer on top of AURA, not part of the safety-critical core.

## Data and Privacy

- analysis runs in-process
- no external network calls by default
- optional ONNX models are local
- context state can be exported/imported, so storage and logging need explicit privacy rules

For child-safety use cases, privacy and explainability should be treated as product requirements, not optional polish.

## License

Proprietary — Ecliptix.
