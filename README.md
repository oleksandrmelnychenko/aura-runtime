# AURA Core

Intelligent protection system for Ecliptix Messenger: content moderation, threat detection (grooming, bullying, manipulation, self-harm, coercion, sextortion), context-aware analysis, and longitudinal behavioral profiling.

## Key Capabilities

- **3-Layer Analysis Pipeline**: Pattern matching (<1ms) + ML classification (5-20ms) + Context analysis
- **37 Event Types**: From flattery to suicide coercion, identity erosion, network poisoning
- **7 Context Detectors**: Grooming (6 stages), Bullying, Manipulation, Self-Harm, Coercion, Raid, Timing
- **Contact Rating System**: Per-contact score (0-100) with trust decay, social circles, weekly snapshots
- **Behavioral Trend Detection**: Stable, Improving, GradualWorsening, RapidWorsening, RoleReversal
- **18 Signal Enricher Categories**: PII self-disclosure, dare/challenge, screenshot blackmail, advanced psychological manipulation
- **3 Languages**: English, Ukrainian, Russian (including teen slang)
- **577 Tests**, 0 warnings

## Architecture

```
aura-core       Orchestration: Analyzer, Action Engine, Context Engine
aura-patterns   Pattern matching, emoji threats, text normalizer, URL checker
aura-ml         ML pipeline: toxicity + sentiment (rule-based fallback + optional ONNX)
aura-ffi        C API for Android NDK, iOS, desktop
```

### Context Engine

| Detector | What it catches |
|----------|----------------|
| Grooming | 6-stage progression: Trust Building → Isolation → Boundary Testing → Sexual Escalation → Financial Dependency → Meeting |
| Bullying | Sustained harassment, target isolation, pile-on, bystander silence |
| Manipulation | Gaslighting, DARVO, love-bomb/devalue cycle, emotional blackmail |
| Self-Harm | Suicidal ideation, hopelessness, farewell messages, contagion patterns |
| Coercion | Suicide coercion, reputation blackmail, debt leverage, combined tactics |
| Contact Profiler | Rating (0-100), trust decay, social circles, behavioral trend detection, shift signals |
| Timing | Response asymmetry, late-night messaging, message frequency |

### Contact Rating & Behavioral Profiling (Novel)

No commercial product (Bark, Qustodio, Thorn) or academic paper implements per-contact longitudinal behavioral shift detection. AURA is first.

- **Rating**: 0-100 per contact, event-driven updates, clamped
- **Trust**: Graduated 0.0-1.0, decays on hostile events (severity * 0.15 per event)
- **Social Circles**: Inner (daily) / Regular (weekly) / Occasional / New (<14 days)
- **Weekly Snapshots**: 26-week rolling window (~1.3KB per contact)
- **Trend Detection**: Compares baseline (first half) vs recent (last 2 weeks)
- **Shift Signals**: RoleReversal (friend→bully), RapidWorsening, GradualWorsening generate DetectionSignals
- **State**: Schema v2, backward-compatible with v1

## Build

```bash
cargo build
cargo test --workspace
```

With ONNX (optional):

```bash
brew install onnxruntime   # macOS
cargo test --all-features --workspace
```

ONNX Runtime path is configured in `.cargo/config.toml` for macOS (Homebrew).

## Usage (Rust)

```rust
use aura_core::{Analyzer, AuraConfig};
use aura_patterns::PatternDatabase;

let config = AuraConfig::default();
let db = PatternDatabase::default_mvp();
let analyzer = Analyzer::new(config, &db);

let input = aura_core::MessageInput {
    content_type: aura_core::ContentType::Text,
    text: Some("Hello".into()),
    image_data: None,
    sender_id: "user_1".into(),
    conversation_id: "conv_1".into(),
    language: None,
};

let result = analyzer.analyze(&input);
```

## FFI (C / Kotlin / Swift)

- **Create:** `aura_init(config_json)` → handle (or null; check `aura_last_error()`).
- **Analyse:** `aura_analyze(handle, text, sender_id, conversation_id)` or `aura_analyze_json(handle, message_json)` → JSON string.
- **Context:** `aura_analyze_context(handle, message_json, timestamp_ms)` for stateful analysis.
- **Batch:** `aura_analyze_batch(handle, messages_json)` — up to 1000 messages.
- **Config:** `aura_update_config(handle, config_json)` — update at runtime.
- **Patterns:** `aura_reload_patterns(handle, json)` — hot-reload pattern database.
- **Errors:** `aura_last_error()` — thread-local last error string (or null).
- **Cleanup:** **`aura_free(handle)`** when done; **`aura_free_string(ptr)`** for every string returned by the API.

Text is truncated at 10,000 chars internally. All returned strings are UTF-8. Invalid UTF-8 or null pointers return error JSON with structured error codes.

## Data and privacy

- Analysis runs in-process; message text, `sender_id`, and `conversation_id` are kept in memory only for the duration of context windows (configurable).
- Context state (timelines, contact profiles, ratings, behavioral snapshots) can be exported/imported; do not persist or log it without user consent and a clear privacy policy.
- No data is sent to external services by default; optional ONNX models are loaded from local paths.

## License

Proprietary — Ecliptix.
