# AURA Core

Intelligent protection system for Ecliptix Messenger: content moderation, threat detection (grooming, bullying, manipulation, self-harm), and context-aware analysis.

## Architecture

- **aura-core** — Orchestration: `Analyzer`, action engine, context (grooming, bullying, manipulation, self-harm, raid, timing), config.
- **aura-patterns** — Pattern matching, emoji threats, text normalizer, URL checker.
- **aura-ml** — ML pipeline: toxicity and sentiment (rule-based fallback + optional ONNX).
- **aura-ffi** — C API for Android NDK, iOS, desktop.

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
- Context state (timelines, contact profiles) can be exported/imported; do not persist or log it without user consent and a clear privacy policy.
- No data is sent to external services by default; optional ONNX models are loaded from local paths.

## License

Proprietary — Ecliptix.
