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
cargo test
```

With ONNX (optional):

```bash
cargo build --features onnx -p aura-ml
cargo test --features onnx -p aura-ml
```

Requires ONNX Runtime library (`libonnxruntime.dylib` / `.so` / `.dll`) for ONNX tests.

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

- **Create:** `aura_init(config_json)` → handle (or null).
- **Analyse:** `aura_analyze(handle, text, sender_id, conversation_id)` or `aura_analyze_json(handle, message_json)` → JSON string; caller must call **`aura_free_string`** on the returned pointer.
- **Context:** `aura_analyze_context(handle, message_json, timestamp_ms)` for stateful analysis.
- **Cleanup:** **`aura_free(handle)`** when done; **`aura_free_string(ptr)`** for every string returned by the API.

All returned strings are UTF-8. Invalid UTF-8 or null pointers return error JSON. Do not pass arbitrary unbounded input length; enforce limits on the caller side if needed.

## Data and privacy

- Analysis runs in-process; message text, `sender_id`, and `conversation_id` are kept in memory only for the duration of context windows (configurable).
- Context state (timelines, contact profiles) can be exported/imported; do not persist or log it without user consent and a clear privacy policy.
- No data is sent to external services by default; optional ONNX models are loaded from local paths.

## License

Proprietary — Ecliptix.
