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
- **Inference-aware messenger policy layer**: `UiAction` outputs are refined by risk horizon, escalation likelihood, and latent psychological states
- **3 languages**: English, Ukrainian, Russian, including slang, shorthand, and noisy chat normalization
- **Protobuf-only FFI**: stable C ABI over encoded bytes via `AuraBuffer`
- **Production release discipline**: persisted release, contract, dataset, audit, FFI smoke, and FFI soak artifacts are aggregated into one machine-readable evidence manifest
- **Boundary hardening**: size-bounded protobuf decode, atomic failure on malformed batch inputs, bounded contact-profile memory, and panic-free FFI behavior from the caller's perspective
- **Pattern and link hardening**: strict pattern-database validation, fail-closed regex loading, and IDN-aware URL normalization
- **Privacy-safe audit path**: structured audit records keep reasons and actions while tokenizing identifiers under a declared salted scheme
- **Evaluation stack**: canonical scenarios, manipulation track, multilingual, noisy/slang, robustness, corpus-style, social-context, realistic curated, and external curated mixed/gold suites
- **Green verification path**: `cargo test --workspace --all-targets --all-features` is the default workspace gate used locally and in CI

## Key Capabilities

- **3-layer analysis pipeline**: pattern matching, ML classification, context analysis
- **46 event types** across grooming, bullying, manipulation, self-harm, coercion, abuse, and protective signals
- **7 context detectors**: grooming, bullying, manipulation, self-harm, coercion, raid, timing
- **20 enricher categories**: PII, probing, screenshot blackmail, suicide coercion, false consensus, debt leverage, platform migration, identity erosion, network poisoning, and more
- **Contact intelligence**: rating, trust level, circle tier, behavioral trend, shift signals
- **Messenger policy actions**: `WarnBeforeSend`, `WarnBeforeDisplay`, `BlurUntilTap`, `ConfirmBeforeOpenLink`, `SuggestBlockContact`, `SuggestReport`, `RestrictUnknownContact`, `SlowDownConversation`, `ShowCrisisSupport`, `EscalateToGuardian`
- **Inference-aware refinement**: policy is adjusted by uncertainty, risk horizon, escalation likelihood, protective factors, and latent states such as coercive control or crisis vulnerability
- **Robustness layers**: mixed-language chats, slang, typos, shorthand, social-context slices, realistic curated corpora

## Architecture

```text
aura-core       Analyzer, action engine, context engine, evaluation stack
aura-patterns   Pattern matching, strict rule validation, normalizer, IDN-aware URL checker, emoji signals
aura-ml         Toxicity + sentiment (fallback + optional local ONNX runtime)
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
- `inference` summary for uncertainty, horizon, escalation likelihood, protective-factor strength, and latent states

That inference summary is active policy input, not passive metadata. Immediate self-harm, coercive-control escalation, and group-escalation pathways now refine `UiAction`, `parent_alert`, and short-horizon intervention behavior.

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
- **External curated suite**: provenance-aware dataset contract with manifest metadata, tiered review quality (`seed_reviewed` / `gold_reviewed` / `mixed_review_tiers`), manifest-aware quality gates, and a derived gold-only suite with stricter thresholds

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

`external_curated_eval` prints both the mixed manifest run and the derived gold-only run.

## Verification

The default production-oriented verification path is:

```bash
cargo build --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
```

Coverage areas include:

- unit tests for each detector and event family
- integration tests for end-to-end analyzer behavior
- property/stress tests for contact rating and tracker behavior
- multilingual and noisy-language regressions
- policy-action gates
- inference-aware policy refinement gates
- realistic and external curated evaluation suites
- protobuf wire-compat fixtures for key messages
- FFI invalid-input, request-limit, export/import, and state-sync stress coverage
- artifact-level release, contract, dataset, and audit evidence generation

## Build

Optional ONNX path:

```bash
brew install onnxruntime
python scripts/download_models.py
AURA_REQUIRE_ONNX_MODELS=1 cargo test --workspace --all-targets --all-features
```

If models are not present, the ONNX integration tests skip by default so a
clean checkout still has a reproducible full-workspace verification path:

```bash
cargo test --workspace --all-targets --all-features
```

Current CI automation uses the same all-targets/all-features build and test
path in both `Rust` and `Promotion Gate` workflows.

Local promotion rehearsal:

```bash
python ci/run_promotion_rehearsal.py --target staging
```

This writes a full local evidence bundle under `artifacts/promotion-rehearsal/`.
If no C compiler is installed locally, the rehearsal records a clearly labeled
`ffi_smoke` stub, the manifest will not go green locally, and the real compile
is left to GitHub Actions on `ubuntu-latest`.

## Release Discipline

Promotion is driven by machine-readable evidence, not by manually reading
example output. The current release bundle includes:

- release report (`schema_version = 3`)
- contract evidence for protobuf, ABI, request limits, and state schema
- dataset evidence with coverage snapshot and changelog linkage
- audit evidence proving forbidden plaintext fields are absent
- FFI header smoke evidence
- FFI state-sync soak evidence
- unified evidence manifest (`aura.evidence_manifest.v1`)

Default workflow entrypoints:

```bash
cargo run --quiet --example release_report -p aura-core -- --output artifacts/release-report.json --require-pass
cargo run --quiet --example contract_evidence -p aura-core -- --output artifacts/contract-evidence.json
python ci/generate_dataset_evidence.py --output artifacts/dataset-evidence.json
cargo run --quiet --example audit_evidence -p aura-core -- --output artifacts/audit-evidence.json
python ci/run_ffi_soak.py --output artifacts/ffi-state-sync-soak.json --iterations 2 --label local-check
python ci/generate_evidence_manifest.py --output artifacts/evidence-manifest.json --label local-check --release-report artifacts/release-report.json --contract-evidence artifacts/contract-evidence.json --dataset-evidence artifacts/dataset-evidence.json --audit-evidence artifacts/audit-evidence.json --ffi-soak artifacts/ffi-state-sync-soak.json --ffi-smoke artifacts/ffi-header-smoke.json
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
- `aura_version`
- `aura_last_error`
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
- `crates/aura-core/data/dataset_changelog.json`

The external curated corpus carries manifest metadata and tiered review quality:

- `schema_version`
- `dataset_id`
- `dataset_label`
- `curation_status` (`seed_reviewed` | `gold_reviewed` | `mixed_review_tiers`)
- `maintainer`
- `created_at_ms`
- `updated_at_ms`

Each case has an independent `review_status`. Gold-reviewed cases are held to stricter quality gates (lower Brier score, tighter calibration, higher detection rate, lower false positive rate). Mixed corpora validate consistency between corpus-level `curation_status` and per-case `review_status`.

The built-in external artifact is currently a mixed review corpus. From that manifest, AURA can derive a gold-only bundle and run the stricter external suite without changing the contract.

The current corpus snapshot, coverage counts, and changelog linkage are tracked
in [`docs/dataset-governance.md`](docs/dataset-governance.md) and the
machine-readable dataset evidence artifact.

## Roadmap Status

The release-hardening track for **Phase 2** is operational. The codebase now
has support-aware release reports, persisted evidence artifacts, compatibility
proofs, privacy-safe audit evidence, and promotion automation.

### Phase 1: Gold-Reviewed Corpus — Done

- Two review tiers: `seed_reviewed` and `gold_reviewed`
- Stricter quality gates for gold-reviewed cases (Brier <= 0.20, ECE <= 0.15, detection >= 90%, FPR <= 3%)
- Mixed corpus mode (`mixed_review_tiers`) with per-slice gate adaptation
- Validation enforces consistency between corpus-level `curation_status` and per-case `review_status`
- Gold-only suite can be run independently with `run_external_curated_gold_suite`

### Phase 2: Production-Oriented Calibration Discipline — Operational

- Structured release report with `PASS`, `FAIL`, `INSUFFICIENT_SUPPORT`, and `BLOCKED`
- Drift comparisons across canonical, realistic, and external corpora
- Mixed-vs-gold external comparison as a real release signal
- CI and promotion bundles with release, contract, dataset, audit, smoke, and soak evidence
- Stable protobuf/ABI/state version stamping and request-limit evidence
- Privacy-safe audit schema with tokenized identifiers and forbidden-field checks
- Dataset governance with coverage snapshots and changelog discipline

### Next Major Focus: Phase 3 Core Policy and Psychological Modeling

- Expand latent psychological state tracking
- Separate self-harm ideation from attempt-proximity logic more explicitly
- Improve coercive-control and reputation/image-abuse pathways
- Preserve protective-factor reasoning, not only threat accumulation
- Extend inference-aware policy beyond `ui_actions` into `parent_alert` and `follow_ups`, especially for trusted-adult boundary and supportive self-harm boundary cases

### Phase 4: Mathematical Upgrades

After policy and psychological pathways are stronger:

- changepoint detection over contact time series
- better uncertainty and abstention handling
- escalation / hazard modeling
- stronger family-specific calibration instead of global tuning

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
- routine audit identifiers are tokenized under a declared salted scheme rather than logged in plaintext
- release and promotion paths include explicit audit evidence that forbidden plaintext fields are absent

For child-safety use cases, privacy and explainability should be treated as product requirements, not optional polish.

## Planning and Operations

Production-oriented stabilization docs now live in [`docs/README.md`](docs/README.md).
The main closeout and handoff document for the release-hardening track is
[`docs/phase-2-production-roadmap.md`](docs/phase-2-production-roadmap.md).

## License

Proprietary — Ecliptix.
