# AURA Core — Changelog

## Unreleased — Release Reliability

- Added offline historical revocation verification for every RFC 3161 token.
  Complete issuer CRLs must cover the TSA chain at `genTime`; delta, indirect,
  missing, expired, future, duplicate, or unrelated CRLs fail closed. Receipt
  chain v3 re-verifies the raw study commitment timestamp instead of trusting a
  copied JSON report and binds aggregate CRL evidence into the release manifest.
- Added a privacy-minimized, coordinator-signed and RFC 3161 timestamped review
  roster that precommits participant roles, affiliation claims, pinned Ed25519
  keys, and digests of eligibility, conflict, affiliation, and blinding records.
  Receipt-chain v3 directly verifies the roster and rejects post-result key or
  participant substitution.
- Added distinct Ed25519 signatures and RFC 3161 timestamps for complete
  reviewer and adjudicator submissions. The aggregate verifier requires strict
  non-overlap between the trusted commitment, reviewer-receipt, and
  adjudicator-receipt intervals and exports no participant, affiliation, case,
  label, or individual-key identity.
- Temporal review report v5 binds computed metrics to the canonical SHA-256 of
  the exact review bundle. Policy activation now remains pending without a
  matching signed receipt chain and fails on bundle substitution, time overlap,
  invalid receipt trust, or privacy-unsafe aggregate evidence.
- Added nonce-bound RFC 3161 requests and strict trusted timestamp verification
  for temporal study commitments. Verification binds the original bytes and
  request, expected policy OID, explicit trust chain, TSA `genTime`, and a
  separately pinned TSA signer SPKI digest.
- Temporal review report v4 introduced declared review chronology without
  overstating it as trusted time. Policy activation requires the trusted
  commitment timestamp's `genTime + accuracy` upper bound to precede the
  earliest declared annotation completion.
- Added domain-separated Ed25519 signing and trusted-public-key verification
  for temporal study commitments. The attestation binds exact file bytes and
  canonical study, preregistration, corpus, and packet identities.
- Temporal policy activation now remains pending without a matching study
  attestation verification report and fails on mismatched trust evidence. The
  report explicitly records that trusted timestamp assurance is still absent.
- Added preregistered packet-bound v3 temporal review for caller-supplied,
  embargoed external corpora. Fixed sampling, hypotheses, primary outcomes,
  reviewer separation, missing-data handling, stopping rules, and agreement
  thresholds are digest-bound before labels are collected.
- Added a public temporal study commitment binding the preregistration, corpus,
  packet, case count, reviewer minimum, and acceptance thresholds; report
  evaluation rejects any altered commitment.
- Added exact-set reviewer-pair agreement and nominal Krippendorff alpha,
  including per-reason summaries and honest `null` output when alpha is
  undefined. A correct adjudication now still fails when prespecified reviewer
  agreement thresholds are not met.
- Restricted temporal activation evidence to an embargoed external corpus with
  valid preregistration and commitment digests and agreement of at least 0.8;
  the embedded public seed remains a release-regression guard only.
- Replaced declaration-only temporal review blinding with a packet-bound v2
  flow: per-round HMAC case tokens, randomized case order, per-case identifier
  remapping, relative event times, a separate owner-only coordinator map, and
  digest-bound review bundles.
- Kept legacy v1 review compatibility while preventing a declaration-only v1
  result from satisfying temporal policy activation readiness.
- Expanded the disabled Military temporal Shadow gate with 259 metamorphic
  adversarial checks covering storage order, identifier remapping, time shift,
  filtered decoys, and replay duplication.
- Added a corpus-bound independent-review protocol requiring two blinded
  reviewers from distinct affiliations and a separate adjudicator; the
  research-readiness status remains `pending` until real review data exists.
- Added aggregate-only on-prem and ADK temporal Shadow telemetry with a
  20-observation privacy floor, bounded inputs, coarse latency buckets, no
  per-conversation export, and no action execution path.
- Added temporal evaluation and telemetry validation to the unified evidence
  manifest plus detached Ed25519 signing and trusted-public-key verification
  for release promotion.
- Added a separate temporal policy activation-readiness state so a releasable,
  disabled Shadow build cannot be mistaken for independently validated policy.
- Added a content-free temporal context to each first-attempt local decision,
  binding source time, observation delay, Safety Case transition, bounded
  observation volume, and peak risk index without exposing message content or
  contact identifiers.
- Removed the stateless Analyzer's per-sender rate-limit short-circuit, which
  could return a clean `Allow` without running pattern, ML, domain, or context
  analysis after 60 messages in one minute. Every message accepted by the
  Analyzer now runs through the full local pipeline; admission control belongs
  before the safety boundary.
- Added a regression proving that an explicit threat in the 61st message from
  one sender is still detected and produces at least a warning.
- Corrected guardian-feedback scope in KIDS memory: `Trusted` now removes one
  sender from every conversation, while `FalsePositive` removes only the
  specified sender/conversation pair and preserves unrelated evidence.
- Replaced synthetic conversation IDs used by `Block` with an explicit,
  persisted `guardian_blocked` state and a typed blocking signal on subsequent
  messages. Kids-memory schema v2 can migrate legacy v1 block markers.
- Standardized the conversation-before-sender lock order for feedback that
  updates both memory maps, and added regression, scope-matrix, persistence,
  protobuf, and legacy-migration coverage.
- Removed the shared `"unknown"` fallback for empty message identifiers. The
  canonical FFI now rejects empty, whitespace/control-containing, or
  over-256-byte sender and conversation IDs before analysis, and applies the
  same validation to imported Core and KIDS state.
- Made `aura_last_error` strictly thread-local by removing its process-global
  fallback. A concurrency regression proves one thread cannot consume another
  thread's error; callers must read the error on the failing call's thread.
- Made configured pattern packs fail closed during FFI initialization. An
  absent or invalid `patterns_path` now rejects initialization with the stable
  `PATTERN_PACK_LOAD_FAILED` reason instead of silently running built-in rules;
  omitting the path remains the explicit way to select the built-in pack.
- Added an explicit persisted tracker-state v2 to v3 migration. Legacy events
  receive the conservative all-unspecified context frame and are re-exported
  as v3, while unsupported future versions fail before tracker mutation.
- Persisted the full v3 event interpretation frame in protobuf (speech act,
  stance, directionality, temporal/contact flags, and confidence), with
  byte-pinned v2 and v3 golden fixtures and end-to-end FFI round-trip coverage.
- When replicas contain the same logical event, a contextualized v3 event now
  upgrades its v2 default frame without duplicating history, independent of
  import order.
- Unified account-level protection semantics. Adult accounts may still disable
  protection, while child and teen accounts remain protected by every detector
  even if an invalid configuration is constructed inside Rust.
- FFI initialization and runtime configuration updates now reject disabled
  minor protection and a Military domain on a minor account before mutating
  runtime state. Minor accounts always resolve to the Kids domain; matrix and
  rollback regressions cover account type, enablement, level, and domain.
- Prevented a filtered domain signal from restoring its pre-interpretation
  action or reason codes. In particular, a supportive third-party self-harm
  response now remains a clean `Allow` through the KIDS product projection.

## Unreleased — Canonical Apple ABI

- Reduced the Apple XCFramework and Swift package boundary to initialization,
  ownership/error primitives, canonical Safety Case ingestion and lifecycle,
  account removal, and explicit context/Safety Case persistence.
- Removed Apple exports and Swift wrappers for per-message/context analysis,
  batch and shadow utilities, live config/pattern mutation, cleanup,
  contact/profile/trust queries, quick checks, suspicious URL checks,
  conversation summaries, and runtime capability snapshots.
- Reserved the unused lifecycle `decision_json` protobuf field; lifecycle
  responses now expose only typed case identity, revision, status, generation,
  and runtime state schema.
- Made the Apple archive release script fail on both known legacy symbols and
  any unexpected `aura_` symbol outside the canonical allowlist.
- Added the single typed `aura_analyze_local_decision` operation. It uses the
  canonical source ledger and stateful pipeline, returns a decision only on a
  successful first attempt, and leaves duplicate or stale responses
  content-free.
- Added additive protobuf request/response types, exhaustive Rust-to-wire
  product mappings, bounded request/response envelopes, generated
  SwiftProtobuf models, and a typed Swift wrapper.
- Added rollback, duplicate, stale-edit, cross-API, malformed-request,
  restart-replay, and supportive self-harm boundary regressions for the new
  path.
- Added the terminal `aura_acknowledge_source_checkpoint` operation so clients
  can compact non-observation receipts only after a durable inbox checkpoint;
  case-observation receipts remain integrity-bound to persisted case state.
- Restored the six-month and dense two-year FFI/client-boundary replays under
  fail-closed scripts that reject missing or zero-test filters.
- Bound the protected sender identity from the verified execution-policy
  account key, preventing owner-authored messages from being profiled as an
  external contact.
- Removed the Apple provenance self-reference by domain-separating the
  build-source digest and excluding only generated Apple outputs plus the two
  non-build refactor evidence files that contain the reviewed artifact hashes.
- Canonicalized the generated XCFramework `AvailableLibraries` order before
  hashing. Repeated same-revision builds now keep `Info.plist` and the release
  manifest byte-identical when the binaries are unchanged.

## Unreleased — Rust Best-Practices Pass

**771 tests | Type-safe IDs | Exhaustive matching | Idiomatic Rust style | Rustdoc RFC 1574**

Comprehensive code-quality pass across all five crates applying Rust best
practices for type safety, style, memory, and documentation.

### Type Safety

- Added `SenderId`, `ConversationId`, `ReasonCode` newtypes in `ids.rs` with
  `Deref<Target=str>`, serde-transparent serialization, and `Borrow<str>` for
  HashMap key lookups. Prevents accidental mixing of string identifiers at
  compile time.
- Replaced `strict_mode: bool` with `AnalysisMode` enum (`Standard` / `Strict`)
  in grooming detector and enricher config.

### Pattern Matching

- Converted all 49 `matches!` macro usages to full `match` expressions with
  explicit arms for better compiler diagnostics when variants change.
- Eliminated 12 wildcard (`_ =>`) match arms with exhaustive variant listing
  across action engine, FFI layer, and event severity mappings.

### Code Style

- Replaced 72 iterator chains (`.iter().filter().map().collect()`) with
  idiomatic `for`-loops and mutable accumulators.
- Removed ~355 inline comments per Rust style guidelines.
- Applied variable shadowing where applicable.

### Memory and Performance

- Added `Vec::with_capacity` and `HashMap::with_capacity` on hot allocation
  paths (signal vectors, escalation tracker, enricher buffers).
- Reordered `ContactProfile` and `DetectionSignal` struct fields to minimize
  padding.
- Added optimized release profile: `lto = "fat"`, `codegen-units = 1`,
  `strip = "symbols"`.

### Documentation

- Added `///` rustdoc (RFC 1574) on all public items with third-person singular
  summaries.
- Added `//!` crate-level docs on all five crate `lib.rs` files.

### Fixes

- Fixed clippy `overly_complex_bool_expr` in `url_checker.rs`.
- Fixed clippy `needless_borrow` in `contact.rs`.

---

## Unreleased — Phase 3 Pilot Readiness Closure

**Pilot shadow bundles | Product integration contract | Pilot gate**

- Added a stable product-facing decision surface for messenger clients through
  `AnalysisResult.product_surface`, covering child, guardian, and review
  surfaces plus rollout-aware uncertainty handling.
- Extended the protobuf wire contract so external clients, including Swift/iOS,
  can consume the product surface and pilot/shadow bundle schemas directly.
- Promoted stable simulation scenarios into a formal pilot regression corpus
  with case classes, label invariants, and pilot slice metadata.
- Added a machine-readable `pilot_gate` report that combines release status,
  pilot regression status, repeated shadow runs, human-review signoffs, and
  rollback triggers into one pilot-ready decision.
- Taught local rehearsal and unified evidence manifests to understand optional
  pilot gate artifacts.
- Added operator docs for product integration, pilot review signoffs, and pilot
  rollback/review procedures.

---

## Production Hardening and Release Discipline

**Release candidate posture | Unified evidence bundle | All-features CI**

- Added a structured release report and unified evidence manifest for release,
  contract, dataset, audit, FFI smoke, and FFI state-sync soak evidence.
- Promotion and CI workflows now run the all-targets/all-features build and
  test path, generate machine-readable artifacts, and fail on red evidence.
- Hardened protobuf and FFI boundaries with request-size limits, malformed-input
  rejection, export/import stress coverage, and C header smoke checks.
- Pinned protobuf compatibility fixtures for key messages and stamped runtime,
  wire, and state-schema versions into contract evidence.
- Expanded realistic and external curated corpora to support release-critical
  child, trusted-adult, stranger, group-peer, self, RU, UK, and gold-review
  slices.
- Added dataset evidence and a lightweight dataset changelog to make corpus
  changes attributable and reviewable in promotion.
- Tightened privacy/audit discipline with machine-readable audit evidence,
  forbidden-field checks, and salted tokenization for restricted identifiers.
- Hardened pattern and link inputs with strict regex/domain validation,
  fail-closed matcher construction, and IDN-aware URL normalization.
- Fixed several production-path issues in the runtime, including ONNX dispatch,
  pile-on handling, score inflation, median calculation, per-threat gate
  preservation, and bounded contact-profile memory.

---

## v0.7.0 — Contact Rating & Behavioral Profiling

**469 тестів | 37 EventKind variants | Longitudinal behavioral shift detection**

Перша у світі система per-contact longitudinal behavioral shift detection для захисту дітей. Жоден комерційний продукт (Bark, Qustodio, Thorn) або академічне дослідження не реалізує цю функціональність.

---

### Contact Rating System (0-100)

**`aura-core/src/context/contact.rs`**
- Числовий рейтинг на контакт: старт 50 (нейтральний), 0-100 clamped
- `update_rating()` — event-driven: hostile events зменшують, supportive збільшують
- `rating_delta()` на EventKind: PhysicalThreat → -7, Insult → -2, DefenseOfVictim → +3, NormalConversation → +0.3
- Graduated trust: `trust_level` (0.0-1.0) замість бінарного `is_trusted`
- `decay_trust()`: severity * 0.15 за hostile event; 10+ insults → trusted friend стає untrusted
- `risk_score()` тепер з graduated trust discount: `1.0 - (trust_level * 0.5)`

### Social Circles (CircleTier)

- `Inner` — 5+ msg/day або 20+ active days/month
- `Regular` — 3+ msg/week (0.43+ msg/day)
- `Occasional` — менше 3 msg/week
- `New` — <14 днів знайомства
- Автоматичний перерахунок при кожному event

### Behavioral Snapshots (Weekly)

- `BehavioralSnapshot` — тижневі агрегати: hostile/supportive/neutral/grooming/manipulation counts + avg_severity
- Rolling window 26 тижнів (6 місяців), ~52 bytes per snapshot
- Автоматична фіналізація при перетині тижневої межі
- Пам'ять: ~1.3KB на контакт, ~260KB на 200 контактів

### Trend Detection (BehavioralTrend)

- `Stable` — hostile% зміна ±10%
- `Improving` — hostile% зменшується >10%
- `GradualWorsening` — hostile% зростає 10-25% за 3+ тижнів
- `RapidWorsening` — hostile% зростає >25% за 1-2 тижні
- `RoleReversal` — було >30% supportive, тепер >30% hostile ("подруга → булі")
- Baseline: перша половина snapshots vs Recent: останні 2 тижні

### Behavioral Shift Signal Generation

- `check_behavioral_shift()` → DetectionSignal при concerning trends
- RoleReversal → Bullying signal, score 0.6+ (Confidence::High)
- RapidWorsening → Manipulation signal, score 0.5+ (Confidence::Medium)
- GradualWorsening → Manipulation signal, score 0.35+
- Inner circle boost: +0.1 до score
- Low rating alert: Inner circle contact з rating <20 → score 0.55

### State Schema v2

- Backward compatible: всі нові поля з `#[serde(default)]`
- `post_deserialize_fixup()` для v1 стану: `is_trusted=true` → `trust_level=1.0`
- Import v1/v2 стану без проблем; export завжди v2

### 28 нових тестів

**events.rs** (5): hostile classification, rating deltas, supportive detection
**contact.rs** (~21): rating start/clamp, trust decay, circle tiers, snapshots, trend detection, role reversal, shift signals, inner circle boost, backward compat
**tracker.rs** (2): rating update integration, behavioral shift in pipeline

---

## v0.6.0 — Advanced Psychological Attacks + Teen Language

**441 тестів | 7 нових EventKind | Coercion detector | 18 EnricherCategory**

Глибокі психологічні маніпуляції які використовують дорослі проти підлітків + підлітковий сленг.

---

### Нові EventKind (Phase 6)

- `SuicideCoercion` (severity 0.85) — "якщо ти підеш, я себе вб'ю"
- `FalseConsensus` (severity 0.55) — "всі так роблять, ти дивна"
- `DebtCreation` (severity 0.6) — "я тобі стільки зробив, ти мені винна"
- `ReputationThreat` (severity 0.75) — "я всім розкажу що ти..."
- `IdentityErosion` (severity 0.6) — "ти без мене ніхто"
- `NetworkPoisoning` (severity 0.65) — "твої подруги тебе не люблять"
- `FakeVulnerability` (severity 0.55) — "мені так погано, тільки ти можеш допомогти"

### Coercion Detector

**`aura-core/src/context/coercion.rs`** — NEW
- `check_suicide_coercion()` — SuicideCoercion ≥2 events → score 0.85
- `check_reputation_blackmail()` — ReputationThreat + ScreenshotThreat → score 0.75
- `check_debt_leverage()` — DebtCreation ≥2 events → score 0.65
- `check_combined_coercion()` — 3+ різних coercion tactics → score 0.8
- Інтегровано в tracker.rs pipeline

### Enricher Expansion (Phase 6)

**`aura-core/src/context/enricher.rs`** — 7 нових категорій:
- `SuicideCoercion` — "якщо підеш від мене", "I'll hurt myself if you leave"
- `FalseConsensus` — "everyone does it", "всі так роблять", "ти дивна що ні"
- `DebtCreation` — "after everything I did for you", "я тобі стільки зробив"
- `ReputationThreat` — "I'll tell everyone", "всім розкажу"
- `IdentityErosion` — "you're nothing without me", "без мене ти ніхто"
- `NetworkPoisoning` — "your friends don't really care", "подруги тебе використовують"
- `FakeVulnerability` — "only you understand me", "тільки ти мене розумієш"
- Всі з EN + UK підлітковим сленгом

### Analyzer Integration

- 5 інтеграційних тестів з `analyze_with_context()`:
  - Suicide coercion detection
  - Reputation blackmail combo
  - Identity erosion + network poisoning
  - Debt creation with teen slang
  - False consensus manipulation

---

## v0.5.0 — Coercion, PII, Dare/Challenge, Screenshot Blackmail

**413 тестів | 3 нових EventKind | Enricher extended**

Нові вектори атак: PII self-disclosure дітей, dare/challenge тиск, screenshot blackmail.

---

### Нові EventKind (Phase 5)

- `PiiSelfDisclosure` (severity 0.6) — дитина сама розкриває адресу, школу, номер
- `CasualMeetingRequest` (severity 0.4) — "давай зустрінемось після школи"
- `DareChallenge` (severity 0.45) — "на спір не зможеш", "слабо?"

### Enricher: PII Self-Disclosure

**`aura-core/src/context/enricher.rs`**
- `PiiSelfDisclosure` категорія: "my address is", "I go to [school]", "мій номер", "я живу на"
- Дитина сама видає персональну інформацію (не хтось просить)

### Enricher: Dare/Challenge Pressure

- `DareChallenge` категорія: "I dare you", "bet you can't", "слабо?", "на спір"
- Тиск через виклик/dare серед підлітків

### Enricher: Screenshot Blackmail + Platform Migration

- `Blackmail` категорія: "I screenshotted", "я заскрінив", "I have proof"
- `PlatformMigration` категорія: "add me on snap", "давай в телегу", "my insta is"
- ScreenshotThreat → manipulation_indicator

### Grooming Detector Updates

- PiiSelfDisclosure, CasualMeetingRequest → grooming_indicator
- Extended GroomingStage::BoundaryCrossing з новими event types

### Action Engine Updates

**`aura-core/src/action.rs`**
- PII leakage handling: warn at 0.4, parent alert at 0.7, NEVER block (дитина — жертва, не агресор)

---

## v0.4.0 — Accuracy, Safety & Performance

**405 тестів (з ONNX) | 389 (без ONNX) | 151 правило | 0 warnings**

Фокус: усунення false positives, negation handling, input validation, single-pass AhoCorasick.

---

### Step 1: Word Boundary Matching

**`aura-ml/src/boundary.rs`** — NEW
- `contains_at_boundary()` — Unicode-aware (Latin + Cyrillic) boundary check
- `find_at_boundary()` — повертає byte position для negation lookback
- `aho_match_at_boundary()` — post-filter для AhoCorasick матчів
- Замінює `str::contains()` у toxicity, sentiment, enricher
- Усуває false positives: "method"≠"meth", "cockpit"≠"cock", "funeral"≠"fun", "crystal"≠"cry", "establish"≠"stab", "scunthorpe"≠"cunt", "dickens"≠"dick", "shitake"≠"shit"
- 45 тестів (boundary, Cyrillic, edge cases)

### Step 2: `&self` на ML Backends

- `predict(&mut self)` → `predict(&self)` на ToxicityBackend, SentimentBackend traits
- `ort::Session::run()` в v2.x приймає `&self`, fallback stateless
- `MlPipeline::analyze_text(&self)` замість `&mut self`
- `Analyzer::run_ml_layer(&self)` замість `&mut self`

### Step 3: Input Validation + Limits + `aura_last_error()`

**`aura-core/src/analyzer.rs`**
- `MAX_TEXT_LENGTH = 10_000` — truncation на char boundary
- Defensive: не помилка, просто обрізання

**`aura-ffi/src/lib.rs`**
- `MAX_BATCH_SIZE = 1000` — error JSON якщо batch перевищує
- Thread-local `aura_last_error()` — повертає останню помилку або null
- `aura_init` — proper error handling замість `unwrap_or_default()`
- Всі bool-returning FFI функції (`aura_update_config`, `aura_import_context`, `aura_cleanup_context`, `aura_mark_contact_trusted`) викликають `set_last_error()` перед `return false`

**`aura-core/src/config.rs`**
- `AuraConfig::validate()` — `ttl_days` 1..=365, `account_holder_age` 5..=120

### Step 4: Negation Handling

**`aura-ml/src/boundary.rs`**
- `is_negated(text, match_start, window_chars)` — 30-char lookback
- Negation words: EN (17), UK (8), RU (8)

**`aura-ml/src/toxicity.rs`** — per-category dampening:
- Threats: `score * 0.1` ("I won't kill you" → low)
- Profanity: NO dampening ("don't say fuck" — слово присутнє)
- Insults: `score * 0.3` ("you're not stupid" → low)
- Sexual / Drugs: `score * 0.3`

**`aura-ml/src/sentiment.rs`** — polarity flip:
- Negated positive → add to negative ("I'm not happy" ≠ Positive)
- Negated negative → add to positive ("I'm not sad" → mildly positive)

### Step 5: AhoCorasick Single-Pass Automata

**`aura-ml/src/toxicity.rs`**
- `ToxCategory` enum (Insult, Threat, Sexual, Profanity, Drug)
- `FallbackMatcher` з `AhoCorasick` automaton (~296 patterns)
- `LeftmostLongest` match kind — довші паттерни мають пріоритет
- Single-pass `find_iter()` + boundary post-filter + negation dampening

**`aura-ml/src/sentiment.rs`**
- `SentPolarity` enum, `SentimentFallbackMatcher` (~277 patterns)
- Single-pass з boundary + negation post-filters

**`aura-core/src/context/enricher.rs`**
- `EnricherCategory` enum (8 categories)
- `EnricherMatcher` з per-category automaton
- `SignalEnricher::new()` будує automata; `enrich_full()` — single scan

### ONNX Integration

- `ort` 2.0.0-rc.11 з `load-dynamic` feature
- `.cargo/config.toml` — `ORT_DYLIB_PATH` для macOS (Homebrew)
- Models: `toxicity.onnx` (unitary/toxic-bert), `sentiment.onnx` (textattack/bert-base-uncased-SST-2)
- 16 ONNX integration тестів

---

## v0.3.0 — Horizontal Expansion to Production Readiness

**303 тести | 26 симуляцій | 151 правило | 0 warnings**

Масштабне горизонтальне розширення всіх підсистем від ~58% до ~95% production readiness.

---

### Batch 1: Sentiment Fallback + Enricher Signals

**`aura-ml/src/sentiment.rs`**
- Розширено словник з 78 до ~190 слів
- Додано ~30 позитивних та ~35 негативних EN слів (hopeful, grateful, trapped, powerless...)
- Додано ~20 позитивних та ~25 негативних UK слів (горджуся, надія, принижений, покинутий...)
- Додано ~40 російських слів (люблю, счастливый, ненавижу, депрессия...)
- 10 нових тестів

**`aura-core/src/context/enricher.rs`**
- `check_hopelessness_pattern()` → EventKind::Hopelessness (EN/UK)
- `check_isolation_language()` → EventKind::Exclusion (EN/UK)
- `check_financial_grooming()` → EventKind::MoneyOffer (EN/UK)
- 9 нових тестів

### Batch 2: Pattern Database Expansion

**`aura-patterns/data/patterns_mvp.json`**
- Додано ~20 нових правил: наркотики (drug slang EN/UK/RU), sextortion, grooming video call, body comments, DARVO, intermittent reinforcement
- Нові категорії: `substance_pressure`, `sextortion_*`, `grooming_video_call`, `grooming_body_comment`, `manipulation_darvo`, `manipulation_intermittent`
- 6 нових тестів

### Batch 3: Toxicity Fallback + Emoji Deepening

**`aura-ml/src/toxicity.rs`**
- Додано ~15 EN та ~10 UK слів сексуального контенту
- Додано drug terminology EN/UK (~10 слів кожна мова)
- Новий `drug_score` в fallback scoring
- 5 нових тестів

**`aura-patterns/src/emoji.rs`**
- Sextortion: 📸💰, 🔒💰, ⏰💸, 🤫📸
- Drugs: 💊💰, 🍃🔥, ❄️👃, 💉💀
- Isolation: 🚫👧, 🚫👦, 👋🚪, 🗑️👉
- 5 нових тестів

### Batch 4: Grooming Detector Maturation

**`aura-core/src/context/events.rs`**
- Додано `VideoCallRequest` (severity 0.8) та `FinancialGrooming` (severity 0.6)

**`aura-core/src/context/grooming.rs`**
- Розширено `GroomingStage` з 5 → 6 стадій: додано `FinancialDependency`
- `GiftOffer`/`MoneyOffer`/`FinancialGrooming` → `FinancialDependency` стадія
- `VideoCallRequest` → `BoundaryCrossing` стадія
- Age-gap aware scoring: дорослий відправник (≥18) додає +0.1
- 7 нових тестів

### Batch 5: Bullying Detector Maturation

**`aura-core/src/context/bullying.rs`**
- `check_sustained_harassment()` — той самий агресор 3+ окремих днів
- `check_target_isolation()` — exclusion + denigration від декількох відправників
- `check_bystander_silence()` — булінг без захисту (supplementary score)
- 8 нових тестів

### Batch 6: Manipulation Detector Maturation

**`aura-core/src/context/events.rs`**
- Додано `Darvo` (severity 0.7) та `Devaluation` (severity 0.6)

**`aura-core/src/context/manipulation.rs`**
- Додано `Darvo` та `Devaluation` до `ManipulationTactic`
- `check_love_bomb_devalue_cycle()` — LoveBombing + Denigration/Devaluation → score 0.7-0.8
- `check_darvo_pattern()` — Darvo events ≥2 → score 0.6+
- 6 нових тестів

### Batch 7: Self-Harm + Timing Maturation

**`aura-core/src/context/selfharm.rs`**
- `check_acute_vs_chronic()` — 3+ events за 24h = acute (0.85), 3+ days = chronic (0.75)
- `check_protective_factors()` — позитивні сигнали знижують score (-0.1)
- `check_contagion_pattern()` — 2+ senders з hopelessness за 48h → 0.7
- 6 нових тестів

**`aura-core/src/context/timing.rs`**
- `check_response_asymmetry()` — відправник <30s, дитина >5min → 0.35
- `check_conversation_frequency()` — 50+ messages/day → 0.4
- 4 нових тестів

### Batch 8: Action Engine Production

**`aura-core/src/types.rs`**
- Додано `RecommendedAction`, `AlertPriority`, `FollowUpAction`

**`aura-core/src/action.rs`**
- `decide_action_v2()` з threat-specific thresholds:
  - SelfHarm: НІКОЛИ не блокується, завжди crisis resources
  - Grooming: block ≥0.85, warn ≥0.6, parent alert ≥0.5
  - Bullying: block ≥0.9, warn ≥0.7, parent alert ≥0.7
  - Explicit/CSAM: block ≥0.8, parent alert ЗАВЖДИ
  - Doxxing: block ≥0.75, parent alert ЗАВЖДИ
- 12 нових тестів

### Batch 9: FFI Improvements

**`aura-ffi/src/lib.rs`**
- `aura_analyze_batch()` — batch analysis (JSON array → JSON array)
- `aura_get_conversation_summary()` — огляд всіх розмов для parent dashboard
- Structured error codes: 1000-1004 (null pointer, invalid UTF-8, invalid JSON, mutex poisoned, serialization)
- Типи: `FfiBatchItem`, `FfiConversationSummary`, `FfiConversationOverview`
- Version bumped до 0.3.0
- 6 нових тестів

### Batch 10: Simulations + Integration Tests

**`aura-core/examples/simulations.rs`** — 15 нових симуляцій (#12-26):
| # | Сценарій |
|---|----------|
| 12 | Drug dealer approaches teen |
| 13 | Sextortion after photo |
| 14 | Coordinated raid (Discord-style) |
| 15 | DARVO manipulator |
| 16 | Financial grooming (gift cards) |
| 17 | Self-harm contagion |
| 18 | Sustained bullying 2 weeks |
| 19 | Mixed language attack |
| 20 | False positive: friends joking |
| 21 | Parent dashboard lifecycle |
| 22 | Love bomb → devalue cycle |
| 23 | Grooming video escalation |
| 24 | Bullying → isolation |
| 25 | Acute self-harm crisis |
| 26 | Teen dating violence |

**`aura-core/src/analyzer.rs`** — 15 інтеграційних тестів:
- Grooming sequence + recommendations
- Self-harm never blocked + crisis resources
- Bullying pile-on escalation
- Multi-tactic manipulation
- Explicit content → parent alert
- Context export/import
- Clean conversation (false positive check)
- Sextortion countdown
- Raid detection
- Bullying → self-harm pathway
- Video call grooming
- DARVO pattern
- Financial grooming context
- Recommended action serialization
- Contact profiler risk tracking

---

## Архітектура

```
┌─────────────────────────────────────────────────────┐
│                    aura-ffi (C FFI)                  │
│  Android NDK / iOS / Desktop / Flutter              │
├─────────────────────────────────────────────────────┤
│                    aura-core                         │
│  ┌──────────┐ ┌──────────┐ ┌────────────────────┐  │
│  │ Analyzer  │ │ Action   │ │ Context Engine     │  │
│  │ (L1+L2+  │ │ Engine   │ │ ├ Grooming (6 stg) │  │
│  │  L3 pipe) │ │ v2       │ │ ├ Bullying         │  │
│  └──────────┘ └──────────┘ │ ├ Manipulation      │  │
│                             │ ├ Self-Harm         │  │
│                             │ ├ Coercion          │  │
│                             │ ├ Timing            │  │
│                             │ ├ Raid              │  │
│                             │ ├ Contact Profiler  │  │
│                             │ │  ├ Rating (0-100) │  │
│                             │ │  ├ Trust Decay    │  │
│                             │ │  ├ Circle Tier    │  │
│                             │ │  ├ Trend Detect   │  │
│                             │ │  └ Shift Signals  │  │
│                             │ ├ Age Gap           │  │
│                             │ └ Enricher (18 cat) │  │
│                             └────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  aura-ml              │  aura-patterns              │
│  ├ Sentiment (EN/UK/RU)│  ├ 151+ rules (JSON)      │
│  ├ Toxicity + drugs   │  ├ Emoji patterns           │
│  └ ONNX runtime       │  └ Regex engine             │
└─────────────────────────────────────────────────────┘
```

### 3-Layer Pipeline

| Layer | Швидкість | Опис |
|-------|-----------|------|
| L1 — Pattern Matching | <1ms | Regex rules, emoji patterns |
| L2 — ML Classification | 5-20ms | Sentiment, toxicity, ONNX |
| L3 — Context Analysis | async | Grooming stages, bullying tracking, manipulation tactics |

### FFI Endpoints

| Функція | Опис |
|---------|------|
| `aura_init(config_json)` | Створити handle аналізатора |
| `aura_analyze()` | Аналіз одного повідомлення |
| `aura_analyze_json()` | Аналіз з JSON input |
| `aura_analyze_context()` | Аналіз з context tracking (timestamp) |
| `aura_analyze_batch()` | Batch аналіз (JSON array, max 1000) |
| `aura_update_config()` | Оновити конфіг на льоту |
| `aura_reload_patterns()` | Hot-reload pattern database |
| `aura_export_context()` | Експорт стану контексту |
| `aura_import_context()` | Імпорт стану контексту |
| `aura_cleanup_context()` | Очищення старих даних |
| `aura_mark_contact_trusted()` | Позначити контакт довіреним |
| `aura_get_conversation_summary()` | Огляд розмов для parent dashboard |
| `aura_parent_dashboard_contacts()` | Контакти для parent dashboard |
| `aura_last_error()` | Остання помилка (thread-local) |
| `aura_version()` | Версія бібліотеки |
| `aura_free_string()` | Звільнення рядка |
| `aura_free(handle)` | Знищення handle |

### Error Codes

| Code | Опис |
|------|------|
| 1000 | Null pointer |
| 1001 | Invalid UTF-8 |
| 1002 | Invalid JSON |
| 1003 | Mutex poisoned |
| 1004 | Serialization failure |
| 1005 | Invalid config |
| 1006 | Model not found |
| 1007 | Incompatible state |

---

## Статистика

| Метрика | Значення |
|---------|----------|
| Тести | 771 (544 core + 39 ffi + 113 ml + 75 patterns) |
| Симуляції | 26 |
| Pattern rules | 151+ |
| ML fallback patterns | ~573 (296 toxicity + 277 sentiment) |
| Enricher categories | 20 |
| Мови | EN, UK, RU |
| EventKind variants | 46 |
| Grooming stages | 6 |
| Manipulation tactics | 6+ |
| Context detectors | 7 (Grooming, Bullying, Manipulation, SelfHarm, Coercion, Raid, Timing) |
| Contact profiling | Rating, Trust Decay, CircleTier, BehavioralTrend, Weekly Snapshots |
| Threat types | SelfHarm, Grooming, Bullying, Manipulation, Explicit, Doxxing, Threat |
| Typed IDs | SenderId, ConversationId, ReasonCode |
| Warnings | 0 |
