# AURA Core — Changelog

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
| Тести | 469 (275 core + 21 ffi + 113 ml + 60 patterns) |
| Симуляції | 26 |
| Pattern rules | 151+ |
| ML fallback patterns | ~573 (296 toxicity + 277 sentiment) |
| Enricher categories | 18 |
| Мови | EN, UK, RU |
| EventKind variants | 37 |
| Grooming stages | 6 |
| Manipulation tactics | 6+ |
| Context detectors | 7 (Grooming, Bullying, Manipulation, SelfHarm, Coercion, Raid, Timing) |
| Contact profiling | Rating, Trust Decay, CircleTier, BehavioralTrend, Weekly Snapshots |
| Threat types | SelfHarm, Grooming, Bullying, Manipulation, Explicit, Doxxing, Threat |
| Warnings | 0 |
