# AURA Core — Changelog

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
│                             │ ├ Timing            │  │
│                             │ ├ Raid              │  │
│                             │ ├ Age Gap           │  │
│                             │ └ Enricher          │  │
│                             └────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  aura-ml              │  aura-patterns              │
│  ├ Sentiment (EN/UK/RU)│  ├ 151 rules (JSON)       │
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
| `aura_create_analyzer()` | Створити handle аналізатора |
| `aura_analyze()` | Аналіз одного повідомлення |
| `aura_analyze_batch()` | Batch аналіз (JSON array) |
| `aura_get_conversation_summary()` | Огляд розмов для parent dashboard |
| `aura_export_context()` | Експорт стану контексту |
| `aura_import_context()` | Імпорт стану контексту |
| `aura_version()` | Версія бібліотеки |
| `aura_free_string()` | Звільнення рядка |
| `aura_destroy_analyzer()` | Знищення handle |

### Error Codes

| Code | Опис |
|------|------|
| 1000 | Null pointer |
| 1001 | Invalid UTF-8 |
| 1002 | Invalid JSON |
| 1003 | Mutex poisoned |
| 1004 | Serialization failure |

---

## Статистика

| Метрика | Значення |
|---------|----------|
| Тести | 303 (183 core + 16 ffi + 44 ml + 60 patterns) |
| Симуляції | 26 |
| Pattern rules | 151 |
| Мови | EN, UK, RU |
| EventKind variants | 20+ |
| Grooming stages | 6 |
| Manipulation tactics | 6+ |
| Threat types | SelfHarm, Grooming, Bullying, Manipulation, Explicit, Doxxing, Threat |
| Warnings | 0 |
