# План завершення переробки AURA Core

Статус: активний план.

Дата фіксації базової точки: 2026-07-24.

Базова ревізія: `8d08e951a0cb9a832d191dec2919790175b15fd2`.

## 1. Мета

Завершити архітектурну міграцію AURA Core без повторного переписування вже
готової функціональності та без прихованої зміни safety-поведінки.

Цільовий runtime-конвеєр:

```text
RawObservation
  -> ThreatContextFrame
  -> ConfirmedEvent
  -> Memory
  -> Inference
  -> Policy
  -> Product Surface
```

Кожен етап повинен мати одного власника семантики:

- detector визначає, що було знайдено;
- interpreter визначає, що означає знайдене в поточному контексті;
- memory накопичує лише підтверджену поведінку;
- inference оцінює траєкторію ризику;
- policy вирішує, яку дію дозволено;
- product layer формує child, guardian і review представлення.

## 2. Що вже зроблено

Цей план не починається з нуля. У поточній базовій ревізії вже є:

- поділ workspace на центральне ядро, `AURA.KIDS`, `AURA.MILITARY`, Agent і
  Relay crates;
- `RawObservation` та observation batch;
- універсальний `ThreatContextFrame`;
- typed `AnalysisContextSummary`;
- interpreter перед довготривалим tracker state;
- окремі domain runtime adapters;
- Agent/Relay deployment split;
- Safety Case runtime і versioned persisted state;
- стабільні protobuf v1, C ABI та Apple artifact contracts;
- release, pilot, lifecycle, FFI replay і performance gates.

Повторно реалізовувати ці шари не потрібно.

## 3. Незакритий архітектурний борг

Поточні залишки:

1. `context_markers` усе ще можуть бути перетворені назад у typed context через
   `AnalysisContextSummary::from_markers`.
2. Interpretation, memory eligibility і policy exceptions ще переважно
   закодовані в Rust `if`/`match`, а не у versioned rule contracts.
3. Повна parity-міграція domain detector logic у `aura-kids` і
   `aura-military` не завершена.
4. Кілька модулів мають забагато відповідальностей:
   - `crates/aura-core/src/analyzer.rs`;
   - `crates/aura-core/src/context/contact.rs`;
   - `crates/aura-agent-ffi/src/lib.rs`;
   - `crates/aura-relay-api/src/lib.rs`.
5. Long-horizon evaluation існує, але не кожне контекстне правило має
   симетричну risky/safe boundary-пару.
6. Старі архітектурні документи описують Phase 2 і Phase 3 як незавершені,
   хоча значна частина цих фаз уже реалізована.

## 4. Незмінні інваріанти

Під час усієї міграції діють такі правила:

1. Ніяких breaking-змін protobuf v1, C ABI або persisted state schema без
   окремого versioned migration plan.
2. Detector не має права напряму створювати довготривалу memory.
3. Лише interpreter присвоює stance, speech act, directionality і reciprocity.
4. Tracker приймає лише підтверджені події.
5. `context_markers` залишаються explainability output, а не джерелом
   business-рішень.
6. Некоректний rule pack не може мовчки перейти на частково завантажені або
   permissive defaults.
7. Нова архітектура не повинна послабити KIDS/TEEN high-recall контур,
   guardian escalation, critical self-harm або coercion paths.
8. Рефакторинг виконується малими reviewable змінами; big-bang rewrite
   заборонений.
9. Кожна навмисна зміна safety-поведінки має окремий evidence diff і не
   маскується під структурний refactor.
10. Новий Apple artifact збирається лише після завершення Rust-гейтів.

## 5. Етап 0 — зафіксувати baseline

Статус: завершено 24 липня 2026 року.

Зафіксований baseline:

- `crates/aura-core/data/refactor_baseline_v1.json`;
- схема `aura.refactor_baseline.v1`;
- differential gate `just refactor-baseline-gate`;
- точні reviewable approvals у `docs/refactor-diff-approvals.json`;
- release, pilot, lifecycle, FFI/client replay і 10k performance evidence
  пройшли без behavioral regression.

### Завдання

- Зберегти machine-readable baseline поточних release/pilot результатів.
- Зафіксувати:
  - workspace crate graph;
  - runtime, wire і state schema versions;
  - C export allowlist;
  - protobuf compatibility fixtures;
  - Apple artifact manifest;
  - release/pilot reports;
  - world lifecycle і performance reports.
- Додати differential harness, який порівнює базову та нову реалізації на
  однакових deterministic fixtures.
- Класифікувати допустимі відмінності:
  - structural-only;
  - approved safety improvement;
  - regression.

### Перевірки

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --all-targets --locked
just verify
just safety-world-v2-smoke
just world-lifecycle-gate
just ffi-world-replay-gate
just client-boundary-replay-gate
```

### Критерій виходу

Є відтворюваний baseline, і будь-яка наступна хвиля показує точний behavioral,
ABI, state та performance diff відносно нього.

## 6. Етап 1 — зробити typed context єдиним джерелом істини

Статус: завершено 24 липня 2026 року.

Реалізовано:

- додано opaque `ConfirmedEvent`; його може створити лише context interpreter;
- production API `ConversationTracker` приймає тільки `ConfirmedEvent`, а
  compile-fail doctest доводить, що raw `ContextEvent` відхиляється;
- fallback `NormalConversation` переведено на
  `RawObservation -> ContextInterpreter -> ConfirmedEvent` без зміни persisted
  event context;
- policy, product, inference, audit і shadow projection споживають
  `AnalysisContextSummary`;
- `context_markers` централізовано генеруються з typed summary та окремих
  diagnostic reason codes;
- marker-only policy functions збережено лише як задокументовані compatibility
  adapters, щоб не ламати публічні реекспорти `aura-agent-policy`;
- додано conflict-тести, де marker-рядки суперечать typed context: рішення
  завжди визначає typed summary;
- наявні quote/report/counter/support тести підтверджують, що пригнічені
  observations не стають confirmed memory events.

Evidence:

- `cargo fmt --all -- --check` — pass;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — pass;
- `cargo test --workspace --all-features --all-targets --locked` — pass,
  зокрема 734 `aura-core` unit tests і 102 realistic simulations;
- `cargo test -p aura-core --doc` — compile-fail boundary pass;
- `just refactor-baseline-gate` — pass: 0 regressions, 0 behavioral safety
  changes, 2 раніше схвалені structural-only FFI changes;
- 10k performance tier — pass: 13 647 events, 20.20 s elapsed, 274.2 MiB
  maximum RSS, 100% labeled recall, 0% clean false-positive rate.

### Завдання

- Заборонити внутрішнім production paths відновлювати семантику з
  `context_markers`.
- Залишити `AnalysisContextSummary::from_markers` лише як тимчасовий
  compatibility/test adapter.
- Перевести `action.rs`, `product.rs`, inference softening і audit projection
  на пряме споживання `AnalysisContextSummary`.
- Генерувати `context_markers` тільки з typed context та окремих diagnostic
  reason codes.
- Додати compile-visible boundary:
  - `RawObservation` може стати `ConfirmedEvent` лише через interpreter;
  - tracker API не приймає raw observation або непідтверджений `ContextEvent`.
- За можливості використати typestate/newtype, щоб некоректний перехід був
  compile-time помилкою, а не runtime boolean.

### Основні файли

- `crates/aura-core/src/types.rs`
- `crates/aura-core/src/context/observation.rs`
- `crates/aura-core/src/context/interpretation.rs`
- `crates/aura-core/src/context/events.rs`
- `crates/aura-core/src/context/tracker.rs`
- `crates/aura-core/src/action.rs`
- `crates/aura-core/src/product.rs`
- `crates/aura-core/src/analyzer/stages.rs`

### Тести

- safe typed context не ескалується через випадковий marker;
- risky typed context не пом'якшується через відсутній marker;
- quote/report/counter/support не забруднюють memory;
- serialization marker output залишається backward-compatible;
- tracker відхиляє непідтверджені події на рівні API.

### Критерій виходу

- Жодне business-critical рішення не парсить `context_markers`.
- У production pipeline існує один шлях
  `RawObservation -> interpretation -> ConfirmedEvent`.
- ABI, protobuf і persisted state schema не змінені.

## 7. Етап 2 — перенести semantic patches у правильний шар

Статус: завершено 25 липня 2026 року.

Реалізовано:

- contextual false-positive filtering перенесено з `Analyzer` до
  `ContextInterpreter` до `RawObservation -> ConfirmedEvent` materialization;
- gaming banter, peer de-escalation, casual media, friendly reciprocity та
  self-referential distress тепер визначають signal/event eligibility всередині
  context interpretation;
- post-tracker semantic filtering і relationship metadata calibration
  інкапсульовано в pure `ContextInterpreter` methods, які отримують лише
  borrowed timeline/snapshot та staged signals;
- `apply_contextual_corroboration_boost` і supportive late-night suppression
  замінено typed `ContextSignalAdjustments`, сформованим із
  `ThreatContextFrame`;
- порядок escalation, contact risk, contextual corroboration та relationship
  boosts збережено, тому адитивні й мультиплікативні score corrections не
  змінили числову поведінку;
- pattern, ML, domain і enricher adapters перевірено: production paths
  повертають `RawObservation`/event hints, а confirmed memory materializes лише
  interpreter;
- видалено старі analyzer implementations, повторні relationship/context
  mappings та fallback створення raw `NormalConversation` після interpreter;
- interpreter не мутує tracker, persisted storage або product surface.

Додано focused regression tests:

- safe group gaming banter не створює bullying signal або confirmed memory;
- лише corroborated grooming pattern+ML pair отримує direct-new-contact boost;
- supportive context видаляє late-night grooming timing signal через typed
  interpreter calibration.

Evidence:

- `cargo fmt --all -- --check` — pass;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  — pass;
- `cargo test --workspace --all-features --all-targets --locked` — pass,
  зокрема 737 `aura-core` unit tests і 102 realistic simulations;
- `cargo test -p aura-core --doc` — compile-fail tracker boundary pass;
- `just refactor-baseline-gate` — pass: 0 regressions, 0 behavioral safety
  changes, 2 раніше схвалені structural-only FFI changes;
- 10k performance tier — pass: 13 647 events, 21.42 s elapsed, 290.0 MiB
  maximum RSS, 100% labeled recall, 0% clean false-positive rate.

### Завдання

- Прибрати post-interpreter semantic mutation з analyzer orchestration.
- Перенести `apply_contextual_corroboration_boost`:
  - в interpreter, якщо правило відповідає на питання про значення поведінки;
  - у policy rule, якщо правило визначає реакцію системи;
  - у inference, якщо правило оцінює траєкторію на основі вже підтверджених
    фактів.
- Перевірити pattern, ML, domain та enricher adapters: вони мають повертати
  observations/hints, а не самостійно підтверджені memory events.
- Прибрати дубльовані mapping і fallback paths.
- Зробити interpreter pure: без прямої мутації tracker, storage або product
  surface.

### Критерій виходу

- Після interpreter analyzer не змінює stance, directionality, reciprocity або
  memory eligibility.
- Orchestrator лише збирає stages і передає typed результати далі.
- Однаковий context contract використовується в runtime, eval і release gates.

## 8. Етап 3 — versioned data-driven context rules

Статус: завершено 25 липня 2026 року.

Реалізовано:

- додано незалежні versioned rule packs: 8 interpretation rules, 9 memory
  eligibility rules і 5 relationship-policy calibration rules;
- `context/rules.rs` містить typed schemas, `deny_unknown_fields` parsing,
  bounded rule/selector/string validation, duplicate/conflict detection та
  deterministic `priority DESC, id ASC` ordering;
- усі три packs парсяться й валідовуються атомарно один раз через
  `OnceLock<Result<Arc<ContextRulePacks>, ContextRuleError>>`; частково
  активований набір або runtime network fallback неможливі;
- додано `ContextInterpreter::try_new` та `Analyzer::try_new`, які повертають
  typed `ContextRuleError`/`AuraError`; сумісні `new` constructors fail closed
  для некоректного bundled artifact;
- hardcoded baseline rules для supportive context, direct grooming
  corroboration, defender/pile-on, safe media, timing, gaming,
  de-escalation, playful reciprocity, profanity, peer compliments і
  relationship trust перенесено у відповідні packs без зміни порядку;
- policy schema не має поля product action: rule може лише додати typed
  calibration/diagnostic evidence, після чого рішення проходить звичайний
  inference і product policy pipeline;
- canonical struct serialization виконується після deterministic sorting;
  release contract evidence містить `policy_version`, rule count і SHA-256
  кожного pack;
- fixture inventory у differential gate нормалізовано за file path, тому
  додавання rule pack дає окремий reviewable diff, а не каскад зміщених array
  indexes.

Додано focused validation/regression tests:

- invalid JSON, unknown field, unsupported schema/policy version;
- duplicate id, conflicting condition, overlong id та deterministic
  priority/tie-break;
- спроба визначити product action у policy pack відхиляється;
- existing safe/risky social-context, tracker-memory, relationship metadata,
  corroboration та realistic simulation cases проходять через активні packs.

Evidence:

- `cargo fmt --all -- --check` — pass;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` —
  pass;
- `cargo test --workspace --all-features --all-targets` — pass, зокрема 746
  `aura-core` unit tests і 102 realistic simulations;
- `cargo test -p aura-core --doc` — compile-fail tracker boundary pass;
- `python3 -m unittest ci.test_refactor_baseline` — 8/8 pass;
- `just refactor-baseline-gate` — pass: 0 regressions, 0 behavioral safety
  changes, 6 exact structural-only changes (2 раніше схвалені FFI та 4
  versioned rule-pack evidence additions);
- lifecycle replay — 20 347 events, 100% labeled recall, 0% clean
  false-positive rate;
- 10k performance tier — pass: 13 647 events, 14.42 s elapsed, 333.9 MiB
  maximum RSS, 100% labeled recall, 0% clean false-positive rate.

### Контракти

Створити три незалежні rule packs:

```text
crates/aura-core/data/context_interpretation_rules.json
crates/aura-core/data/context_memory_rules.json
crates/aura-core/data/context_policy_rules.json
```

Вони не повинні змішувати різні рішення:

- interpretation rules: що означає observation у цьому контексті;
- memory rules: чи дозволено зберігати confirmed behavior;
- policy rules: яку дію дозволено після inference.

### Вимоги до rule pack

- явний `schema_version`;
- стабільний `policy_version`;
- canonical serialization;
- SHA-256 digest у release evidence;
- bounded кількість правил і bounded довжини полів;
- unknown fields/enum values відхиляються;
- duplicate/conflicting rules відхиляються;
- пріоритет і tie-breaking детерміновані;
- жодного network fetch у on-device hot path;
- валідація виконується один раз до активації;
- помилка повертається як typed `Result`, без `unwrap`, `expect` або
  часткового fallback.

### Реалізація

- Додати typed schema, parser і validator.
- На першій хвилі перенести лише правила, уже підтверджені current baseline.
- Для кожного перенесеного правила додати:
  - позитивний risky case;
  - симетричний safe/counterfactual case;
  - invalid schema case;
  - conflict/priority case.
- Не дозволяти rule pack напряму створювати product action без проходження
  typed policy layer.

### Критерій виходу

- Основні context exceptions declarative та versioned.
- Зміна порогу або контекстного винятку дає reviewable data diff.
- Invalid pack fail-closed і блокує release evidence.

## 9. Етап 4 — завершити domain ownership і parity

Статус: завершено 25 липня 2026 року.

Реалізовано:

- у `aura-domain` додано typed `DomainEventKind`, `DomainSignalRoute` і
  `DomainOutput::routed`; маршрут прив'язаний до індексу сигналу після
  фінального domain sorting і не змінює serialized `DomainOutput` shape;
- `aura-kids` і `aura-military` самі визначають semantic event для кожного
  detector, compound і memory signal; `reason_code` та `threat_key` більше не
  використовуються core як неявний routing protocol;
- core будує `RawObservation` безпосередньо з `DomainOutput` і робить лише
  вичерпне enum-to-enum перетворення; unrouted domain signal лишається signal
  без synthesized event;
- legacy Layer 1 pattern ID compatibility перенесено в `aura-patterns`, тобто
  crate, який володіє pattern pack; subtype та coordinate-shadow guards також
  більше не містять rule-name conventions у core;
- dependency graph не змінено: `aura-patterns` має власний typed
  `PatternEventKind` і не залежить від domain crates;
- direct military social-engineering context exception більше не перевіряє
  KIDS/MILITARY reason-code prefixes;
- додано negative boundary test та exhaustive lexicon routing tests: кожен
  KIDS і MILITARY lexical rule має typed route.

### Реалізована parity matrix

| Domain family | Threat/subtype ownership | Confirmed event ownership | Memory/inference/policy parity |
| --- | --- | --- | --- |
| KIDS grooming | `aura-kids` detector metadata | KIDS typed route | grooming progression, sender trajectory, guardian action і product surface без diff |
| KIDS bullying | `aura-kids` detector metadata | KIDS typed route | pile-on/self-harm cascade, raid і guardian surface без diff |
| KIDS self-harm | `aura-kids` detector metadata | KIDS typed route | crisis trajectory, memory eligibility та non-blocking policy без diff |
| KIDS manipulation | `aura-kids` detector metadata | KIDS typed route | blackmail/sextortion/coercion memory й actions без diff |
| MILITARY OPSEC/coordinates | `aura-military` detector metadata | MILITARY typed route | warning/report context, tracker memory і product action без diff |
| MILITARY psyops | `aura-military` detector metadata | MILITARY typed route | propaganda/trajectory integration та action без diff |
| MILITARY social engineering | `aura-military` detector metadata | MILITARY typed route | subtype, quote/report boundary та product surface без diff |

Для кожного рядка differential evidence перевіряє стабільність threat type,
subtype, score/confidence, reason codes, confirmed event, memory mutation,
inference trajectory, action і product projection. Legacy pattern coverage
додатково лишається за typed compatibility adapter у `aura-patterns`.

### Shared cross-domain механізми

У `aura-core` навмисно залишаються лише механізми, що працюють на typed
observations незалежно від домену:

- coercion composition;
- contact trust і cross-conversation sender history;
- timing/frequency analysis;
- raid/burst aggregation;
- relationship та risk trajectory;
- interpretation, confirmed-memory boundary, inference, policy orchestration і
  product projection.

Evidence:

- `cargo fmt --all -- --check` — pass;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` —
  pass;
- `cargo test --workspace --all-features --all-targets --locked` — pass,
  зокрема 747 `aura-core`, 52 `aura-kids`, 105 `aura-military` unit tests і
  102 realistic simulations;
- `cargo test -p aura-core --doc` — compile-fail tracker boundary pass;
- FFI last-error isolation — 5 послідовних прогони по 16/16 tests;
- `just refactor-baseline-gate` — pass: 0 regressions, 0 behavioral safety
  changes, 6 раніше схвалених structural-only changes;
- lifecycle replay — 20 347 events, 100% labeled recall, 0% clean
  false-positive rate;
- 10k performance tier — pass: 13 647 events, 16.06 s elapsed, 309.4 MiB
  maximum RSS, 100% labeled recall, 0% clean false-positive rate.

### Завдання

- Завершити перенесення KIDS detector logic у `aura-kids`.
- Завершити перенесення MILITARY detector logic у `aura-military`.
- Залишити в `aura-core` лише справді спільні:
  - observation contracts;
  - interpretation;
  - memory primitives;
  - inference;
  - policy orchestration;
  - product projection.
- Domain runtime bridge має працювати через `aura-domain` contracts і registry,
  а не через rule-name prefixes у core.
- Видалити дубльовану legacy-логіку тільки після differential parity.
- Зафіксувати, які cross-domain механізми залишаються спільними:
  coercion, contact trust, timing, raid/burst і relationship trajectory.

### Parity matrix

Для кожного domain family перевірити:

- threat type;
- subtype;
- score/confidence;
- reason codes;
- confirmed event;
- memory mutation;
- inference trajectory;
- action;
- product surface.

### Критерій виходу

- `aura-core` не знає domain-specific filename/rule-prefix conventions.
- KIDS і MILITARY мають власні detector/policy tests.
- Видалення legacy path не змінює output без окремо схваленого evidence diff.

## 10. Етап 5 — декомпозиція великих модулів

Статус: завершено 25 липня 2026 року; verification evidence наведено нижче.

Це структурний етап після стабілізації семантичних меж. Його не можна
поєднувати з масовим tuning правил.

### Реалізована карта модулів

`aura-core/analyzer` зберігає `analyzer.rs` як documented public façade та
re-export `Analyzer`. Приватна реалізація розкладена так:

```text
analyzer/
  orchestrator.rs
  orchestrator/
    stages.rs
    stages/observations.rs
    inference.rs
    tests.rs
```

`context/contact.rs` лишається стабільним façade для всіх попередніх public і
crate-internal paths. Contact state має окремих власників:

```text
context/contact/
  relationship.rs
  relationship/
    model.rs
    state.rs
    tests.rs
```

FFI export surface і crate attributes лишаються у `aura-agent-ffi/src/lib.rs`;
`pub use` зберігає Rust paths, а `export_name`/`no_mangle` — C symbols:

```text
src/
  lib.rs
  execution_policy.rs
  lifecycle.rs
  lifecycle/
    analysis.rs
    buffers.rs
    errors.rs
    state.rs
    tests.rs
```

Relay wire/API surface лишається у `aura-relay-api/src/lib.rs`, тоді як
orchestration, persistence adapters та typed configuration errors розділені:

```text
src/
  lib.rs
  service.rs
  service/
    adapters.rs
    config.rs
    tests.rs
```

Move був structural-only: scoring thresholds, detector rules, policy decisions,
protobuf schema, persisted-state schema й exported C names не змінювалися.
Нові внутрішні межі використовують лише module-scoped visibility
(`pub(super)`), без нових `dyn Trait`, dependency edges або глобальних locks.
Великі test modules винесені поруч із відповідними owners, тому production
файли більше не змішують orchestration з тисячами рядків scenario evidence.

### `aura-core/analyzer`

Залишити `Analyzer` як публічний façade, а реалізацію розкласти за
відповідальністю:

```text
analyzer/
  mod.rs
  orchestrator.rs
  collectors/
    pattern.rs
    ml.rs
    domain.rs
    enricher.rs
  interpretation_stage.rs
  memory_stage.rs
  inference.rs
  result_builder.rs
```

### `context/contact`

Розділити:

```text
context/contact/
  mod.rs
  model.rs
  state.rs
  trust.rs
  risk.rs
  relationship.rs
  trajectory.rs
```

### `aura-agent-ffi`

Зберегти існуючі export names у `lib.rs`, а внутрішню реалізацію рознести:

```text
src/
  lib.rs
  lifecycle.rs
  analysis.rs
  state.rs
  execution_policy.rs
  buffers.rs
  errors.rs
```

### `aura-relay-api`

Розділити wire/API façade, service orchestration, adapters і typed errors без
зміни зовнішнього контракту.

### Правила декомпозиції

- Один commit/PR — одна відповідальність.
- Спочатку move/re-export, потім окремий behavioral cleanup.
- Не оптимізувати без benchmark.
- Не додавати `dyn Trait`, якщо runtime polymorphism не потрібен.
- Не приховувати dependency cycle через глобальний `Arc<Mutex<_>>`.
- Library errors залишаються typed `thiserror`; `anyhow` дозволений лише
  binary/tool boundaries.
- Public API має module docs і compile-tested examples.

### Критерій виходу

- Кожен модуль має одного власника відповідальності.
- Public paths та ABI залишилися сумісними через façade/re-export.
- Немає циклічних crate/module dependencies.
- Hot path не має непідтвердженого performance regression.

### Verification evidence

- `cargo fmt --all -- --check` — pass;
- strict workspace Clippy з `--all-targets --all-features --locked
  -- -D warnings` — pass;
- повний workspace test gate — pass, зокрема 747 `aura-core`, 102 realistic
  simulations, 52 KIDS, 105 MILITARY, 38 Relay API і 16 FFI tests;
- workspace rustdoc — pass; compile-fail tracker boundary та новий
  contract-evidence regression test для decomposed FFI sources — pass;
- FFI last-error/lifecycle isolation — 5 послідовних прогонів по 16/16;
- C header smoke компілюється з `-std=c11 -Wall -Wextra -pedantic`, а release
  `dylib` експортує попередні `aura_*`/`aura_agent_*` symbols після re-export;
- `just refactor-baseline-gate` — pass: 9 review-approved structural-only
  changes, 0 regressions, 0 invalid approvals;
- lifecycle replay — 16 worlds, 20 347 events, 100% labeled recall, 0% clean
  false-positive rate, 0 findings;
- release 10k performance tier — pass: 13 647 events, 14.71 s elapsed,
  298.3 MiB maximum RSS, 100% labeled recall, 0% clean false-positive rate.

Public façade files тепер мають 9–12 рядків. Найбільші production owners у
змінених зонах мають 1 418 рядків або менше; великі scenario/test bodies
зберігаються в окремих `tests.rs` і не маскують runtime responsibility.

## 11. Етап 6 — long-horizon evaluation і quality gates

Статус: engineering complete. Усі автоматизовані release, replay, KIDS,
baseline і performance checks зелені. Promotion залишається заблокованим лише
до чотирьох реальних human review sign-offs; pending template не вважається
approval і не підміняється автоматично.

### Обов'язкові boundary cohorts

- `propaganda_discussion_boundary`;
- `selfharm_support_boundary`;
- `peer_banter_boundary`;
- `trusted_adult_logistics_boundary`;
- `opsec_warning_boundary`;
- `hate_counter_speech_boundary`.

Кожен cohort містить:

- risky positive;
- safe negative з подібною поверхневою лексикою;
- multi-turn escalation;
- replay/import/export continuation;
- account/domain/profile boundary.

### Додаткові докази

- memory contamination tests;
- counterfactual pair tests;
- deterministic ordering tests;
- malformed rule-pack tests;
- future-schema rejection;
- state round-trip і restart replay;
- FFI null, truncated, oversized і ownership paths;
- long-world KIDS memory stress;
- 10k/50k/100k performance tiers.

### Performance правило

Ніяка оптимізація або деградація не приймається за припущенням. Порівнюються
release-build benchmark і world performance reports. Регресія понад поточний
budget потребує окремого профілювання, пояснення та схвалення.

### Повний verification gate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --all-targets --locked
just verify
just safety-world-v2-smoke
just world-lifecycle-gate
just ffi-world-replay-gate
just client-boundary-replay-gate
just world-performance-gate
just kids-memory-health-strict
just pilot-gate-strict
```

ONNX gate запускається окремо з governed model bundle:

```bash
AURA_RUN_SAFETY_INTENT_ONNX=1 \
  cargo test -p aura-ml --features onnx --test onnx_integration
```

### Verification evidence

- mandatory cohort validator вимагає точний набір із шести boundary cohorts,
  risky/safe labels, multi-turn trajectories, account/domain boundary та
  відомий style profile;
- counterfactual, restart export/import, contamination і deterministic-order
  тести проходять для всіх 12 risky/safe trajectories;
- canonical hate/counterspeech pack входить до окремого
  `hate_counter_speech_boundary`: 30 positive, 12 negative, 100% detection,
  0% negative false positives, strict calibration gates — pass;
- FFI null/truncated/output-buffer/ownership edge paths — 19/19;
- `cargo fmt`, strict workspace Clippy і повний workspace test gate — pass;
- lifecycle suite — 16 worlds, 20 347 events, 100% recall/precision, 0% clean
  false positives, 0 findings;
- KIDS memory health — pass, 96 memory hits; pre-prod dry-run — pass;
- pilot technical gate — 9/9 automated checks pass, 604 shadow events із
  потрібних 500; окремо pending чотири human sign-offs;
- performance gate — pass: 13 647 / 54 495 / 102 151 events для
  10k/50k/100k tiers, 100% recall/precision і 0% clean false positives;
- refactor baseline diff — pass: 15 exact `structural_only` (13 Stage 5/6 plus
  2 Apple export-evidence entries), 41 exact `approved_safety_improvement`,
  0 regressions, 0 invalid approvals.

### Критерій виходу

- Кожне велике context rule має risky/safe boundary evidence.
- Release, lifecycle, FFI replay, state replay і performance gates зелені;
  automated pilot checks зелені, promotion чекає human review sign-offs.
- Навмисні зміни метрик задокументовані, випадкові — відсутні.

## 12. Етап 7 — release artifact та інтеграція

Статус: core artifact complete, client acceptance pending. Clean source
`fa6945d3ab7ebf1f0e25f7a3fb3402af6e06af9c` зібрано в перевірений
artifact-коміт `42b4f13b4f3ba32f0bb1601a4d9ce44d4e727f5c` для всіх п'яти Apple
target triples. Manifest має `shippable=true`; slices, architectures, embedded
headers, binary hashes і точний export allowlist пройшли незалежну перевірку.
Залишається окремий client gate: iOS має прийняти manifest v5/descriptor v3,
закріпити точні hashes і викликати terminal-source checkpoint лише після
довготривало збереженого terminal inbox state. Ця міграція не змішується з
незавершеним BLE/offline worktree.

### Завдання

- Перевірити protobuf fixtures, C header і exported symbol allowlist.
- За потреби оновити runtime release version окремо від wire/state versions.
- Зібрати Apple XCFramework із locked dependencies і точним feature set.
- Згенерувати source/binary hashes та release manifest.
- Перевірити всі slices і embedded headers.
- Оновити iOS pin лише після успішної artifact verification.
- Запустити iOS contract tests проти нового артефакту.
- Не змішувати цей етап із незавершеним offline/BLE worktree.

### Критерій виходу

- Rust source, Apple binary, headers, hashes і iOS pin вказують на одну
  перевірену ревізію.
- Жодної несинхронізованої source/binary межі.
- Release evidence відтворюється з чистого checkout.

### Поточний evidence contract

- `ci/apple_artifact.py source-digest` створює deterministic SHA-256 для
  reviewable source tree, виключаючи лише generated Apple outputs;
- release manifest v5 і runtime descriptor v3 роздільно фіксують Git revision,
  source-tree digest/dirty state, runtime/wire/state/FFI versions, Cargo
  profile/features, trust keyring, headers і binaries;
- `include/aura_ffi.exports` є точним machine-readable allowlist для всіх Apple
  slices;
- `just apple-artifact-build-local` дозволяє перевіряти dirty worktree, не
  перезаписуючи shippable `dist/apple`;
- `just apple-artifact-build-release` відмовляється працювати з dirty source і
  після збірки вимагає clean-source verification.

Майбутня докторантська доказова програма описана окремо в
`docs/research-evidence-roadmap.md`. Production gates є її відтворюваною
інфраструктурою, але не замінюють preregistered наукові експерименти.

## 13. Рекомендований порядок змін

1. Baseline/evidence harness.
2. Typed-context single authority.
3. Interpreter-only confirmation boundary.
4. Data-driven rule schemas та validator.
5. Поступове перенесення чинних context rules.
6. KIDS/MILITARY parity migration.
7. Декомпозиція analyzer.
8. Декомпозиція contact, FFI і Relay API.
9. Long-horizon/eval expansion.
10. Повний release gate.
11. Apple artifact та iOS pin.

Кожен пункт має завершуватися зеленим targeted gate. Повний workspace gate
обов'язковий перед переходом між semantic, domain, structural і release
хвилями.

## 14. Definition of Done

Переробка ядра завершена, коли одночасно виконано все:

- існує один canonical typed context path;
- detector output не потрапляє в memory без interpreter;
- policy не парсить string markers;
- post-interpreter semantic patches відсутні;
- interpretation, memory і policy rule contracts розділені та versioned;
- domain-specific detector logic належить domain crates;
- core orchestration не залежить від domain rule-name conventions;
- великі модулі розділені за відповідальністю без API/ABI drift;
- protobuf v1, C ABI і persisted state compatibility доведені;
- release/pilot/lifecycle/replay/performance gates зелені;
- Apple artifact відтворюваний і cryptographically прив'язаний до source;
- iOS використовує саме перевірений artifact;
- документація описує фактичну, а не історичну архітектуру.

## 15. Не входить у цей план

- нові threat families;
- новий продуктовий UI;
- зміна guardian/family product semantics;
- перенавчання моделей;
- заміна protobuf v1;
- зміна persisted state schema без окремої міграції;
- server API redesign;
- динамічне завантаження policy з мережі;
- змішування AURA Core refactor з offline/BLE feature work.
