# Генеральний план надійного випуску AURA

Статус: проєкт головного плану, 1 серпня 2026 року.

Цей документ визначає не календар випуску, а систему доказів, за якою AURA
може бути допущена до використання. Жодна дата, кількість виконаних завдань або
загальна кількість тестів не замінює критеріїв виходу, установлених нижче.

## 1. Рішення щодо стратегії випуску

AURA не випускається як один неподільний об'єкт. Готовність встановлюється
окремо для чотирьох контурів:

1. `AURA Agent / Apple` — локальний аналіз, пам'ять, політика та негайна дія.
2. `AURA.KIDS` — дитяча безпека, опікунські рішення і кризові сценарії.
3. `AURA.MILITARY` — OPSEC, психологічні операції та військова соціальна
   інженерія.
4. `AURA Relay` — віддалені підказки, репутація і міждіалогова кореляція.

Першою метою є надійний локальний випуск `AURA Agent + AURA.KIDS` для Apple у
режимі, що не залежить від Relay. `AURA.MILITARY` і Relay отримують окремі
рішення про допуск. Неготовність Relay не може блокувати локальний захист, але
Relay повинен бути технічно вимкнений у профілі, де його готовність не доведена.

Поточний Apple-артефакт без ONNX може бути основою лише для явно названого
профілю `local-rules-context`. Він не може рекламуватися як модельний або
гібридний випуск. Профілі з ONNX та Relay проходять окремі перевірки.

## 2. Класи випуску

| Клас | Склад | Дозволене використання |
| --- | --- | --- |
| `engineering` | локальна збірка, синтетичні дані | розробка |
| `verified-artifact` | чисте джерело, перевірені хеші, ABI та slices | інтеграційні перевірки |
| `internal-shadow` | повний продукт без впливу на користувача | внутрішня перевірка |
| `controlled-pilot` | обмежена група, явна згода, оперативний нагляд | пілот |
| `production-limited` | поетапне ввімкнення окремого профілю/домену | обмежений випуск |
| `production-general` | усі обов'язкові докази і стабільне спостереження | загальний випуск |

Поле `shippable` у manifest означає лише цілісність походження артефакту. Воно
не є дозволом на пілот або продукційне використання.

## 3. Незмінні інваріанти безпеки

Порушення будь-якого інваріанта автоматично дає `NO-GO`.

### 3.1 Локальний захист

- Явний локальний ризик ніколи не перетворюється на `Allow` через обмеження
  частоти, недоступність Relay, відсутність моделі або внутрішню деградацію.
- Остаточна негайна дія належить Agent, а не Relay.
- Relay може підвищити точність або додати доказ, але не є єдиним джерелом
  мінімального захисту.
- Один вхід застосовується до пам'яті та Safety Case не більше одного разу.
- Невдала фіксація стану не залишає частково оновленого рішення.

### 3.2 Дані і приватність

- Відкритий текст, медіа та сирі ідентифікатори не потрапляють у штатні журнали,
  телеметрію, shadow-звіти або release evidence.
- Звичайний Relay-запит використовує `MetadataOnly`; відкритий текст можливий
  лише в окремому явно дозволеному дослідному середовищі.
- Стан діалогів і KIDS memory зберігається застосунком у зашифрованому вигляді.
- Жодна процедура інциденту автоматично не скасовує правила приватності.

### 3.3 Сумісність і стан

- Protobuf v1 не змінює значення наявних полів і не використовує повторно
  вилучені номери.
- ABI v1 не змінює layout, володіння пам'яттю або семантику чинних функцій.
- Попередній підтримуваний формат стану або мігрується, або випуск блокується.
- Пошкоджений, майбутній чи надмірний стан відхиляється без часткової зміни
  поточного стану.

### 3.4 Дитяча безпека

- Підтримувальна відповідь на повідомлення про самоушкодження не позначається
  як джерело кризи.
- Довіра до дорослого не вимикає аналіз і не скасовує явні ознаки ризику.
- Обов'язкові `kids.memory.*` причини не знижуються під час налаштування порогів.
- Рішення опікуна змінює лише визначений обліковий запис, контакт і діалог.

## 4. Початкові блокувальники та поточний стан

### Блокувальники локального Agent/KIDS випуску

| Код | Стан | Проблема | Необхідний результат |
| --- | --- | --- | --- |
| `REL-001` | закрито | після rate limit повертався чистий `Allow` | Analyzer більше не має внутрішнього пропуску; кожне прийняте повідомлення проходить повний pipeline |
| `REL-002` | source реалізовано; приймання відкрито | Apple API не повертав негайний product decision | типізований локальний decision API реалізовано; потрібні artifact pin та фактичний iOS/UI gate |
| `REL-003` | закрито | помилка заданого pattern pack приховано вмикала вбудовані правила | заданий шлях завантажується повністю або блокує init зі стабільною причиною; відсутній шлях явно обирає built-in pack |
| `REL-004` | закрито | persisted state v2 відхилявся, а v3 wire втрачав контекстну рамку події | детермінована v2 -> v3 міграція, повний v3 context wire і byte-pinned v2/v3 golden fixtures |
| `REL-005` | закрито | guardian feedback очищав неправильний обсяг пам'яті й кодував `Block` вигаданими діалогами | точна ізольована семантика account/sender/conversation та версійований стан блокування |
| `REL-006` | закрито | порожні FFI IDs ставали спільним `unknown` | неправильні live та persisted sender/conversation IDs відхиляються до зміни стану |
| `REL-007` | закрито | `aura_last_error` міг повертати помилку іншого потоку | суто thread-local канал із багатопотоковим regression test |
| `REL-008` | закрито | `enabled=false` суперечив недозволеному вимкненню для minor | child/teen завжди мають активний захист і Kids domain; суперечливий init/update відхиляється до мутації |
| `REL-009` | artifact готовий; iOS приймання відкрито | iOS ще не приймає manifest v5/descriptor v3 | чистий XCFramework перевірено; потрібні зовнішній exact pin і Swift contract tests |
| `REL-010` | відкрито | чотири людські signoff залишаються pending | реальні підписані рішення |

### Окремі блокувальники Relay

| Код | Проблема | Необхідний результат |
| --- | --- | --- |
| `RLY-001` | plaintext `MessageOnly` є типовим режимом | типовий `MetadataOnly`, явний дозвіл на інші режими |
| `RLY-002` | тип загрози і score можуть походити з різних observation | збереження типізованої пари і визначене ранжування |
| `RLY-003` | inference є заглушкою | справжній bounded finding contract або Relay вимкнений |
| `RLY-004` | немає production ingress, deadline і rate-limit | автентифікований транспорт із негативними тестами |
| `RLY-005` | shared semantic contract дублюється з core | одна канонічна семантика Agent/Relay |
| `RLY-006` | немає kill switch і model rollback | підписане вимкнення підказок і попередній known-good bundle |

### Окремі блокувальники модельного профілю

| Код | Проблема | Необхідний результат |
| --- | --- | --- |
| `ML-001` | governed ONNX bundle відсутній у checkout/artifact | отримані файли з перевіреними хешами і походженням |
| `ML-002` | Apple binary зібрано без `onnx` | feature identity засвідчена в manifest |
| `ML-003` | застосунок не гарантує `models_path` | інтеграційний тест на реальному bundle |
| `ML-004` | fallback може маскувати відсутність моделі | capability attestation і профільна fail policy |
| `ML-005` | немає достатньої зовнішньої калібрації | окремі model-vs-rules та safe-cohort докази |

## 5. Єдиний продуктово-технічний контракт

### 5.1 Рекомендована межа Apple API

Канонічний Safety Case lifecycle залишається вузьким. Для негайної дії
реалізовано окрему additive ABI-функцію `aura_analyze_local_decision` з
protobuf-запитом і protobuf-відповіддю.

Вона:

- запускати той самий stateful Agent pipeline, що використовується в product;
- приймати стабільні `message_id`, `sender_id`, `conversation_id`, timestamp і
  account/domain configuration;
- повертати типізовані `product_surface`, `recommended_action`, `reason_codes`,
  `inference`, `case_id/revision` і ознаку деградації;
- атомарно узгоджувати результат із context/Safety Case;
- мати exactly-once семантику за source identity/revision;
- не повертати довільний JSON;
- не відновлювати весь вилучений legacy API.

Контракт фіксує
[`ADR 0001`](./adr/0001-canonical-local-decision-api.md): власника стану,
момент фіксації, повторний виклик, помилку збереження та відновлення після
restart.

### 5.2 Профілі виконання

Кожний артефакт містить точний профіль:

- `agent-kids-rules-context` — локальні правила, контекст, пам'ять і політика;
- `agent-kids-onnx` — те саме плюс засвідчений локальний model bundle;
- `agent-military-rules-context` — окремо допущений Military domain;
- `agent-relay-assisted` — локальний захист плюс необов'язкові Relay findings;
- `internal-shadow` — не впливає на рішення користувача.

`not_in_scope` дозволяється лише тоді, коли можливість фізично або політично
вимкнена і це доведено тестом. Прихована доступність не вважається виключенням
зі scope.

## 6. Послідовність виконання

### Хвиля 0 — замороження вихідної точки

Мета: створити відтворювану основу, від якої вимірюються всі зміни.

Завдання:

- зафіксувати commit, Cargo.lock, toolchain, Xcode/SDK і мінімальну iOS версію;
- зберегти поточний unified evidence manifest та Apple verification;
- зняти release, pilot, lifecycle, replay і performance baseline;
- створити реєстр `REL-*`, `RLY-*`, `ML-*` із власником і станом;
- заборонити нові threat families і несуміжні переробки до закриття REL-001–010;
- визначити перший release profile і твердження, які дозволено робити про нього.

Критерій виходу:

- baseline відтворюється з чистого checkout;
- усі подальші відмінності класифікуються як виправлення, навмисна зміна
  політики, зміна контракту або регресія.

### Хвиля 1 — виправлення інваріантів безпеки

Мета: прибрати поведінку, що може дати неправильний дозвіл або зіпсувати
довготривалу пам'ять.

Завдання:

1. Усунути rate-limit fail-open:
   - внутрішній per-sender short-circuit вилучено з Analyzer;
   - кожне повідомлення, уже прийняте safety boundary, проходить повний pipeline;
   - admission control переноситься перед Analyzer і не може підробити clean result;
   - regression перевіряє 60 безпечних + 61-ше ризикове повідомлення;
   - повний аналіз 1000 повідомлень залишається всередині чинного performance
     budget.
2. Виправлено guardian feedback:
   - `Trusted` очищає визначеного sender у всіх conversations і не зачіпає
     інших учасників;
   - `FalsePositive` видаляє лише відповідну sender/conversation evidence та
     узгоджено прибирає цю пару з cross-conversation memory;
   - `Block` зберігається явним полем `guardian_blocked`, а не синтетичними
     ідентифікаторами, і створює типізований блокувальний сигнал для наступних
     повідомлень;
   - kids-memory schema v2 читає v1 та мігрує старі block markers без втрати
     справжньої історії діалогів;
   - усі операції над двома memory maps використовують один порядок блокувань;
   - regression і scope-matrix tests доводять збереження всіх непов'язаних пар.
3. Реалізовано сувору перевірку FFI ідентифікаторів:
   - live message sender/conversation IDs більше не замінюються спільним
     `unknown`;
   - порожні, довші за 256 bytes, whitespace/control IDs відхиляються до
     аналізу та мутації state;
   - ті самі правила діють для вкладених timeline/event/contact/KIDS IDs під
     час імпорту persisted context.
4. Ізольовано last-error:
   - process-global fallback вилучено;
   - `aura_last_error` читає тільки помилку потоку, в якому стався виклик;
   - C header фіксує same-thread requirement;
   - barrier-based concurrency regression доводить відсутність cross-thread
     leakage.
5. ✅ Уніфіковано minor configuration:
   - protection для child/teen не вимикається жодною комбінацією внутрішніх
     полів;
   - `enabled=false` і Military domain для minor відхиляються до init/update;
   - child/teen завжди отримують Kids domain, а adult disable semantics
     залишаються явними;
   - матричні, FFI та no-partial-mutation regressions фіксують контракт.
6. Виправити Relay observation pairing, навіть якщо Relay залишається вимкненим.

Обов'язкові докази:

- targeted unit/regression tests для кожного дефекту;
- property tests для scope очищення пам'яті;
- concurrency test для FFI error channel;
- контрприклади до і після виправлення;
- відсутність непередбачених змін у refactor differential report.

Критерій виходу: `REL-001`, `REL-005`, `REL-006`, `REL-007`, `REL-008` і
`RLY-002` закриті; жодного нового silent-allow шляху.

### Хвиля 2 — конфігурація, набори правил і відмовна поведінка

Мета: застосунок завжди знає, що саме реально запущено.

Завдання:

- ✅ заданий і неправильний `patterns_path` блокує ініціалізацію з
  `PATTERN_PACK_LOAD_FAILED`;
- fallback дозволяється лише профілем, який прямо це декларує;
- pattern validator перевіряє унікальність/non-empty ID, відомий threat type,
  score range, непорожню matcher semantics і schema version;
- runtime/artifact attestation містить pattern bundle ID/hash, model backend,
  model ID/hash, policy version/hash і fallback reason;
- missing/corrupt model має різну політику для `rules-context` та `onnx` профілів;
- усі відмови мають стабільний машинозчитуваний reason code.

Негативні випробування:

- відсутній файл, неправильний JSON, неправильний regex, дубльований ID;
- невідомий threat type, NaN/out-of-range score, порожнє правило;
- model hash mismatch, неправильний tokenizer, несумісна output shape;
- read-only storage, відсутній каталог, перерваний запис.

Критерій виходу: неможливо переплутати requested configuration з effective
configuration; `REL-003` і `ML-004` закриті.

### Хвиля 3 — сумісність стану та відновлення

Мета: оновлення застосунку не втрачає і не змішує історію безпеки.

Завдання:

- ✅ реалізовано v2 -> v3 migration: відсутній у v2 контекст отримує
  консервативний legacy-default, наступний export нормалізується до v3;
- ✅ збережено незмінний byte-pinned v2 fixture і додано v3 golden fixture з
  повною event interpretation frame;
- зробити імпорт транзакційним: validate -> migrate -> bound -> commit;
- створювати зашифровану резервну копію стану перед першою міграцією;
- визначити поведінку downgrade і multi-device conflict;
- перевірити monotonic event IDs, case revision/generation і dedup після restart;
- перевірити context, contact, KIDS memory та Safety Case окремо і разом.

Матриця відмов:

- v2, v3, future version;
- truncated/corrupt/oversized payload;
- повторний імпорт;
- процес завершено між validate і commit;
- нестача місця;
- два пристрої з різними revisions;
- rollback runtime після вже виконаної міграції.

Критерій виходу: `REL-004` закритий; попередній підтримуваний стан не губиться,
future/corrupt state не змінює чинну пам'ять.

### Хвиля 4 — замикання продуктового Apple-контракту

Мета: рішення, обчислене ядром, без втрати семантики доходить до інтерфейсу.

Завдання:

- затвердити ADR локального decision API;
- додати protobuf messages additive способом;
- додати одну нову ABI-функцію та exact export allowlist;
- реалізувати Swift wrapper із безпечним володінням буферами;
- синхронізувати `product-integration-contract.md`, README і CHANGELOG;
- створити мінімальний iOS integration harness;
- перевірити кожну дію: warn, blur, link confirm, block/report suggestion,
  restrict unknown, slow down, crisis support, guardian escalation;
- перевірити локалізовані copy keys окремо від safety decision;
- довести відсутність double-apply між local decision і Safety Case lifecycle.

Обов'язкові end-to-end сценарії:

- одне ризикове повідомлення;
- багатокрокове наростання ризику;
- duplicate та out-of-order request;
- app restart між аналізом і відображенням;
- помилка збереження після обчислення;
- background/foreground transition;
- offline режим;
- safe trusted-adult і supportive self-harm boundaries.

Критерій виходу: `REL-002` закритий; Rust result, protobuf, C ABI, Swift object і
фактична UI-дія мають одну семантику.

### Хвиля 5 — Apple artifact і supply-chain доказ

Мета: застосунок використовує саме перевірений binary, а не лише правильний
source commit.

Завдання:

- оновити Swift validator на manifest v5 та descriptor v3;
- завершити або ізолювати BLE/offline worktree в iOS repository;
- зробити exact pin на Rust source revision, artifact commit і binary hashes;
- перевірити device, simulator і Mac Catalyst slices;
- перевірити runtime/wire/state/FFI versions між manifest, descriptor і native;
- перевірити trust keyring, execution policy, headers та export allowlist;
- створити SBOM, dependency/license/advisory report;
- виконати clean-room rebuild або задокументувати й усунути джерела
  невідтворюваності;
- підписати release decision artifact і зберегти його разом з binaries.

Критерій виходу: `REL-009` закритий; два незалежні перевіряльники отримують
однакову source identity та однакові очікувані binaries/headers/contracts.

### Хвиля 6 — повна технічна перевірка кандидата

Мета: отримати один незмінний release candidate і не підмінювати докази з
різних commits.

Обов'язковий набір:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --all-targets --locked
cargo doc --workspace --all-features --no-deps
just verify
just safety-world-v2-smoke
just world-lifecycle-gate
just ffi-world-replay-gate
just client-boundary-replay-gate
just world-performance-gate
just refactor-baseline-gate
just kids-memory-health-strict
just pilot-gate-strict
just apple-artifact-verify-release
```

Додаткові reliability перевірки:

- fuzz: protobuf decode, state import, pattern JSON, Relay wire payload;
- sanitizer/Miri для FFI ownership і критичних unsafe paths;
- довгий FFI init/analyze/export/import/destroy soak;
- паралельні handles і concurrent last-error;
- clock rollback/forward, timestamp overflow, duplicate/out-of-order events;
- memory pressure, disk-full і interrupted persistence;
- реальні Apple devices: мінімальна iOS, поточна iOS, simulator;
- airplane mode, повільна мережа, Relay timeout і DNS failure;
- cold start, background termination і повторний запуск.

Правила доказів:

- усі артефакти створюються з одного RC commit;
- rerun після зміни коду створює новий RC, старі signoff не переносяться
  автоматично;
- ignored/skipped test має письмове обґрунтування; release-critical skip дає
  `BLOCKED`;
- `INSUFFICIENT_SUPPORT` не вважається успіхом;
- загальна метрика не перекриває провал критичного slice.

### Хвиля 7 — людська перевірка і контрольований shadow

Мета: перевірити семантику, яку не можна довести лише тестовим кодом.

Обов'язкові підписи:

| Ділянка | Хто затверджує |
| --- | --- |
| runtime/FFI correctness | відповідальний за Rust runtime |
| Apple integration | відповідальний за iOS/Swift |
| security/privacy | незалежний security/privacy reviewer |
| child-safety policy | фахівець із дитячої безпеки |
| self-harm boundaries | кваліфікований предметний консультант |
| product actions/copy | safety product owner |
| data/model evidence | data/model owner |
| operations/rollback | release operator |
| Military domain | окремий предметний reviewer, якщо домен у scope |

Мінімальний shadow contract:

- два послідовні чисті технічні shadow runs;
- окремий людський перегляд false-positive hotspots;
- окремий перегляд supportive self-harm;
- trusted-adult, image/reputation abuse та KIDS memory review;
- Military boundary review, якщо цей профіль увімкнено;
- нуль відкритого тексту і сирих IDs у shadow artifacts;
- зафіксовані rollback triggers до початку пілоту.

Критерій виходу: `REL-010` закритий; усі підписи стосуються точного RC hash.

### Хвиля 8 — контрольований пілот

Мета: перевірити продуктову поведінку без передчасного широкого впливу.

Порядок:

1. Внутрішня синтетична перевірка.
2. Добровільний shadow без автоматичних жорстких дій.
3. Обмежений guardian-review pilot з явною згодою.
4. Невеликий `production-limited` cohort.
5. Поступове розширення лише після стабільного вікна спостереження.

На кожному ступені окремо фіксуються:

- profile/domain/platform/locale/age band;
- кількість рішень за action class;
- guardian review rate і overturn rate;
- критичні false negatives;
- harmful false positives;
- latency, crash-free sessions, persistence failures;
- privacy/audit violations;
- частка degraded/fallback decisions;
- точна версія runtime/pattern/model/policy/corpus.

Жодне автоматичне розширення cohort не дозволяється. Перехід затверджується
людиною на основі машинозчитуваного звіту.

### Хвиля 9 — окремий Relay/hybrid допуск

Мета: Relay покращує рішення, але не створює нової критичної залежності.

До ввімкнення Relay необхідно:

- `MetadataOnly` як fail-safe default;
- production transport, auth, attestation, replay protection, deadline і
  abuse-resistant rate limiting;
- одна канонічна observation/finding semantics;
- модель або алгоритм, що робить більше, ніж повернення локальних hints;
- calibrated bounded findings із confidence, reason, freshness і TTL;
- Agent fusion policy, що не дозволяє слабкому Relay hint стати hard action;
- timeout/degraded/offline integration tests;
- poisoning, sybil, replay і cross-account isolation tests;
- privacy threat model і data retention contract;
- server model rollback та signed kill switch;
- порівняння local-only проти relay-assisted на однакових сценаріях.

Relay спочатку працює лише у shadow. Він переходить до advisory mode лише після
доведеного приросту корисності без порушення false-positive і privacy budgets.

### Хвиля 10 — загальний випуск і післярелізний контроль

Мета: підтримувати доведений стан після розширення використання.

- щоденний KIDS memory health у першому вікні випуску;
- щоденний перегляд critical incidents і degraded decisions;
- drift report за мовою, віком, relationship, threat family і action;
- щотижневе підтвердження pattern/model/policy identities;
- регулярний restart/state replay;
- новий release gate для кожної policy, pattern, model або contract зміни;
- жодного silent threshold tuning у production;
- post-release review із переліком пропущених сигналів і нових regression gates.

## 7. Матриця відмовної поведінки

| Відмова | Обов'язкова поведінка |
| --- | --- |
| перевищення ingress rate limit | повідомлення або не приймається до safety boundary з явним статусом, або після прийняття проходить повний Analyzer pipeline; не silent allow |
| Relay timeout/down | локальне рішення, ознака remote unavailable |
| model missing у rules profile | засвідчений rules fallback |
| model missing у ONNX profile | ініціалізація/допуск заблоковані |
| configured pattern pack invalid | ініціалізація заблокована |
| corrupt persisted state | чинний стан не змінюється; контрольована помилка |
| older supported state | атомарна міграція |
| future state | fail-safe rejection без mutation |
| storage commit failure | rollback рішення/стану, можливість retry |
| duplicate event | exactly-once disposition |
| empty IDs | boundary rejection |
| clock rollback | deterministic bounded handling |
| stale signed policy | anti-rollback rejection |
| privacy evidence failure | release/pilot автоматично blocked |
| unavailable telemetry | захист працює; promotion evidence blocked, якщо telemetry обов'язкова |

## 8. Версії та одиниці відкочування

Окремо версіонуються:

- runtime release;
- protobuf wire major;
- FFI contract;
- persisted state schema;
- pattern bundle;
- context rule pack;
- execution policy;
- model bundle;
- product copy/resources;
- evaluation corpus;
- Relay API/model.

Кожний release decision містить усі ці identities та їхні SHA-256. Попередня
відомо добра комбінація зберігається як неподільний rollback set.

Відкочування не повинно вимагати видалення локальної пам'яті. Якщо старий
runtime не може читати вже мігрований стан, до випуску потрібен forward-compatible
reader, downgrade migration або заборона відкочування з іншим планом відновлення.

## 9. Kill switches

Окремо і підписано можуть бути послаблені або вимкнені:

- Relay findings;
- optional ML;
- конкретний model/pattern/policy bundle;
- експериментальна action branch;
- окремий domain profile.

Не можна віддалено вимкнути мінімальні локальні critical protections для child
account. Kill switch не повинен переводити явний ризик у silent allow.

## 10. Єдиний release decision artifact

Потрібен верхньорівневий документ, окремий від Apple `shippable`:

Статус реалізації: fail-closed агрегатор, зовнішній client-acceptance contract
і окремі Ed25519 sign/verify команди реалізовано в
`ci/release_decision.py`. До фактичного iOS acceptance та чотирьох реальних
pilot signoff поточний кандидат зобов'язаний залишатися `no-go`; автоматизація
не підміняє ці зовнішні рішення.

```json
{
  "schema_version": "aura.release_decision.v2",
  "candidate": "<runtime-version+commit>",
  "profile": "agent-kids-rules-context",
  "artifact_integrity": "pass",
  "runtime_safety": "pass",
  "contract_compatibility": "pass",
  "product_integration": "pass",
  "privacy_security": "pass",
  "operational_readiness": "pass",
  "model_readiness": "not_in_scope",
  "relay_readiness": "not_in_scope",
  "human_signoffs": "pass",
  "decision": "go"
}
```

Правила:

- `not_in_scope` потребує доказу, що функція вимкнена;
- будь-який `fail`, `blocked`, missing або required `insufficient_support`
  перетворює рішення на `no-go`;
- hashes усіх дочірніх evidence artifacts входять до decision artifact;
- decision підписується release operator і перевіряється застосунком/CI там,
  де це технічно доречно.

## 11. GO/NO-GO на випуск

### `GO` можливий лише коли

- усі блокувальники обраного профілю закриті;
- поточний RC не змінювався після повного gate;
- усі required suites `PASS`, required slices мають достатню підтримку;
- state migration, FFI replay і client restart replay пройдені;
- продукт отримує і правильно застосовує local decision;
- Apple pin відповідає перевіреному binary;
- privacy evidence не містить заборонених полів;
- rollback set реально доступний і перевірений;
- signoff належать точному RC;
- rollout cohort і stop conditions задані до ввімкнення.

### Автоматичний `NO-GO`

- будь-який шлях silent allow для явного ризику;
- нерозв'язана двозначність між requested та effective configuration;
- відсутня міграція підтримуваного стану;
- Apple API не доставляє потрібну product action;
- змішані source/binary/evidence revisions;
- модель заявлена, але не засвідчена або фактично працює fallback;
- Relay у production path без offline-safe degradation;
- plaintext/raw IDs у штатних artifacts;
- critical slice має `FAIL` або `INSUFFICIENT_SUPPORT`;
- підпис зроблено не для поточного RC;
- rollback не перевірений.

## 12. Оперативні stop conditions після ввімкнення

Негайне зупинення розширення та розгляд відкочування:

- підтверджений critical false negative;
- harmful self-harm або trusted-adult false positive;
- неправильна guardian escalation через contaminated memory;
- corruption або масова втрата persisted state;
- protobuf/ABI несумісність;
- raw-content/privacy leak;
- crash, latency або memory regression, що пропускає safety deadline;
- невідома effective model/pattern/policy identity;
- Relay hint спричинив hard action поза дозволеною fusion policy.

Після stop condition:

1. Заморозити candidate і evidence.
2. Визначити одиницю дефекту: runtime, state, pattern, model, policy, Relay або
   client integration.
3. Порівняти з previous known-good set.
4. Активувати найвужчий безпечний kill switch або rollback.
5. Додати regression test/gate до повторного допуску.
6. Повторити повний gate для нового RC; старі підписи не успадковувати.

## 13. Межа між випуском і науковим доказом

Цей план може довести:

- відтворюваність програмної реалізації;
- дотримання контрактів;
- стійкість до визначених відмов;
- результати на контрольованих наборах і симуляціях;
- керованість пілоту та відкочування.

Він не доводить загальну наукову ефективність AURA. Для цього окремо потрібні
попередньо зареєстровані гіпотези, незалежні дані, порівняльні методи, ablation,
статистична потужність, оцінка зовнішньої чинності та етичне схвалення. Release
evidence є інфраструктурою докторського дослідження, але не його результатом.

## 14. Рекомендований точний порядок робіт

1. ✅ `REL-001` rate-limit safety — внутрішній fail-open шлях вилучено.
2. ✅ `REL-005` guardian memory scope — точні межі `Trusted`/`FalsePositive`,
   явний версійований `Block` і міграція v1 -> v2.
3. ✅ `REL-006` ID validation і `REL-007` error isolation — bounded FFI IDs,
   перевірка imported state та суто thread-local `aura_last_error`.
4. ✅ `REL-003` pattern/config fail semantics — заданий зовнішній pack більше
   не може бути мовчки замінений built-in rules.
5. ✅ `REL-004` state v2 -> v3 migration — legacy import, v3 context
   persistence, golden fixtures і безпечна відмова future version.
6. ✅ `REL-008` minor configuration invariant — єдина fail-closed семантика
   для config, Analyzer, AgentRuntime і FFI.
7. ◐ ADR і source-реалізація `REL-002` local product decision API завершені;
   artifact pin та фактичний iOS/UI gate залишаються відкритими.
8. ◐ Чистий `REL-009` XCFramework і незалежна artifact verification готові;
   iOS integration harness та зовнішній exact pin залишаються відкритими.
9. Повний RC gate і реальні `REL-010` signoffs.
10. Controlled local-only KIDS pilot.
11. Окремий Military допуск.
12. `RLY-001`–`RLY-006` і лише потім Relay shadow/advisory rollout.
13. `ML-001`–`ML-005` перед будь-якою заявою про model-backed profile.

Нові фічі не додаються між пунктами 1–10, крім тих, що безпосередньо потрібні
для закриття release blocker або створення доказу.

## 15. Definition of Done першого надійного випуску

Перший випуск `AURA Agent + AURA.KIDS` завершений лише коли:

- локальний stateful pipeline є єдиним product path;
- явний ризик не може пройти через rate limit/degradation як clean `Allow`;
- Apple client отримує типізоване негайне рішення;
- Safety Case, context і product decision мають exactly-once та restart-safe
  семантику;
- неправильні IDs/config/pattern/model/state відхиляються визначеним способом;
- v2 state має перевірену міграцію до v3;
- guardian feedback не очищає чужу пам'ять;
- Rust, protobuf, C ABI, Swift wrapper і UI scenario tests узгоджені;
- artifact integrity відокремлена від product readiness;
- Apple binary точно прикріплений до iOS release;
- full workspace, lifecycle, FFI replay, client restart, performance, privacy,
  pilot і device gates зелені на одному RC;
- rollback set і stop conditions перевірені;
- усі необхідні людські підписи реальні;
- Relay, ONNX і Military або окремо допущені, або доведено вимкнені;
- документація описує фактичний стан без застарілих заяв;
- верхньорівневий `aura.release_decision.v2` має `decision = go`.
