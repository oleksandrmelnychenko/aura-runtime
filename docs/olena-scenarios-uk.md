# Як AURA захищає Олену: реалістичні сценарії

Це продуктовий сценарний документ, вирівняний з поточним runtime AURA станом
на March 16, 2026. Усі `score` нижче ілюстративні: точне значення залежить від
історії контакту, inferred age, reason codes, latent-state inference і того,
скільки сигналів накопичився в розмові.

## Дійові особи

- Олена: дівчинка 12 років, користувачка Ecliptix Messenger
- Марія, Даша: однокласниці та подруги Олени
- "Макс": невідомий контакт, потенційно дорослий зловмисник
- Мама Олени: опікун, який отримує guardian alerts від AURA

## Налаштування захисту

- `account_type = child`
- `protection_level = high`
- Стандартні базові пороги для `high`: `mark >= 0.20`, `blur >= 0.35`,
  `warn >= 0.50`, `block >= 0.80`
- Далі поверх цього працюють threat-specific overrides: грумінг, булінг,
  фішинг, `PII`, `self-harm`

## Сценарій 1: поступовий грумінг від незнайомця

| Крок | Повідомлення від "Макса" | Що бачить AURA | Типова реакція |
| --- | --- | --- | --- |
| День 1 | "Привіт! Ти так круто грала, я такого не бачив!" | `EventKind::Flattery`, `TrustBuilding`, новий контакт | Зазвичай `Mark`. AURA починає моніторити контакт і вмикає unknown-contact restrictions |
| День 2 | "Хочу тобі подарувати скін, скинь свій нік" | `EventKind::GiftOffer`, `FinancialDependency`, уже multi-stage sequence | Зазвичай `Blur`, а якщо профіль уже схиляється до дорослого або накопичив більше ризикових сигналів, може перейти в `Warn` |
| День 3 | "Тільки не кажи мамі, це наш секрет" | `EventKind::SecrecyRequest`, `Isolation`, швидка ескалація | `Warn`, `AlertPriority::High`, `SuggestBlockContact`, `RestrictUnknownContact`, `EscalateToGuardian` |
| День 4 | "Скинь фоточку, хочу побачити яка ти красива" | `EventKind::PhotoRequest`, `BoundaryCrossing`, уже сформований grooming chain | Часто `Block`, якщо сумарний `grooming score` доходить до `0.85+` |

Що важливо:

- Для `ThreatType::Grooming` AURA блокує не по загальному порогу `0.80`, а по
  власному правилу: `warn >= 0.60`, `block >= 0.85`.
- У грумінгу `parent_alert` для сильних кейсів зараз `High`, не `Urgent`.
- Якщо контакт уже виглядає дорослим або підозріло накопичує grooming-події,
  оцінка росте швидше.

Типове пояснення від системи:

> Multi-stage grooming sequence detected: trust building, financial leverage,
> isolation pressure, and boundary crossing.

## Сценарій 2: булінг у груповому чаті

| Крок | Що відбувається | Що бачить AURA | Типова реакція |
| --- | --- | --- | --- |
| 1 | Даша: "Олена тупа, всі це знають" | `ThreatType::Bullying`, pattern + content signals, `score ~0.45` | `Blur` і `BlurUntilTap` |
| 2 | Ще 3 дівчини пишуть подібне за 10 хвилин | `abuse.bullying.pile_on`, 4 різні агресори, `pile-on score = 0.80` | `Warn`, `SuggestReport`, `SlowDownConversation`, `EscalateToGuardian`, `AlertPriority::High` |
| 3 | "Завтра в школі тобі кінець" | `ThreatType::Threat`, високий ризик прямої погрози | Зазвичай `Warn`, `SuggestBlockContact`, `SuggestReport`, guardian escalation |

Що важливо:

- `pile-on` зараз приходить як context signal з `reason_code =
  abuse.bullying.pile_on`; це не окремий `EventKind`.
- Для `ThreatType::Bullying` AURA додає `SuggestReport` і
  `SlowDownConversation`, коли score доходить до warn band або до `0.60+`.

## Сценарій 3: Олена ділиться адресою

| Повідомлення | Що бачить AURA | Типова реакція |
| --- | --- | --- |
| "Я живу на вул. Шевченка 15, кв 42" | `ThreatType::PiiLeakage`, `score ~0.70` | `Warn`, показує `WarnBeforeSend` перед відправкою |
| Олена все одно тисне "Відправити" | Повідомлення не блокується | AURA пропускає повідомлення, але піднімає guardian alert і додає `ReviewContactProfile` |

Ключовий принцип:

- `PII leakage` не блокується. Це не атака дитини на когось іншого, а ризикова
  саморозкритість.
- Для `ThreatType::PiiLeakage` правила такі: `mark >= 0.40`, `warn >= 0.70`,
  `block` ніколи не використовується.

## Сценарій 4: селфхарм і кризова ситуація

| Повідомлення | Що бачить AURA | Типова реакція |
| --- | --- | --- |
| "Мені так погано, не хочу більше жити" | `ThreatType::SelfHarm`, `RiskHorizon::Immediate`, `score ~0.65` | Завжди `Warn`, ніколи не `Block`; показує `ShowCrisisSupport`, піднімає `AlertPriority::Urgent`, додає `EscalateToGuardian` |

Що бачить Олена:

> Якщо тобі дуже важко, звернись по допомогу зараз. Ти не одна.

Ключовий принцип:

- `Self-harm` не блокується, щоб не ізолювати дитину в момент кризи.
- У кризових кейсах AURA піднімає `crisis_resources = true` і змушує guardian
  escalation.

## Сценарій 5: фішингове посилання

| Повідомлення | Що бачить AURA | Типова реакція |
| --- | --- | --- |
| "Зайди сюди отримати безкоштовні робукси!!! http://fr33-r0bux.xyz/claim" | `ThreatType::Phishing`, підозрілий домен, `score ~0.85+` | `Block`, `ConfirmBeforeOpenLink`, `SuggestReport`, `AlertPriority::Medium` |

Що важливо:

- Для `ThreatType::Phishing` правила зараз такі: `warn >= 0.60`,
  `block >= 0.85`.
- Посилання деактивується ще до відкриття.

## Сценарій 6: маніпуляція від знайомого старшого підлітка

| Крок | Повідомлення | Що бачить AURA | Типова реакція |
| --- | --- | --- | --- |
| 1 | "Якщо ти мене не послухаєш, я розповім усім що ти..." | `ThreatType::Manipulation`, `reason_code = conversation.manipulation.screenshot_reputation_blackmail` | Зазвичай `Warn`, `SuggestBlockContact`, `SuggestReport`, `AlertPriority::Medium` |
| 2 | Повторні тиски протягом днів | Росте latent state `CoerciveControl` | AURA додає `SlowDownConversation`, а при сильнішій ескалації лишає або підсилює `SuggestReport` |

Що важливо:

- Для `ThreatType::Manipulation` базові пороги зараз: `warn >= 0.65`,
  `block >= 0.90`.
- `SuggestReport` тут часто додається не тільки через сам threat, а й через
  reportable reason codes та inference про coercive control.

## Як AURA дивиться на контакт з часом

`ContactProfiler` не зберігає людські ярлики на кшталт `Stranger`. Реальні поля
зараз такі:

- `circle_tier`: `New`, `Occasional`, `Regular`, `Inner`
- `trend`: `Stable`, `Improving`, `GradualWorsening`, `RapidWorsening`,
  `RoleReversal`

Приклад:

```text
"Макс": low rating, low trust, circle_tier = New
  - week 1: flattery, gift leverage, secrecy, photo request
  - trend: RapidWorsening
  - contacts_many_minors: heuristic risk flag, not a verified age graph

"Марія": high rating, high trust, circle_tier = Inner
  - long stable history of normal peer conversation
  - trend: Stable
```

Важлива деталь:

- `contacts_many_minors` у поточному коді це евристика ризику
  (`conversation_count >= 5 && grooming_event_count >= 3`), а не доведений
  граф контактів з неповнолітніми.
- Низький рейтинг контакту не змінює policy thresholds напряму, але впливає на
  context risk, inference та те, наскільки підозріло AURA трактує ескалацію.

## Підсумок рівнів реакції

Для `ProtectionLevel::High` базова шкала така:

| Дія | Коли спрацьовує | Що бачить дитина |
| --- | --- | --- |
| `Allow` | `score < 0.20` | Нічого |
| `Mark` | `0.20-0.34` | Тонка позначка на повідомленні |
| `Blur` | `0.35-0.49` | Текст розмитий до натискання |
| `Warn` | `0.50-0.79` | Попередження перед показом або перед відправкою |
| `Block` | `0.80+` | Контент блокується |

Threat-specific overrides важливіші за базову шкалу:

- `Grooming`: `warn >= 0.60`, `block >= 0.85`
- `Bullying`: `warn >= 0.70`, `block >= 0.90`
- `Phishing`: `warn >= 0.60`, `block >= 0.85`
- `PiiLeakage`: `mark >= 0.40`, `warn >= 0.70`, без `block`
- `SelfHarm`: завжди `Warn` + crisis support
