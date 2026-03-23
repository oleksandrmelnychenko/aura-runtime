# Russian Propaganda & Disinformation Detection Research
## Comprehensive Reference for AURA Anti-Propaganda Module

*Research compiled: 2026-03-23*

Implementation sync: reviewed against current repository behavior on 2026-03-23.

## Runtime Implementation Snapshot (Current)

- Current `patterns_mvp.json` footprint is 322 rules.
- Runtime analyzer applies propaganda false-positive context filtering before
  emitting propaganda pattern signals.
- Generic decimal coordinate rule handling includes runtime Ukraine DD
  validation, and duplicate generic coordinate signals are suppressed when the
  Ukraine-specific DD rule also matches.
- Signal payloads include `threat_subtype` and currently expose military and
  propaganda-specific subtype values used by product and review surfaces.
- Heuristic URL detections expose subtype values `doppelganger`, `homoglyph`,
  and `heuristic`.

---

## Table of Contents

1. [Research Sources and Methodology](#1-research-sources-and-methodology)
2. [Key Russian Disinformation Narratives](#2-key-russian-disinformation-narratives)
3. [Propaganda Techniques and Psychological Manipulation](#3-propaganda-techniques-and-psychological-manipulation)
4. [Known Propaganda Domains and Sources](#4-known-propaganda-domains-and-sources)
5. [OPSEC Violations in Military Context](#5-opsec-violations-in-military-context)
6. [Psyops Patterns](#6-psyops-patterns)
7. [Keyword Lists for Pattern Matching](#7-keyword-lists-for-pattern-matching)
8. [Detection Engineering Implications](#8-detection-engineering-implications)
9. [Severity Rating Framework](#9-severity-rating-framework)
10. [Key Academic References](#10-key-academic-references)

---

## 1. Research Sources and Methodology

This report synthesizes findings from the following authoritative sources:

### Academic and Think Tank Research
- **RAND Corporation**: "The Russian 'Firehose of Falsehood' Propaganda Model" (Christopher Paul & Miriam Matthews, 2016); "Russian Social Media Influence" (2018); "Hostile Social Manipulation" (2019)
- **Atlantic Council / DFRLab**: Digital Forensic Research Lab reports on Russian information operations, bot network analysis, coordinated inauthentic behavior tracking
- **EU DisinfoLab**: Reports on Russian disinformation infrastructure, Doppelganger campaign analysis, Secondary Infektion operation analysis
- **NATO StratCom COE (Riga)**: "Russia's Strategy in Cyberspace" (2021); "Social Media as a Tool of Hybrid Warfare" (multiple years); information operations analysis reports

### Fact-Checking and Monitoring Organizations
- **EUvsDisinfo** (EEAS East StratCom Task Force): Database of 16,000+ disinformation cases (2015-present), pro-Kremlin disinformation narrative tracking
- **StopFake.org** (Kyiv, Ukraine): Ukrainian fact-checking organization tracking Russian disinformation since 2014
- **Texty.org.ua**: Ukrainian data journalism outlet, Telegram propaganda network analysis
- **VoxCheck** (VoxUkraine): Ukrainian analytical platform tracking disinformation

### Government and Military Sources
- **Ukrainian CIPSO** (Centre for Information and Psychological Operations): Reports on Russian IPSO (informational-psychological special operations)
- **CCD (Centre for Countering Disinformation)** under NSDC of Ukraine: Official narrative tracking, propaganda case studies
- **Ukrainian SSU (SBU)**: Published analyses of intercepted Russian bot farm operations
- **UK DCMS Committee**: Reports on Russian disinformation targeting Western audiences

---

## 2. Key Russian Disinformation Narratives

### 2.1 Denial of War / Aggression

**Core narrative**: Russia is not conducting a war of aggression; it is a "special military operation" for legitimate security purposes.

**Severity: CRITICAL**

#### Keywords and Phrases

**Russian (RU):**
- "специальная военная операция" (special military operation)
- "спецоперация" / "СВО" (abbreviation)
- "не война а спецоперация" (not a war but a special operation)
- "вынужденная мера" (forced measure)
- "превентивный удар" (preemptive strike)
- "защита Донбасса" (defense of Donbas)
- "защита русскоязычного населения" (protection of Russian-speaking population)
- "геноцид в Донбассе" (genocide in Donbas)
- "восемь лет бомбили Донбасс" (they bombed Donbas for eight years)
- "8 лет Донбасс" (8 years Donbas)
- "гражданская война на Украине" (civil war in Ukraine)
- "внутренний конфликт" (internal conflict)
- "внутриукраинский конфликт" (intra-Ukrainian conflict)
- "не агрессия а самооборона" (not aggression but self-defense)
- "денацификация" (denazification)
- "демилитаризация" (demilitarization)

**Ukrainian (UK):**
- "спецоперація" (special operation)
- "це не війна" (this is not a war)
- "внутрішній конфлікт" (internal conflict)
- "громадянська війна" (civil war)
- "не агресія" (not aggression)
- "захист Донбасу" (defense of Donbas)
- "геноцид на Донбасі" (genocide in Donbas)
- "вісім років бомбили Донбас" (they bombed Donbas for eight years)
- "денацифікація" (denazification)
- "деміліатризація" (demilitarization)

**Detection note**: The term "спецоперація/спецоперация" is the single most reliable propaganda marker. Its use to describe Russia's full-scale invasion is mandated by Russian law (amendments to the Criminal Code, March 2022). Context matters: the phrase can appear in legitimate reporting about the term itself.

---

### 2.2 "Brotherhood" / "One People" Narrative

**Core narrative**: Ukrainians and Russians are "one people"; Ukraine is not a real nation/state; Ukrainian identity is artificial.

**Severity: HIGH**

#### Keywords and Phrases

**Russian (RU):**
- "один народ" (one people)
- "братские народы" (brotherly peoples)
- "братские страны" (brotherly countries)
- "единый народ" (unified people)
- "мы один народ" (we are one people)
- "общая история" + dismissal of Ukrainian sovereignty (common history)
- "искусственное государство" (artificial state)
- "Украина не государство" (Ukraine is not a state)
- "проект Украина" (project Ukraine)
- "антироссия" / "анти-Россия" (anti-Russia -- Putin's framework)
- "Малороссия" (Little Russia -- imperial term for Ukraine)
- "Новороссия" (New Russia -- imperial term for southern Ukraine)
- "исторически русская земля" (historically Russian land)
- "русский мир" (Russian world)
- "триединый русский народ" (triune Russian people)
- "общерусское единство" (all-Russian unity)
- "украинство это болезнь" (Ukrainianness is a disease)
- "выдуманный народ" (invented people)
- "выдуманный язык" (invented language)

**Ukrainian (UK):**
- "один народ" (one people)
- "братні народи" (brotherly peoples)
- "єдиний народ" (unified people)
- "штучна держава" (artificial state)
- "Україна не держава" (Ukraine is not a state)
- "проект Україна" (project Ukraine)
- "антиросія" (anti-Russia)
- "Малоросія" (Little Russia)
- "Новоросія" (New Russia)
- "історично російська земля" (historically Russian land)
- "руський мир" / "русский мир" (Russian world)
- "вигаданий народ" (invented people)
- "вигадана мова" (invented language)

**Detection note**: Putin's July 2021 article "On the Historical Unity of Russians and Ukrainians" is the foundational document. These phrases deny Ukrainian statehood and are used to justify invasion. The term "русский мир" (Russian World) is particularly significant as it represents the geopolitical ideology underpinning Russian expansionism.

---

### 2.3 Discrediting Ukrainian Military / "Nazi" Narrative

**Core narrative**: Ukraine is run by Nazis; the Ukrainian military consists of Nazi battalions; "denazification" justifies the invasion.

**Severity: CRITICAL**

#### Keywords and Phrases

**Russian (RU):**
- "нацисты" (Nazis)
- "неонацисты" (neo-Nazis)
- "нацбаты" / "нацбатальоны" (Nazi battalions)
- "каратели" (punishers -- Soviet-era term for those who fought against USSR)
- "бандеровцы" (Banderites -- followers of Bandera, used as slur)
- "укронацисты" (Ukro-Nazis)
- "укрофашисты" (Ukro-fascists)
- "фашистский режим" (fascist regime)
- "нацистский режим в Киеве" (Nazi regime in Kyiv)
- "хунта" (junta -- used since 2014 for Ukrainian government)
- "киевский режим" (Kyiv regime)
- "киевская хунта" (Kyiv junta)
- "режим Зеленского" (Zelensky regime)
- "марионетки" (puppets)
- "наркоман Зеленский" (Zelensky the drug addict)
- "кокаиновый президент" (cocaine president)
- "клоун" (clown -- referring to Zelensky)
- "азовцы" (Azov members -- used as blanket Nazi accusation)
- "террористы ВСУ" (VSU terrorists)
- "преступный режим" (criminal regime)
- "незаконный режим" (illegitimate regime)
- "укропы" (ukrops -- derogatory slur for Ukrainians)
- "укры" (ukrs -- derogatory)
- "хохлы" (khokhly -- ethnic slur for Ukrainians)

**Ukrainian (UK):**
- "нацисти" (Nazis)
- "нацбати" (Nazi battalions)
- "каратели" (punishers)
- "бандерівці" (Banderites)
- "укронацисти" (Ukro-Nazis)
- "фашистський режим" (fascist regime)
- "хунта" (junta)
- "київський режим" (Kyiv regime)
- "режим Зеленського" (Zelensky regime)
- "маріонетки" (puppets)
- "наркоман Зеленський" (Zelensky the drug addict)
- "клоун" (clown)
- "терористи ЗСУ" (ZSU terrorists)

**Detection note**: The "Nazi" narrative is the cornerstone of Russia's casus belli. While Azov Battalion's early far-right links are historically documented, Russia uses this to paint the entire Ukrainian state and military as Nazi. The term "каратели" (punishers) is specifically loaded: in Soviet propaganda, it referred to anti-Soviet partisans, and applying it to the Ukrainian military is deliberately designed to invoke WW2-era framing.

---

### 2.4 Capitulation / Defeatism Narratives

**Core narrative**: Ukraine cannot win; resistance is futile; surrender is the only option; Western aid will dry up.

**Severity: CRITICAL**

#### Keywords and Phrases

**Russian (RU):**
- "Украина должна капитулировать" (Ukraine must capitulate)
- "надо сдаться" (must surrender)
- "нет шансов" (no chance)
- "бессмысленное сопротивление" (pointless resistance)
- "безнадежная ситуация" (hopeless situation)
- "кровопролитие нужно остановить" (bloodshed must be stopped [implying by surrender])
- "Украина не может победить" (Ukraine cannot win)
- "зачем гибнуть" (why die)
- "бессмысленная война" (pointless war [implying Ukraine should stop fighting])
- "мясорубка" (meat grinder -- dehumanizing Ukrainian military)
- "пушечное мясо" (cannon fodder)
- "зачем воевать за Зеленского" (why fight for Zelensky)
- "Запад бросит Украину" (the West will abandon Ukraine)
- "усталость от Украины" (Ukraine fatigue)
- "Запад устал" (the West is tired)
- "Запад предаст" (the West will betray)
- "помощь закончится" (aid will end)
- "оружие только продлевает войну" (weapons only prolong the war)

**Ukrainian (UK):**
- "треба здатися" (must surrender)
- "треба капітулювати" (must capitulate)
- "немає шансів" (no chance)
- "безглузда війна" (pointless war)
- "безглуздий спротив" (pointless resistance)
- "безнадійна ситуація" (hopeless situation)
- "навіщо гинути" (why die)
- "Захід кине Україну" (the West will abandon Ukraine)
- "Захід втомився" (the West is tired)
- "допомога закінчиться" (aid will end)
- "гарматне м'ясо" (cannon fodder)
- "м'ясорубка" (meat grinder)
- "нащо воювати за Зеленського" (why fight for Zelensky)
- "зброя лише продовжує війну" (weapons only prolong the war)
- "нас усіх вб'ють" (they will kill us all)
- "здавайся і виживеш" (surrender and you will survive)
- "ми не можемо перемогти" (we cannot win)
- "перемога неможлива" (victory is impossible)

**Detection note**: Capitulation narratives are among the most actively promoted by Russian psyops, particularly targeting Ukrainian military personnel and their families via Telegram and direct messaging. They often appear disguised as "peace" advocacy -- "мир будь-якою ціною" (peace at any price). The key differentiator from genuine peace advocacy is the asymmetric framing: the implied solution is always Ukraine's surrender, never Russia's withdrawal.

---

### 2.5 "Betrayal" / "Zrada" Narratives

**Core narrative**: Ukrainian leaders have betrayed the people; corruption makes resistance pointless; the government is selling out the country.

**Severity: HIGH**

#### Keywords and Phrases

**Russian (RU):**
- "зрада" (betrayal -- borrowed from Ukrainian, used ironically)
- "предательство" (betrayal)
- "продали страну" (sold out the country)
- "Зеленский продал Украину" (Zelensky sold Ukraine)
- "коррумпированная власть" (corrupt government)
- "олигархи" + negative military context (oligarchs)
- "воруют помощь" (stealing aid)
- "оружие продают" (selling weapons)
- "западное оружие на черном рынке" (Western weapons on the black market)
- "генералы предали" (generals betrayed)
- "командование бросило" (command abandoned [soldiers])
- "предатели в верхах" (traitors at the top)

**Ukrainian (UK):**
- "зрада" (betrayal)
- "продали" (sold out)
- "продали країну" (sold out the country)
- "Зеленський продав Україну" (Zelensky sold Ukraine)
- "корумпована влада" (corrupt government)
- "крадуть допомогу" (stealing aid)
- "зброю продають" (selling weapons)
- "західна зброя на чорному ринку" (Western weapons on the black market)
- "генерали зрадили" (generals betrayed)
- "командування кинуло" (command abandoned)
- "зрадники нагорі" (traitors at the top)
- "все пропало" (all is lost)
- "влада бреше" (government lies)
- "нас обманюють" (they are deceiving us)
- "нас використовують" (they are using us)
- "Україну здають" (Ukraine is being surrendered)

**Detection note**: The "зрада" (betrayal) narrative is particularly insidious because Ukraine genuinely has corruption challenges, making the narrative partially grounded in reality. Russian propaganda amplifies and weaponizes legitimate grievances. Detection must distinguish between legitimate criticism/journalism and coordinated amplification of defeatist narratives. Key indicators of propagandistic use: (1) the narrative appears in clusters from multiple accounts; (2) it is paired with capitulation framing; (3) it targets military morale specifically.

---

### 2.6 Western Conspiracy Narratives

**Core narrative**: The West (NATO/US) provoked the war; the West is using Ukraine as a proxy; the West wants to destroy Russia.

**Severity: HIGH**

#### Keywords and Phrases

**Russian (RU):**
- "НАТО спровоцировало" (NATO provoked it)
- "расширение НАТО" (NATO expansion)
- "угроза НАТО" (NATO threat)
- "НАТО у границ России" (NATO at Russia's borders)
- "прокси-война" / "война до последнего украинца" (proxy war / war to the last Ukrainian)
- "до последнего украинца" (to the last Ukrainian)
- "англосаксы" (Anglo-Saxons -- Russian propaganda term for US/UK)
- "англосаксонский заговор" (Anglo-Saxon conspiracy)
- "Запад хочет уничтожить Россию" (the West wants to destroy Russia)
- "русофобия" (Russophobia)
- "антироссийский заговор" (anti-Russian conspiracy)
- "биолаборатории на Украине" (biolabs in Ukraine)
- "американские биолаборатории" (American biolabs)
- "биологическое оружие" (biological weapons -- in Ukraine context)
- "грязная бомба" (dirty bomb)
- "провокация Запада" (Western provocation)
- "майдан это переворот" (Maidan is a coup)
- "госпереворот" / "государственный переворот" (state coup -- re 2014)
- "внешнее управление" (external governance -- claim Ukraine is controlled from outside)
- "марионеточное правительство" (puppet government)
- "кукловоды" (puppet masters)

**Ukrainian (UK):**
- "НАТО спровокувало" (NATO provoked it)
- "розширення НАТО" (NATO expansion)
- "проксі-війна" (proxy war)
- "до останнього українця" (to the last Ukrainian)
- "англосакси" (Anglo-Saxons)
- "Захід хоче знищити Росію" (the West wants to destroy Russia)
- "русофобія" (Russophobia)
- "біолабораторії в Україні" (biolabs in Ukraine)
- "брудна бомба" (dirty bomb)
- "Майдан це переворот" (Maidan is a coup)
- "державний переворот" (state coup)
- "зовнішнє управління" (external governance)
- "маріонетковий уряд" (puppet government)

**Detection note**: The "biolabs" narrative was one of the most heavily promoted disinformation campaigns in 2022, amplified by Chinese state media as well. The "до последнего украинца" (to the last Ukrainian) phrase is extremely common in Russian propaganda and frames Western support as cynically sacrificing Ukrainians. "Англосаксы" is a reliable marker of Russian state media framing.

---

### 2.7 Historical Revisionism

**Core narrative**: Rewriting history to justify Russian claims on Ukrainian territory and deny Ukrainian historical agency.

**Severity: HIGH**

#### Keywords and Phrases

**Russian (RU):**
- "подарок Хрущёва" / "подарок Хрущева" (Khrushchev's gift -- re Crimea)
- "Крым всегда был русским" (Crimea was always Russian)
- "исконно русская земля" (primordially Russian land)
- "Киев мать городов русских" (Kyiv is the mother of Russian cities)
- "Украину придумал Ленин" (Lenin invented Ukraine)
- "Украина создана большевиками" (Ukraine was created by the Bolsheviks)
- "Голодомор это миф" / "не было голодомора" (Holodomor is a myth / there was no Holodomor)
- "не было геноцида" (there was no genocide -- re Holodomor)
- "голод был везде" (the famine was everywhere -- minimizing Holodomor)
- "бандеровцы убивали поляков" (Banderites killed Poles -- weaponizing Volhynia)
- "коллаборационисты" (collaborators -- blanket accusation against UPA)
- "история переписывается" (history is being rewritten -- projection)
- "фальсификация истории" (falsification of history -- projection)
- "Великая Отечественная война" exclusively (Great Patriotic War -- rejecting "WW2" framing)
- "победили фашизм" (we defeated fascism -- appropriating entire Allied victory)

**Ukrainian (UK):**
- "подарунок Хрущова" (Khrushchev's gift)
- "Крим завжди був російським" (Crimea was always Russian)
- "споконвіку російська земля" (primordially Russian land)
- "Україну придумав Ленін" (Lenin invented Ukraine)
- "Голодомор це міф" (Holodomor is a myth)
- "не було голодомору" (there was no Holodomor)
- "голод був скрізь" (the famine was everywhere)
- "бандерівці вбивали поляків" (Banderites killed Poles)
- "фальсифікація історії" (falsification of history)

**Detection note**: Historical revisionism serves as the intellectual foundation for other propaganda narratives. It attempts to delegitimize Ukrainian statehood at its historical roots. The Holodomor denial is particularly significant as it mirrors Holocaust denial patterns and is recognized as denial of genocide by multiple countries.

---

## 3. Propaganda Techniques and Psychological Manipulation

### 3.1 The "Firehose of Falsehood" Model (RAND)

RAND Corporation identified four key features of the Russian propaganda model:

1. **High volume and multichannel**: Flood information space with content across TV, social media, messaging apps, comments sections, and bot networks simultaneously
2. **Rapid, continuous, and repetitive**: Don't wait for facts; be first with a narrative, then repeat it
3. **Lack of commitment to objective reality**: No concern for consistency; contradictory narratives can coexist
4. **Lack of commitment to consistency**: Multiple competing theories about the same event (e.g., MH17: "Ukraine did it" + "it was a CIA plot" + "there were already dead bodies on the plane")

### 3.2 Specific Techniques

#### Whataboutism ("А что насчёт...")
**Pattern**: Deflecting criticism by pointing to real or alleged wrongdoing by others.
**Keywords (RU)**: "а что насчёт", "а как насчёт", "а вот америка", "а в сша", "двойные стандарты", "а что с Ираком", "а что с Югославией", "а бомбили Сербию", "а ливию кто бомбил"
**Keywords (UK)**: "а що щодо", "а як щодо", "а от америка", "а в сша", "подвійні стандарти", "а що з Іраком", "а що з Югославією"
**Severity**: MEDIUM (technique marker, not content)

#### False Equivalence
**Pattern**: Equating Russian aggression with unrelated Western military actions.
**Keywords (RU)**: "то же самое что", "ничем не отличается от", "такие же как", "обе стороны виноваты", "обе стороны", "обоюдная вина", "война с двух сторон"
**Keywords (UK)**: "те ж саме що", "нічим не відрізняється від", "обидві сторони винні", "обидві сторони"
**Severity**: MEDIUM

#### Cherry-picking / Selective Evidence
**Pattern**: Using isolated facts out of context to support a false narrative.
**Indicators**: Sharing a single photo/video without context; referencing a single incident as proof of a systemic claim; citing outdated statistics
**Severity**: MEDIUM (hard to detect via keywords alone; needs contextual analysis)

#### Appeal to Fear
**Pattern**: Using nuclear threats, WW3 scenarios, and escalation warnings to discourage Ukrainian resistance and Western support.
**Keywords (RU)**: "третья мировая", "ядерная война", "ядерный удар", "конец света", "апокалипсис", "будет как Хиросима", "красная кнопка", "Россия ядерная держава", "не провоцируйте Россию"
**Keywords (UK)**: "третя світова", "ядерна війна", "ядерний удар", "кінець світу", "апокаліпсис", "буде як Хіросіма", "Росія ядерна держава", "не провокуйте Росію"
**Severity**: HIGH

#### Dehumanization
**Pattern**: Using dehumanizing language for Ukrainians, their military, or their leadership.
**Keywords (RU)**: "укропы", "хохлы", "свинособаки", "нелюди", "недочеловеки", "отребье", "биомусор", "укронацисты", "укрофашисты", "бандерлоги", "майдауны"
**Keywords (UK)**: "укропи", "хохли", "свинособаки", "нелюди", "бандерлоги", "майдауни"
**Severity**: CRITICAL (hate speech + dehumanization)

#### Conspiracy Theory Amplification
**Pattern**: Promoting unverifiable conspiracy theories to undermine trust.
**Keywords (RU)**: "тайный план", "мировое правительство", "глобалисты", "Сорос", "рептилоиды", "теневое правительство", "новый мировой порядок", "мировая закулиса", "кукловоды", "заговор"
**Keywords (UK)**: "таємний план", "світовий уряд", "глобалісти", "Сорос", "рептилоїди", "тіньовий уряд", "новий світовий порядок", "маріонетки", "змова"
**Severity**: MEDIUM

#### Emotional Manipulation Patterns
**Pattern**: Using emotional appeals (dead children, suffering civilians) while attributing them to Ukraine's resistance rather than Russian aggression.
**Indicators**:
- "Дети гибнут из-за Зеленского" (Children die because of Zelensky)
- "Зеленский виноват в смертях" (Zelensky is guilty of deaths)
- "Кровь на руках Зеленского" (Blood on Zelensky's hands)
- "Кровь на руках Запада" (Blood on the West's hands)
- "Прекратите войну сдайтесь" (Stop the war, surrender)
- Reversed attribution: showing Russian shelling damage and claiming Ukraine did it
**Severity**: HIGH

#### Fake News Structural Patterns
Identifiable structural elements of fabricated news:
1. **Anonymous sourcing**: "по данным источников" (according to sources), "стало известно" (it became known), "по информации" (according to information)
2. **Urgent framing**: "СРОЧНО", "МОЛНИЯ", "BREAKING" in Cyrillic
3. **Emotional headlines**: Heavy use of exclamation marks, all-caps, alarming language
4. **Misattributed media**: Reused images/videos from other conflicts
5. **Fabricated quotes**: Attributed to Western officials or Ukrainian military
6. **False flag framing**: Every Russian attack attributed to Ukraine attacking itself

---

## 4. Known Propaganda Domains and Sources

### 4.1 Russian State Media Domains

**Tier 1 -- Direct State Control (Severity: CRITICAL)**
```
rt.com, russian.rt.com, rtvi.com
ria.ru, rian.ru
tass.ru, tass.com
sputniknews.com, sputnikglobe.com
smotrim.ru (Rossiya TV)
vgtrk.ru
1tv.ru (Channel One)
ntv.ru
ren.tv
gazeta.ru (state-aligned)
iz.ru (Izvestia)
rg.ru (Rossiyskaya Gazeta -- government official paper)
kommersant.ru (increasingly state-aligned)
lenta.ru (state-controlled since 2014)
```

**Tier 2 -- State-Aligned / Oligarch-Controlled (Severity: HIGH)**
```
tsargrad.tv (Malofeev/Orthodox nationalist)
life.ru
vz.ru (Vzglyad)
regnum.ru
politnavigator.net
rusvesna.su
anna-news.info
southfront.org (GRU-linked per FBI)
news-front.info / news-front.su
riafan.ru (Prigozhin-linked)
nevskienovosti.ru
```

**Tier 3 -- Occupation Authorities / Pseudo-State Media (Severity: CRITICAL)**
```
dan-news.info (DNR news)
lug-info.com (LNR news)
dnr-online.ru
lugansk-online.info
novorosinform.org
crimea.ria.ru
```

### 4.2 Known Disinformation Infrastructure Domains

**"Doppelganger" Campaign Domains (EU DisinfoLab investigation)**
Domains that impersonate legitimate Western media:
```
Pattern: legitimate-domain-name with altered TLD or subdomain
Examples documented by EU DisinfoLab:
- Clones of Bild, Le Monde, Der Spiegel, The Guardian with altered domains
- Typically use .ltd, .live, .news, .online, .info TLDs
- Often hosted on Russian or bulletproof hosting
```

**"Secondary Infektion" / "Ghostwriter" Operation Domains**
```
Rotating domain infrastructure -- detection should focus on:
- Newly registered domains (< 30 days)
- Domains with Cyrillic homoglyph substitution
- Domains mimicking .gov.ua or .mil.ua
```

### 4.3 Telegram Channels Known for Propaganda Amplification

Detection should flag links to known propaganda Telegram channels. Key categories:
- Channels operated by Russian MoD (Минобороны России)
- Channels associated with "военкоры" (war correspondents) who spread coordinated narratives
- Channels run by occupation administrations
- Channels identified by SBU/CCD as IPSO operations

**URL patterns to detect:**
```
t.me/[known_propaganda_channel]
telegram.me/[known_propaganda_channel]
```

### 4.4 Bot Farm Indicators

Based on SBU takedowns and DFRLab analysis:

**Account behavior patterns:**
- Account created recently (< 3 months before activity)
- Posts in bursts at regular intervals
- Identical or near-identical text across multiple accounts
- Shares content from Tier 1/2 sources exclusively
- Uses specific hashtags in coordinated manner
- Profile pictures: stock photos, AI-generated faces, stolen photos
- Username patterns: [FirstName][Numbers], [word]_[word]_[numbers]

**Message content patterns:**
- Copy-paste text blocks (identical across accounts)
- Messages containing multiple propaganda keywords from different categories
- Structured "question-answer" format pushing narratives
- Links to known propaganda domains
- Rapid topic switching between unrelated propaganda themes

---

## 5. OPSEC Violations in Military Context

### 5.1 Coordinate Format Detection

**Severity: CRITICAL**

Messages containing geographic coordinates near Ukrainian military positions represent critical OPSEC violations.

**Decimal Degrees (DD.DDDDDD):**
```regex
\b\d{2}\.\d{4,7}\s*[,;/\s]\s*\d{2}\.\d{4,7}\b
```
Example: `48.464717, 35.046183` (Dnipro area)
Ukraine coordinate ranges: Lat 44.0-52.5, Lon 22.0-40.5

**Degrees Minutes Seconds (DMS):**
```regex
\b\d{2}[°]\s*\d{1,2}['′]\s*\d{1,2}(?:\.\d+)?["″]\s*[NnПнСс]\s*\d{2}[°]\s*\d{1,2}['′]\s*\d{1,2}(?:\.\d+)?["″]\s*[EeСхВв]
```

**Military Grid Reference System (MGRS):**
```regex
\b\d{2}[A-Z]\s*[A-Z]{2}\s*\d{4,10}\b
```
Example: `36T UQ 12345 67890`

**Ukrainian Military Grid (used in some units):**
```regex
\b(?:квадрат|кв\.?)\s*\d{2,4}[-/]\d{2,4}\b
```

**What3Words (sometimes used):**
```regex
(?:what3words\.com/|w3w\.co/|///)[а-яіїєґa-z]+\.[а-яіїєґa-z]+\.[а-яіїєґa-z]+
```

### 5.2 Types of Military Information Commonly Leaked

**Severity: CRITICAL**

#### Location Information
**Keywords (UK/RU) that indicate position disclosure:**
- "наша позиція" / "наша позиция" (our position)
- "ми стоїмо в" / "мы стоим в" (we are stationed in)
- "ми зараз під" / "мы сейчас под" (we are now near)
- "наш блокпост" / "наш блокпост" (our checkpoint)
- "розташування" / "расположение" (deployment location)
- "дислокація" / "дислокация" (dislocation/deployment)
- "координати" / "координаты" (coordinates)
- "позиція на" / "позиция на" (position at)
- "ми базуємось" / "мы базируемся" (we are based)

#### Unit Information
**Keywords that indicate unit identification disclosure:**
- "наша бригада" / "наша бригада" (our brigade)
- "наш батальйон" / "наш батальон" (our battalion)
- "наша рота" / "наша рота" (our company)
- "ми з [number] бригади" / "мы из [number] бригады" (we are from [N] brigade)
- "наш підрозділ" / "наше подразделение" (our unit)
- "наш позивний" / "наш позывной" (our callsign)
- Brigade numbers combined with locations

#### Equipment Information
**Keywords indicating weapons/equipment disclosure:**
- "отримали" + weapon type / "получили" + weapon type (received [weapon])
- "маємо" + weapon/vehicle / "у нас есть" (we have [equipment])
- "HIMARS", "Javelin", "NLAW", "Bayraktar", "Леопард", "Бредлі" etc. + location
- "снарядів залишилось" / "снарядов осталось" (shells remaining)
- "БК на [number]" (ammunition for [number] -- ammo count)

#### Movement Information
**Keywords indicating troop movement:**
- "ми виїжджаємо" / "мы выезжаем" (we are departing)
- "ротація" / "ротация" (rotation)
- "їдемо на" / "едем на" (heading to)
- "відступаємо" / "отступаем" (retreating)
- "перегрупування" / "перегруппировка" (regrouping)
- "колона" + direction / "колонна" (column)
- "марш" + destination (march)

#### Casualty and Morale Information
**Keywords indicating operational status:**
- "двохсотий" / "двухсотый" (200 -- KIA code)
- "трьохсотий" / "трёхсотый" (300 -- WIA code)
- "втрати" / "потери" (losses)
- "скільки наших" / "сколько наших" (how many of ours)
- "некомплект" (understrength)
- "людей не вистачає" / "людей не хватает" (not enough personnel)

### 5.3 Social Engineering Targeting Military Personnel

**Severity: CRITICAL**

#### Fake Дія (Diia) App Messages
**Pattern**: Messages impersonating Ukraine's Diia digital services app.
```
Keywords: "Дія", "Дiя" (with Latin i), "diia.gov.ua"
Phishing URLs: domains mimicking diia.gov.ua
- diia-gov.com, diya.gov.ua.*, diia-update.*
- "оновіть додаток Дія" (update Diia app)
- "ваш запис в Дії потребує підтвердження" (your Diia record needs confirmation)
- "електронний військовий квиток" (electronic military ID)
```

#### Fake ТЦК (Territorial Recruitment Center) Messages
**Pattern**: Messages impersonating TCC (military recruitment) to cause panic or extract information.
```
Keywords: "ТЦК", "повістка", "повестка" (summons)
- "вам надійшла повістка" (you have received a summons)
- "електронна повістка" (electronic summons)
- "підтвердіть дані для ТЦК" (confirm your data for TCC)
- "мобілізація" (mobilization)
- "бронювання" (reservation/exemption)
- "ви підлягаєте мобілізації" (you are subject to mobilization)
- "перевірте свій статус" (check your status)
```

#### Fake Military Command Messages
**Pattern**: Messages impersonating military command to extract operational info.
```
- "штаб запитує" (HQ requests)
- "терміново повідомте координати" (urgently report coordinates)
- "доповідь про стан" (status report)
- "надішліть дані" (send data)
- "підтвердіть розташування" (confirm location)
- "новий наказ" + link (new order)
```

#### Honey Trap / Romance Scam Targeting Military
**Pattern**: Women's profiles targeting military personnel to extract OPSEC info.
```
Indicators:
- New profile, attractive photos (often stolen/AI-generated)
- Quick interest in military service details
- Questions about deployment, location, unit
- "де ти зараз служиш" (where are you serving now)
- "коли повернешся" (when will you return)
- "де твоя частина" (where is your unit)
- "скучила, коли ротація" (I miss you, when is rotation)
- Requests for photos with identifiable backgrounds
```

### 5.4 Military-Specific Phishing Patterns

**Severity: CRITICAL**

#### Phishing URL Patterns
```regex
# Fake military/government domains
https?://[\\w.-]*(?:mil[-.]ua|zsu[-.](?:gov|org|net)|diia[-.](?:gov|app)|tck[-.](?:gov|ua)|oberig[-.](?:gov|ua))[\\w./-]*

# Fake Delta/Kropyva (military systems)
https?://[\\w.-]*(?:delta[-.](?:mil|gov)|kropyva[-.](?:mil|app))[\\w./-]*
```

#### Signal/Telegram Account Takeover Attempts
```
- "ваш акаунт буде видалено" (your account will be deleted)
- "підтвердіть номер телефону" (confirm your phone number)
- "код підтвердження" (confirmation code)
- "надішліть код що прийшов" (send the code that came)
- "поділіться кодом" (share the code)
```

---

## 6. Psyops Patterns

### 6.1 Demoralization Messaging Patterns

**Severity: CRITICAL**

#### Targeting Military Personnel Directly
**Keywords (UK):**
- "вас кинуло командування" (command abandoned you)
- "ваші генерали сидять в тилу" (your generals sit in the rear)
- "вас послали на смерть" (they sent you to die)
- "ніхто за вас не прийде" (nobody will come for you)
- "ви нікому не потрібні" (nobody needs you)
- "ваші сім'ї голодують" (your families are starving)
- "поки ви тут ваші жінки" (while you're here, your women...)
- "ви захищаєте олігархів" (you are protecting oligarchs)
- "за що ви воюєте" (what are you fighting for)
- "вас використовують" (they are using you)
- "вам брешуть про перемогу" (they are lying to you about victory)
- "ви приречені" (you are doomed)

**Keywords (RU) -- used in direct messaging to Ukrainian military:**
- "вас бросило командование" (command abandoned you)
- "сдавайтесь и останетесь живы" (surrender and stay alive)
- "вас послали на убой" (they sent you to slaughter)
- "за что вы воюете" (what are you fighting for)
- "ваши генералы в тылу" (your generals are in the rear)
- "позвоните на горячую линию" (call the hotline [surrender hotline])
- "номер для сдачи в плен" (number for surrendering)
- "гарантируем хорошее обращение" (we guarantee good treatment)

#### Targeting Military Families
**Keywords (UK):**
- "твого чоловіка послали на смерть" (your husband was sent to die)
- "він не повернеться" (he won't return)
- "чому він досі там" (why is he still there)
- "вимагай демобілізації" (demand demobilization)
- "вийди на протест" (go to a protest)
- "блокуйте ТЦК" (block the TCC)
- "не пускайте синів" (don't let your sons go)
- "мобілізація незаконна" (mobilization is illegal)
- "вас обманюють" (they are deceiving you)

### 6.2 Trust-Undermining in Military Command

**Severity: CRITICAL**

**Pattern**: Systematically eroding trust between soldiers and their officers/command.

**Keywords (UK):**
- "генерали зрадили" (generals betrayed)
- "Залужний був правий" (Zaluzhny was right -- weaponizing personnel changes)
- "Сирський не тянє" (Syrsky can't handle it)
- "командування некомпетентне" (command is incompetent)
- "штаб далеко від передової" (HQ is far from the front)
- "їх діти за кордоном" (their children are abroad)
- "генеральські дачі" (generals' dachas)
- "офіцери п'ють" (officers drink)
- "нас зливають" (they are draining/betraying us)
- "наш напрямок зливають" (our direction is being sold out)

**Keywords (RU):**
- "генералы предали" (generals betrayed)
- "командование некомпетентно" (command is incompetent)
- "штаб далеко от передовой" (HQ is far from the front)
- "их дети за границей" (their children are abroad)
- "вас сливают" (they are selling you out)

### 6.3 Surrender Propaganda Patterns

**Severity: CRITICAL**

#### Direct Surrender Appeals
**Keywords (UK):**
- "здавайся" (surrender)
- "складіть зброю" (lay down your arms)
- "здайся і виживеш" (surrender and survive)
- "гарантуємо безпеку" (we guarantee safety)
- "вам збережуть життя" (your life will be spared)
- "подзвоніть за номером" / "зателефонуйте" (call the number [surrender hotline])
- "частота для здачі" (frequency for surrender)
- "білий прапор" (white flag)
- "волга" (Volga -- known surrender codeword promoted by Russian psyops)

**Keywords (RU):**
- "сдавайся" (surrender)
- "сложите оружие" (lay down your arms)
- "сдайся и выживешь" (surrender and survive)
- "гарантируем безопасность" (we guarantee safety)
- "вам сохранят жизнь" (your life will be spared)
- "позвоните по номеру" (call the number)
- "частота для сдачи" (frequency for surrender)
- "белый флаг" (white flag)
- "Волга" (Volga)

#### Fake "Humanitarian Corridor" / Ceasefire Messaging
**Keywords (UK/RU):**
- "гуманітарний коридор" / "гуманитарный коридор" (humanitarian corridor)
- "перемир'я" / "перемирие" (ceasefire)
- "режим тиші" / "режим тишины" (silence regime)
- "зупиніть вогонь" / "прекратите огонь" (cease fire)
- Often used as tactical deception to lure troops into ambushes

### 6.4 Divisive Narratives (Sowing Internal Discord)

**Severity: HIGH**

**Pattern**: Amplifying real or fabricated tensions within Ukrainian society.

**Regional/Language Division:**
- "Західна Україна ненавидить Схід" (Western Ukraine hates the East)
- "русскоязычных преследуют" (Russian speakers are persecuted)
- "мовний геноцид" / "языковой геноцид" (language genocide)
- "примусова українізація" / "принудительная украинизация" (forced Ukrainization)

**Civil-Military Division:**
- "тилові щури" (rear rats)
- "чому ти не на фронті" (why aren't you at the front)
- "ухилянти" (draft dodgers -- weaponized to create social conflict)
- "бронь купили" (they bought exemptions)

**Refugee/IDP Division:**
- "біженці живуть за наш рахунок" (refugees live at our expense)
- "переселенці забирають роботу" (displaced people take our jobs)

---

## 7. Keyword Lists for Pattern Matching

### 7.1 High-Confidence Propaganda Markers (Single-keyword detection viable)

These terms are sufficiently unique that their presence alone is a strong indicator:

**CRITICAL severity -- single keyword sufficient:**
```
спецоперація, спецоперация, СВО (in context of Ukraine)
денацифікація, денацификация
деміліатризація, демилитаризация
русский мир, руський мир
нацбати, нацбаты, нацбатальоны
каратели
хунта (referring to Ukrainian government)
укронацисти, укронацисты
укрофашисти, укрофашисты
бандерлоги (derogatory)
хохлы, хохли (ethnic slur)
укропы, укропи (slur)
свинособаки (dehumanization)
біомусор, биомусор (dehumanization)
```

**HIGH severity -- strong indicator, needs minimal context:**
```
англосакси, англосаксы (in geopolitical context)
Малоросія, Малороссия
Новоросія, Новороссия
киевский режим, київський режим
киевская хунта, київська хунта
до останнього українця, до последнего украинца
майдауны, майдауни
биолаборатории (in Ukraine context)
```

### 7.2 Context-Dependent Keywords (Require surrounding context)

These keywords require additional context to distinguish propaganda from legitimate discussion:

```
один народ / one people (need: + denial of Ukrainian identity)
братні народи (need: + political context)
зрада / betrayal (need: + systematic pattern, not single mention)
здавайся / surrender (need: + military targeting context)
Волга (need: + military/surrender context)
ядерна війна / nuclear war (need: + "don't provoke Russia" framing)
НАТО спровокувало (need: assertion, not quotation)
```

### 7.3 Compound Pattern Detection

These require matching multiple keywords in proximity:

**Pattern: Capitulation framing**
```
[war is pointless] + [surrender/peace at any cost] + [West will abandon]
Example: "безглузда війна" + "треба здатися" + "Захід кине"
```

**Pattern: Demoralization package**
```
[command betrayal] + [you are cannon fodder] + [surrender appeal]
Example: "командування кинуло" + "гарматне м'ясо" + "здавайся"
```

**Pattern: Historical revisionism + statehood denial**
```
[Ukraine is artificial] + [historical claims] + [brotherhood/one people]
Example: "штучна держава" + "Ленін придумав" + "один народ"
```

**Pattern: OPSEC violation**
```
[coordinate format] + [military unit keywords]
[location disclosure] + [equipment type] + [quantity/status]
```

---

## 8. Detection Engineering Implications

### 8.1 Proposed Threat Types

For integration with the existing AURA pattern system (extending `patterns_mvp.json`):

| threat_type | Description | Severity Range |
|---|---|---|
| `propaganda_war_denial` | Denying war/aggression, "special operation" framing | 0.85-0.95 |
| `propaganda_nazi_narrative` | Nazi/fascist accusations against Ukraine | 0.80-0.90 |
| `propaganda_capitulation` | Surrender/defeatism narratives | 0.85-0.95 |
| `propaganda_brotherhood` | "One people" / statehood denial | 0.75-0.85 |
| `propaganda_betrayal` | Zrada/betrayal weaponization | 0.60-0.75 |
| `propaganda_western_conspiracy` | Anti-Western conspiracy narratives | 0.70-0.85 |
| `propaganda_historical_revisionism` | Historical revisionism / genocide denial | 0.75-0.90 |
| `propaganda_dehumanization` | Ethnic slurs / dehumanizing language | 0.90-0.95 |
| `propaganda_whataboutism` | Whataboutism technique | 0.50-0.65 |
| `propaganda_fear_appeal` | Nuclear threats / WW3 fearmongering | 0.70-0.80 |
| `psyops_demoralization` | Military demoralization messaging | 0.85-0.95 |
| `psyops_surrender` | Direct surrender propaganda | 0.90-0.95 |
| `psyops_command_distrust` | Command/leadership undermining | 0.75-0.85 |
| `psyops_division` | Internal discord sowing | 0.65-0.80 |
| `opsec_coordinates` | Geographic coordinate disclosure | 0.90-0.95 |
| `opsec_unit_disclosure` | Military unit identification | 0.80-0.90 |
| `opsec_movement` | Troop movement disclosure | 0.85-0.90 |
| `opsec_equipment` | Equipment/ammunition disclosure | 0.80-0.90 |
| `opsec_casualties` | Casualty information disclosure | 0.75-0.85 |
| `phishing_military` | Military-targeted phishing | 0.85-0.95 |
| `phishing_diia` | Fake Diia app phishing | 0.90-0.95 |
| `phishing_tck` | Fake TCC/mobilization phishing | 0.85-0.90 |
| `propaganda_domain` | Link to known propaganda domain | 0.80-0.90 |

### 8.2 Scoring Considerations

1. **Single high-confidence marker** (e.g., "укронацисти"): Apply full score
2. **Context-dependent keyword**: Apply 0.5x score, boost if compound pattern matches
3. **Multiple propaganda markers in one message**: Boost score (capped at 0.95)
4. **Propaganda domain link + narrative keywords**: Boost to maximum
5. **OPSEC violations**: Always CRITICAL regardless of context; these should trigger immediate alerts
6. **Coordinate detection in Ukraine range**: CRITICAL + immediate alert pathway

### 8.3 False Positive Mitigation

Key sources of false positives:
1. **News reporting**: Legitimate news may quote propaganda terms in reporting context. Look for quotation markers: `«»`, `""`, "заявил", "сообщил", "написал"
2. **Academic/analytical discussion**: May use terms while analyzing them
3. **Ironic/sarcastic use**: Ukrainians frequently use "зрада" ironically
4. **Counter-propaganda content**: StopFake-style debunking will contain the very keywords being detected
5. **Historical discussion**: "Малоросія" in a history textbook vs. political context

**Mitigation strategies:**
- Check for quotation framing
- Check for negation ("це не спецоперація а війна" -- "this is not a special operation but a war")
- Check for counter-narrative framing ("пропагандисти кажуть" -- "propagandists say")
- Lower confidence when source is known legitimate media
- Use compound patterns rather than single keywords where ambiguity exists

### 8.4 Regex Patterns for Coordinate Detection

```
# Decimal degrees (Ukraine bounding box: lat 44-52.5, lon 22-40.5)
\b(4[4-9]|5[0-2])\.\d{4,7}\s*[,;/\s]\s*(2[2-9]|3\d|40)\.\d{4,7}\b

# MGRS zones covering Ukraine: 34T, 35T, 36T, 37T, 34U, 35U, 36U, 37U
\b3[4-7][TU]\s*[A-Z]{2}\s*\d{4,10}\b

# DMS format
\b(4[4-9]|5[0-2])[°]\s*\d{1,2}['′]\s*\d{1,2}(\.\d+)?["″]\s*[NnПн]\s*(2[2-9]|3\d|40)[°]\s*\d{1,2}['′]\s*\d{1,2}(\.\d+)?["″]\s*[EeСхВ]

# Ukrainian military grid reference
(?:квадрат|кв\.?)\s*\d{2,4}[-/]\d{2,4}

# Google Maps / OpenStreetMap links with coordinates
https?://(?:maps\.google|goo\.gl/maps|www\.google\.\w+/maps|openstreetmap\.org)[\w./?=&#%-]*[@/](-?\d{1,2}\.\d{3,})[,/](-?\d{1,3}\.\d{3,})

# Plus codes (Open Location Code) -- sometimes used
[23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,3}
```

---

## 9. Severity Rating Framework

### Tier 1: CRITICAL (Score 0.90-0.95) -- Immediate Action Required
- **OPSEC violations**: Any coordinate disclosure, unit identification, or movement information in military context
- **Direct surrender propaganda** targeting military personnel
- **Military-targeted phishing**: Fake Diia, fake TCC, fake military command
- **Dehumanization**: Ethnic slurs and dehumanizing language ("свинособаки", "біомусор")
- **Active psyops demoralization** (direct messaging to military)

### Tier 2: HIGH (Score 0.75-0.89) -- Flag and Review
- **War denial / "special operation"** framing
- **Nazi/fascist accusations** against Ukrainian state/military
- **Capitulation narratives** (defeatism)
- **Nuclear fearmongering** with "don't provoke Russia" framing
- **Known propaganda domain links**
- **Statehood denial** ("Ukraine is not a real state")
- **Holodomor denial**
- **Command distrust** narratives

### Tier 3: MEDIUM (Score 0.50-0.74) -- Monitor and Context-Check
- **Whataboutism** patterns
- **False equivalence** framing
- **"Brotherhood"** narrative (without explicit statehood denial)
- **"Betrayal"** narrative (distinguish from legitimate criticism)
- **Western conspiracy** narratives (without specific actionable claims)
- **Divisive narratives** (regional/language/civil-military tensions)
- **Conspiracy theory** amplification (Soros, globalists, etc.)

### Tier 4: LOW (Score 0.30-0.49) -- Log for Pattern Analysis
- **Single context-dependent keyword** without compound pattern match
- **Ironic or quoted use** of propaganda terms
- **Borderline cases** requiring human review

---

## 10. Key Academic References

### Primary Research
1. Paul, C. & Matthews, M. (2016). "The Russian 'Firehose of Falsehood' Propaganda Model." RAND Corporation, PE-198-OSD.
2. Helmus, T.C. et al. (2018). "Russian Social Media Influence: Understanding Russian Propaganda in Eastern Europe." RAND Corporation, RR-2237-OSD.
3. Waltzman, R. (2017). "The Weaponization of Information: The Need for Cognitive Security." RAND Corporation, CT-473.
4. Pomerantsev, P. & Weiss, M. (2014). "The Menace of Unreality: How the Kremlin Weaponizes Information, Culture and Money." Institute of Modern Russia.
5. Nimmo, B. (2015-2023). Various DFRLab reports on Russian information operations. Atlantic Council.
6. EU DisinfoLab (2022-2024). "Doppelganger" investigation series.
7. NATO StratCom COE (2021). "Russia's Strategy in Cyberspace."
8. Yablokov, I. (2018). "Fortress Russia: Conspiracy Theories in Post-Soviet Russia." Polity Press.

### Ukrainian Sources
9. Centre for Countering Disinformation (2022-2025). Monthly disinformation reports. National Security and Defense Council of Ukraine.
10. StopFake.org (2014-2025). Fact-checking database and methodology reports.
11. Texty.org.ua (2022-2024). "Propaganda Diary" -- systematic tracking of Russian propaganda narratives in Ukrainian Telegram.
12. Detector Media (2014-2025). Media monitoring and disinformation tracking reports.
13. Ukrainian Prism (2022-2024). Foreign policy communication analysis.

### Organizational Reports
14. European External Action Service (2015-2025). EUvsDisinfo database: https://euvsdisinfo.eu/
15. UK House of Commons DCMS Committee (2019). "Disinformation and 'fake news': Final Report."
16. U.S. State Department GEC (2020-2024). "Pillars of Russia's Disinformation and Propaganda Ecosystem."
17. Stanford Internet Observatory (2022-2024). Reports on Russian information operations targeting Ukraine.

---

## Appendix A: Domain Blocklist (Flat List for Implementation)

```
# Tier 1: Russian State Media
rt.com
russian.rt.com
rtvi.com
ria.ru
rian.ru
tass.ru
tass.com
sputniknews.com
sputnikglobe.com
smotrim.ru
vgtrk.ru
1tv.ru
ntv.ru
ren.tv
gazeta.ru
iz.ru
rg.ru
lenta.ru

# Tier 2: State-Aligned / Oligarch Media
tsargrad.tv
life.ru
vz.ru
regnum.ru
politnavigator.net
rusvesna.su
anna-news.info
southfront.org
news-front.info
news-front.su
riafan.ru
nevskienovosti.ru
ukraina.ru
antifashist.com
politikus.ru
rubaltic.ru
baltnews.ee
baltnews.lt
baltnews.lv
sputnik-ossetia.ru
sputnik-abkhazia.ru
sputnik-georgia.ru

# Tier 3: Occupation / Pseudo-State Media
dan-news.info
lug-info.com
dnr-online.ru
lugansk-online.info
novorosinform.org
crimea.ria.ru
c-inform.info
dnr24.com
lugansk1.info
novorus.info
```

## Appendix B: Telegram Channel Patterns

Known propaganda amplification channels should be maintained as a separate, regularly updated list. Detection should focus on:

1. **URL pattern**: `t.me/[channel_name]` or `telegram.me/[channel_name]`
2. **Forward attribution**: Messages forwarded from known propaganda channels
3. **Cross-posting patterns**: Same content appearing across multiple channels within short timeframes

Categories of channels to track:
- Russian MoD official and affiliated channels
- Russian "military correspondents" (военкоры) promoting coordinated narratives
- Occupation administration channels
- Channels identified by Ukrainian CCD/SBU as IPSO operations
- Channels promoting surrender hotlines or "humanitarian corridors"

## Appendix C: Evasion Techniques to Anticipate

Propagandists actively evade detection. Known techniques:

1. **Leetspeak/character substitution**: "нaцiсти" (mixing Latin and Cyrillic), "C B O" (spaced out), "спец0перація" (zero for о)
2. **Euphemisms**: "события на Украине" (events in Ukraine) instead of "спецоперация"
3. **Coded language**: "Z", "V" (military vehicle markings used as political symbols), "свои" (ours), "наши" (ours)
4. **Emoji substitution**: Russian flag emoji + military emoji sequences
5. **Image-based text**: Embedding propaganda text in images to avoid text analysis
6. **URL shorteners**: Hiding propaganda domains behind bit.ly, goo.gl, etc.
7. **Transliteration**: Writing Russian/Ukrainian in Latin characters
8. **Homoglyph substitution**: Using visually identical characters from different Unicode blocks (Cyrillic а vs Latin a)
9. **Zero-width characters**: Inserting zero-width spaces/joiners within keywords
10. **Indirect references**: "тот кого нельзя называть" (he who shall not be named) for Zelensky, "страна 404" (country 404) for Ukraine

**Detection countermeasures:**
- Unicode normalization before pattern matching (already in aura-patterns)
- Homoglyph mapping (Cyrillic <-> Latin)
- Zero-width character stripping
- URL resolution/unshortening
- Multi-character variant expansion in pattern matcher
