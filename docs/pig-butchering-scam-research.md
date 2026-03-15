# Pig Butchering Scam Research for Messenger Detection
## Comprehensive Reference for AURA Detection Engine

*Research compiled: 2026-03-15*

---

## Table of Contents

1. [Scam Lifecycle Stages](#1-scam-lifecycle-stages)
2. [Linguistic Patterns](#2-linguistic-patterns)
3. [Behavioral Signals](#3-behavioral-signals)
4. [Statistics and Scale](#4-statistics-and-scale)
5. [The Scam Compounds](#5-the-scam-compounds)
6. [Existing Detection Approaches](#6-existing-detection-approaches)
7. [Ukrainian/Russian-Speaking Context](#7-ukrainianrussian-speaking-context)
8. [Related Scam Types](#8-related-scam-types)
9. [Detection Engineering Implications](#9-detection-engineering-implications)
10. [Key Academic References](#10-key-academic-references)

---

## 1. Scam Lifecycle Stages

Pig butchering (sha zhu pan / 杀猪盘) is a hybrid fraud combining romance scams with fake investment schemes. The name comes from the Chinese idiom of "fattening a pig before slaughter" -- scammers invest weeks to months building trust before extracting maximum financial value. The scam follows a highly structured lifecycle with seven distinct phases.

### Phase 1: Target Selection and Initial Contact ("Finding the Pig")

**Timeline:** Day 0

**Channels:**
- Wrong-number SMS/text messages ("Hi David, this is Christine. Do you remember me?")
- Dating apps (Tinder, Bumble, Hinge, specialized community apps)
- Social media (Instagram, Facebook, LinkedIn, Twitter/X, TikTok)
- Messaging apps (WhatsApp, Telegram, WeChat)
- Professional networking sites

**Tactics:**
- Seemingly accidental or mistaken contact, followed by eagerness to keep talking
- Using attractive stolen profile photos (often East Asian or mixed-ethnicity women/men)
- Claiming shared interests discovered through "coincidence"
- Targeting lonely, recently divorced/widowed, or financially stable individuals
- Operating across multiple platforms simultaneously to maximize reach

**Key data collected during contact:** Age, occupation, marital status, home ownership, vehicles -- nearly all leaked scammer manuals instruct collecting these five details early.

### Phase 2: Trust-Building and Emotional Bonding ("Raising the Pig" / "Fattening")

**Timeline:** 2 weeks to 11 months (median 3-8 weeks for crypto variants; 2-6 months for romance variants)

76.9% of victims report scammers built trust over extended periods before introducing investment opportunities.

**Tactics:**
- Daily messaging, often multiple times per day
- Sharing personal photos, daily life updates, fabricated backstories
- "Love bombing" -- using pet names like "honey," "my love," "babe" within days
- Creating shared narratives about future plans together
- Establishing emotional dependency through constant availability
- Mirroring victim's communication style, interests, values
- Gradually self-disclosing fabricated personal information
- Building a persona of wealth, success, and financial sophistication

**Platform migration:** At this stage, scammers strongly push to move conversations from dating apps or social media to encrypted messaging (WhatsApp, Telegram, Signal, WeChat). This serves two purposes: (a) avoiding platform moderation/fraud detection, and (b) creating an illusion of intimacy and privacy.

### Phase 3: Investment Introduction ("Showing the Trough")

**Timeline:** After trust is firmly established

**Tactics:**
- Casually mentioning recent financial success: "My uncle taught me about this platform..."
- Showing screenshots of fabricated profits on trading platforms
- Framing the opportunity as exclusive or insider knowledge
- Claiming expertise in crypto, forex, gold (XAUUSD), or stock trading
- Presenting themselves or a "mentor" as successful investor
- Offering to teach the victim how to invest

**Key linguistic markers:**
- References to MetaTrader 4/5, custom crypto exchange platforms
- Claims of consistent 20-50%+ returns
- Discussion of Bitcoin, Ethereum, Litecoin, USDT
- Mention of "special" or "insider" trading groups

### Phase 4: Small Test Investment ("First Taste")

**Timeline:** Days to weeks after introduction

**Tactics:**
- Encouraging a small initial investment ($100-$500)
- Sometimes providing fake demo accounts with simulated money
- Allowing victims to withdraw small "profits" to build confidence
- Showing fabricated returns of 4-10% on initial deposits
- Using fake platforms that mirror legitimate exchanges (cloned HTML from real sites like Upbit)

**Critical detection signal:** The victim is allowed to withdraw their initial gains -- this is the bait that makes the scam feel legitimate.

### Phase 5: Escalation and Maximum Extraction ("Fattening Phase")

**Timeline:** Weeks to months

**Tactics:**
- Encouraging progressively larger investments
- Introducing urgency: "the market is about to spike," "this opportunity won't last"
- Creating scarcity: "only a few spots left in this trading group"
- Showing ever-larger fabricated returns to fuel greed
- Encouraging victims to take loans, liquidate retirement, borrow from family
- Discouraging discussion with friends, family, or financial advisors
- Framing investment as "our shared future" or "our secret"
- Claims that "banks don't understand crypto" and "friends will make you miss out"

**Isolation language:** The scammer monopolizes attention, discourages outside advice, and frames the investment as something private -- "a personal opportunity" or "a surprise for our future together."

### Phase 6: Blocking Withdrawals ("The Slaughter")

**Timeline:** When victim tries to withdraw significant funds

**Tactics:**
- Platform shows "account frozen" due to "regulatory issues"
- Demanding additional fees, taxes, or "verification deposits" to unlock funds
- Claiming anti-money-laundering compliance requires additional payments
- Inventing new fees for each attempted withdrawal
- Applying emotional pressure: "I invested too, we'll get through this together"

### Phase 7: Exit and Encore Scams ("Ghosting and Recovery Fraud")

**Timeline:** After maximum extraction

**Primary exit:** Complete disappearance -- all accounts deleted, phone numbers disconnected.

**Encore scam (affects ~57.7% of victims):**
- Follow-up contacts from fake "law enforcement officers" or "recovery agents"
- Claims they can help recover stolen money for a fee
- Presentation of fake "official" documents and identification
- 34.6% of victims asked to pay upfront fees for "legal" or "tax" processing
- Some victims scammed multiple times through successive recovery frauds

---

## 2. Linguistic Patterns

### 2.1 Opening Messages (Phase 1)

**Wrong-number / cold approach patterns:**
- "Hello, is this [Name]?"
- "Hi [Name], this is [Female name]. Do you remember me?"
- "Long time no see!"
- "Hey, it was so good catching up with you at the reunion!"
- "I think I have the wrong number, sorry!"
- Simple "Hello" or "Hi" followed by a second engaging message
- "I got your number from [mutual friend / business contact]"

**After being told it's a wrong number:**
- "Oh I'm sorry! But since we're here, maybe it's fate?"
- "What a coincidence! Would you like to be friends anyway?"
- Immediate pivot to personal questions and compliments

**Dating app openers:**
- Compliments about profile photos
- Claiming shared interests or backgrounds
- Expressing desire for "serious relationship" or "meaningful connection"

### 2.2 Trust-Building Language (Phase 2)

**Intimacy acceleration:**
- Pet names within days: "honey," "baby," "my love," "dear," "sweetheart"
- "I feel like I've known you forever"
- "You're different from everyone else I've talked to"
- "I've never felt this way about someone so quickly"
- "I think we were meant to find each other"

**Persona construction:**
- Claims of financial sophistication: "I run my own business," "I work in finance"
- Family-oriented language: "I take care of my parents," "family is everything"
- Lifestyle signaling: sharing photos of expensive restaurants, travel, luxury items
- Emotional vulnerability: "I was hurt before," "I'm looking for something real"

**Mirroring/validation:**
- "We think so alike!"
- "I completely understand how you feel"
- Echoing victim's stated values and aspirations
- Apologizing frequently to appear considerate

### 2.3 Financial Discussion Patterns (Phase 3-5)

**Investment introduction (casual):**
- "My uncle/mentor taught me about this amazing platform"
- "I've been making really good returns lately on [crypto/forex/gold]"
- "Have you ever thought about investing in cryptocurrency?"
- "I wish I could share this opportunity with someone I trust"

**Platform promotion:**
- "This platform is available on the App Store, so it's safe"
- "My friend/analyst has insider information about market movements"
- "I can teach you, it's really easy once you understand it"
- "Let me show you my portfolio" (followed by fake screenshots)

**Escalation pressure:**
- "The market is about to move, we need to act now"
- "You'll make less money if you wait"
- "I just made $10,000 today -- you could too"
- "This is a once-in-a-lifetime opportunity"
- "I'm investing everything I have, I believe in this so much"

**Isolation/secrecy:**
- "Don't tell anyone about this yet -- it's our special thing"
- "Your friends won't understand this kind of investing"
- "Banks don't understand crypto -- they'll just try to stop you"
- "This is between us -- let's surprise everyone with our success"
- "Financial advisors are too conservative, they'll talk you out of it"

### 2.4 Withdrawal Blocking Language (Phase 6)

- "Your account has been flagged for tax compliance"
- "You need to pay a 10% withdrawal fee"
- "Anti-money laundering regulations require a verification deposit"
- "The platform requires a security deposit before large withdrawals"
- "I'm having the same problem, let me talk to my contact"

### 2.5 AI-Generated Content Markers

Scam syndicates now routinely use ChatGPT and uncensored variants (WormGPT, FraudGPT) to generate messages. Detectable markers include:
- Overuse of words like "crucial," "navigate," "array," "conclusion," "furthermore"
- Unnaturally polished grammar in contexts where native speakers use slang/abbreviations
- Inconsistent register -- formal phrasing mixed with attempted casual tone
- Copy-paste artifacts: "As a language model..." or "I don't have feelings or emotions"
- Repetitive sentence structures across different conversational contexts
- Text that is "too polished" -- lacking typos, incomplete sentences, or genuine slang

---

## 3. Behavioral Signals

### 3.1 Profile Characteristics

**Red flags:**
- Overly attractive photos with professional-quality lighting (often stolen from models/influencers)
- Same face used across multiple platforms under different names
- Minimal profile information or generic bio text
- Recently created accounts with little history
- Claimed location inconsistent with IP/time zone
- Photos that fail reverse image search (watermark-removed stock/model photos)
- Profession listed as vague business owner, crypto trader, or finance professional

### 3.2 Message Timing Patterns

- Consistent response times suggesting shift-based work (scam compound operators work in shifts)
- Messages clustered in patterns matching Southeast Asian business hours (GMT+7/+8)
- Unusual response speed -- very fast replies at all hours (multiple operators sharing one persona)
- Gradual increase in message frequency as emotional manipulation deepens
- In escalation phase: multiple messages or calls daily emphasizing urgency

### 3.3 Conversation Progression Red Flags

- **Rapid intimacy escalation:** Moving from stranger to "in love" within days to weeks
- **Platform migration pressure:** Insistent requests to move from dating apps to WhatsApp/Telegram/Signal
- **Financial topic pivot:** Natural-seeming transition from personal conversation to investment discussion
- **Information harvesting:** Early and systematic questioning about finances, property, employment
- **Inconsistency in backstory:** Details that change or contradict between messages
- **Refusal to video call or meet in person** (though deepfake video calls are now used to overcome this objection)
- **Sending links to unknown investment platforms** or custom trading apps
- **Encouraging installation of APK files** or apps not in official app stores
- **Introducing a "mentor" or "analyst"** who provides trading signals

### 3.4 Behavioral Transaction Patterns (On-chain)

- Initial small deposits followed by small "profit" withdrawals (baiting pattern)
- Progressively larger deposits with no corresponding withdrawals
- Multiple victims' funds flowing to the same wallet address
- 75% of pig butchering wallets exhibit on-chain money laundering signatures
- Funds quickly split across multiple intermediary addresses and exchanges
- Transactions structured just below reporting thresholds

---

## 4. Statistics and Scale

### 4.1 Financial Losses

| Metric | Value | Source / Year |
|--------|-------|--------------|
| FBI IC3 total cybercrime losses | $16.6 billion | FBI IC3 2024 Report |
| Cryptocurrency fraud losses (FBI) | $9.3 billion (+66% YoY) | FBI IC3 2024 |
| Pig butchering specifically (FBI) | $5.8 billion (41,557 complaints) | FBI IC3 2024 |
| Investment fraud (total category) | $6.57 billion | FBI IC3 2024 |
| Estimated global pig butchering losses | Up to $75B moved to crypto exchanges (2020-2024) | Academic estimate |
| Projected 2025 global losses | $142.83 billion | ScamWatchHQ |
| Average individual victim loss | ~$177,000 | Various studies |
| Largest documented individual loss | $2 million+ | Multiple reports |
| DOJ largest forfeiture action | ~$15 billion in Bitcoin | DOJ Oct 2025 |
| Losses for over-60 victims (FBI) | $4.9 billion (147,127 complaints) | FBI IC3 2024 |
| Northern California 2025 losses | $43.3 million (doubled from prior year) | SF Standard |

### 4.2 Prevalence

- Global Anti-Scam Alliance (2025): 57% of 46,000 surveyed adults across 42 countries were scammed in the past year; 23% lost money
- Pig butchering crypto scam revenue grew 40% year-over-year in 2024 (Chainalysis)
- Over half of pig butchering schemes exhibit links to large transnational organized crime groups
- Scammers operate across virtually every communication platform: Tinder, Bumble, Hinge, WhatsApp, Telegram, Instagram, Facebook, LinkedIn, Twitter/X, WeChat, Signal

### 4.3 Victim Demographics

| Demographic | Finding |
|-------------|---------|
| Highest-loss age range | 30-49 years old |
| Highest complaint volume | 60+ years old |
| Victim age range (studies) | 25-89 years (median 51) |
| Gender (study 1) | 69% female, aged 25-40 |
| Gender (study 2) | 80.8% male |
| Education | Bachelor's or master's degrees common |
| Professions targeted | Engineers, finance workers, doctors, communications |
| Financial status | High-earning professionals, individuals near retirement |

**Particularly vulnerable groups:**
- Recently divorced or widowed individuals
- Lonely or isolated people
- Crypto-curious individuals lacking deep knowledge of legitimate exchanges
- Professionals with high salaries and aspirations for wealth growth

### 4.4 FBI Operation Level Up

The FBI's proactive program has:
- Notified 5,831 victims of cryptocurrency investment fraud
- 77% of notified victims were unaware they were being scammed
- Saved victims over $359 million
- Referred 59 victims to FBI victim specialists for suicide intervention

---

## 5. The Scam Compounds

### 5.1 Geography and Scale

Scam compounds are concentrated in:
- **Myanmar** (particularly regions near Chinese border, Shan State, Karen State)
- **Cambodia** (Sihanoukville, Phnom Penh outskirts, special economic zones)
- **Laos** (Golden Triangle special economic zone)
- **Philippines**
- **Thailand** (border regions)
- **Emerging:** Operations also detected in Eastern Europe (Georgia), West Africa, and the Middle East

**Scale:** The United Nations estimates more than 200,000 people are held in scam compounds across Southeast Asia, forced to perpetrate fraud under threat of violence.

### 5.2 Organizational Structure

- Primarily run by overseas Chinese criminal syndicates based in Southeast Asia
- Hierarchical structure with clear roles: managers, trainers, operators
- Workers traffic in ethnic Chinese and others into "fraud factories"
- Operations run from compound facilities resembling office buildings or hotel complexes
- Seated at desktop computers, workers follow detailed operating scripts
- Archives of past successful chat histories are provided for study and replication
- Shift-based operations running 24/7 to cover multiple time zones

### 5.3 Human Trafficking

Scam compound workers are often victims of human trafficking themselves:
- Recruited through fake job advertisements (IT, customer service, translation)
- Passports and devices confiscated on arrival
- Physical abuse, isolation, restriction of movement
- Arbitrary fines and fees for underperformance
- Threats of sexual exploitation
- Forced to meet financial quotas under threat of violence
- Some workers sold between compounds

### 5.4 Financial Infrastructure

**Huione Group (Cambodia):**
- Operated Huione Guarantee, a Telegram-based marketplace with at least $24 billion in transactions -- the largest illicit online marketplace ever documented
- Laundered at least $4 billion in illicit proceeds (Aug 2021 - Jan 2025)
- Provided one-stop-shop services: targeted data lists, web hosting, social media accounts, AI software, deepfake tools
- AI service vendors' revenue on the platform grew 1,900% (2021-2024)
- Telegram blocked Huione Guarantee in 2025
- U.S. Treasury designated Huione Group as primary money laundering concern
- FinCEN proposed rules to cut off Huione from U.S. financial system

**Money laundering methods:**
- Cryptocurrency (primarily USDT/Tether, Bitcoin, Ethereum)
- Multiple intermediary wallet addresses
- Stablecoins for cross-border transfers
- Shell companies and bank accounts in Southeast Asia
- Huione launched its own stablecoin to evade sanctions

### 5.5 Recent Enforcement (2025-2026)

- January 2026: Key figure arrested by Cambodian authorities and extradited to China
- Ly Kuong, casino and real-estate tycoon, charged with scam-related crimes
- Thousands of workers released from scam compounds following arrests in Cambodia
- U.S. DOJ filed largest-ever forfeiture action (~$15 billion in Bitcoin)
- December 2025: First Joint Disruption Week led by Royal Thai Police, Meta, DOJ, FBI, HSI, USSS -- removed 59,000+ accounts, Pages, and Groups
- U.S. sanctions on Funnull CDN for role in $200M pig butchering infrastructure
- Tether froze 39 wallet addresses containing $225 million in stolen USDT

---

## 6. Existing Detection Approaches

### 6.1 Platform-Level Detection (Meta/WhatsApp/Messenger)

**Meta's measures (2025-2026):**
- Banned 6.8 million WhatsApp accounts linked to pig butchering schemes
- Removed 2 million accounts in a single enforcement action (late 2024)
- Messenger conversation-pattern analysis detecting: urgency, secrecy, payment pressure, crypto/gift card pivots
- In-thread scam alerts when conversations resemble romance, investment, giveaway, or pig butchering patterns
- WhatsApp flagging risky device-linking attempts
- FIRE (Fraud Intelligence Reciprocal Exchange): banks share fraud intelligence directly with Meta

### 6.2 Behavioral Transaction Monitoring (On-Chain)

**Elliptic's approach:**
- Machine learning to identify wallet addresses performing actions correlated with scam activity
- Pattern: initial deposits -> small baiting "profit" returns -> larger deposits -> blocked withdrawals
- Same wallet interacting with multiple victims in similar patterns triggers automatic flagging
- 75% of pig butchering wallets show money laundering signatures

**Chainalysis/TRM Labs:**
- Blockchain forensics tracking fund flows through intermediary addresses
- Identifying clusters of related scam wallets
- Mapping connections to known scam infrastructure (Huione, etc.)

### 6.3 NLP and Conversation Analysis

**Current research status:**
- Testing of popular moderation tools against hundreds of simulated romance baiting conversations showed detection rates of only **0% to 18.8%** -- none correctly identified as scams
- LLM safeguards consistently fail to detect the "Hook" and "Line" phases because emotionally supportive behavior is not inherently malicious
- Crime script analysis using keyword analysis and unsupervised learning has identified recurring language patterns and key scammer personas
- Academic research (2024-2025) focuses more on qualitative characterization than automated detection

**Key research gap:** No production-grade NLP system has been demonstrated to reliably detect pig butchering in the trust-building phase. Detection is easiest in the financial pitch and extraction phases.

### 6.4 AI-Enhanced Scam Operations (Adversary Capabilities)

Scammers are adopting AI faster than defenders:
- ChatGPT and uncensored variants (WormGPT, FraudGPT) for fluent multilingual messaging
- Real-time deepfake video for live video calls (defeating "ask for a video call" advice)
- Voice cloning for phone calls
- AI-generated profile photos that pass reverse image search
- Every scam compound insider interviewed in late 2024-early 2025 reported daily use of LLMs
- Haotian AI: Telegram-based face-swap robot service marketed to scam operators
- AI service vendors on Huione platform saw 1,900% revenue growth

### 6.5 Law Enforcement Approaches

- FBI Operation Level Up: proactive victim notification program
- DOJ Scam Center Strike Force
- International Joint Disruption Weeks (multi-agency coordinated takedowns)
- OFAC sanctions on human trafficking networks engaged in pig butchering
- Cryptocurrency seizure and forfeiture actions

### 6.6 Key Academic Papers

| Paper | Venue / Year | Contribution |
|-------|-------------|--------------|
| "Hello, is this Anna?" (Oak et al.) | USENIX SOUPS 2025 | First qualitative lifecycle analysis, 26 victim interviews |
| "Fake it till you make it" | Journal of Cybersecurity (Oxford), 2025 | Psychological and communication tactics analysis from leaked manuals |
| "An Explorative Study of Pig Butchering Scams" (Acharya et al.) | arXiv, Dec 2024 | Comprehensive study: 430K accounts, 770K posts, 3,200 abuse reports |
| "Love, Lies, and Language Models" | arXiv, Dec 2025 | Dual NLP/LLM analysis of romance baiting automation |
| Elliptic behavioral detection | Industry report, 2024 | On-chain pig butchering wallet detection methodology |
| Chainalysis 2024 report | Industry report, 2025 | 40% YoY revenue growth analysis |
| NLP for message-based threats (systematic review) | MDPI Electronics, 2025 | PRISMA review of NLP threat detection techniques |

---

## 7. Ukrainian/Russian-Speaking Context

### 7.1 Eastern European Romance Scam Ecosystem

The Ukrainian/Russian dating scam ecosystem is a distinct but overlapping threat landscape:

**Operational structure:**
- Organized call-center operations across Eastern Europe
- Scammers (frequently men) create fake profiles using stolen images of attractive Ukrainian/Russian women
- Operate on paid platforms: OnlyFans, webcam sites, agencies like UkrainianCharm
- Migrate to Telegram, WhatsApp, or Viber for extraction
- Some operations discovered in Georgia targeting cryptocurrency investment fraud

**Platform-specific activity:**
- Telegram channels called "Divinchik" (a dating app popular in Russia) used for matching with victims
- Scammers show off rosters of fake profiles on encrypted Telegram channels -- all featuring attractive women
- Same face reused with multiple names across dating sites, TikTok, Facebook, Telegram

### 7.2 Localized Script Patterns

**War-themed exploitation scripts (post-2022):**
- "War emergency" -- claiming to need money to flee conflict zones
- "Medical bills" -- fabricated injuries from conflict
- "Travel money" -- funding a plane ticket to escape or visit the victim
- "Rent" -- claims of displacement
- "Mobilization" -- male persona variant claiming to need help avoiding military service

**Classic Eastern European romance fraud scripts:**
- Visa/travel money to visit the victim (never arrives)
- Sick family member requiring urgent medical care
- Lost job due to economic hardship
- Planned trip that keeps getting "delayed" with new expenses each time

### 7.3 Convergence with Pig Butchering

Pig butchering schemes linked to Southeast Asian counterparts are now appearing in Eastern European operations:
- Georgian call centers running crypto investment fraud
- Money trails from romance scams connecting to Russian intelligence-associated infrastructure (at least one documented case)
- Eastern European scam operations adopting the Chinese pig butchering playbook
- Crypto investment overlay added to traditional romance fraud patterns

### 7.4 Detection Considerations for CIS/Eastern European Context

- **Language patterns:** Russian and Ukrainian scam scripts tend to use specific romantic vocabulary and cultural references
- **Platform preferences:** Viber is widely used in Ukraine; Telegram and VK in Russia; these are primary scam channels
- **Cultural hooks:** References to Ukrainian war, economic hardship, desire to emigrate
- **Payment methods:** May request crypto, Western Union, MoneyGram, or direct bank transfers in addition to crypto
- **Photo sources:** Stolen from Ukrainian/Russian social media (VK, OK.ru, Instagram)

---

## 8. Related Scam Types

### 8.1 Advance Fee Fraud (419 Scams)

**Pattern:** Promise of a large windfall (inheritance, lottery, business deal) in exchange for upfront "processing fees."

**Detection signals:**
- Claims of large sums needing to be moved out of a country
- Requests for fees to unlock funds (taxes, legal fees, bribes)
- Unsolicited messages from "lawyers," "bankers," or "government officials"
- Escalating fee requests (each payment unlocks a new "requirement")
- Often uses email rather than messaging apps

### 8.2 Sextortion

**Pattern:** Coercing victims into sharing intimate images, then demanding payment to prevent distribution.

**Statistics (2025):**
- Risk of being targeted in the U.S. rose 137% in 2025
- 1 in 5 teens experienced sextortion
- 1 in 6 victims were age 12 or younger at first experience
- Average financial impact: ~$2,400
- ~98% of cases go unreported
- 30% of victims received demands within 24 hours of initial contact
- 40% of victims who paid received daily threats afterward

**Detection signals:**
- Rapid escalation to intimate/sexual content requests
- Requests for nude or explicit photos early in conversation
- Sudden shift from friendly to threatening tone
- Demands for payment via crypto, gift cards, or wire transfer
- AI deepfake threats: fabricated explicit images using victim's face
- Threats to send images to victim's contacts/employer
- Time pressure: "pay within 24 hours or..."

**AI-enhanced sextortion:**
- Criminals create deepfake explicit images from public social media photos
- Emails contain fabricated footage and images of victims' real homes (from Google Street View)
- No actual intimate exchange needed -- entirely fabricated material used for extortion

### 8.3 Money Mule Recruitment

**Pattern:** Recruiting individuals to transfer stolen funds through their personal accounts.

**Detection signals:**
- Job offers for "payment processing," "financial agent," or "local representative"
- Promises of significant earnings for minimal effort
- Requests to receive funds and forward them (minus a "commission")
- Jobs requiring no experience, all work done online
- Direct messages disguised as "requests for help"
- Terms like "liquidity," "payment processing," "cross-border transfers"

**Demographics:** 18-24 year olds most targeted; 35% of Gen Z would consider moving money for someone they don't know if offered a fee (Barclays 2025).

**Transaction signals:**
- Multiple small incoming payments followed by rapid outgoing transfers
- Transactions just below reporting thresholds
- High-volume transfers with minimal account balances

### 8.4 Fake Charity / Humanitarian Scams

**Pattern:** Exploiting real crises (wars, natural disasters) to solicit fraudulent donations.

**Detection signals:**
- Urgency tied to current events (Ukraine war, earthquake, hurricane)
- Requests for crypto or gift card donations (legitimate charities rarely do this)
- Newly created accounts or organizations
- Pressure to donate immediately before "it's too late"
- Vague details about how funds will be used

### 8.5 Loan/Credit Scams

**Pattern:** Offering guaranteed loans or credit regardless of credit history, requiring upfront fees.

**Detection signals:**
- Guaranteed approval regardless of credit score
- Upfront "processing" or "insurance" fees required
- No verification of income or employment
- Pressure to act quickly before "offer expires"
- Communication exclusively through messaging apps

### 8.6 Job Scams and Task Scams

**Pattern:** Fake job offers that require upfront payment or steal personal information. Task scams ask victims to complete simple online tasks (liking videos, rating products) and then demand "deposits" to continue earning.

**Detection signals:**
- "Work from home, earn $500/day"
- Task-based earning with initial small payouts that stop after deposits are made
- Requiring payment for "training materials" or "equipment"
- Collecting SSN, bank details, or ID documents early in process

---

## 9. Detection Engineering Implications

### 9.1 Multi-Phase Detection Strategy

Detection should be layered across the scam lifecycle, with different signals weighted at each phase:

**Phase 1 (Contact) -- High-confidence signals:**
- Wrong-number pattern messages to unknown contacts
- Bulk messaging patterns from single accounts
- Recently created accounts with model/stolen photos
- Profile metadata inconsistencies (timezone, language, location)

**Phase 2 (Trust-building) -- Medium-confidence signals (high false-positive risk):**
- Rapid intimacy escalation in language (pet names, love declarations within days)
- Platform migration requests (move to WhatsApp/Telegram)
- Systematic personal information harvesting
- Inconsistencies in self-reported details across messages

**Phase 3-5 (Investment/Extraction) -- High-confidence signals:**
- Financial topic introduction after relationship-building phase
- Links to unknown investment/trading platforms
- Mentions of specific crypto assets, trading platforms, "guaranteed returns"
- Urgency/scarcity language around financial decisions
- Isolation language discouraging outside advice
- Requests for increasing amounts of money
- Mentions of withdrawal problems, fees, or taxes

**Phase 6-7 (Blocking/Exit) -- Post-hoc signals:**
- Sudden account deletion or silence after money transfers
- Recovery scam contacts from new accounts referencing prior conversations

### 9.2 Key Detection Features for NLP/ML Models

**Lexical features:**
- Wrong-number opener vocabulary
- Pet name density and acceleration rate
- Financial/investment term frequency and timing
- Urgency/scarcity keyword presence
- Isolation/secrecy language markers
- AI-generated text markers (overuse of "crucial," "navigate," etc.)
- Copy-paste artifacts from LLM outputs

**Conversational features:**
- Rate of intimacy escalation (sentiment trajectory)
- Topic transition patterns (personal -> financial)
- Question/answer asymmetry (scammer asks many questions, reveals little verifiable info)
- Platform migration requests
- Link sharing patterns (external platform URLs)
- Response time consistency (shift-based patterns)

**Behavioral features:**
- Account age and creation pattern
- Profile photo reverse-image-search results
- Geographic inconsistency between claimed and actual location
- Multi-account coordination (same operator, multiple personas)
- Message volume patterns (daily frequency, time-of-day clustering)

### 9.3 Key Challenges

1. **Phase 2 detection is hardest:** Emotionally supportive behavior is not inherently malicious; current detection rates are 0-18.8%
2. **AI-generated content:** Scammers using LLMs produce fluent, natural-sounding messages that blend with legitimate communication
3. **Deepfake escalation:** Real-time video deepfakes defeat traditional "verify with video call" advice
4. **Cross-platform operation:** Scammers operate across multiple apps; no single platform sees the full picture
5. **Scale vs. precision:** High false-positive rates risk alienating legitimate users, especially in dating contexts
6. **Multilingual operation:** Scams conducted in dozens of languages with culturally adapted scripts
7. **Adversarial adaptation:** Scam operators quickly adjust tactics when detection methods are publicized

### 9.4 Recommended Detection Tiers

**Tier 1 -- Hard signals (block/warn immediately):**
- Known scam platform URLs or domain patterns
- Known scam wallet addresses
- Bulk messaging to unknown contacts with wrong-number templates
- Accounts matching known stolen photo databases

**Tier 2 -- Soft signals (aggregate and warn):**
- Platform migration pressure + financial topic introduction
- Rapid intimacy escalation + information harvesting
- Urgency language + isolation language in financial context
- AI-generated text markers in relationship context

**Tier 3 -- Contextual signals (monitor and learn):**
- Conversation sentiment trajectory analysis
- Response timing patterns
- Profile metadata anomalies
- Cross-referencing user reports and known scam patterns

---

## 10. Key Academic References

1. Oak et al. "Hello, is this Anna?": Unpacking the Lifecycle of Pig-Butchering Scams. USENIX SOUPS 2025. https://arxiv.org/html/2503.20821v2
2. "Fake it till you make it: the psychological and communication tactics behind 'Pig Butchering' scams." Journal of Cybersecurity (Oxford Academic), 2025. https://academic.oup.com/cybersecurity/article/12/1/tyag003/8449214
3. Acharya et al. "An Explorative Study of Pig Butchering Scams." arXiv, December 2024. https://arxiv.org/abs/2412.15423
4. "Love, Lies, and Language Models: Investigating AI's Role in Romance-Baiting Scams." arXiv, December 2025. https://arxiv.org/html/2512.16280v1
5. Chainalysis. "2024 Pig Butchering Crypto Scam Revenue Grows 40% YoY." 2025. https://www.chainalysis.com/blog/2024-pig-butchering-scam-revenue-grows-yoy/
6. Elliptic. "The behavioral detection of pig butchering scams on blockchain." 2024. https://www.elliptic.co/blog/the-behavioral-detection-of-pig-butchering-scams-on-blockchain-flagging-suspect-wallets-and-speeding-up-investigations
7. TRM Labs. "Unmasking Pig Butchering Scams: The $4 Billion Crypto Scheme." https://www.trmlabs.com/resources/blog/unmasking-pig-butchering-scams-the-4-billion-crypto-scheme-preying-on-vulnerable-investors
8. FBI IC3 2024 Annual Report. https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf
9. Meta. "Cracking Down on Organized Crime Behind Scam Centers." November 2024. https://about.fb.com/news/2024/11/cracking-down-organized-crime-scam-centers/
10. FinCEN. "FinCEN Finds Cambodia-Based Huione Group to be of Primary Money Laundering Concern." 2025. https://www.fincen.gov/news/news-releases/fincen-finds-cambodia-based-huione-group-be-primary-money-laundering-concern
11. MDPI Electronics. "Advances in NLP Techniques for Detection of Message-Based Threats in Digital Platforms: A Systematic Review." 2025. https://www.mdpi.com/2079-9292/14/13/2551
12. DFPI. "Pig Butchering Scam Playbook." March 2025. https://dfpi.ca.gov/wp-content/uploads/2025/03/Pig-Butchering-Scam-Playbook.pdf

---

## Sources

- [FBI IC3 2024 Annual Report](https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf)
- [FBI Operation Level Up](https://www.fbi.gov/how-we-can-help-you/victim-services/national-crimes-and-victim-resources/operation-level-up)
- ["Hello, is this Anna?" -- USENIX SOUPS 2025](https://arxiv.org/html/2503.20821v2)
- ["Fake it till you make it" -- Journal of Cybersecurity (Oxford)](https://academic.oup.com/cybersecurity/article/12/1/tyag003/8449214)
- [An Explorative Study of Pig Butchering Scams -- arXiv](https://arxiv.org/abs/2412.15423)
- [Love, Lies, and Language Models -- arXiv](https://arxiv.org/html/2512.16280v1)
- [Chainalysis: Pig Butchering Revenue Grows 40% YoY](https://www.chainalysis.com/blog/2024-pig-butchering-scam-revenue-grows-yoy/)
- [Elliptic: Behavioral Detection of Pig Butchering on Blockchain](https://www.elliptic.co/blog/the-behavioral-detection-of-pig-butchering-scams-on-blockchain-flagging-suspect-wallets-and-speeding-up-investigations)
- [TRM Labs: Unmasking Pig Butchering Scams](https://www.trmlabs.com/resources/blog/unmasking-pig-butchering-scams-the-4-billion-crypto-scheme-preying-on-vulnerable-investors)
- [Meta: Cracking Down on Organized Crime Behind Scam Centers](https://about.fb.com/news/2024/11/cracking-down-organized-crime-scam-centers/)
- [$75 Billion Lost to Pig-Butchering Scam -- TIME](https://time.com/6836703/pig-butchering-scam-victim-loss-money-study-crypto/)
- [2025 Global Scam Landscape -- ScamWatchHQ](https://scamwatchhq.com/the-2025-global-scam-landscape-a-year-of-ai-powered-deception-record-losses-and-human-trafficking/)
- [FinCEN: Huione Group Primary Money Laundering Concern](https://www.fincen.gov/news/news-releases/fincen-finds-cambodia-based-huione-group-be-primary-money-laundering-concern)
- [Huione: Largest Ever Illicit Online Marketplace -- Elliptic](https://www.elliptic.co/blog/huione-largest-ever-illicit-online-marketplace-stablecoin)
- [U.S. and U.K. Take Largest Action Targeting Cybercriminal Networks -- Treasury](https://home.treasury.gov/news/press-releases/sb0278)
- [DFPI Pig Butchering Scam Playbook](https://dfpi.ca.gov/wp-content/uploads/2025/03/Pig-Butchering-Scam-Playbook.pdf)
- [Meta Removes 6.8 Million WhatsApp Accounts](https://finance.yahoo.com/news/meta-removes-6-8-million-153700798.html)
- [Meta Rolls Out New Scam Protection Tools](https://thehackernews.com/2025/10/meta-rolls-out-new-tools-to-protect.html)
- [Merklescience: Detecting AI-Driven Pig Butchering Scams](https://www.merklescience.com/blog/detecting-and-disrupting-ai-driven-pig-butchering-scams)
- [How Pig Butchering Scams Work -- ProPublica](https://www.propublica.org/article/whats-a-pig-butchering-scam-heres-how-to-avoid-falling-victim-to-one)
- [Pig Butchering -- Wikipedia](https://en.wikipedia.org/wiki/Pig_butchering_scam)
- [NCA: Pig Butchering Scams -- National Cybersecurity Alliance](https://www.staysafeonline.org/articles/what-is-pig-butchering-and-how-to-spot-the-scam)
- [AARP: Pig Butchering Scams](https://www.aarp.org/money/scams-fraud/what-are-pig-butchering-scams.html)
- [Romance Scammers Exploit Ukraine War -- Computer Weekly](https://www.computerweekly.com/news/252522145/Romance-scammers-exploit-Ukraine-war-in-cynical-campaign)
- [Ukrainian Passport: Pig Butchering Scams](https://ukrainian-passport.com/blog/pig-butchering-scams/)
- [Krebs on Security: Fraudsters Automate Russian Dating Scams](https://krebsonsecurity.com/2016/01/fraudsters-automate-russian-dating-scams/)
- [Thorn: State of Sextortion in 2025](https://www.thorn.org/blog/the-state-of-sextortion-in-2025/)
- [2025 Sextortion Statistics](https://www.digitalforensics.com/blog/sextortion-online/sextortion-statistics/)
- [FBI: Common Frauds and Scams](https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-frauds-and-scams)
- [Barclays: Gen Z Money Mule Risk](https://home.barclays/news/press-releases/2025/10/a-third-of-gen-z-risk-unknowingly-becoming-money-mules/)
- [Sumsub: Money Mule Prevention 2025](https://sumsub.com/blog/money-muling/)
- [PCWorld: Live AI Deepfake Video in Pig Butchering](https://www.pcworld.com/article/2492762/live-ai-deepfake-video-makes-pig-butchering-scams-more-convincing.html)
- [Fortune: Southeast Asia Scam Centers](https://fortune.com/2025/11/15/southeast-asia-scam-centers-cambodia-myanmar-human-trafficking-cybercrime/)
- [Foreign Policy: Myanmar Pig-Butchering Scams](https://foreignpolicy.com/2025/10/23/myanmar-china-pig-butchering-scams-slavery/)
- [RFA: Scam Parks Explained](https://www.rfa.org/english/china/2025/01/23/scam-parks-compounds-cambodia-thailand-myanmar-laos/)
- [NLP for Message-Based Threats -- MDPI](https://www.mdpi.com/2079-9292/14/13/2551)
- [LLMs Automating Romance Scams -- Help Net Security](https://www.helpnetsecurity.com/2025/12/29/llms-romance-baiting-scams-study/)
- [SF Standard: AI Dating Scams 2025](https://sfstandard.com/2026/02/13/san-francisco-ai-dating-scams-pig-butchering-2025/)
- [Crypto Scams 2025-2026 -- Tron Weekly](https://www.tronweekly.com/crypto-scams-hit-millions-in-2025-2026-through/)
