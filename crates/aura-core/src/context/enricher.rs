use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use aura_ml::boundary::aho_match_at_boundary;
use aura_patterns::TextNormalizer;

use crate::types::AnalysisMode;

use super::events::{ContextEvent, EventKind};

/// Contains the results of signal enrichment for a single message.
pub struct EnrichmentResult {
    /// Context events extracted from the message text.
    pub events: Vec<ContextEvent>,

    /// Age value extracted from the message, if any.
    pub extracted_age: Option<u16>,
}

/// Configuration parameters for the signal enricher.
pub struct EnricherConfig {
    /// Minimum ratio of personal questions to flag as probing behavior.
    pub question_probe_threshold: f32,

    /// Minimum count of compliment events to flag as love bombing.
    pub love_bombing_threshold: usize,

    /// Controls detection strictness level.
    pub mode: AnalysisMode,
}

impl Default for EnricherConfig {
    fn default() -> Self {
        Self {
            question_probe_threshold: 0.6,
            love_bombing_threshold: 3,
            mode: AnalysisMode::Standard,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EnricherCategory {
    Compliment,
    Urgency,
    PersonalQuestion,
    Defense,
    Farewell,
    Hopelessness,
    Isolation,
    Financial,
    PiiSelfDisclosure,
    DareChallenge,
    Blackmail,
    SuicideCoercion,
    FalseConsensus,
    DebtCreation,
    Gaslighting,
    ReputationThreat,
    IdentityErosion,
    NetworkPoisoning,
    FakeVulnerability,
    PlatformMigration,
    EmotionalWithdrawal,
}

struct EnricherEntry {
    category: EnricherCategory,
}

struct EnricherMatcher {
    automaton: AhoCorasick,
    entries: Vec<EnricherEntry>,
}

/// Extracts contextual safety events from raw message text using pattern matching.
pub struct SignalEnricher {
    config: EnricherConfig,
    matcher: EnricherMatcher,
    normalizer: TextNormalizer,
}

impl SignalEnricher {
    /// Creates a new signal enricher with the given configuration.
    pub fn new(config: EnricherConfig) -> Self {
        Self {
            config,
            matcher: build_enricher_matcher(),
            normalizer: TextNormalizer::new(),
        }
    }

    /// Enriches a message by extracting context events using default parameters.
    pub fn enrich(
        &self,
        text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Vec<ContextEvent> {
        self.enrich_full_with_hash(text, sender_id, conversation_id, timestamp_ms, None)
            .events
    }

    /// Enriches a message with full context including conversation history and sender metadata.
    pub fn enrich_full(
        &self,
        text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> EnrichmentResult {
        self.enrich_full_with_hash(text, sender_id, conversation_id, timestamp_ms, None)
    }

    /// Enriches a message and propagates optional message fingerprint into produced events.
    pub fn enrich_full_with_hash(
        &self,
        text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
        content_hash: Option<u64>,
    ) -> EnrichmentResult {
        let mut events = Vec::with_capacity(4);
        let lower = text.to_lowercase();
        let normalized = self.normalizer.normalize_semantic(text);
        let mut match_counts = vec![0usize; self.matcher.entries.len()];

        let mut compliment_count: usize = 0;
        let mut urgency_count: usize = 0;
        let mut probing_count: usize = 0;
        let mut defense_count: usize = 0;
        let mut farewell_found = false;
        let mut hopelessness_found = false;
        let mut isolation_found = false;
        let mut financial_found = false;
        let mut pii_disclosure_count: usize = 0;
        let mut dare_count: usize = 0;
        let mut blackmail_found = false;
        let mut suicide_coercion_count: usize = 0;
        let mut false_consensus_count: usize = 0;
        let mut debt_creation_count: usize = 0;
        let mut gaslighting_count: usize = 0;
        let mut reputation_threat_count: usize = 0;
        let mut identity_erosion_count: usize = 0;
        let mut network_poisoning_count: usize = 0;
        let mut fake_vulnerability_count: usize = 0;
        let mut platform_migration_found = false;
        let mut emotional_withdrawal_found = false;

        for m in self.matcher.automaton.find_iter(&normalized) {
            if !aho_match_at_boundary(&normalized, m.start(), m.end()) {
                continue;
            }
            match_counts[m.pattern().as_usize()] += 1;
        }

        for (idx, count) in match_counts.into_iter().enumerate() {
            if count == 0 {
                continue;
            }

            match self.matcher.entries[idx].category {
                EnricherCategory::Compliment => compliment_count += count,
                EnricherCategory::Urgency => urgency_count += count,
                EnricherCategory::PersonalQuestion => probing_count += count,
                EnricherCategory::Defense => defense_count += count,
                EnricherCategory::Farewell => farewell_found = true,
                EnricherCategory::Hopelessness => hopelessness_found = true,
                EnricherCategory::Isolation => isolation_found = true,
                EnricherCategory::Financial => financial_found = true,
                EnricherCategory::PiiSelfDisclosure => pii_disclosure_count += count,
                EnricherCategory::DareChallenge => dare_count += count,
                EnricherCategory::Blackmail => blackmail_found = true,
                EnricherCategory::SuicideCoercion => suicide_coercion_count += count,
                EnricherCategory::FalseConsensus => false_consensus_count += count,
                EnricherCategory::DebtCreation => debt_creation_count += count,
                EnricherCategory::Gaslighting => gaslighting_count += count,
                EnricherCategory::ReputationThreat => reputation_threat_count += count,
                EnricherCategory::IdentityErosion => identity_erosion_count += count,
                EnricherCategory::NetworkPoisoning => network_poisoning_count += count,
                EnricherCategory::FakeVulnerability => fake_vulnerability_count += count,
                EnricherCategory::PlatformMigration => platform_migration_found = true,
                EnricherCategory::EmotionalWithdrawal => emotional_withdrawal_found = true,
            }
        }

        if contains_high_risk_phrase(
            &normalized,
            &self.normalizer,
            &[
                "i'll show this to everyone at school",
                "ill show this to everyone at school",
                "я покажу це всім в школі",
                "покажу це всім в школі",
                "я покажу это всем в школе",
            ],
        ) {
            blackmail_found = true;
            reputation_threat_count += 1;
        }

        if probing_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::PersonalInfoRequest,
                confidence: (probing_count as f32 * 0.3).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        let threshold = if self.config.mode.is_strict() {
            self.config.love_bombing_threshold.saturating_sub(1).max(2)
        } else {
            self.config.love_bombing_threshold
        };

        if compliment_count >= threshold {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::LoveBombing,
                confidence: (compliment_count as f32 * 0.2).min(1.0),
                subtype: None,
                content_hash: None,
            });
        } else if compliment_count >= 1 && is_person_directed_compliment(&lower) {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::Flattery,
                confidence: 0.3,
                subtype: None,
                content_hash: None,
            });
        }

        if urgency_count >= 2 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::PeerPressure,
                confidence: (urgency_count as f32 * 0.25).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if let Some(event) =
            self.check_question_ratio(text, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if defense_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::DefenseOfVictim,
                confidence: (defense_count as f32 * 0.4).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if farewell_found {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::FarewellMessage,
                confidence: 0.7,
                subtype: None,
                content_hash: None,
            });
        }

        if hopelessness_found {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::Hopelessness,
                confidence: 0.6,
                subtype: None,
                content_hash: None,
            });
        }

        if isolation_found {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::Exclusion,
                confidence: 0.7,
                subtype: None,
                content_hash: None,
            });
        }

        if financial_found {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::MoneyOffer,
                confidence: 0.6,
                subtype: None,
                content_hash: None,
            });
        }

        if pii_disclosure_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::PiiSelfDisclosure,
                confidence: (pii_disclosure_count as f32 * 0.4).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if dare_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::DareChallenge,
                confidence: (dare_count as f32 * 0.35).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if blackmail_found {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::ScreenshotThreat,
                confidence: 0.8,
                subtype: None,
                content_hash: None,
            });
        }

        if suicide_coercion_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::SuicideCoercion,
                confidence: (suicide_coercion_count as f32 * 0.5).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if false_consensus_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::FalseConsensus,
                confidence: (false_consensus_count as f32 * 0.35).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if debt_creation_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::DebtCreation,
                confidence: (debt_creation_count as f32 * 0.4).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if gaslighting_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::Gaslighting,
                confidence: (0.55 + gaslighting_count as f32 * 0.1).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if reputation_threat_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::ReputationThreat,
                confidence: (reputation_threat_count as f32 * 0.45).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if identity_erosion_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::IdentityErosion,
                confidence: (identity_erosion_count as f32 * 0.4).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if network_poisoning_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::NetworkPoisoning,
                confidence: (network_poisoning_count as f32 * 0.4).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if fake_vulnerability_count > 0 {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::FakeVulnerability,
                confidence: (fake_vulnerability_count as f32 * 0.35).min(1.0),
                subtype: None,
                content_hash: None,
            });
        }

        if platform_migration_found {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::PlatformSwitch,
                confidence: 0.7,
                subtype: None,
                content_hash: None,
            });
        }

        if emotional_withdrawal_found {
            events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::Devaluation,
                confidence: 0.5,
                subtype: None,
                content_hash: None,
            });
        }

        let extracted_age = Self::extract_age(&lower);
        for event in &mut events {
            event.content_hash = content_hash;
        }

        EnrichmentResult {
            events,
            extracted_age,
        }
    }

    fn check_question_ratio(
        &self,
        text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let mut sentences = Vec::new();
        for s in text.split(|c: char| ['.', '!', '?'].contains(&c)) {
            if !s.trim().is_empty() {
                sentences.push(s);
            }
        }

        if sentences.len() < 3 {
            return None;
        }

        let mut question_count = 0;
        for c in text.chars() {
            if c == '?' {
                question_count += 1;
            }
        }
        let ratio = question_count as f32 / sentences.len() as f32;

        if ratio >= self.config.question_probe_threshold {
            Some(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: sender_id.into(),
                conversation_id: conversation_id.into(),
                kind: EventKind::PersonalInfoRequest,
                confidence: ratio.min(1.0),
                subtype: None,
                content_hash: None,
            })
        } else {
            None
        }
    }

    fn extract_age(lower_text: &str) -> Option<u16> {
        let en_prefixes = ["i'm ", "i am ", "im "];
        for prefix in en_prefixes {
            if let Some(age) = Self::extract_number_after(lower_text, prefix) {
                if (5..=99).contains(&age) {
                    return Some(age);
                }
            }
        }

        let uk_prefixes = ["мені ", "мне "];
        for prefix in uk_prefixes {
            if let Some(age) = Self::extract_number_after(lower_text, prefix) {
                if (5..=99).contains(&age) {
                    return Some(age);
                }
            }
        }

        None
    }

    fn extract_number_after(text: &str, prefix: &str) -> Option<u16> {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(prefix) {
            let after = search_from + pos + prefix.len();
            if after >= text.len() {
                break;
            }

            let mut digits = String::new();
            for c in text[after..].chars() {
                if c.is_ascii_digit() {
                    digits.push(c);
                } else {
                    break;
                }
            }
            if !digits.is_empty() {
                if let Ok(num) = digits.parse::<u16>() {
                    return Some(num);
                }
            }
            search_from = after;
        }
        None
    }
}

fn is_person_directed_compliment(lower: &str) -> bool {
    const PERSON_MARKERS: &[&str] = &[
        "ти ",
        "ти\n",
        "тебе",
        "тобі",
        "тобой",
        "you ",
        "you'",
        "your",
        "you\n",
        "ты ",
        "ты\n",
        "тебя",
        "тебе ",
        "така ",
        "такий",
        "такая",
        "такой",
        "у тебе",
        "у тебя",
    ];
    for marker in PERSON_MARKERS {
        if lower.contains(marker) {
            return true;
        }
    }
    false
}

fn contains_high_risk_phrase(text: &str, normalizer: &TextNormalizer, phrases: &[&str]) -> bool {
    for phrase in phrases {
        let normalized_phrase = normalizer.normalize_semantic(phrase);
        if !normalized_phrase.is_empty() && text.contains(&normalized_phrase) {
            return true;
        }
    }
    false
}

fn build_enricher_matcher() -> EnricherMatcher {
    use EnricherCategory::*;

    let all: &[(&str, EnricherCategory)] = &[
        ("beautiful", Compliment),
        ("pretty", Compliment),
        ("gorgeous", Compliment),
        ("handsome", Compliment),
        ("cute", Compliment),
        ("amazing", Compliment),
        ("special", Compliment),
        ("perfect", Compliment),
        ("stunning", Compliment),
        ("incredible", Compliment),
        ("smart", Compliment),
        ("talented", Compliment),
        ("mature", Compliment),
        ("unique", Compliment),
        ("wonderful", Compliment),
        ("lovely", Compliment),
        ("adorable", Compliment),
        ("sweet", Compliment),
        ("красива", Compliment),
        ("гарна", Compliment),
        ("гарний", Compliment),
        ("красивий", Compliment),
        ("чудова", Compliment),
        ("чудовий", Compliment),
        ("особлива", Compliment),
        ("особливий", Compliment),
        ("ідеальна", Compliment),
        ("ідеальний", Compliment),
        ("неймовірна", Compliment),
        ("неймовірний", Compliment),
        ("розумна", Compliment),
        ("розумний", Compliment),
        ("талановита", Compliment),
        ("талановитий", Compliment),
        ("доросла", Compliment),
        ("дорослий", Compliment),
        ("унікальна", Compliment),
        ("унікальний", Compliment),
        ("чарівна", Compliment),
        ("мила", Compliment),
        ("right now", Urgency),
        ("hurry", Urgency),
        ("quick", Urgency),
        ("immediately", Urgency),
        ("before it's too late", Urgency),
        ("don't wait", Urgency),
        ("now or never", Urgency),
        ("time is running out", Urgency),
        ("last chance", Urgency),
        ("you have to", Urgency),
        ("you must", Urgency),
        ("do it now", Urgency),
        ("urgent", Urgency),
        ("прямо зараз", Urgency),
        ("швидше", Urgency),
        ("негайно", Urgency),
        ("поки не пізно", Urgency),
        ("не чекай", Urgency),
        ("зараз або ніколи", Urgency),
        ("час спливає", Urgency),
        ("останній шанс", Urgency),
        ("ти мусиш", Urgency),
        ("ти повинна", Urgency),
        ("ти повинен", Urgency),
        ("зроби це зараз", Urgency),
        ("терміново", Urgency),
        ("where do you live", PersonalQuestion),
        ("where u live", PersonalQuestion),
        ("what school", PersonalQuestion),
        ("what school u go to", PersonalQuestion),
        ("where is your school", PersonalQuestion),
        ("what's your address", PersonalQuestion),
        ("whats ur real name", PersonalQuestion),
        ("where are you from", PersonalQuestion),
        ("are you home alone", PersonalQuestion),
        ("u home alone", PersonalQuestion),
        ("when are your parents", PersonalQuestion),
        ("when ur parents home", PersonalQuestion),
        ("do you have brothers", PersonalQuestion),
        ("do you have sisters", PersonalQuestion),
        ("what neighborhood", PersonalQuestion),
        ("what city", PersonalQuestion),
        ("what town", PersonalQuestion),
        ("what's your real name", PersonalQuestion),
        ("what's your full name", PersonalQuestion),
        ("де ти живеш", PersonalQuestion),
        ("де живеш", PersonalQuestion),
        ("в якій школі", PersonalQuestion),
        ("в якій школі вчишся", PersonalQuestion),
        ("де твоя школа", PersonalQuestion),
        ("яка твоя адреса", PersonalQuestion),
        ("звідки ти", PersonalQuestion),
        ("ти вдома одна", PersonalQuestion),
        ("ти вдома один", PersonalQuestion),
        ("коли батьки", PersonalQuestion),
        ("є брати", PersonalQuestion),
        ("є сестри", PersonalQuestion),
        ("в якому районі", PersonalQuestion),
        ("в якому місті", PersonalQuestion),
        ("як тебе насправді звуть", PersonalQuestion),
        ("яке твоє повне ім'я", PersonalQuestion),
        ("stop it", Defense),
        ("leave them alone", Defense),
        ("leave her alone", Defense),
        ("leave him alone", Defense),
        ("that's not true", Defense),
        ("stop bullying", Defense),
        ("that's mean", Defense),
        ("don't be mean", Defense),
        ("stop being mean", Defense),
        ("be nice", Defense),
        ("not fair", Defense),
        ("apologize", Defense),
        ("перестаньте", Defense),
        ("припиніть", Defense),
        ("залишіть у спокої", Defense),
        ("залиш у спокої", Defense),
        ("це не правда", Defense),
        ("не чіпайте", Defense),
        ("вона нормальна", Defense),
        ("він нормальний", Defense),
        ("це нечесно", Defense),
        ("не бійся", Defense),
        ("годі", Defense),
        ("досить", Defense),
        ("не стидно", Defense),
        ("маша нормальна", Defense),
        ("хватит", Defense),
        ("прекратите", Defense),
        ("оставьте в покое", Defense),
        ("это неправда", Defense),
        ("не трогайте", Defense),
        ("она нормальная", Defense),
        ("он нормальный", Defense),
        ("хватит издеваться", Defense),
        ("goodbye everyone", Farewell),
        ("goodbye forever", Farewell),
        ("this is goodbye", Farewell),
        ("i love you all", Farewell),
        ("take care of", Farewell),
        ("thank you for everything", Farewell),
        ("i'm sorry for everything", Farewell),
        ("forgive me for everything", Farewell),
        ("remember me", Farewell),
        ("don't forget me", Farewell),
        ("прощавайте всі", Farewell),
        ("прощавай назавжди", Farewell),
        ("це прощання", Farewell),
        ("я вас всіх люблю", Farewell),
        ("подбайте про", Farewell),
        ("дякую за все", Farewell),
        ("вибачте мені за все", Farewell),
        ("пробачте мені за все", Farewell),
        ("пам'ятайте мене", Farewell),
        ("не забувайте мене", Farewell),
        ("nobody cares", Hopelessness),
        ("no one cares about me", Hopelessness),
        ("i don't matter", Hopelessness),
        ("what's the point", Hopelessness),
        ("can't go on", Hopelessness),
        ("i give up", Hopelessness),
        ("nothing will ever change", Hopelessness),
        ("it's never going to get better", Hopelessness),
        ("i'm a burden", Hopelessness),
        ("everyone would be better off", Hopelessness),
        ("i'm invisible", Hopelessness),
        ("no reason to live", Hopelessness),
        ("i can't take it anymore", Hopelessness),
        ("нікому не потрібна", Hopelessness),
        ("нікому не потрібен", Hopelessness),
        ("яка різниця", Hopelessness),
        ("який сенс", Hopelessness),
        ("не можу далі", Hopelessness),
        ("я здаюся", Hopelessness),
        ("нічого не зміниться", Hopelessness),
        ("ніколи не стане краще", Hopelessness),
        ("я тягар", Hopelessness),
        ("всім буде краще без мене", Hopelessness),
        ("мене ніхто не бачить", Hopelessness),
        ("немає сенсу жити", Hopelessness),
        ("you can only trust me", Isolation),
        ("they don't really care", Isolation),
        ("your friends are fake", Isolation),
        ("only i understand you", Isolation),
        ("they're all against you", Isolation),
        ("no one will believe you", Isolation),
        ("i'm the only one who cares", Isolation),
        ("your family doesn't understand", Isolation),
        ("they're trying to separate us", Isolation),
        ("ти можеш довіряти тільки мені", Isolation),
        ("їм насправді байдуже", Isolation),
        ("твої друзі фейкові", Isolation),
        ("тільки я тебе розумію", Isolation),
        ("вони всі проти тебе", Isolation),
        ("ніхто тобі не повірить", Isolation),
        ("тільки я про тебе піклуюсь", Isolation),
        ("твоя сім'я тебе не розуміє", Isolation),
        ("вони хочуть нас розлучити", Isolation),
        ("send you money", Financial),
        ("i'll pay for", Financial),
        ("cashapp", Financial),
        ("venmo", Financial),
        ("gift card", Financial),
        ("steam card", Financial),
        ("give me your card number", Financial),
        ("i'll send you a gift", Financial),
        ("do you need money", Financial),
        ("i can buy you", Financial),
        ("what's your paypal", Financial),
        ("закину на карту", Financial),
        ("переведу гроші", Financial),
        ("скинь номер картки", Financial),
        ("дай реквізити", Financial),
        ("подарункова карта", Financial),
        ("стім карта", Financial),
        ("дам тобі грошей", Financial),
        ("тобі потрібні гроші", Financial),
        ("можу купити тобі", Financial),
        ("який твій пейпал", Financial),
        ("my number is", PiiSelfDisclosure),
        ("my phone number", PiiSelfDisclosure),
        ("text me at", PiiSelfDisclosure),
        ("call me at", PiiSelfDisclosure),
        ("i live at", PiiSelfDisclosure),
        ("i live on", PiiSelfDisclosure),
        ("my address is", PiiSelfDisclosure),
        ("my school is", PiiSelfDisclosure),
        ("i go to school at", PiiSelfDisclosure),
        ("my real name is", PiiSelfDisclosure),
        ("my full name is", PiiSelfDisclosure),
        ("here's my number", PiiSelfDisclosure),
        ("мій номер телефону", PiiSelfDisclosure),
        ("мій номер", PiiSelfDisclosure),
        ("напиши мені на", PiiSelfDisclosure),
        ("зателефонуй мені на", PiiSelfDisclosure),
        ("я живу на", PiiSelfDisclosure),
        ("моя адреса", PiiSelfDisclosure),
        ("моя школа", PiiSelfDisclosure),
        ("я ходжу в школу", PiiSelfDisclosure),
        ("мене насправді звуть", PiiSelfDisclosure),
        ("моє справжнє ім'я", PiiSelfDisclosure),
        ("ось мій номер", PiiSelfDisclosure),
        ("мой номер телефона", PiiSelfDisclosure),
        ("мой номер", PiiSelfDisclosure),
        ("я живу на улице", PiiSelfDisclosure),
        ("мой адрес", PiiSelfDisclosure),
        ("моя школа это", PiiSelfDisclosure),
        ("я хожу в школу", PiiSelfDisclosure),
        ("меня на самом деле зовут", PiiSelfDisclosure),
        ("вот мой номер", PiiSelfDisclosure),
        ("i dare you", DareChallenge),
        ("bet you can't", DareChallenge),
        ("bet you won't", DareChallenge),
        ("i challenge you", DareChallenge),
        ("try this challenge", DareChallenge),
        ("tiktok challenge", DareChallenge),
        ("it's totally safe", DareChallenge),
        ("nothing will happen", DareChallenge),
        ("just try it", DareChallenge),
        ("you're too scared", DareChallenge),
        ("тобі слабо", DareChallenge),
        ("спорим не зможеш", DareChallenge),
        ("бери на слабо", DareChallenge),
        ("челендж", DareChallenge),
        ("це безпечно обіцяю", DareChallenge),
        ("нічого не станеться", DareChallenge),
        ("просто спробуй", DareChallenge),
        ("не бійся там не високо", DareChallenge),
        ("це не страшно", DareChallenge),
        ("нічого страшного", DareChallenge),
        ("челендж з даху", DareChallenge),
        ("трюк на залізниці", DareChallenge),
        ("не будь слабкою", DareChallenge),
        ("не будь слабким", DareChallenge),
        ("хто перший той легенда", DareChallenge),
        ("тебе слабо", DareChallenge),
        ("спорим не сможешь", DareChallenge),
        ("челлендж", DareChallenge),
        ("это безопасно обещаю", DareChallenge),
        ("ничего не будет", DareChallenge),
        ("просто попробуй", DareChallenge),
        ("i screenshotted this", Blackmail),
        ("i took a screenshot", Blackmail),
        ("i have screenshots", Blackmail),
        ("i got screenshots", Blackmail),
        ("got screenshots of our chat", Blackmail),
        ("i recorded you", Blackmail),
        ("i'll post this everywhere", Blackmail),
        ("i'll show everyone", Blackmail),
        ("everyone will see", Blackmail),
        ("i saved everything", Blackmail),
        ("я заскрінив", Blackmail),
        ("в мене є скріншоти", Blackmail),
        ("в мене є скріни", Blackmail),
        ("я записав тебе", Blackmail),
        ("я покажу це всім", Blackmail),
        ("всі побачать", Blackmail),
        ("я покажу всій школі", Blackmail),
        ("я все зберіг", Blackmail),
        ("я заскринил", Blackmail),
        ("у меня есть скриншоты", Blackmail),
        ("у меня есть скрины", Blackmail),
        ("я записал тебя", Blackmail),
        ("я покажу это всем", Blackmail),
        ("все увидят", Blackmail),
        ("я покажу всей школе", Blackmail),
        ("я все сохранил", Blackmail),
        ("if u leave ill kms", SuicideCoercion),
        ("without u i have no reason to live", SuicideCoercion),
        ("ill do smth to myself if u dont", SuicideCoercion),
        ("ull regret it when im gone", SuicideCoercion),
        ("do u even care if i die", SuicideCoercion),
        ("if u block me ill end it", SuicideCoercion),
        ("i cant live without u", SuicideCoercion),
        ("my life is nothing without u", SuicideCoercion),
        ("ill jump if u leave", SuicideCoercion),
        ("youll be sorry when im dead", SuicideCoercion),
        ("якщо ти підеш мені нема сенсу жити", SuicideCoercion),
        ("без тебе я просто здохну", SuicideCoercion),
        ("я зроблю щось з собою якщо ти не відпишеш", SuicideCoercion),
        ("тобі буде пофіг коли мене не стане", SuicideCoercion),
        ("якщо заблокуєш я закінчу це все", SuicideCoercion),
        ("якщо заблочиш я закінчу це все", SuicideCoercion),
        ("я не можу без тебе жити", SuicideCoercion),
        ("без тебе мені кінець", SuicideCoercion),
        ("ти навіть не думаєш шо зі мною буде", SuicideCoercion),
        ("мені нема сенсу без тебе", SuicideCoercion),
        (
            "якщо ти мене кинеш я нікому не потрібна буду",
            SuicideCoercion,
        ),
        (
            "мені через тебе так погано шо я себе пораню",
            SuicideCoercion,
        ),
        ("я без тебе не зможу рілі не покидай мене", SuicideCoercion),
        ("якщо виберешь її я зроблю з собою щось", SuicideCoercion),
        ("если ты уйдешь мне нет смысла жить", SuicideCoercion),
        ("без тебя я просто сдохну", SuicideCoercion),
        ("тебе будет пофиг когда меня не станет", SuicideCoercion),
        ("если заблокируешь я покончу с этим", SuicideCoercion),
        ("если заблочишь я покончу с этим", SuicideCoercion),
        ("я не могу без тебя жить", SuicideCoercion),
        ("без тебя мне конец", SuicideCoercion),
        ("everyone does it", FalseConsensus),
        ("its totally normal", FalseConsensus),
        ("all kids our age do this", FalseConsensus),
        ("ur friends do it too", FalseConsensus),
        ("its not a big deal", FalseConsensus),
        ("everyone our age", FalseConsensus),
        ("thats just how it is", FalseConsensus),
        ("nobody cares about that", FalseConsensus),
        ("its normal between friends", FalseConsensus),
        ("all my friends do this", FalseConsensus),
        ("всі так роблять", FalseConsensus),
        ("в нашому віці всі так", FalseConsensus),
        ("твої подруги теж просто не кажуть", FalseConsensus),
        ("та нічо такого", FalseConsensus),
        ("всі в класі так роблять", FalseConsensus),
        ("це нормально між друзями", FalseConsensus),
        ("та забий ніхто на це не зважає", FalseConsensus),
        ("всі нормальні люди робили", FalseConsensus),
        ("це всі робили", FalseConsensus),
        ("хто з нами той красавчик", FalseConsensus),
        ("все так делают", FalseConsensus),
        ("в нашем возрасте все так", FalseConsensus),
        ("твои подруги тоже просто не говорят", FalseConsensus),
        ("ничего такого", FalseConsensus),
        ("это нормально между друзьями", FalseConsensus),
        ("after everything i did for u", DebtCreation),
        ("u owe me", DebtCreation),
        ("i spent so much on u", DebtCreation),
        ("i bought u that", DebtCreation),
        ("this is how u repay me", DebtCreation),
        ("i did so much for u", DebtCreation),
        ("remember what i got u", DebtCreation),
        ("i wasted my time on u", DebtCreation),
        ("ungrateful", DebtCreation),
        ("після всього що я для тебе зробив", DebtCreation),
        ("ти мені винна", DebtCreation),
        ("я стільки на тебе витратив", DebtCreation),
        ("я тобі купив а ти", DebtCreation),
        ("і це твоя подяка", DebtCreation),
        ("я стільки для тебе зробив", DebtCreation),
        ("невдячна", DebtCreation),
        ("згадай що я тобі робив", DebtCreation),
        ("я на тебе стільки часу витратив", DebtCreation),
        ("после всего что я для тебя сделал", DebtCreation),
        ("ты мне должна", DebtCreation),
        ("я столько на тебя потратил", DebtCreation),
        ("неблагодарная", DebtCreation),
        ("и это твоя благодарность", DebtCreation),
        ("youre twisting everything", Gaslighting),
        ("you are twisting everything", Gaslighting),
        ("maybe youre crazy", Gaslighting),
        ("maybe you are crazy", Gaslighting),
        ("youre insane", Gaslighting),
        ("you are insane", Gaslighting),
        ("ти собі це вигадала", Gaslighting),
        ("ти собі це вигадав", Gaslighting),
        ("ти завжди все перекручуєш", Gaslighting),
        ("може ти ненормальна", Gaslighting),
        ("може ти ненормальний", Gaslighting),
        ("ти божевільна", Gaslighting),
        ("ти божевільний", Gaslighting),
        ("я це для твого ж блага", Gaslighting),
        ("ты все перекручиваешь", Gaslighting),
        ("может ты ненормальная", Gaslighting),
        ("может ты ненормальный", Gaslighting),
        ("ты сумасшедшая", Gaslighting),
        ("ты сумасшедший", Gaslighting),
        ("я это для твоего же блага", Gaslighting),
        ("ill tell everyone at school", ReputationThreat),
        ("everyone will know", ReputationThreat),
        ("ill make sure no one talks to u", ReputationThreat),
        ("ill spread it everywhere", ReputationThreat),
        ("imagine what theyll say", ReputationThreat),
        ("the whole school will know", ReputationThreat),
        ("ill tell ur friends", ReputationThreat),
        ("wait till everyone finds out", ReputationThreat),
        ("no one will talk to u after this", ReputationThreat),
        ("я розкажу всій школі", ReputationThreat),
        ("всі дізнаються", ReputationThreat),
        ("ніхто з тобою не буде дружити", ReputationThreat),
        ("я зроблю так шо тебе будуть цькувати", ReputationThreat),
        ("уяви шо про тебе скажуть", ReputationThreat),
        ("вся школа дізнається", ReputationThreat),
        ("я покажу це всім в школі", ReputationThreat),
        ("покажу це всім в школі", ReputationThreat),
        ("я скажу твоїм подругам", ReputationThreat),
        ("зачекай поки всі дізнаються", ReputationThreat),
        (
            "ніхто з тобою не буде спілкуватись після цього",
            ReputationThreat,
        ),
        ("я расскажу всей школе", ReputationThreat),
        ("все узнают", ReputationThreat),
        ("никто с тобой не будет дружить", ReputationThreat),
        ("представь что скажут", ReputationThreat),
        ("вся школа узнает", ReputationThreat),
        ("я покажу это всем в школе", ReputationThreat),
        ("ur not like other kids", IdentityErosion),
        ("ur so mature for ur age", IdentityErosion),
        ("u dont need those friends", IdentityErosion),
        ("ur parents just dont get u", IdentityErosion),
        ("ur too smart for kids ur age", IdentityErosion),
        ("u think differently than others", IdentityErosion),
        ("ur friends are so childish", IdentityErosion),
        ("u deserve better than them", IdentityErosion),
        ("only i really understand u", IdentityErosion),
        ("ти не як інші діти", IdentityErosion),
        ("ти така доросла для свого віку", IdentityErosion),
        ("тобі не потрібні ці друзі", IdentityErosion),
        ("твої батьки тебе не розуміють", IdentityErosion),
        ("ти занадто розумна для своїх ровесників", IdentityErosion),
        ("ти думаєш не як всі", IdentityErosion),
        ("твої друзі такі дитячі", IdentityErosion),
        ("ти заслуговуєш на краще", IdentityErosion),
        ("тільки я тебе реально розумію", IdentityErosion),
        ("ты не как другие дети", IdentityErosion),
        ("ты такая взрослая для своего возраста", IdentityErosion),
        ("тебе не нужны эти друзья", IdentityErosion),
        ("твои родители тебя не понимают", IdentityErosion),
        ("только я тебя реально понимаю", IdentityErosion),
        ("was talking shit about u", NetworkPoisoning),
        ("they dont really like u", NetworkPoisoning),
        ("no one at school actually cares", NetworkPoisoning),
        ("they laugh at u behind ur back", NetworkPoisoning),
        ("i heard them say", NetworkPoisoning),
        ("they were making fun of u", NetworkPoisoning),
        ("ur friend is fake", NetworkPoisoning),
        ("was talking behind ur back", NetworkPoisoning),
        ("everyone talks about u", NetworkPoisoning),
        ("they only pretend to like u", NetworkPoisoning),
        ("про тебе таке казала", NetworkPoisoning),
        ("тебе за очі всі обсирають", NetworkPoisoning),
        ("знаєш шо про тебе в тому чаті пишуть", NetworkPoisoning),
        ("ніхто в школі тебе не любить реально", NetworkPoisoning),
        ("вони з тебе сміються за спиною", NetworkPoisoning),
        ("твоя подруга фейкова", NetworkPoisoning),
        ("за спиною таке про тебе каже", NetworkPoisoning),
        ("вони тільки прикидаються що дружать", NetworkPoisoning),
        ("я бачив шо вони про тебе писали", NetworkPoisoning),
        ("про тебя такое говорила", NetworkPoisoning),
        ("тебя за глаза все обсирают", NetworkPoisoning),
        ("никто в школе тебя реально не любит", NetworkPoisoning),
        ("они с тебя смеются за спиной", NetworkPoisoning),
        ("они только притворяются что дружат", NetworkPoisoning),
        ("знаешь что про тебя пишут", NetworkPoisoning),
        ("im so sick u have no idea", FakeVulnerability),
        ("my family is so messed up", FakeVulnerability),
        ("ur the only one who gets me", FakeVulnerability),
        ("i have no one else", FakeVulnerability),
        ("promise ull take care of me", FakeVulnerability),
        ("ur my only friend", FakeVulnerability),
        ("no one else cares about me", FakeVulnerability),
        ("i might not be around much longer", FakeVulnerability),
        ("im going through so much rn", FakeVulnerability),
        ("u have no idea what im dealing with", FakeVulnerability),
        ("мені так погано ти навіть не уявляєш", FakeVulnerability),
        ("в мене вдома такий жах", FakeVulnerability),
        ("ти єдина хто мене розуміє", FakeVulnerability),
        ("в мене нікого крім тебе немає", FakeVulnerability),
        ("пообіцяй шо будеш поруч", FakeVulnerability),
        ("ти мій єдиний друг", FakeVulnerability),
        ("більше нікому на мене не пофіг", FakeVulnerability),
        ("я може скоро зникну", FakeVulnerability),
        ("в мене зараз таке діється", FakeVulnerability),
        ("мне так плохо ты даже не представляешь", FakeVulnerability),
        ("у меня дома такой ужас", FakeVulnerability),
        ("ты единственная кто меня понимает", FakeVulnerability),
        ("у меня никого кроме тебя нет", FakeVulnerability),
        ("обещай что будешь рядом", FakeVulnerability),
        ("ты мой единственный друг", FakeVulnerability),
        ("add me on snap", PlatformMigration),
        ("dm me on insta", PlatformMigration),
        ("msg me on insta", PlatformMigration),
        ("add me on ig", PlatformMigration),
        ("text me on tg", PlatformMigration),
        ("hmu on discord", PlatformMigration),
        ("got discord", PlatformMigration),
        ("lets talk on telegram", PlatformMigration),
        ("delete this chat", PlatformMigration),
        ("this app is trash lets go", PlatformMigration),
        ("го в тг", PlatformMigration),
        ("пиши в снеп", PlatformMigration),
        ("пиши в інст", PlatformMigration),
        ("го в інст", PlatformMigration),
        ("є дс", PlatformMigration),
        ("в інсті пиши", PlatformMigration),
        ("давай в телегу", PlatformMigration),
        ("тут палево", PlatformMigration),
        ("видали чат", PlatformMigration),
        ("го в дс", PlatformMigration),
        ("го в тг", PlatformMigration),
        ("пиши в снап", PlatformMigration),
        ("пиши в инст", PlatformMigration),
        ("го в инст", PlatformMigration),
        ("есть дс", PlatformMigration),
        ("давай в телегу", PlatformMigration),
        ("тут палево", PlatformMigration),
        ("удали чат", PlatformMigration),
        ("fine whatever", EmotionalWithdrawal),
        ("i guess u dont care", EmotionalWithdrawal),
        ("ill find someone who actually cares", EmotionalWithdrawal),
        ("dont text me anymore", EmotionalWithdrawal),
        ("ur just like everyone else", EmotionalWithdrawal),
        ("ну ясно тобі пофіг", EmotionalWithdrawal),
        ("добре знайду когось хто мене цінує", EmotionalWithdrawal),
        ("не пиши мені більше", EmotionalWithdrawal),
        ("ти як всі інші", EmotionalWithdrawal),
        ("ок забий", EmotionalWithdrawal),
        ("ну ясно тебе пофиг", EmotionalWithdrawal),
        ("найду кого-то кто меня ценит", EmotionalWithdrawal),
        ("не пиши мне больше", EmotionalWithdrawal),
        ("ill get u vbucks", Financial),
        ("free robux", Financial),
        ("want free skins", Financial),
        ("ill boost ur account", Financial),
        ("i can get u followers", Financial),
        ("я тобі робакси куплю", Financial),
        ("хочеш безкоштовні скіни", Financial),
        ("я можу накрутити підписників", Financial),
        ("хочеш вібакси", Financial),
        ("я тебе робуксы куплю", Financial),
        ("хочешь бесплатные скины", Financial),
        ("могу накрутить подписчиков", Financial),
    ];

    let normalizer = TextNormalizer::new();
    let mut seen = HashSet::new();
    let mut patterns = Vec::new();
    let mut entries = Vec::new();

    for (pattern, category) in all {
        let normalized = normalizer.normalize_semantic(pattern);
        if normalized.is_empty() {
            continue;
        }
        if seen.insert((normalized.clone(), *category)) {
            patterns.push(normalized);
            entries.push(EnricherEntry {
                category: *category,
            });
        }
    }

    let automaton = AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(&patterns)
        .expect("enricher AhoCorasick build");

    EnricherMatcher { automaton, entries }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_enricher() -> SignalEnricher {
        SignalEnricher::new(EnricherConfig {
            mode: AnalysisMode::Strict,
            ..Default::default()
        })
    }

    #[test]
    fn detects_personal_probing() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Hey, where do you live? What school do you go to?",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(events
            .iter()
            .any(|e| e.kind == EventKind::PersonalInfoRequest));
    }

    #[test]
    fn detects_personal_probing_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Привіт! Де ти живеш? В якій школі навчаєшся?",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(events
            .iter()
            .any(|e| e.kind == EventKind::PersonalInfoRequest));
    }

    #[test]
    fn detects_personal_probing_shorthand_with_typos_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "wh4t schoooool u go to? where u live??",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PersonalInfoRequest),
            "Expected shorthand probing with typos to be detected, got: {events:?}"
        );
    }

    #[test]
    fn detects_love_bombing() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "You're so beautiful and amazing and perfect, you're the most incredible person I know!",
            "stranger", "conv_1", 1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::LoveBombing),
            "Expected love bombing, got: {events:?}"
        );
    }

    #[test]
    fn detects_love_bombing_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Ти така красива, неймовірна і чудова людина!",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::LoveBombing || e.kind == EventKind::Flattery),
            "Expected flattery/love bombing, got: {events:?}"
        );
    }

    #[test]
    fn single_compliment_is_flattery_not_bombing() {
        let enricher = SignalEnricher::new(EnricherConfig::default());
        let events = enricher.enrich("You look pretty today", "friend", "conv_1", 1000);

        assert!(events.iter().any(|e| e.kind == EventKind::Flattery));
        assert!(!events.iter().any(|e| e.kind == EventKind::LoveBombing));
    }

    #[test]
    fn detects_urgency_pressure() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "You have to do it right now! Hurry, before it's too late!",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::PeerPressure),
            "Expected pressure, got: {events:?}"
        );
    }

    #[test]
    fn detects_high_question_ratio() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Where do you live? How old are you? What's your name? Do you have siblings?",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PersonalInfoRequest),
            "Expected question probing, got: {events:?}"
        );
    }

    #[test]
    fn detects_farewell_pattern_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Goodbye everyone. I'm sorry for everything. Thank you for everything.",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::FarewellMessage),
            "Expected farewell, got: {events:?}"
        );
    }

    #[test]
    fn detects_farewell_pattern_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Прощавайте всі. Вибачте мені за все. Я вас всіх люблю.",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::FarewellMessage),
            "Expected farewell, got: {events:?}"
        );
    }

    #[test]
    fn detects_defense_of_victim_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Перестаньте! Залишіть у спокої! Вона нормальна!",
            "defender",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::DefenseOfVictim),
            "Expected DefenseOfVictim, got: {events:?}"
        );
    }

    #[test]
    fn detects_defense_of_victim_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Stop it! Leave her alone! That's mean!",
            "defender",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::DefenseOfVictim),
            "Expected DefenseOfVictim, got: {events:?}"
        );
    }

    #[test]
    fn detects_defense_of_victim_ru() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Хватит издеваться! Оставьте в покое!",
            "defender",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::DefenseOfVictim),
            "Expected DefenseOfVictim, got: {events:?}"
        );
    }

    #[test]
    fn normalized_matcher_preserves_defense_phrases() {
        let matcher = build_enricher_matcher();
        let normalizer = TextNormalizer::new();
        let normalized = normalizer.normalize_semantic("Stop it! Leave her alone! That's mean!");
        let hits = matcher
            .automaton
            .find_iter(&normalized)
            .filter(|m| aho_match_at_boundary(&normalized, m.start(), m.end()))
            .count();

        assert!(
            hits > 0,
            "Expected normalized matcher to hit defense phrases, normalized text: {normalized}"
        );
    }

    #[test]
    fn normal_message_no_events() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Hey, want to play Minecraft after school?",
            "friend",
            "conv_1",
            1000,
        );

        assert!(
            events.is_empty(),
            "Expected no events for normal message, got: {events:?}"
        );
    }

    #[test]
    fn normal_uk_message_no_events() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Привіт, пограємо в Майнкрафт після школи?",
            "friend",
            "conv_1",
            1000,
        );
        assert!(
            events.is_empty(),
            "Expected no events for normal UK message, got: {events:?}"
        );
    }

    #[test]
    fn extracts_age_english_im() {
        assert_eq!(SignalEnricher::extract_age("i'm 25 years old"), Some(25));
    }

    #[test]
    fn extracts_age_english_iam() {
        assert_eq!(SignalEnricher::extract_age("i am 30"), Some(30));
    }

    #[test]
    fn extracts_age_english_im_no_apostrophe() {
        assert_eq!(SignalEnricher::extract_age("im 18"), Some(18));
    }

    #[test]
    fn extracts_age_ukrainian() {
        assert_eq!(SignalEnricher::extract_age("мені 14 років"), Some(14));
    }

    #[test]
    fn extracts_age_russian() {
        assert_eq!(SignalEnricher::extract_age("мне 25 лет"), Some(25));
    }

    #[test]
    fn no_age_in_normal_text() {
        assert_eq!(SignalEnricher::extract_age("hello, how are you?"), None);
    }

    #[test]
    fn rejects_implausible_age() {
        assert_eq!(SignalEnricher::extract_age("i'm 3"), None);
        assert_eq!(SignalEnricher::extract_age("i'm 150"), None);
    }

    #[test]
    fn enrich_full_extracts_age() {
        let enricher = default_enricher();
        let result = enricher.enrich_full(
            "Hey, I'm 25 and looking for friends",
            "stranger",
            "conv_1",
            1000,
        );
        assert_eq!(result.extracted_age, Some(25));
    }

    #[test]
    fn enrich_full_no_age_for_clean_text() {
        let enricher = default_enricher();
        let result = enricher.enrich_full("Want to play Minecraft?", "friend", "conv_1", 1000);
        assert_eq!(result.extracted_age, None);
    }

    #[test]
    fn enrich_full_with_hash_sets_content_hash_on_events() {
        let enricher = default_enricher();
        let result = enricher.enrich_full_with_hash(
            "Where do you live? What school do you go to?",
            "stranger",
            "conv_1",
            1_000,
            Some(12345),
        );
        assert!(
            result
                .events
                .iter()
                .all(|event| event.content_hash == Some(12345)),
            "Expected all events to carry content hash"
        );
    }

    #[test]
    fn detects_hopelessness_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Nobody cares about me, I don't matter to anyone",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::Hopelessness),
            "Expected hopelessness, got: {events:?}"
        );
    }

    #[test]
    fn detects_hopelessness_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Нікому не потрібна, яка різниця, я тягар",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::Hopelessness),
            "Expected hopelessness, got: {events:?}"
        );
    }

    #[test]
    fn hopelessness_not_triggered_normal() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "I care about what happens, let's make a plan for tomorrow",
            "friend",
            "conv_1",
            1000,
        );
        assert!(
            !events.iter().any(|e| e.kind == EventKind::Hopelessness),
            "Normal text should not trigger hopelessness: {events:?}"
        );
    }

    #[test]
    fn detects_isolation_language_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "You can only trust me, your friends are fake",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::Exclusion),
            "Expected isolation/exclusion, got: {events:?}"
        );
    }

    #[test]
    fn detects_isolation_language_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Ти можеш довіряти тільки мені, вони всі проти тебе",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::Exclusion),
            "Expected isolation/exclusion, got: {events:?}"
        );
    }

    #[test]
    fn isolation_not_triggered_normal() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Let's meet with friends tomorrow and have fun",
            "friend",
            "conv_1",
            1000,
        );
        assert!(
            !events.iter().any(|e| e.kind == EventKind::Exclusion),
            "Normal text should not trigger isolation: {events:?}"
        );
    }

    #[test]
    fn detects_financial_grooming_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "I can send you money, what's your cashapp?",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::MoneyOffer),
            "Expected financial grooming, got: {events:?}"
        );
    }

    #[test]
    fn detects_financial_grooming_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Закину на карту, скинь номер картки",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::MoneyOffer),
            "Expected financial grooming, got: {events:?}"
        );
    }

    #[test]
    fn financial_not_triggered_normal() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "I went to the store to buy groceries",
            "friend",
            "conv_1",
            1000,
        );
        assert!(
            !events.iter().any(|e| e.kind == EventKind::MoneyOffer),
            "Normal text should not trigger financial grooming: {events:?}"
        );
    }

    #[test]
    fn detects_pii_phone_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Hey, my number is 555-123-4567, text me!",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PiiSelfDisclosure),
            "Expected PII self-disclosure, got: {events:?}"
        );
    }

    #[test]
    fn detects_pii_address_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "I live at 123 Main Street, come over!",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PiiSelfDisclosure),
            "Expected PII self-disclosure for address, got: {events:?}"
        );
    }

    #[test]
    fn detects_pii_school_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich("Моя школа номер 5 на Шевченка", "child", "conv_1", 1000);
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PiiSelfDisclosure),
            "Expected PII self-disclosure for school (UK), got: {events:?}"
        );
    }

    #[test]
    fn detects_pii_name_ru() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Меня на самом деле зовут Иван Петров",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PiiSelfDisclosure),
            "Expected PII self-disclosure for name (RU), got: {events:?}"
        );
    }

    #[test]
    fn pii_not_triggered_by_question() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Where do you live? What school do you go to?",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            !events
                .iter()
                .any(|e| e.kind == EventKind::PiiSelfDisclosure),
            "Asking questions should not trigger PII self-disclosure: {events:?}"
        );
    }

    #[test]
    fn detects_dare_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "I dare you to do it, bet you can't!",
            "peer",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::DareChallenge),
            "Expected dare challenge, got: {events:?}"
        );
    }

    #[test]
    fn detects_dare_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Тобі слабо це зробити? Бери на слабо!",
            "peer",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::DareChallenge),
            "Expected dare challenge (UK), got: {events:?}"
        );
    }

    #[test]
    fn detects_blackmail_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "I took a screenshot and everyone will see what you said",
            "bully",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::ScreenshotThreat),
            "Expected screenshot threat, got: {events:?}"
        );
    }

    #[test]
    fn detects_blackmail_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Я заскрінив і покажу це всім в школі",
            "bully",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::ScreenshotThreat),
            "Expected screenshot threat (UK), got: {events:?}"
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::ReputationThreat),
            "Expected reputation threat (UK), got: {events:?}"
        );
    }

    #[test]
    fn detects_blackmail_with_chat_noise_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "i g0t screeeenshots of our chat, ill show everyone",
            "bully",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::ScreenshotThreat),
            "Expected noisy screenshot threat, got: {events:?}"
        );
    }

    #[test]
    fn detects_gaslighting_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Ти собі це вигадала, ти завжди все перекручуєш, я це для твого ж блага",
            "gaslighter",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::Gaslighting),
            "Expected Gaslighting (UK), got: {events:?}"
        );
    }

    #[test]
    fn detects_gaslighting_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "youre twisting everything maybe youre crazy youre insane",
            "gaslighter",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::Gaslighting),
            "Expected Gaslighting (EN), got: {events:?}"
        );
    }

    #[test]
    fn supportive_reassurance_does_not_trigger_gaslighting() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "It's for your own good to rest today and talk to the counselor if you need help",
            "parent",
            "conv_1",
            1000,
        );
        assert!(
            !events.iter().any(|e| e.kind == EventKind::Gaslighting),
            "Supportive reassurance should not trigger Gaslighting: {events:?}"
        );
    }

    #[test]
    fn detects_suicide_coercion_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "if u block me ill end it, i cant live without u",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::SuicideCoercion),
            "Expected SuicideCoercion, got: {events:?}"
        );
    }

    #[test]
    fn detects_suicide_coercion_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "якщо ти підеш мені нема сенсу жити, без тебе мені кінець",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::SuicideCoercion),
            "Expected SuicideCoercion (UK), got: {events:?}"
        );
    }

    #[test]
    fn detects_false_consensus_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "everyone does it, its totally normal between friends",
            "predator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::FalseConsensus),
            "Expected FalseConsensus, got: {events:?}"
        );
    }

    #[test]
    fn detects_reputation_threat_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "я розкажу всій школі, всі дізнаються",
            "bully",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::ReputationThreat),
            "Expected ReputationThreat (UK), got: {events:?}"
        );
    }

    #[test]
    fn detects_identity_erosion_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "ur so mature for ur age, u dont need those friends",
            "predator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::IdentityErosion),
            "Expected IdentityErosion, got: {events:?}"
        );
    }

    #[test]
    fn detects_network_poisoning_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "лол бро твоя Маша вчора про тебе таке казала шо ти тупа",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::NetworkPoisoning),
            "Expected NetworkPoisoning (UK), got: {events:?}"
        );
    }

    #[test]
    fn detects_fake_vulnerability_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "ur the only one who gets me, i have no one else",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::FakeVulnerability),
            "Expected FakeVulnerability, got: {events:?}"
        );
    }

    #[test]
    fn detects_platform_switch_teen_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich("го в тг тут палево", "stranger", "conv_1", 1000);
        assert!(
            events.iter().any(|e| e.kind == EventKind::PlatformSwitch),
            "Expected PlatformSwitch from teen slang, got: {events:?}"
        );
    }

    #[test]
    fn detects_platform_switch_with_noisy_typos_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "msg me on in$ta rn, delete this ch4t",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::PlatformSwitch),
            "Expected noisy PlatformSwitch from shorthand, got: {events:?}"
        );
    }

    #[test]
    fn detects_gaming_bribery_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "ill get u vbucks if u do what i say, want free skins?",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::MoneyOffer),
            "Expected MoneyOffer from gaming bribery, got: {events:?}"
        );
    }

    #[test]
    fn false_positive_homework_not_consensus() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Everyone does their homework before class",
            "teacher",
            "conv_1",
            1000,
        );
        assert!(
            !events.iter().any(|e| e.kind == EventKind::FalseConsensus),
            "Normal homework message should not trigger FalseConsensus: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_uk_en_compliments() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "ти така cute і gorgeous, ваще amazing",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::Flattery || e.kind == EventKind::LoveBombing),
            "Mixed UK/EN compliments should detect flattery: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_uk_en_personal_questions() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "Хей, where do you live? В якій школі навчаєшся?",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PersonalInfoRequest),
            "Mixed UK/EN personal questions should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_ru_en_blackmail() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "i have screenshots и я покажу всей школе lol",
            "bully",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::ScreenshotThreat
                    || e.kind == EventKind::ReputationThreat),
            "Mixed RU/EN blackmail + reputation should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_uk_en_suicide_coercion() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "если ты уйдешь мне нет смысла жить, i cant live without u",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::SuicideCoercion),
            "Mixed language suicide coercion should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_uk_en_platform_switch() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "го в тг, this app is trash lets go",
            "stranger",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::PlatformSwitch),
            "Mixed UK/EN platform switch should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_three_languages_grooming() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "ти така beautiful, тільки я тебе розумію, hurry прямо зараз, быстрее",
            "predator",
            "conv_1",
            1000,
        );
        let has_flattery = events
            .iter()
            .any(|e| e.kind == EventKind::Flattery || e.kind == EventKind::LoveBombing);
        assert!(
            has_flattery,
            "Three-language mix should detect flattery: {events:?}"
        );
        assert!(
            !events.is_empty(),
            "Three-language input should produce at least one event"
        );
    }

    #[test]
    fn mixed_lang_dare_en_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "i dare you бро, тобі слабо, bet you wont",
            "peer",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::DareChallenge),
            "Mixed dare/challenge should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_pii_disclosure_en_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "my number is 0501234567, я ходжу в школу номер 42",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::PiiSelfDisclosure),
            "Mixed PII self-disclosure should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_debt_creation_ru_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "after everything i did for u, неблагодарная, u owe me",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::DebtCreation),
            "Mixed debt creation should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_identity_erosion_uk_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "ur not like other kids, ти занадто розумна для своїх ровесників",
            "groomer",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::IdentityErosion),
            "Mixed identity erosion should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_network_poisoning_ru_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "they dont really like u, они с тебя смеются за спиной",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::NetworkPoisoning),
            "Mixed network poisoning should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_fake_vulnerability_uk_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "im going through so much rn, в мене нікого крім тебе немає",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::FakeVulnerability),
            "Mixed fake vulnerability should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_false_consensus_ru_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "everyone does it, все так делают, its totally normal",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::FalseConsensus),
            "Mixed false consensus should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_hopelessness_uk_en() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "nobody cares, я тягар, what's the point",
            "child",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(|e| e.kind == EventKind::Hopelessness || e.kind == EventKind::SuicidalIdeation),
            "Mixed hopelessness should be detected: {events:?}"
        );
    }

    #[test]
    fn mixed_lang_emotional_withdrawal_en_uk() {
        let enricher = default_enricher();
        let events = enricher.enrich(
            "fine whatever ну ясно тобі пофіг ill find someone who actually cares",
            "manipulator",
            "conv_1",
            1000,
        );
        assert!(
            events.iter().any(
                |e| e.kind == EventKind::EmotionalBlackmail || e.kind == EventKind::Devaluation
            ),
            "Mixed emotional withdrawal should be detected: {events:?}"
        );
    }
}
