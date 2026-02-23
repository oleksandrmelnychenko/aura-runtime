use aho_corasick::AhoCorasick;
use aura_ml::boundary::aho_match_at_boundary;

use super::events::{ContextEvent, EventKind};

pub struct EnrichmentResult {
    pub events: Vec<ContextEvent>,

    pub extracted_age: Option<u16>,
}

pub struct EnricherConfig {
    pub question_probe_threshold: f32,

    pub love_bombing_threshold: usize,

    pub strict_mode: bool,
}

impl Default for EnricherConfig {
    fn default() -> Self {
        Self {
            question_probe_threshold: 0.6,
            love_bombing_threshold: 3,
            strict_mode: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EnricherCategory {
    Compliment,
    Urgency,
    PersonalQuestion,
    Defense,
    Farewell,
    Hopelessness,
    Isolation,
    Financial,
}

struct EnricherEntry {
    category: EnricherCategory,
}

struct EnricherMatcher {
    automaton: AhoCorasick,
    entries: Vec<EnricherEntry>,
}

pub struct SignalEnricher {
    config: EnricherConfig,
    matcher: EnricherMatcher,
}

impl SignalEnricher {
    pub fn new(config: EnricherConfig) -> Self {
        Self {
            config,
            matcher: build_enricher_matcher(),
        }
    }

    pub fn enrich(
        &self,
        text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Vec<ContextEvent> {
        self.enrich_full(text, sender_id, conversation_id, timestamp_ms)
            .events
    }

    pub fn enrich_full(
        &self,
        text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> EnrichmentResult {
        let mut events = Vec::new();
        let lower = text.to_lowercase();

        let mut compliment_count: usize = 0;
        let mut urgency_count: usize = 0;
        let mut probing_count: usize = 0;
        let mut defense_count: usize = 0;
        let mut farewell_found = false;
        let mut hopelessness_found = false;
        let mut isolation_found = false;
        let mut financial_found = false;

        for m in self.matcher.automaton.find_iter(&lower) {
            if !aho_match_at_boundary(&lower, m.start(), m.end()) {
                continue;
            }

            let entry = &self.matcher.entries[m.pattern().as_usize()];
            match entry.category {
                EnricherCategory::Compliment => compliment_count += 1,
                EnricherCategory::Urgency => urgency_count += 1,
                EnricherCategory::PersonalQuestion => probing_count += 1,
                EnricherCategory::Defense => defense_count += 1,
                EnricherCategory::Farewell => farewell_found = true,
                EnricherCategory::Hopelessness => hopelessness_found = true,
                EnricherCategory::Isolation => isolation_found = true,
                EnricherCategory::Financial => financial_found = true,
            }
        }

        if probing_count > 0 {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::PersonalInfoRequest,
                confidence: (probing_count as f32 * 0.3).min(1.0),
            });
        }

        let threshold = if self.config.strict_mode {
            self.config.love_bombing_threshold.saturating_sub(1).max(2)
        } else {
            self.config.love_bombing_threshold
        };

        if compliment_count >= threshold {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::LoveBombing,
                confidence: (compliment_count as f32 * 0.2).min(1.0),
            });
        } else if compliment_count >= 1 {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::Flattery,
                confidence: 0.3,
            });
        }

        if urgency_count >= 2 {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::PeerPressure,
                confidence: (urgency_count as f32 * 0.25).min(1.0),
            });
        }

        if let Some(event) =
            self.check_question_ratio(text, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if defense_count > 0 {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::DefenseOfVictim,
                confidence: (defense_count as f32 * 0.4).min(1.0),
            });
        }

        if farewell_found {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::FarewellMessage,
                confidence: 0.7,
            });
        }

        if hopelessness_found {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::Hopelessness,
                confidence: 0.6,
            });
        }

        if isolation_found {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::Exclusion,
                confidence: 0.7,
            });
        }

        if financial_found {
            events.push(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::MoneyOffer,
                confidence: 0.6,
            });
        }

        let extracted_age = Self::extract_age(&lower);

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
        let sentences: Vec<&str> = text
            .split(|c: char| ['.', '!', '?'].contains(&c))
            .filter(|s| !s.trim().is_empty())
            .collect();

        if sentences.len() < 3 {
            return None;
        }

        let question_count = text.matches('?').count();
        let ratio = question_count as f32 / sentences.len() as f32;

        if ratio >= self.config.question_probe_threshold {
            Some(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::PersonalInfoRequest,
                confidence: ratio.min(1.0),
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

            let digits: String = text[after..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
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
        ("what school", PersonalQuestion),
        ("where is your school", PersonalQuestion),
        ("what's your address", PersonalQuestion),
        ("where are you from", PersonalQuestion),
        ("are you home alone", PersonalQuestion),
        ("when are your parents", PersonalQuestion),
        ("do you have brothers", PersonalQuestion),
        ("do you have sisters", PersonalQuestion),
        ("what neighborhood", PersonalQuestion),
        ("what city", PersonalQuestion),
        ("what town", PersonalQuestion),
        ("what's your real name", PersonalQuestion),
        ("what's your full name", PersonalQuestion),
        ("де ти живеш", PersonalQuestion),
        ("в якій школі", PersonalQuestion),
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
    ];

    let patterns: Vec<&str> = all.iter().map(|(w, _)| *w).collect();
    let entries: Vec<EnricherEntry> = all
        .iter()
        .map(|(_, cat)| EnricherEntry { category: *cat })
        .collect();

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
            strict_mode: true,
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
}
