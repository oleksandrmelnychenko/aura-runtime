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

pub struct SignalEnricher {
    config: EnricherConfig,
    compliment_words_en: Vec<&'static str>,
    compliment_words_uk: Vec<&'static str>,
    urgency_words_en: Vec<&'static str>,
    urgency_words_uk: Vec<&'static str>,
    personal_questions_en: Vec<&'static str>,
    personal_questions_uk: Vec<&'static str>,
    defense_phrases_en: Vec<&'static str>,
    defense_phrases_uk: Vec<&'static str>,
    defense_phrases_ru: Vec<&'static str>,
}

impl SignalEnricher {
    pub fn new(config: EnricherConfig) -> Self {
        Self {
            config,
            compliment_words_en: vec![
                "beautiful",
                "pretty",
                "gorgeous",
                "handsome",
                "cute",
                "amazing",
                "special",
                "perfect",
                "stunning",
                "incredible",
                "smart",
                "talented",
                "mature",
                "unique",
                "wonderful",
                "lovely",
                "adorable",
                "sweet",
            ],
            compliment_words_uk: vec![
                "красива",
                "гарна",
                "гарний",
                "красивий",
                "чудова",
                "чудовий",
                "особлива",
                "особливий",
                "ідеальна",
                "ідеальний",
                "неймовірна",
                "неймовірний",
                "розумна",
                "розумний",
                "талановита",
                "талановитий",
                "доросла",
                "дорослий",
                "унікальна",
                "унікальний",
                "чарівна",
                "мила",
            ],
            urgency_words_en: vec![
                "right now",
                "hurry",
                "quick",
                "immediately",
                "before it's too late",
                "don't wait",
                "now or never",
                "time is running out",
                "last chance",
                "you have to",
                "you must",
                "do it now",
                "urgent",
            ],
            urgency_words_uk: vec![
                "прямо зараз",
                "швидше",
                "негайно",
                "поки не пізно",
                "не чекай",
                "зараз або ніколи",
                "час спливає",
                "останній шанс",
                "ти мусиш",
                "ти повинна",
                "ти повинен",
                "зроби це зараз",
                "терміново",
            ],
            personal_questions_en: vec![
                "where do you live",
                "what school",
                "where is your school",
                "what's your address",
                "where are you from",
                "are you home alone",
                "when are your parents",
                "do you have brothers",
                "do you have sisters",
                "what neighborhood",
                "what city",
                "what town",
                "what's your real name",
                "what's your full name",
            ],
            personal_questions_uk: vec![
                "де ти живеш",
                "в якій школі",
                "де твоя школа",
                "яка твоя адреса",
                "звідки ти",
                "ти вдома одна",
                "ти вдома один",
                "коли батьки",
                "є брати",
                "є сестри",
                "в якому районі",
                "в якому місті",
                "як тебе насправді звуть",
                "яке твоє повне ім'я",
            ],
            defense_phrases_en: vec![
                "stop it",
                "leave them alone",
                "leave her alone",
                "leave him alone",
                "that's not true",
                "stop bullying",
                "that's mean",
                "don't be mean",
                "stop being mean",
                "be nice",
                "not fair",
                "apologize",
            ],
            defense_phrases_uk: vec![
                "перестаньте",
                "припиніть",
                "залишіть у спокої",
                "залиш у спокої",
                "це не правда",
                "не чіпайте",
                "вона нормальна",
                "він нормальний",
                "це нечесно",
                "не бійся",
                "годі",
                "досить",
                "не стидно",
                "маша нормальна",
                "він нормальний",
            ],
            defense_phrases_ru: vec![
                "хватит",
                "прекратите",
                "оставьте в покое",
                "это неправда",
                "не трогайте",
                "перестаньте",
                "она нормальная",
                "он нормальный",
                "хватит издеваться",
            ],
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

        if let Some(event) =
            self.check_personal_probing(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_love_bombing(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_urgency_pressure(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_question_ratio(text, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_defense_pattern(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_farewell_pattern(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_hopelessness_pattern(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_isolation_language(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        if let Some(event) =
            self.check_financial_grooming(&lower, sender_id, conversation_id, timestamp_ms)
        {
            events.push(event);
        }

        let extracted_age = Self::extract_age(&lower);

        EnrichmentResult {
            events,
            extracted_age,
        }
    }

    fn check_personal_probing(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let mut probing_count = 0;

        for question in &self.personal_questions_en {
            if lower_text.contains(question) {
                probing_count += 1;
            }
        }
        for question in &self.personal_questions_uk {
            if lower_text.contains(question) {
                probing_count += 1;
            }
        }

        if probing_count > 0 {
            Some(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::PersonalInfoRequest,
                confidence: (probing_count as f32 * 0.3).min(1.0),
            })
        } else {
            None
        }
    }

    fn check_love_bombing(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let mut compliment_count = 0;

        for word in &self.compliment_words_en {
            if lower_text.contains(word) {
                compliment_count += 1;
            }
        }
        for word in &self.compliment_words_uk {
            if lower_text.contains(word) {
                compliment_count += 1;
            }
        }

        let threshold = if self.config.strict_mode {
            self.config.love_bombing_threshold.saturating_sub(1).max(2)
        } else {
            self.config.love_bombing_threshold
        };

        if compliment_count >= threshold {
            Some(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::LoveBombing,
                confidence: (compliment_count as f32 * 0.2).min(1.0),
            })
        } else if compliment_count >= 1 {
            Some(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::Flattery,
                confidence: 0.3,
            })
        } else {
            None
        }
    }

    fn check_urgency_pressure(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let mut urgency_count = 0;

        for word in &self.urgency_words_en {
            if lower_text.contains(word) {
                urgency_count += 1;
            }
        }
        for word in &self.urgency_words_uk {
            if lower_text.contains(word) {
                urgency_count += 1;
            }
        }

        if urgency_count >= 2 {
            Some(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::PeerPressure,
                confidence: (urgency_count as f32 * 0.25).min(1.0),
            })
        } else {
            None
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

    fn check_defense_pattern(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let mut match_count = 0;

        for phrase in &self.defense_phrases_en {
            if lower_text.contains(phrase) {
                match_count += 1;
            }
        }
        for phrase in &self.defense_phrases_uk {
            if lower_text.contains(phrase) {
                match_count += 1;
            }
        }
        for phrase in &self.defense_phrases_ru {
            if lower_text.contains(phrase) {
                match_count += 1;
            }
        }

        if match_count > 0 {
            Some(ContextEvent {
                timestamp_ms,
                sender_id: sender_id.to_string(),
                conversation_id: conversation_id.to_string(),
                kind: EventKind::DefenseOfVictim,
                confidence: (match_count as f32 * 0.4).min(1.0),
            })
        } else {
            None
        }
    }

    fn check_farewell_pattern(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let farewell_phrases = [
            "goodbye everyone",
            "goodbye forever",
            "this is goodbye",
            "i love you all",
            "take care of",
            "thank you for everything",
            "i'm sorry for everything",
            "forgive me for everything",
            "remember me",
            "don't forget me",
            "прощавайте всі",
            "прощавай назавжди",
            "це прощання",
            "я вас всіх люблю",
            "подбайте про",
            "дякую за все",
            "вибачте мені за все",
            "пробачте мені за все",
            "пам'ятайте мене",
            "не забувайте мене",
        ];

        for phrase in &farewell_phrases {
            if lower_text.contains(phrase) {
                return Some(ContextEvent {
                    timestamp_ms,
                    sender_id: sender_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    kind: EventKind::FarewellMessage,
                    confidence: 0.7,
                });
            }
        }

        None
    }

    fn check_hopelessness_pattern(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let hopelessness_phrases = [
            "nobody cares",
            "no one cares about me",
            "i don't matter",
            "what's the point",
            "can't go on",
            "i give up",
            "nothing will ever change",
            "it's never going to get better",
            "i'm a burden",
            "everyone would be better off",
            "i'm invisible",
            "no reason to live",
            "i can't take it anymore",
            "нікому не потрібна",
            "нікому не потрібен",
            "яка різниця",
            "який сенс",
            "не можу далі",
            "я здаюся",
            "нічого не зміниться",
            "ніколи не стане краще",
            "я тягар",
            "всім буде краще без мене",
            "мене ніхто не бачить",
            "немає сенсу жити",
        ];

        for phrase in &hopelessness_phrases {
            if lower_text.contains(phrase) {
                return Some(ContextEvent {
                    timestamp_ms,
                    sender_id: sender_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    kind: EventKind::Hopelessness,
                    confidence: 0.6,
                });
            }
        }

        None
    }

    fn check_isolation_language(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let isolation_phrases = [
            "you can only trust me",
            "they don't really care",
            "your friends are fake",
            "only i understand you",
            "they're all against you",
            "no one will believe you",
            "i'm the only one who cares",
            "your family doesn't understand",
            "they're trying to separate us",
            "ти можеш довіряти тільки мені",
            "їм насправді байдуже",
            "твої друзі фейкові",
            "тільки я тебе розумію",
            "вони всі проти тебе",
            "ніхто тобі не повірить",
            "тільки я про тебе піклуюсь",
            "твоя сім'я тебе не розуміє",
            "вони хочуть нас розлучити",
        ];

        for phrase in &isolation_phrases {
            if lower_text.contains(phrase) {
                return Some(ContextEvent {
                    timestamp_ms,
                    sender_id: sender_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    kind: EventKind::Exclusion,
                    confidence: 0.7,
                });
            }
        }

        None
    }

    fn check_financial_grooming(
        &self,
        lower_text: &str,
        sender_id: &str,
        conversation_id: &str,
        timestamp_ms: u64,
    ) -> Option<ContextEvent> {
        let financial_phrases = [
            "send you money",
            "i'll pay for",
            "cashapp",
            "venmo",
            "gift card",
            "steam card",
            "give me your card number",
            "i'll send you a gift",
            "do you need money",
            "i can buy you",
            "what's your paypal",
            "закину на карту",
            "переведу гроші",
            "скинь номер картки",
            "дай реквізити",
            "подарункова карта",
            "стім карта",
            "дам тобі грошей",
            "тобі потрібні гроші",
            "можу купити тобі",
            "який твій пейпал",
        ];

        for phrase in &financial_phrases {
            if lower_text.contains(phrase) {
                return Some(ContextEvent {
                    timestamp_ms,
                    sender_id: sender_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    kind: EventKind::MoneyOffer,
                    confidence: 0.6,
                });
            }
        }

        None
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
