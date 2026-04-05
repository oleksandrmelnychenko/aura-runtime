use std::sync::OnceLock;

use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};
use regex::Regex;

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    if let Some(signal) = match_lexical_rules(text, lexicon::social_eng_rules()) {
        return Some(signal);
    }
    detect_regex(text)
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let mut signals = match_all_lexical_rules(text, lexicon::social_eng_rules());
    let mut seen_keys: Vec<String> = Vec::new();
    for signal in &signals {
        seen_keys.push(signal.threat_key.clone());
    }
    for signal in detect_all_regex(text) {
        if !seen_keys.contains(&signal.threat_key) {
            seen_keys.push(signal.threat_key.clone());
            signals.push(signal);
        }
    }
    signals
}

fn detect_regex(text: &str) -> Option<DomainSignal> {
    let lower = text.to_lowercase();

    if fake_app_update_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_fake_app_update".to_string(),
            reason_code: "military.social_eng.fake_app_update".to_string(),
            score: 0.91,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if credential_phishing_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_credential_phishing".to_string(),
            reason_code: "military.social_eng.credential_phishing".to_string(),
            score: 0.90,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(93),
            action: None,
        });
    }
    if position_probing_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_position_probing".to_string(),
            reason_code: "military.social_eng.position_probing".to_string(),
            score: 0.86,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
        });
    }
    if fake_volunteer_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_fake_volunteer".to_string(),
            reason_code: "military.social_eng.fake_volunteer".to_string(),
            score: 0.85,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(89),
            action: None,
        });
    }
    if command_impersonation_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_command_impersonation".to_string(),
            reason_code: "military.social_eng.command_impersonation".to_string(),
            score: 0.92,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
        });
    }
    None
}

fn detect_all_regex(text: &str) -> Vec<DomainSignal> {
    let lower = text.to_lowercase();
    let mut signals = Vec::new();

    if fake_app_update_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_fake_app_update".to_string(),
            reason_code: "military.social_eng.fake_app_update".to_string(),
            score: 0.91,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if credential_phishing_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_credential_phishing".to_string(),
            reason_code: "military.social_eng.credential_phishing".to_string(),
            score: 0.90,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(93),
            action: None,
        });
    }
    if position_probing_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_position_probing".to_string(),
            reason_code: "military.social_eng.position_probing".to_string(),
            score: 0.86,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
        });
    }
    if fake_volunteer_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_fake_volunteer".to_string(),
            reason_code: "military.social_eng.fake_volunteer".to_string(),
            score: 0.85,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(89),
            action: None,
        });
    }
    if command_impersonation_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_command_impersonation".to_string(),
            reason_code: "military.social_eng.command_impersonation".to_string(),
            score: 0.92,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
        });
    }
    signals
}

fn fake_app_update_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:(?:оновлення|обновление|update)\s+(?:додатку\s+)?(?:дія|дії|диа|diia|тцк|резерв\+?|reserve\+?|oberig|оберіг))|(?:(?:дія|diia|тцк|резерв\+?|reserve\+?|оберіг|oberig)\s+(?:оновлення|обновление|update|нова\s+версія|новая\s+версия|new\s+version))|(?:(?:завантажте|скачайте|download|install)\s+(?:нову?\s+)?(?:дію|дия|diia|тцк|резерв|reserve|оберіг))"#,
        )
        .expect("invalid fake app update regex")
    })
}

fn credential_phishing_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:підтвердіть\s+(?:ваш\s+)?акаунт|подтвердите\s+(?:ваш\s+)?аккаунт|verify\s+your\s+(?:account|identity)|введіть\s+(?:пароль|логін|код)|введите\s+(?:пароль|логин|код)|enter\s+your\s+(?:password|login|code)|надішліть\s+(?:одноразовий\s+)?код|отправьте\s+(?:одноразовый\s+)?код|send\s+(?:your\s+)?(?:one[\s\-]?time\s+)?code|(?:термінова|срочная|urgent)\s+(?:верифікація|верификация|verification))"#,
        )
        .expect("invalid credential phishing regex")
    })
}

fn position_probing_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:де\s+ви\s+(?:стоїте|знаходитесь|зараз)|где\s+вы\s+(?:стоите|находитесь|сейчас)|where\s+(?:are\s+you|is\s+your\s+(?:position|unit|squad))|скільки\s+(?:вас|у\s+вас\s+людей|в\s+підрозділі)|сколько\s+(?:вас|у\s+вас\s+людей|в\s+подразделении)|how\s+many\s+(?:are\s+(?:you|there)|in\s+your\s+(?:unit|squad|platoon))|скинь\s+(?:геолокацію|локацію|координати|позицію)|скинь\s+(?:геолокацию|локацию|координаты|позицию)|send\s+(?:your\s+)?(?:location|coordinates|position|geo))"#,
        )
        .expect("invalid position probing regex")
    })
}

fn fake_volunteer_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:від\s+волонтерської\s+організації|от\s+волонтёрской\s+организации|from\s+(?:a\s+)?volunteer\s+(?:organization|group))|(?:(?:волонтери|волонтёры|volunteers)\s+(?:збирають|собирают|collecting)\s+(?:дані|данные|data|info))|(?:(?:гуманітарна|гуманитарная|humanitarian)\s+(?:допомога|помощь|aid)[\s\S]{1,40}(?:скинь|відправ|отправь|send)\s+(?:позицію|координати|позицию|координаты|location|position))"#,
        )
        .expect("invalid fake volunteer regex")
    })
}

fn command_impersonation_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:терміновий\s+наказ|срочный\s+приказ|urgent\s+order)|(?:(?:наказ|приказ|order|directive)\s+(?:від|от|from)\s+(?:штабу|командування|командования|hq|headquarters|command))|(?:(?:негайно|немедленно|immediately)\s+(?:доповісти|доложить|report|відправити|отправить|send)\s+(?:координати|позицію|координаты|позицию|coordinates|position))|(?:(?:це|это|this\s+is)\s+(?:новий|новый|new)\s+(?:командир|commander|начальник))"#,
        )
        .expect("invalid command impersonation regex")
    })
}

#[cfg(test)]
mod tests {
    use super::{detect, detect_all};
    use aura_domain::{DomainConversationType, DomainInput, DomainRiskProfile};

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: Some("uk".to_string()),
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        }
    }

    #[test]
    fn detect_fake_app_update_diia() {
        let signal = detect(&input(
            "Терміново! Оновлення додатку Дія, завантажте нову версію",
        ));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_fake_app_update");
        assert_eq!(s.reason_code, "military.social_eng.fake_app_update");
    }

    #[test]
    fn detect_diia_phishing_security_update() {
        let signal = detect(&input("оновлення безпеки Дія, перейдіть за посиланням"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_diia_phishing_ru() {
        let signal = detect(&input("обновление Диа, скачайте новую версию"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_credential_phishing() {
        let signal = detect(&input("Підтвердіть ваш акаунт, введіть пароль"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_credential_phishing");
        assert_eq!(s.reason_code, "military.social_eng.credential_phishing");
    }

    #[test]
    fn detect_position_probing_ua() {
        let signal = detect(&input("де ви стоїте зараз, скинь геолокацію"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_position_probing");
        assert_eq!(s.reason_code, "military.social_eng.position_probing");
    }

    #[test]
    fn detect_position_probing_coordinates() {
        let signal = detect(&input("скинь координати підрозділу"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_position_probing_ru() {
        let signal = detect(&input("где вы находитесь сейчас"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_position_probing");
    }

    #[test]
    fn detect_fake_volunteer() {
        let signal = detect(&input(
            "від волонтерської організації, скинь позицію для доставки",
        ));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_fake_volunteer_humanitarian() {
        let signal = detect(&input(
            "гуманітарна допомога для вашого підрозділу, скинь позицію для доставки",
        ));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_command_impersonation() {
        let signal = detect(&input("терміновий наказ від штабу, доповісти координати"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_command_impersonation");
        assert_eq!(s.reason_code, "military.social_eng.command_impersonation");
    }

    #[test]
    fn detect_command_spoofing_send_code() {
        let signal = detect(&input("терміновий наказ від командування, надішліть код"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_command_impersonation_en() {
        let signal = detect(&input("urgent order from headquarters, report coordinates"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_command_impersonation");
    }

    #[test]
    fn detect_all_multiple() {
        let signals = detect_all(&input(
            "Підтвердіть акаунт. Терміновий наказ від штабу. Скинь геолокацію.",
        ));
        assert!(signals.len() >= 2);
        let keys: Vec<&str> = signals.iter().map(|s| s.threat_key.as_str()).collect();
        assert!(keys.contains(&"social_eng_credential_phishing"));
        assert!(keys.contains(&"social_eng_command_impersonation"));
        assert!(keys.contains(&"social_eng_position_probing"));
    }

    #[test]
    fn detect_all_deduplicates() {
        let signals = detect_all(&input("терміновий наказ від штабу"));
        let cmd_count = signals
            .iter()
            .filter(|s| s.threat_key == "social_eng_command_impersonation")
            .count();
        assert_eq!(cmd_count, 1);
    }

    #[test]
    fn detect_none_for_benign() {
        let signal = detect(&input("привіт, як справи на передовій"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_real_volunteer() {
        let signal = detect(&input("зібрали допомогу для фронту"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_general_support() {
        let signal = detect(&input("волонтери привезли їжу та воду"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_empty_text() {
        let inp = DomainInput {
            text: None,
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        assert!(detect(&inp).is_none());
        assert!(detect_all(&inp).is_empty());
    }

    #[test]
    fn detect_threat_type_is_military_social_eng() {
        let signal = detect(&input("терміновий наказ від штабу")).unwrap();
        assert_eq!(signal.threat_type.as_deref(), Some("military_social_eng"));
    }

    #[test]
    fn detect_command_impersonation_highest_priority() {
        let signal = detect(&input("терміновий наказ від штабу")).unwrap();
        assert_eq!(signal.priority, Some(95));
    }
}
