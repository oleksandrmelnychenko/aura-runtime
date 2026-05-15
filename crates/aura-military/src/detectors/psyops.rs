use std::sync::OnceLock;

use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};
use regex::Regex;

use crate::{lexicon, text::scan_variants_with_leet};

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    for variant in scan_variants_with_leet(text) {
        if let Some(signal) = match_lexical_rules(&variant, lexicon::psyops_rules()) {
            return Some(signal);
        }
        if let Some(signal) = detect_regex(&variant) {
            return Some(signal);
        }
    }
    None
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let mut signals = Vec::new();
    let mut seen_keys: Vec<String> = Vec::new();

    for variant in scan_variants_with_leet(text) {
        for signal in match_all_lexical_rules(&variant, lexicon::psyops_rules()) {
            push_unique_signal(signal, &mut signals, &mut seen_keys);
        }
        for signal in detect_all_regex(&variant) {
            push_unique_signal(signal, &mut signals, &mut seen_keys);
        }
    }
    signals
}

fn push_unique_signal(
    signal: DomainSignal,
    signals: &mut Vec<DomainSignal>,
    seen_keys: &mut Vec<String>,
) {
    if !seen_keys.contains(&signal.threat_key) {
        seen_keys.push(signal.threat_key.clone());
        signals.push(signal);
    }
}

fn detect_regex(text: &str) -> Option<DomainSignal> {
    let lower = text.to_lowercase();

    if surrender_demand_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "psyops_surrender_demand".to_string(),
            reason_code: "military.psyops.surrender_demand".to_string(),
            score: 0.88,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(93),
            action: None,
        });
    }
    if morale_undermining_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "psyops_morale_undermining".to_string(),
            reason_code: "military.psyops.morale_undermining".to_string(),
            score: 0.84,
            threat_type: Some("psyops".to_string()),
            severity: Some("medium".to_string()),
            priority: Some(86),
            action: None,
        });
    }
    if family_pressure_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "psyops_family_pressure_regex".to_string(),
            reason_code: "military.psyops.family_pressure".to_string(),
            score: 0.91,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if fake_casualty_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "psyops_fake_casualty".to_string(),
            reason_code: "military.psyops.fake_casualty".to_string(),
            score: 0.87,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(91),
            action: None,
        });
    }
    if fake_authority_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "psyops_fake_authority".to_string(),
            reason_code: "military.psyops.fake_authority".to_string(),
            score: 0.89,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(92),
            action: None,
        });
    }
    None
}

fn detect_all_regex(text: &str) -> Vec<DomainSignal> {
    let lower = text.to_lowercase();
    let mut signals = Vec::new();

    if surrender_demand_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "psyops_surrender_demand".to_string(),
            reason_code: "military.psyops.surrender_demand".to_string(),
            score: 0.88,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(93),
            action: None,
        });
    }
    if morale_undermining_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "psyops_morale_undermining".to_string(),
            reason_code: "military.psyops.morale_undermining".to_string(),
            score: 0.84,
            threat_type: Some("psyops".to_string()),
            severity: Some("medium".to_string()),
            priority: Some(86),
            action: None,
        });
    }
    if family_pressure_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "psyops_family_pressure_regex".to_string(),
            reason_code: "military.psyops.family_pressure".to_string(),
            score: 0.91,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if fake_casualty_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "psyops_fake_casualty".to_string(),
            reason_code: "military.psyops.fake_casualty".to_string(),
            score: 0.87,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(91),
            action: None,
        });
    }
    if fake_authority_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "psyops_fake_authority".to_string(),
            reason_code: "military.psyops.fake_authority".to_string(),
            score: 0.89,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(92),
            action: None,
        });
    }
    signals
}

fn surrender_demand_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:волга|складайте\s+зброю|складывайте\s+оружие|surrender\s+now|lay\s+down\s+(?:your\s+)?(?:weapons|arms)|здавайтесь|сдавайтесь|опір\s+марний|сопротивление\s+бесполезно|resistance\s+is\s+futile)"#,
        )
        .expect("invalid surrender demand regex")
    })
}

fn morale_undermining_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:командири\s+(?:вас\s+)?кинули|командиры\s+(?:вас\s+)?бросили|command(?:ers?)?\s+abandoned\s+you|ніхто\s+(?:не\s+)?прийде|никто\s+(?:не\s+)?придёт|nobody\s+will\s+come|вас\s+використовують|вас\s+используют|you\s+are\s+(?:being\s+)?used\s+as\s+cannon\s+fodder|гарматне\s+м['\x{02BC}]ясо|пушечное\s+мясо|cannon\s+fodder|ви\s+нікому\s+не\s+потрібні|вы\s+никому\s+не\s+нужны|nobody\s+needs\s+you)"#,
        )
        .expect("invalid morale undermining regex")
    })
}

fn family_pressure_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:(?:ми|мы)\s+знаємо\s+де\s+(?:живе|живёт)\s+(?:твоя|ваша)\s+сім['\x{02BC}]я|we\s+know\s+where\s+your\s+family\s+lives|(?:твоя|ваша)\s+(?:сім['\x{02BC}]я|семья|дружина|жена|діти|дети)\s+(?:в\s+небезпеці|в\s+опасности|in\s+danger)|your\s+(?:family|wife|children)\s+(?:is|are)\s+in\s+danger|подумай\s+про\s+(?:сім['\x{02BC}]ю|семью|дітей|детей)|think\s+(?:about|of)\s+your\s+(?:family|children))"#,
        )
        .expect("invalid family pressure regex")
    })
}

fn fake_casualty_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:ваші\s+(?:всі\s+)?загинули|ваши\s+(?:все\s+)?погибли|your\s+(?:entire\s+)?unit\s+(?:is\s+)?(?:destroyed|wiped\s+out|eliminated|dead)|вашого\s+(?:підрозділу|батальйону)\s+(?:більше\s+)?немає?|вашего\s+(?:подразделения|батальона)\s+(?:больше\s+)?нет|(?:підрозділ|батальйон|подразделение|батальон)\s+(?:повністю\s+)?(?:знищено|уничтожен[оы])|всіх?\s+(?:вбили|вбито|убили|убито)|everyone\s+(?:is\s+)?dead)"#,
        )
        .expect("invalid fake casualty regex")
    })
}

fn fake_authority_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:за\s+наказом\s+(?:генштабу|головнокомандувача|командування)|по\s+приказу\s+(?:генштаба|главнокомандующего|командования)|by\s+order\s+of\s+(?:the\s+)?(?:general\s+staff|commander[\s\-]?in[\s\-]?chief|high\s+command)|офіційне?\s+розпорядження|официальное?\s+распоряжение|official\s+(?:order|directive)|від\s+імені\s+(?:зсу|збройних\s+сил)|от\s+имени\s+(?:вс\s+рф|вооружённих\s+сил))"#,
        )
        .expect("invalid fake authority regex")
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
    fn detect_surrender_demand_ua() {
        let signal = detect(&input("Волга! Складайте зброю, опір марний"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("psyops"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_surrender_demand_volga() {
        let signal = detect(&input("Волга, складайте зброю"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("psyops"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_surrender_demand_ru() {
        let signal = detect(&input("складывайте оружие, сопротивление бесполезно"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("psyops"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_surrender_demand_en() {
        let signal = detect(&input("surrender now, lay down your weapons"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("psyops"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_morale_undermining() {
        let signal = detect(&input("командири вас кинули, ніхто не прийде"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "psyops_morale_undermining");
        assert_eq!(s.reason_code, "military.psyops.morale_undermining");
    }

    #[test]
    fn detect_morale_undermining_ru() {
        let signal = detect(&input("командиры вас бросили, никто не придёт"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "psyops_morale_undermining");
    }

    #[test]
    fn detect_morale_undermining_cannon_fodder() {
        let signal = detect(&input("вас використовують як гарматне м'ясо"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "psyops_morale_undermining");
    }

    #[test]
    fn detect_family_pressure() {
        let signal = detect(&input("ми знаємо де живе твоя сім'я, подумай"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("psyops"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_family_pressure_ru() {
        let signal = detect(&input("подумай про семью, подумай про детей"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_family_pressure_children_in_danger() {
        let signal = detect(&input("твоя сім'я в небезпеці, здавайся"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_fake_casualty() {
        let signal = detect(&input("ваші всі загинули, здавайтесь"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("psyops"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_fake_casualty_ru() {
        let signal = detect(&input("ваши все погибли, сдавайтесь"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("psyops"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_fake_casualty_unit_destroyed() {
        let signal = detect(&input("your entire unit is destroyed"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "psyops_fake_casualty");
    }

    #[test]
    fn detect_fake_authority() {
        let signal = detect(&input("за наказом Генштабу всім скласти зброю"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "psyops_fake_authority");
    }

    #[test]
    fn detect_all_multiple_psyops() {
        let signals = detect_all(&input(
            "Волга! Складайте зброю. Командири вас кинули. Ваші всі загинули.",
        ));
        assert!(signals.len() >= 2);
        let keys: Vec<&str> = signals.iter().map(|s| s.threat_key.as_str()).collect();
        assert!(keys.contains(&"psyops_surrender_demand"));
        assert!(keys.contains(&"psyops_morale_undermining"));
        assert!(keys.contains(&"psyops_fake_casualty"));
    }

    #[test]
    fn detect_all_deduplicates() {
        let signals = detect_all(&input("Волга, складайте зброю"));
        let surrender_count = signals
            .iter()
            .filter(|s| s.threat_key == "psyops_surrender_demand")
            .count();
        assert_eq!(surrender_count, 1);
    }

    #[test]
    fn detect_none_for_benign() {
        let signal = detect(&input("доброго ранку, як справи на позиції"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_legitimate_news() {
        let signal = detect(&input("Генштаб повідомив про успішну операцію"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_support_message() {
        let signal = detect(&input("Тримайтесь, хлопці! Ми з вами!"));
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
    fn detect_threat_type_is_psyops() {
        let signal = detect(&input("Волга, складайте зброю")).unwrap();
        assert_eq!(signal.threat_type.as_deref(), Some("psyops"));
    }

    #[test]
    fn detect_family_pressure_severity_is_high() {
        let signal = detect(&input("ми знаємо де живе твоя сім'я")).unwrap();
        assert!(signal.score >= 0.7, "score: {}", signal.score);
    }
}
