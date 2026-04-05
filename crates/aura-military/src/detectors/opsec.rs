use std::sync::OnceLock;

use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};
use regex::Regex;

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    if let Some(signal) = match_lexical_rules(text, lexicon::opsec_rules()) {
        return Some(signal);
    }
    detect_regex(text)
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let mut signals = match_all_lexical_rules(text, lexicon::opsec_rules());
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

    if callsign_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_callsign_leak".to_string(),
            reason_code: "military.opsec.callsign_leak".to_string(),
            score: 0.87,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if equipment_count_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_equipment_count".to_string(),
            reason_code: "military.opsec.equipment_count".to_string(),
            score: 0.90,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(97),
            action: None,
        });
    }
    if rotation_timing_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_rotation_timing".to_string(),
            reason_code: "military.opsec.rotation_timing".to_string(),
            score: 0.89,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if ammo_supply_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_ammo_supply".to_string(),
            reason_code: "military.opsec.ammo_supply".to_string(),
            score: 0.85,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if grid_reference_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_grid_reference".to_string(),
            reason_code: "military.opsec.grid_reference".to_string(),
            score: 0.93,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(99),
            action: None,
        });
    }
    if personnel_count_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_personnel_count".to_string(),
            reason_code: "military.opsec.personnel_count".to_string(),
            score: 0.86,
            threat_type: Some("opsec_violation".to_string()),
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

    if callsign_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_callsign_leak".to_string(),
            reason_code: "military.opsec.callsign_leak".to_string(),
            score: 0.87,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if equipment_count_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_equipment_count".to_string(),
            reason_code: "military.opsec.equipment_count".to_string(),
            score: 0.90,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(97),
            action: None,
        });
    }
    if rotation_timing_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_rotation_timing".to_string(),
            reason_code: "military.opsec.rotation_timing".to_string(),
            score: 0.89,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if ammo_supply_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_ammo_supply".to_string(),
            reason_code: "military.opsec.ammo_supply".to_string(),
            score: 0.85,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if grid_reference_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_grid_reference".to_string(),
            reason_code: "military.opsec.grid_reference".to_string(),
            score: 0.93,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(99),
            action: None,
        });
    }
    if personnel_count_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_personnel_count".to_string(),
            reason_code: "military.opsec.personnel_count".to_string(),
            score: 0.86,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
        });
    }
    signals
}

fn callsign_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:\bпозивний|\bпозивной|\bcallsign|\bcall[\s\-]?sign)\s*[:\-\s]\s*\w+"#)
            .expect("invalid callsign regex")
    })
}

fn equipment_count_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\d+\s*(?:бмп|бтр|танк(?:ів|и|а|ов)?|leopard|бредлі|bradley|гаубиц(?:ь|я|і)|howitzer|stryker|страйкер|мста|m777|himars|хаймарс|javelin|джавелін|nlaw|stinger|стінгер|patriot|патріот|gepard|гепард|iris[\s\-]?t|nasams|hawk|marder|мардер)"#,
        )
        .expect("invalid equipment count regex")
    })
}

fn rotation_timing_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:ротація|зміна|виїзд|відхід|марш|rotation|departure|movement|convoy)\s*(?:о|в|at|around)?\s*\d{1,2}[\s:\.]\d{2}"#,
        )
        .expect("invalid rotation timing regex")
    })
}

fn ammo_supply_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:залишилось|осталось|лишилось|left|remaining|have)\s*\d+\s*(?:бк|снарядів|снарядов|патронів|патронов|мін|мин|ракет|rounds|shells|ammo|missiles|пзрк|рпг|rpg)|(?:бк|боєкомплект|боекомплект|ammo|ammunition)\s*(?:на\s*)?(?:\d+|нуль|zero|вичерпано|кончается|закінчується)"#,
        )
        .expect("invalid ammo supply regex")
    })
}

fn grid_reference_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:квадрат|grid|square|mgrs|мгрс)\s*[:\-\s]?\s*\d{2}\s*[A-Za-z\p{Cyrillic}]{1,3}\s*\d{4,10}|\b\d{2}[A-Z]\s?[A-Z]{2}\s?\d{4,10}\b"#,
        )
        .expect("invalid grid reference regex")
    })
}

fn personnel_count_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:скільки\s+людей|сколько\s+людей|how\s+many\s+(?:soldiers|men|people|troops))|\d+\s*(?:бійців|бойцов|поранених|раненых|двохсотих|трьохсотих|двухсотых|трёхсотых|wounded|kia|soldiers|troops|casualties)|(?:(?:в\s+нас|у\s+нас|we\s+have|our\s+(?:unit|squad|platoon))\s+\d+\s*(?:людей|чоловік|человек|people|men))"#,
        )
        .expect("invalid personnel count regex")
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

    fn input_no_lang(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        }
    }

    #[test]
    fn detect_callsign_ua() {
        let signal = detect(&input("позивний: Сокіл, ми на місці"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
    }

    #[test]
    fn detect_callsign_with_frequency() {
        let signal = detect(&input("позивний Сокіл, частота 149.5"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
        assert_eq!(s.reason_code, "military.opsec.callsign_leak");
    }

    #[test]
    fn detect_callsign_ru() {
        let signal = detect(&input("позивной Ястреб, приём"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
    }

    #[test]
    fn detect_callsign_en() {
        let signal = detect(&input("callsign Eagle, standing by"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
    }

    #[test]
    fn detect_equipment_count() {
        let signal = detect(&input("у нас 3 БМП і 2 танки"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_equipment_count");
    }

    #[test]
    fn detect_equipment_count_leopard() {
        let signal = detect(&input("у нас 3 БМП та 2 Leopard"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_equipment_count");
        assert!(s.score >= 0.9);
    }

    #[test]
    fn detect_equipment_count_himars() {
        let signal = detect(&input("маємо 4 HIMARS на позиції"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_equipment_count");
    }

    #[test]
    fn detect_rotation_timing() {
        let signal = detect(&input("ротація о 04:30 завтра"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_rotation_timing");
    }

    #[test]
    fn detect_rotation_timing_morning() {
        let signal = detect(&input("ротація о 06:00 ранку"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_rotation_timing");
        assert_eq!(s.reason_code, "military.opsec.rotation_timing");
    }

    #[test]
    fn detect_rotation_timing_en() {
        let signal = detect(&input("rotation at 06:00 tomorrow"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_rotation_timing");
    }

    #[test]
    fn detect_ammo_supply() {
        let signal = detect(&input("залишилось 12 снарядів, патронів мало"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_ammo_supply");
    }

    #[test]
    fn detect_grid_reference() {
        let signal = detect(&input("квадрат 36T UQ 12345678"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_grid_reference");
    }

    #[test]
    fn detect_personnel_count_ua() {
        let signal = detect(&input("в нас 24 бійців на позиції"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
    }

    #[test]
    fn detect_personnel_count_wounded() {
        let signal = detect(&input("45 бійців, 8 поранених"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
        assert_eq!(s.reason_code, "military.opsec.personnel_count");
    }

    #[test]
    fn detect_personnel_count_ru() {
        let signal = detect(&input("у нас 30 бойцов, 5 раненых"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
    }

    #[test]
    fn detect_personnel_count_en() {
        let signal = detect(&input("we have 50 soldiers in the area"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
    }

    #[test]
    fn detect_all_multiple_violations() {
        let signals = detect_all(&input("позивний Сокіл, у нас 3 БМП, ротація о 06:00"));
        assert!(signals.len() >= 2);
        let keys: Vec<&str> = signals.iter().map(|s| s.threat_key.as_str()).collect();
        assert!(keys.contains(&"opsec_callsign_leak"));
        assert!(keys.contains(&"opsec_equipment_count"));
        assert!(keys.contains(&"opsec_rotation_timing"));
    }

    #[test]
    fn detect_all_deduplicates() {
        let signals = detect_all(&input("позивний Сокіл, ми тут"));
        let callsign_count = signals
            .iter()
            .filter(|s| s.threat_key == "opsec_callsign_leak")
            .count();
        assert_eq!(callsign_count, 1);
    }

    #[test]
    fn detect_none_for_benign() {
        let signal = detect(&input("добрий день, як справи"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_benign_military_talk() {
        let signal = detect(&input("Служу Україні!"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_generic_patriotic() {
        let signal = detect(&input("Слава Україні! Героям Слава!"));
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
    fn detect_severity_is_high() {
        let signal = detect(&input("позивний Сокіл, частота 149.5")).unwrap();
        assert_eq!(signal.severity.as_deref(), Some("high"));
        assert_eq!(signal.threat_type.as_deref(), Some("opsec_violation"));
    }

    #[test]
    fn detect_grid_severity_is_critical() {
        let signal = detect(&input("квадрат 36T UQ 12345678")).unwrap();
        assert_eq!(signal.severity.as_deref(), Some("critical"));
        assert_eq!(signal.priority, Some(99));
    }

    #[test]
    fn detect_no_lang_field_still_works() {
        let signal = detect(&input_no_lang("позивний Сокіл, частота 149.5"));
        assert!(signal.is_some());
    }
}
