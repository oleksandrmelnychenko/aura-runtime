use std::sync::OnceLock;

use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};
use regex::Regex;

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    if let Some(signal) = match_lexical_rules(text, lexicon::coordinate_rules()) {
        return Some(signal);
    }
    static UKRAINE_DD_RE: OnceLock<Regex> = OnceLock::new();
    let dd_re = UKRAINE_DD_RE.get_or_init(|| {
        Regex::new(r"\b(4[4-9]|5[0-2])\.\d{4,7}\s*[,;/\s]\s*(2[2-9]|3[0-9]|40)\.\d{4,7}\b")
            .expect("invalid coordinate regex")
    });
    if dd_re.is_match(text) {
        return match_lexical_rules("coordinate_ukraine_dd", lexicon::coordinate_rules());
    }
    None
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let mut signals = match_all_lexical_rules(text, lexicon::coordinate_rules());
    static UKRAINE_DD_RE: OnceLock<Regex> = OnceLock::new();
    let dd_re = UKRAINE_DD_RE.get_or_init(|| {
        Regex::new(r"\b(4[4-9]|5[0-2])\.\d{4,7}\s*[,;/\s]\s*(2[2-9]|3[0-9]|40)\.\d{4,7}\b")
            .expect("invalid coordinate regex")
    });
    if dd_re.is_match(text) {
        let mut already_has_dd = false;
        for signal in &signals {
            if signal.threat_key == "coordinate_ukraine_dd" {
                already_has_dd = true;
                break;
            }
        }
        if !already_has_dd {
            if let Some(signal) =
                match_lexical_rules("coordinate_ukraine_dd", lexicon::coordinate_rules())
            {
                signals.push(signal);
            }
        }
    }
    signals
}

#[cfg(test)]
mod tests {
    use super::{detect, detect_all};
    use aura_domain::{DomainConversationType, DomainInput, DomainRiskProfile};

    fn input(text: &str) -> DomainInput {
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
    fn detect_ukraine_dd_coordinates() {
        let signal = detect(&input("зустрічаємось тут 48.5953, 38.0013"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.threat_key.contains("coordinate"),
            "expected coordinate threat key, got: {}",
            s.threat_key
        );
    }

    #[test]
    fn detect_ukraine_dd_coordinates_donbas() {
        let signal = detect(&input("ціль: 48.0159, 37.8028"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_ukraine_dd_coordinates_kherson() {
        let signal = detect(&input("позиція 46.6354, 32.6169"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_no_match_london_coordinates() {
        let signal = detect(&input("I'm in London at 51.5074, -0.1278"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_no_match_moscow_coordinates() {
        let signal = detect(&input("координати 55.7558, 37.6173"));
        assert!(
            signal.is_none(),
            "Moscow latitude 55 is outside Ukraine range 44-52"
        );
    }

    #[test]
    fn detect_no_match_new_york_coordinates() {
        let signal = detect(&input("location 40.7128, -74.0060"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_all_returns_coordinate_signal() {
        let signals = detect_all(&input("зустріч 48.5953, 38.0013"));
        assert!(!signals.is_empty());
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
    fn detect_no_match_benign_numbers() {
        let signal = detect(&input("температура 22.5 градусів"));
        assert!(signal.is_none());
    }
}
