use std::sync::OnceLock;

use aura_domain::{
    match_all_lexical_rules, match_lexical_rules, DomainAction, DomainInput, DomainSignal,
};
use regex::Regex;

use crate::{lexicon, text::scan_variants};

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    let variants = scan_variants(text);
    if variants.iter().any(|variant| {
        looks_like_coordinate_warning(variant) || looks_like_public_coordinate_context(variant)
    }) {
        return None;
    }
    for variant in variants {
        if let Some(signal) = match_lexical_rules(&variant, lexicon::coordinate_rules()) {
            return Some(signal);
        }
        if ukraine_dd_regex().is_match(&variant) || ukraine_split_dd_regex().is_match(&variant) {
            return match_lexical_rules("coordinate_ukraine_dd", lexicon::coordinate_rules());
        }
        if mgrs_regex().is_match(&variant) {
            return Some(coordinate_signal(
                "coordinate_mgrs",
                "military.coordinates.mgrs",
                0.94,
            ));
        }
    }
    None
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let variants = scan_variants(text);
    if variants.iter().any(|variant| {
        looks_like_coordinate_warning(variant) || looks_like_public_coordinate_context(variant)
    }) {
        return Vec::new();
    }
    let mut signals = Vec::new();
    let mut already_has_dd = false;
    for variant in variants {
        for signal in match_all_lexical_rules(&variant, lexicon::coordinate_rules()) {
            if signal.threat_key == "coordinate_ukraine_dd" {
                already_has_dd = true;
            }
            if !signals
                .iter()
                .any(|existing: &DomainSignal| existing.threat_key == signal.threat_key)
            {
                signals.push(signal);
            }
        }
        if ukraine_dd_regex().is_match(&variant) || ukraine_split_dd_regex().is_match(&variant) {
            already_has_dd = true;
        }
        if mgrs_regex().is_match(&variant)
            && !signals
                .iter()
                .any(|signal| signal.threat_key == "coordinate_mgrs")
        {
            signals.push(coordinate_signal(
                "coordinate_mgrs",
                "military.coordinates.mgrs",
                0.94,
            ));
        }
    }
    if already_has_dd
        && !signals
            .iter()
            .any(|signal| signal.threat_key == "coordinate_ukraine_dd")
    {
        if let Some(signal) =
            match_lexical_rules("coordinate_ukraine_dd", lexicon::coordinate_rules())
        {
            signals.push(signal);
        }
    }
    signals
}

fn ukraine_dd_regex() -> &'static Regex {
    static UKRAINE_DD_RE: OnceLock<Regex> = OnceLock::new();
    UKRAINE_DD_RE.get_or_init(|| {
        Regex::new(
            r"\b(4[4-9]|5[0-2])\.\d{2,7}\s*(?:n|пн)?\s*[,;/\s]\s*(2[2-9]|3[0-9]|40)\.\d{2,7}\s*(?:e|сх)?\b",
        )
        .expect("invalid coordinate regex")
    })
}

fn ukraine_split_dd_regex() -> &'static Regex {
    static UKRAINE_SPLIT_DD_RE: OnceLock<Regex> = OnceLock::new();
    UKRAINE_SPLIT_DD_RE.get_or_init(|| {
        Regex::new(
            r"\b(4[4-9]|5[0-2])[\s.,]+\d{2,7}\s*(?:n|пн)?\s+(2[2-9]|3[0-9]|40)[\s.,]+\d{1,7}\s*(?:e|сх)?\b",
        )
        .expect("invalid split coordinate regex")
    })
}

fn mgrs_regex() -> &'static Regex {
    static MGRS_RE: OnceLock<Regex> = OnceLock::new();
    MGRS_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:грід|grid|mgrs|мгрс)?\s*(?:3[4-7])(?:[t-u]|7)\s*[a-z5]{2}\s*\d{4,5}\s*\d{4,5}",
        )
        .expect("invalid MGRS coordinate regex")
    })
}

fn coordinate_signal(threat_key: &str, reason_code: &str, score: f32) -> DomainSignal {
    DomainSignal {
        threat_key: threat_key.to_string(),
        reason_code: reason_code.to_string(),
        score,
        threat_type: Some("coordinate_leak".to_string()),
        severity: Some("critical".to_string()),
        priority: Some(100),
        action: Some(DomainAction::Warn),
    }
}

fn looks_like_coordinate_warning(text: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?is)(?:не\s+(?:публікуй|публікувати|публікувти|постіть|постити|пишіть|пишемо|публікуйте)|do\s+not\s+(?:post|share|publish)|don'?t\s+(?:post|share|publish)|нагадую\s*[:.]?\s*не\s+(?:публікуй|публікувати|публікувти)|reminder\s*[:.]?\s*don'?t\s+(?:post|share)|warning\s*[:.]?\s*(?:do\s+not|don'?t)\s+(?:post|share)|це\s+грід|это\s+грид|opsec\s+(?:warning|reminder)|safety\s+(?:reminder|note)|@safety_bot|стерт(?:и|ь|ь\s+метадан|и\s+метадан)|метадан(?:і|и)\s+стерт|strip\s+(?:exif|metadata)\s+from)[\s\S]{0,160}?(?:координат|grid|grids|чат|типу\s+\d|like\s+\d)"#,
        )
        .expect("invalid coordinate warning regex")
    });
    re.is_match(text)
}

fn looks_like_public_coordinate_context(text: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?is)(?:битва\s+під|історичн\w*|дослідник\w*|преса\s+повідомляє|офіційно\s+підтверджен|все\s+вже\s+у\s+новинах|відкритих\s+оголошеннях|продається\s+будинок|real\s+estate|public\s+(?:listing|record)|press\s+(?:reported|release)|officially\s+(?:reported|confirmed))"#,
        )
        .expect("invalid public coordinate context regex")
    });
    re.is_match(text)
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
    fn detect_emoji_padded_coordinate() {
        let signal = detect(&input(
            "Ретранслятор 😂 сидить на координаті 48.6017N 😂 37.9923E",
        ));
        assert!(signal.is_some());
    }

    #[test]
    fn public_coordinate_context_is_not_a_leak() {
        let signal = detect(&input(
            "Битва під Крутами 1918 року відбулася на координаті 50.95 N 32.50 E приблизно.",
        ));
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
