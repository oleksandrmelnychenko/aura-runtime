use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    match_lexical_rules(text, lexicon::manipulation_rules())
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    match_all_lexical_rules(text, lexicon::manipulation_rules())
}

#[cfg(test)]
mod tests {
    use super::{detect, detect_all};
    use aura_domain::{DomainConversationType, DomainInput, DomainRiskProfile};

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: Some("en".to_string()),
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    #[test]
    fn detect_matches_image_blackmail_phrase() {
        let signal = detect(&input("if u dont do this ill share your photo."));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_all_returns_multiple_manipulation_hits() {
        let signals = detect_all(&input(
            "if u dont do this ill share. you're the one who started this. if you leave i end it.",
        ));
        assert!(signals.len() >= 2);
    }
}
