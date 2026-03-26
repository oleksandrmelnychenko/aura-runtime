use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    match_lexical_rules(text, lexicon::grooming_rules())
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    match_all_lexical_rules(text, lexicon::grooming_rules())
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
        }
    }

    #[test]
    fn detect_matches_grooming_secrecy_phrase() {
        let signal = detect(&input("don't tell your parents about our little secret."));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_all_returns_multiple_grooming_hits() {
        let signals = detect_all(&input("our little secret. move to private chat. meet me tonight."));
        assert!(signals.len() >= 2);
    }
}
