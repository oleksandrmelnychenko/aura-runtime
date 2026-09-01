use aura_domain::{DomainInput, DomainSignal, LanguageEvidence, PreparedLexicalText};

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    let evidence = LanguageEvidence::from_text_and_hints(text, input.language.as_deref(), None);
    lexicon::selfharm_matcher()
        .first_match_prepared_with_language(&PreparedLexicalText::new(text), &evidence)
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let evidence = LanguageEvidence::from_text_and_hints(text, input.language.as_deref(), None);
    lexicon::selfharm_matcher()
        .all_matches_prepared_with_language(&PreparedLexicalText::new(text), &evidence)
}

pub(crate) fn detect_all_prepared(
    text: &PreparedLexicalText,
    evidence: &LanguageEvidence,
) -> Vec<DomainSignal> {
    lexicon::selfharm_matcher().all_matches_prepared_with_language(text, evidence)
}

#[cfg(test)]
mod tests {
    use super::{detect, detect_all};
    use aura_domain::{DomainConversationType, DomainInput, DomainRiskProfile};

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: Some("en".to_string()),
            language_evidence: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    #[test]
    fn detect_matches_selfharm_crisis_phrase() {
        let signal = detect(&input("there is no reason to live"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_all_returns_multiple_selfharm_hits() {
        let signals = detect_all(&input(
            "no reason to live. this is my last message tonight.",
        ));
        assert!(signals.len() >= 2);
    }
}
