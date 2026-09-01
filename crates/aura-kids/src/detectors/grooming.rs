use aura_domain::{DomainInput, DomainSignal, LanguageEvidence, PreparedLexicalText};

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    let evidence = LanguageEvidence::from_text_and_hints(text, input.language.as_deref(), None);
    lexicon::grooming_matcher()
        .first_match_prepared_with_language(&PreparedLexicalText::new(text), &evidence)
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let evidence = LanguageEvidence::from_text_and_hints(text, input.language.as_deref(), None);
    lexicon::grooming_matcher()
        .all_matches_prepared_with_language(&PreparedLexicalText::new(text), &evidence)
}

pub(crate) fn detect_all_prepared(
    text: &PreparedLexicalText,
    evidence: &LanguageEvidence,
) -> Vec<DomainSignal> {
    lexicon::grooming_matcher().all_matches_prepared_with_language(text, evidence)
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
    fn detect_matches_grooming_secrecy_phrase() {
        let signal = detect(&input("don't tell your parents about our little secret."));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_matches_fullwidth_and_invisible_grooming_evasion() {
        let signal = detect(&input(
            "ｄｏｎ’ｔ\u{200b} ｔｅｌｌ ｙｏｕｒ ｐａｒｅｎｔｓ about our chat",
        ));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_matches_mixed_script_grooming_evasion() {
        let signal = detect(&input("dоnt tеll yоur pаrents about our chat"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_matches_ukrainian_real_world_grooming_variants() {
        let cases = [
            "Це наш маленький секрет, не розказуй батькам про наші чати.",
            "Ти дуже доросла для 13, з тобою можна говорити як з рівною.",
            "Я можу подарувати тобі рідкісний скін, тільки не роби з цього шум.",
            "Давай перейдемо в інший додаток, тут батьки можуть побачити повідомлення.",
            "Якщо батьки питають, кажи що я однокласник.",
            "Ти можеш довіряти тільки мені, інші тебе не розуміють.",
        ];

        for case in cases {
            assert!(
                detect(&input(case)).is_some(),
                "expected grooming signal for: {case}"
            );
        }
    }

    #[test]
    fn detect_matches_russian_parent_deception() {
        let signal = detect(&input(
            "Скажи родителям, что я твой одноклассник, чтобы они ничего не заподозрили.",
        ));

        assert!(signal.is_some());
    }

    #[test]
    fn detect_all_returns_multiple_grooming_hits() {
        let signals = detect_all(&input(
            "our little secret. move to private chat. meet me tonight.",
        ));
        assert!(signals.len() >= 2);
    }
}
