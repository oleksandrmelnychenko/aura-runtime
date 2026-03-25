use std::sync::OnceLock;

use aura_domain::{match_lexical_rules, DomainInput, DomainSignal};
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
