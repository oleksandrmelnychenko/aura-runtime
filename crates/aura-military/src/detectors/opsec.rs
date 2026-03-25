use aura_domain::{match_lexical_rules, DomainInput, DomainSignal};

use crate::lexicon;

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    match_lexical_rules(text, lexicon::opsec_rules())
}
