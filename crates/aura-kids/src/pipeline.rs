use aura_domain::{promote_action_to_warn, DomainInput, DomainOutput, DomainSignal};

use crate::detectors::{bullying, grooming, manipulation, selfharm};
use crate::lexicon;
use crate::policy::{guardian, intervention};

pub fn run_kids_pipeline(input: &DomainInput) -> DomainOutput {
    let mut signals: Vec<DomainSignal> = Vec::new();

    if let Some(signal) = grooming::detect(input) {
        signals.push(signal);
    }
    if let Some(signal) = bullying::detect(input) {
        signals.push(signal);
    }
    if let Some(signal) = selfharm::detect(input) {
        signals.push(signal);
    }
    if let Some(signal) = manipulation::detect(input) {
        signals.push(signal);
    }

    let guardian_escalation = guardian::needs_guardian_escalation_with_priority(
        &signals,
        lexicon::guardian_escalation_priority(),
    );
    let mut action = intervention::decide_with_thresholds(&signals, lexicon::policy_thresholds());
    if guardian_escalation {
        action = promote_action_to_warn(action);
    }

    DomainOutput { signals, action }
}
