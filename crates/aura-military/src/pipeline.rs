use aura_domain::{promote_action_to_warn, DomainInput, DomainOutput, DomainSignal};

use crate::detectors::{coordinate_leak, opsec, psyops, social_eng};
use crate::lexicon;
use crate::policy::{escalation, response};

pub fn run_military_pipeline(input: &DomainInput) -> DomainOutput {
    let mut signals: Vec<DomainSignal> = Vec::new();

    if let Some(signal) = opsec::detect(input) {
        signals.push(signal);
    }
    if let Some(signal) = coordinate_leak::detect(input) {
        signals.push(signal);
    }
    if let Some(signal) = psyops::detect(input) {
        signals.push(signal);
    }
    if let Some(signal) = social_eng::detect(input) {
        signals.push(signal);
    }

    let priority_escalation = escalation::needs_priority_escalation_with_priority(
        &signals,
        lexicon::priority_escalation_priority(),
    );
    let mut action = response::decide_with_thresholds(&signals, lexicon::policy_thresholds());
    if priority_escalation {
        action = promote_action_to_warn(action);
    }

    DomainOutput { signals, action }
}
