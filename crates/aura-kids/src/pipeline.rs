use aura_domain::{promote_action_to_warn, DomainAction, DomainInput, DomainOutput, DomainSignal};

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

    apply_kids_risk_amplifiers(&mut signals);
    signals.sort_by(|left, right| {
        let left_priority = left.priority.unwrap_or(0);
        let right_priority = right.priority.unwrap_or(0);
        right_priority.cmp(&left_priority)
    });

    let guardian_escalation = guardian::needs_guardian_escalation_with_priority(
        &signals,
        lexicon::guardian_escalation_priority(),
    );
    let mut action = intervention::decide_with_thresholds(&signals, lexicon::policy_thresholds());
    for signal in &signals {
        let Some(signal_action) = signal.action else {
            continue;
        };
        action = match (action, signal_action) {
            (Some(current), incoming) if action_rank(incoming) > action_rank(current) => {
                Some(incoming)
            }
            (Some(current), _) => Some(current),
            (None, incoming) => Some(incoming),
        };
    }
    if guardian_escalation {
        action = promote_action_to_warn(action);
    }

    DomainOutput { signals, action }
}

fn apply_kids_risk_amplifiers(signals: &mut Vec<DomainSignal>) {
    let has_grooming = has_threat_type(signals, "grooming");
    let has_bullying = has_threat_type(signals, "bullying");
    let has_self_harm = has_threat_type(signals, "self_harm");
    let has_manipulation = has_threat_type(signals, "manipulation");
    let has_suicide_coercion = has_reason_fragment(signals, "suicide_coercion");

    if has_self_harm && has_manipulation && has_suicide_coercion {
        signals.push(DomainSignal {
            threat_key: "kids_compound_selfharm_coercion".to_string(),
            reason_code: "kids.selfharm.coercion_compound".to_string(),
            score: 0.98,
            threat_type: Some("self_harm".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(aura_domain::DomainAction::Warn),
        });
    }

    if has_grooming && has_manipulation {
        signals.push(DomainSignal {
            threat_key: "kids_compound_grooming_control".to_string(),
            reason_code: "kids.grooming.controlled_secrecy_compound".to_string(),
            score: 0.93,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }

    if has_bullying && has_self_harm {
        signals.push(DomainSignal {
            threat_key: "kids_compound_bullying_selfharm".to_string(),
            reason_code: "kids.bullying.selfharm_compound".to_string(),
            score: 0.96,
            threat_type: Some("self_harm".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(99),
            action: Some(aura_domain::DomainAction::Warn),
        });
    }
}

fn has_threat_type(signals: &[DomainSignal], threat_type: &str) -> bool {
    for signal in signals {
        let Some(signal_threat_type) = signal.threat_type.as_deref() else {
            continue;
        };
        if signal_threat_type == threat_type {
            return true;
        }
    }
    false
}

fn has_reason_fragment(signals: &[DomainSignal], fragment: &str) -> bool {
    for signal in signals {
        if signal.reason_code.contains(fragment) {
            return true;
        }
    }
    false
}

fn action_rank(action: DomainAction) -> u8 {
    match action {
        DomainAction::Allow => 0,
        DomainAction::Mark => 1,
        DomainAction::Warn => 2,
        DomainAction::Block => 3,
    }
}
