use aura_domain::{promote_action_to_warn, DomainAction, DomainInput, DomainOutput, DomainSignal};

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

    apply_military_risk_amplifiers(&mut signals);
    signals.sort_by(|left, right| {
        let left_priority = left.priority.unwrap_or(0);
        let right_priority = right.priority.unwrap_or(0);
        right_priority.cmp(&left_priority)
    });

    let priority_escalation = escalation::needs_priority_escalation_with_priority(
        &signals,
        lexicon::priority_escalation_priority(),
    );
    let mut action = response::decide_with_thresholds(&signals, lexicon::policy_thresholds());
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
    if priority_escalation {
        action = promote_action_to_warn(action);
    }

    DomainOutput { signals, action }
}

fn apply_military_risk_amplifiers(signals: &mut Vec<DomainSignal>) {
    let has_opsec = has_threat_type(signals, "opsec_violation");
    let has_coordinate = has_threat_type(signals, "coordinate_leak");
    let has_psyops = has_threat_type(signals, "psyops");
    let has_social_eng = has_threat_type(signals, "military_social_eng");

    if has_opsec && has_coordinate {
        signals.push(DomainSignal {
            threat_key: "military_compound_coordinate_opsec".to_string(),
            reason_code: "military.opsec.coordinate_compound".to_string(),
            score: 0.98,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(aura_domain::DomainAction::Warn),
        });
    }

    if has_psyops && has_social_eng {
        signals.push(DomainSignal {
            threat_key: "military_compound_psyops_social_eng".to_string(),
            reason_code: "military.psyops.social_eng_compound".to_string(),
            score: 0.94,
            threat_type: Some("psyops".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
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

fn action_rank(action: DomainAction) -> u8 {
    match action {
        DomainAction::Allow => 0,
        DomainAction::Mark => 1,
        DomainAction::Warn => 2,
        DomainAction::Block => 3,
    }
}
