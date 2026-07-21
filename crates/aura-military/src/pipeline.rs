use aura_domain::{promote_action_to_warn, DomainAction, DomainInput, DomainOutput, DomainSignal};

use crate::detectors::{coordinate_leak, opsec, psyops, social_eng};
use crate::lexicon;
use crate::policy::{escalation, response};

pub fn run_military_pipeline(input: &DomainInput) -> DomainOutput {
    let mut signals: Vec<DomainSignal> = Vec::new();

    signals.extend(opsec::detect_all(input));
    signals.extend(coordinate_leak::detect_all(input));
    signals.extend(psyops::detect_all(input));
    signals.extend(social_eng::detect_all(input));

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

#[cfg(test)]
mod tests {
    use super::run_military_pipeline;
    use aura_domain::{DomainAction, DomainConversationType, DomainInput, DomainRiskProfile};

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    #[test]
    fn compound_opsec_coordinate_critical_escalation() {
        let output = run_military_pipeline(&input("позивний Сокіл, координати 48.5953, 38.0013"));
        let keys: Vec<&str> = output
            .signals
            .iter()
            .map(|s| s.threat_key.as_str())
            .collect();
        assert!(
            keys.contains(&"military_compound_coordinate_opsec"),
            "expected compound opsec+coordinate signal, got keys: {:?}",
            keys
        );
        let compound = output
            .signals
            .iter()
            .find(|s| s.threat_key == "military_compound_coordinate_opsec")
            .unwrap();
        assert_eq!(compound.severity.as_deref(), Some("critical"));
        assert_eq!(compound.priority, Some(100));
        assert!(compound.score >= 0.98);
        assert_eq!(compound.action, Some(DomainAction::Warn));
    }

    #[test]
    fn compound_psyops_social_eng_high_escalation() {
        let output = run_military_pipeline(&input(
            "Волга, складайте зброю. Терміновий наказ від штабу, доповісти координати.",
        ));
        let keys: Vec<&str> = output
            .signals
            .iter()
            .map(|s| s.threat_key.as_str())
            .collect();
        assert!(
            keys.contains(&"military_compound_psyops_social_eng"),
            "expected compound psyops+social_eng signal, got keys: {:?}",
            keys
        );
        let compound = output
            .signals
            .iter()
            .find(|s| s.threat_key == "military_compound_psyops_social_eng")
            .unwrap();
        assert_eq!(compound.severity.as_deref(), Some("high"));
        assert_eq!(compound.priority, Some(95));
    }

    #[test]
    fn multiple_threats_in_one_message() {
        let output = run_military_pipeline(&input(
            "позивний Сокіл, у нас 3 БМП, Волга складайте зброю, терміновий наказ від штабу",
        ));
        assert!(
            output.signals.len() >= 4,
            "expected at least 4 signals for multi-threat message, got {}",
            output.signals.len()
        );
        let has_opsec = output
            .signals
            .iter()
            .any(|s| s.threat_type.as_deref() == Some("opsec_violation"));
        let has_psyops = output
            .signals
            .iter()
            .any(|s| s.threat_type.as_deref() == Some("psyops"));
        let has_social = output
            .signals
            .iter()
            .any(|s| s.threat_type.as_deref() == Some("military_social_eng"));
        assert!(has_opsec, "expected opsec signals");
        assert!(has_psyops, "expected psyops signals");
        assert!(has_social, "expected social_eng signals");
    }

    #[test]
    fn benign_message_produces_no_signals() {
        let output = run_military_pipeline(&input("Слава Україні! Героям Слава!"));
        assert!(
            output.signals.is_empty(),
            "expected no signals for benign message, got: {:?}",
            output
                .signals
                .iter()
                .map(|s| &s.threat_key)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn benign_message_no_action() {
        let output = run_military_pipeline(&input("добрий день, як справи"));
        assert!(
            output.action.is_none() || output.action == Some(DomainAction::Allow),
            "expected allow or no action for benign message, got: {:?}",
            output.action
        );
    }

    #[test]
    fn signals_sorted_by_priority_descending() {
        let output = run_military_pipeline(&input(
            "позивний Сокіл, у нас 3 БМП, ротація о 06:00, 24 бійців",
        ));
        if output.signals.len() >= 2 {
            for pair in output.signals.windows(2) {
                let left_priority = pair[0].priority.unwrap_or(0);
                let right_priority = pair[1].priority.unwrap_or(0);
                assert!(
                    left_priority >= right_priority,
                    "signals not sorted by priority: {} < {}",
                    left_priority,
                    right_priority
                );
            }
        }
    }

    #[test]
    fn empty_text_produces_no_signals() {
        let inp = DomainInput {
            text: None,
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        };
        let output = run_military_pipeline(&inp);
        assert!(output.signals.is_empty());
    }

    #[test]
    fn opsec_only_no_compound() {
        let output = run_military_pipeline(&input("позивний Сокіл, ми на місці"));
        let has_compound = output
            .signals
            .iter()
            .any(|s| s.threat_key.starts_with("military_compound"));
        assert!(
            !has_compound,
            "opsec-only message should not produce compound signals"
        );
    }
}
