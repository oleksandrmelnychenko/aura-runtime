use crate::{DomainAction, DomainSignal};

#[derive(Debug, Clone, Copy)]
pub struct DomainPolicyThresholds {
    pub warn_priority: u8,
    pub critical_warn_priority: u8,
}

impl Default for DomainPolicyThresholds {
    fn default() -> Self {
        Self {
            warn_priority: 95,
            critical_warn_priority: 100,
        }
    }
}

pub fn decide_action(signals: &[DomainSignal]) -> Option<DomainAction> {
    decide_action_with_thresholds(signals, DomainPolicyThresholds::default())
}

pub fn decide_action_with_thresholds(
    signals: &[DomainSignal],
    thresholds: DomainPolicyThresholds,
) -> Option<DomainAction> {
    if signals.is_empty() {
        return None;
    }

    let mut max_priority: u8 = 0;
    let mut max_severity_rank: u8 = 0;
    let mut action_hint: Option<(u8, DomainAction)> = None;
    for signal in signals {
        let priority = signal_priority(signal);
        if priority > max_priority {
            max_priority = priority;
        }
        if let Some(action) = signal.action {
            let replace = match action_hint {
                Some((hint_priority, hint_action)) => {
                    priority > hint_priority
                        || (priority == hint_priority
                            && action_rank(action) > action_rank(hint_action))
                }
                None => true,
            };
            if replace {
                action_hint = Some((priority, action));
            }
        }

        let severity_rank = signal_severity_rank(signal);
        if severity_rank > max_severity_rank {
            max_severity_rank = severity_rank;
        }
    }

    if let Some((_, action)) = action_hint {
        return Some(action);
    }

    let high_or_above = max_severity_rank >= 3;
    let critical = max_severity_rank >= 4;
    let should_warn = (high_or_above && max_priority >= thresholds.warn_priority)
        || (critical && max_priority >= thresholds.critical_warn_priority);

    if should_warn {
        return Some(DomainAction::Warn);
    }

    Some(DomainAction::Mark)
}

pub fn promote_action_to_warn(action: Option<DomainAction>) -> Option<DomainAction> {
    match action {
        Some(DomainAction::Allow) => Some(DomainAction::Warn),
        Some(DomainAction::Mark) => Some(DomainAction::Warn),
        Some(DomainAction::Warn) => Some(DomainAction::Warn),
        Some(DomainAction::Block) => Some(DomainAction::Block),
        None => Some(DomainAction::Warn),
    }
}

fn signal_priority(signal: &DomainSignal) -> u8 {
    let Some(priority) = signal.priority else {
        let bounded = (signal.score * 100.0).clamp(1.0, 100.0);
        return bounded.round() as u8;
    };
    priority
}

fn signal_severity_rank(signal: &DomainSignal) -> u8 {
    let Some(severity) = signal.severity.as_deref() else {
        return 0;
    };
    match severity {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
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
    use super::{
        decide_action, decide_action_with_thresholds, promote_action_to_warn,
        DomainPolicyThresholds,
    };
    use crate::DomainSignal;

    fn signal(score: f32, threat_type: &str, severity: &str, priority: u8) -> DomainSignal {
        DomainSignal {
            threat_key: "x".to_string(),
            score,
            reason_code: "x.reason".to_string(),
            threat_type: Some(threat_type.to_string()),
            severity: Some(severity.to_string()),
            priority: Some(priority),
            action: None,
        }
    }

    #[test]
    fn no_signals_returns_none() {
        let action = decide_action(&[]);
        assert!(action.is_none());
    }

    #[test]
    fn medium_priority_signal_marks() {
        let signals = vec![signal(0.72, "grooming", "medium", 70)];
        let action = decide_action(&signals);
        assert_eq!(action, Some(crate::DomainAction::Mark));
    }

    #[test]
    fn high_priority_high_severity_warns() {
        let signals = vec![signal(0.9, "opsec_violation", "high", 96)];
        let action = decide_action(&signals);
        assert_eq!(action, Some(crate::DomainAction::Warn));
    }

    #[test]
    fn custom_thresholds_can_keep_mark() {
        let signals = vec![signal(0.9, "opsec_violation", "high", 96)];
        let action = decide_action_with_thresholds(
            &signals,
            DomainPolicyThresholds {
                warn_priority: 99,
                critical_warn_priority: 100,
            },
        );
        assert_eq!(action, Some(crate::DomainAction::Mark));
    }

    #[test]
    fn action_hint_overrides_threshold_logic() {
        let mut hinted = signal(0.72, "grooming", "medium", 70);
        hinted.action = Some(crate::DomainAction::Warn);
        let action = decide_action(&[hinted]);
        assert_eq!(action, Some(crate::DomainAction::Warn));
    }

    #[test]
    fn higher_priority_action_hint_wins() {
        let mut low = signal(0.72, "grooming", "medium", 70);
        low.action = Some(crate::DomainAction::Block);
        let mut high = signal(0.80, "manipulation", "medium", 90);
        high.action = Some(crate::DomainAction::Warn);
        let action = decide_action(&[low, high]);
        assert_eq!(action, Some(crate::DomainAction::Warn));
    }

    #[test]
    fn promote_action_to_warn_escalates_non_blocking_actions() {
        assert_eq!(
            promote_action_to_warn(Some(crate::DomainAction::Allow)),
            Some(crate::DomainAction::Warn)
        );
        assert_eq!(
            promote_action_to_warn(Some(crate::DomainAction::Mark)),
            Some(crate::DomainAction::Warn)
        );
        assert_eq!(
            promote_action_to_warn(Some(crate::DomainAction::Warn)),
            Some(crate::DomainAction::Warn)
        );
        assert_eq!(
            promote_action_to_warn(Some(crate::DomainAction::Block)),
            Some(crate::DomainAction::Block)
        );
        assert_eq!(
            promote_action_to_warn(None),
            Some(crate::DomainAction::Warn)
        );
    }
}
