use aura_domain::DomainSignal;

pub fn needs_guardian_escalation(signals: &[DomainSignal]) -> bool {
    needs_guardian_escalation_with_priority(signals, 92)
}

pub fn needs_guardian_escalation_with_priority(signals: &[DomainSignal], min_priority: u8) -> bool {
    for signal in signals {
        if let Some(priority) = signal.priority {
            if priority >= min_priority {
                return true;
            }
        }
        let is_critical = match signal.severity.as_deref() {
            Some("critical") => true,
            Some(_) => false,
            None => false,
        };
        if is_critical {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::needs_guardian_escalation_with_priority;
    use aura_domain::DomainSignal;

    fn signal(priority: Option<u8>, severity: Option<&str>) -> DomainSignal {
        DomainSignal {
            threat_key: "t".to_string(),
            score: 0.5,
            reason_code: "r".to_string(),
            threat_type: Some("grooming".to_string()),
            severity: severity.map(ToString::to_string),
            priority,
            action: None,
        }
    }

    #[test]
    fn escalates_on_priority_threshold() {
        let signals = vec![signal(Some(92), Some("high"))];
        assert!(needs_guardian_escalation_with_priority(&signals, 92));
    }

    #[test]
    fn escalates_on_critical_even_below_priority_threshold() {
        let signals = vec![signal(Some(40), Some("critical"))];
        assert!(needs_guardian_escalation_with_priority(&signals, 92));
    }

    #[test]
    fn does_not_escalate_below_threshold_without_critical() {
        let signals = vec![signal(Some(70), Some("high"))];
        assert!(!needs_guardian_escalation_with_priority(&signals, 92));
    }
}
