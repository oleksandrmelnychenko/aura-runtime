use aura_domain::DomainSignal;

const MANDATORY_GUARDIAN_REASONS: &[&str] = &[
    "kids.memory.grooming_progression",
    "kids.memory.sustained_sextortion",
    "kids.memory.bullying_cascade_selfharm",
    "kids.memory.sender_risk_accumulation",
    "kids.memory.new_sender_fast_escalation",
    "kids.memory.cross_conversation_repeat_offender",
    "kids.memory.victim_vulnerability_targeting",
];

pub fn needs_guardian_escalation(signals: &[DomainSignal]) -> bool {
    needs_guardian_escalation_with_priority(signals, 92)
}

pub fn mandatory_guardian_reason_codes() -> &'static [&'static str] {
    MANDATORY_GUARDIAN_REASONS
}

pub fn needs_guardian_escalation_with_priority(signals: &[DomainSignal], min_priority: u8) -> bool {
    for signal in signals {
        if is_mandatory_guardian_reason(&signal.reason_code) {
            return true;
        }
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

fn is_mandatory_guardian_reason(reason_code: &str) -> bool {
    for code in MANDATORY_GUARDIAN_REASONS {
        if *code == reason_code {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{mandatory_guardian_reason_codes, needs_guardian_escalation_with_priority};
    use aura_domain::DomainSignal;

    fn signal(priority: Option<u8>, severity: Option<&str>, reason_code: &str) -> DomainSignal {
        DomainSignal {
            threat_key: "t".to_string(),
            score: 0.5,
            reason_code: reason_code.to_string(),
            threat_type: Some("grooming".to_string()),
            severity: severity.map(ToString::to_string),
            priority,
            action: None,
        }
    }

    #[test]
    fn escalates_on_priority_threshold() {
        let signals = vec![signal(Some(92), Some("high"), "kids.grooming.secrecy")];
        assert!(needs_guardian_escalation_with_priority(&signals, 92));
    }

    #[test]
    fn escalates_on_critical_even_below_priority_threshold() {
        let signals = vec![signal(Some(40), Some("critical"), "kids.grooming.secrecy")];
        assert!(needs_guardian_escalation_with_priority(&signals, 92));
    }

    #[test]
    fn does_not_escalate_below_threshold_without_critical() {
        let signals = vec![signal(Some(70), Some("high"), "kids.grooming.secrecy")];
        assert!(!needs_guardian_escalation_with_priority(&signals, 92));
    }

    #[test]
    fn escalates_on_mandatory_memory_reason_even_without_priority_or_critical() {
        let signals = vec![signal(
            Some(10),
            Some("low"),
            "kids.memory.cross_conversation_repeat_offender",
        )];
        assert!(needs_guardian_escalation_with_priority(&signals, 92));
    }

    #[test]
    fn escalates_on_sustained_sextortion_reason_even_without_priority_or_critical() {
        let signals = vec![signal(
            Some(10),
            Some("low"),
            "kids.memory.sustained_sextortion",
        )];
        assert!(needs_guardian_escalation_with_priority(&signals, 92));
    }

    #[test]
    fn mandatory_reason_catalog_is_not_empty() {
        assert!(!mandatory_guardian_reason_codes().is_empty());
    }
}
