use aura_domain::{DomainEventKind, DomainSignal};

pub(crate) fn event_kind_for_signal(signal: &DomainSignal) -> Option<DomainEventKind> {
    let reason = signal.reason_code.as_str();
    if reason.contains("military.opsec.coordinate_compound") {
        return Some(DomainEventKind::CoordinateMention);
    }
    if reason.contains("military.psyops.social_eng_compound")
        || reason.contains("military.psyops.family_pressure")
    {
        return Some(DomainEventKind::MilitaryDisinfo);
    }
    if reason.contains("military.social_eng.command_spoof") {
        return Some(DomainEventKind::MilitaryPhishing);
    }

    match signal.threat_type.as_deref() {
        Some("opsec_violation") => Some(DomainEventKind::PositionLeak),
        Some("coordinate_leak") => Some(DomainEventKind::CoordinateMention),
        Some("psyops") => Some(DomainEventKind::PsyopsPattern),
        Some("military_social_eng") => Some(DomainEventKind::IntelGathering),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::event_kind_for_signal;
    use crate::lexicon;
    use aura_domain::{DomainEventKind, DomainSignal};

    fn signal(reason_code: &str, threat_type: &str) -> DomainSignal {
        DomainSignal {
            reason_code: reason_code.to_string(),
            threat_type: Some(threat_type.to_string()),
            ..DomainSignal::default()
        }
    }

    #[test]
    fn military_owns_specific_and_family_fallback_routing() {
        assert_eq!(
            event_kind_for_signal(&signal(
                "military.social_eng.command_spoof",
                "military_social_eng"
            )),
            Some(DomainEventKind::MilitaryPhishing)
        );
        assert_eq!(
            event_kind_for_signal(&signal(
                "military.social_eng.position_probing",
                "military_social_eng"
            )),
            Some(DomainEventKind::IntelGathering)
        );
    }

    #[test]
    fn every_military_lexicon_rule_has_a_typed_route() {
        let families = [
            lexicon::opsec_rules(),
            lexicon::coordinate_rules(),
            lexicon::psyops_rules(),
            lexicon::social_eng_rules(),
        ];

        for rules in families {
            for rule in rules {
                let signal = signal(
                    rule.reason_code.as_str(),
                    rule.threat_type.as_deref().unwrap_or_default(),
                );
                assert!(
                    event_kind_for_signal(&signal).is_some(),
                    "missing typed route for {}",
                    rule.reason_code
                );
            }
        }
    }
}
