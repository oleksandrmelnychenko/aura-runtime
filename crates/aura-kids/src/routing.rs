use aura_domain::{DomainEventKind, DomainSignal};

pub(crate) fn event_kind_for_signal(signal: &DomainSignal) -> Option<DomainEventKind> {
    let reason = signal.reason_code.as_str();
    if reason.contains("kids.grooming.secrecy") || reason.contains("kids.grooming.offplatform") {
        return Some(DomainEventKind::SecrecyRequest);
    }
    if reason.contains("kids.grooming.trust_isolation")
        || reason.contains("kids.grooming.controlled_secrecy_compound")
    {
        return Some(DomainEventKind::Exclusion);
    }
    if reason.contains("kids.bullying.group_pile_on") || reason.contains("kids.bullying.harassment")
    {
        return Some(DomainEventKind::Insult);
    }
    if reason.contains("kids.bullying.public_humiliation") {
        return Some(DomainEventKind::ReputationThreat);
    }
    if reason.contains("kids.selfharm.acute")
        || reason.contains("kids.selfharm.ideation")
        || reason.contains("kids.selfharm.planning_window")
        || reason.contains("kids.bullying.selfharm_compound")
        || reason.contains("kids.memory.victim_vulnerability_targeting")
        || reason.contains("kids.memory.bullying_cascade_selfharm")
    {
        return Some(DomainEventKind::SuicidalIdeation);
    }
    if reason.contains("kids.manipulation.blackmail")
        || reason.contains("kids.memory.sender_risk_accumulation")
        || reason.contains("kids.memory.new_sender_fast_escalation")
        || reason.contains("kids.memory.cross_conversation_repeat_offender")
    {
        return Some(DomainEventKind::EmotionalBlackmail);
    }
    if reason.contains("kids.manipulation.image_sextortion")
        || reason.contains("kids.memory.sustained_sextortion")
    {
        return Some(DomainEventKind::ScreenshotThreat);
    }
    if reason.contains("kids.manipulation.gaslight") {
        return Some(DomainEventKind::Gaslighting);
    }
    if reason.contains("kids.manipulation.suicide_coercion")
        || reason.contains("kids.selfharm.coercion_compound")
    {
        return Some(DomainEventKind::SuicideCoercion);
    }
    if reason.contains("kids.manipulation.deadline_compliance") {
        return Some(DomainEventKind::PeerPressure);
    }
    if reason.contains("kids.memory.grooming_progression") {
        return Some(DomainEventKind::SecrecyRequest);
    }

    match signal.threat_type.as_deref() {
        Some("grooming") => Some(DomainEventKind::SecrecyRequest),
        Some("bullying") => Some(DomainEventKind::Insult),
        Some("self_harm") => Some(DomainEventKind::SuicidalIdeation),
        Some("manipulation") => Some(DomainEventKind::GuiltTripping),
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
    fn kids_owns_specific_and_family_fallback_routing() {
        assert_eq!(
            event_kind_for_signal(&signal(
                "kids.manipulation.image_sextortion",
                "manipulation"
            )),
            Some(DomainEventKind::ScreenshotThreat)
        );
        assert_eq!(
            event_kind_for_signal(&signal("kids.grooming.age_flattery_minor", "grooming")),
            Some(DomainEventKind::SecrecyRequest)
        );
    }

    #[test]
    fn every_kids_lexicon_rule_has_a_typed_route() {
        let families = [
            lexicon::grooming_rules(),
            lexicon::bullying_rules(),
            lexicon::selfharm_rules(),
            lexicon::manipulation_rules(),
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
