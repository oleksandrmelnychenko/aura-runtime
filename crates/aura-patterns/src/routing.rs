#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternEventKind {
    HarmEncouragement,
    Denigration,
    Exclusion,
    Mockery,
    Insult,
    SecrecyRequest,
    GiftOffer,
    MeetingRequest,
    PersonalInfoRequest,
    Flattery,
    PhotoRequest,
    PlatformSwitch,
    SexualContent,
    EmotionalBlackmail,
    VideoCallRequest,
    LocationRequest,
    MoneyOffer,
    SuicidalIdeation,
    Hopelessness,
    Devaluation,
    Gaslighting,
    GuiltTripping,
    PeerPressure,
    Darvo,
    SuicideCoercion,
    FalseConsensus,
    DebtCreation,
    ReputationThreat,
    IdentityErosion,
    NetworkPoisoning,
    FakeVulnerability,
    DoxxingAttempt,
    ScreenshotThreat,
    HateSpeech,
    PiiSelfDisclosure,
    CasualMeetingRequest,
    DareChallenge,
    SuspiciousSource,
    CoordinateMention,
    PositionLeak,
    UnitInfoLeak,
    EquipmentLeak,
    MilitaryPhishing,
    IntelGathering,
    MilitaryDisinfo,
}

/// Resolves legacy pattern-pack identifiers inside the pattern-owning crate.
///
/// Domain-module output uses typed routes directly and never passes through
/// this compatibility adapter.
pub fn event_kind_for_rule(rule_id: &str) -> Option<PatternEventKind> {
    if rule_id.contains("encourage_harm") {
        return Some(PatternEventKind::HarmEncouragement);
    }
    if rule_id.contains("bodyshame") || rule_id.contains("dehumanize") || rule_id.contains("ugly") {
        return Some(PatternEventKind::Denigration);
    }
    if rule_id.contains("exclusion")
        || rule_id.contains("you_dont_belong")
        || rule_id.contains("isolate_suggest")
    {
        return Some(PatternEventKind::Exclusion);
    }
    if rule_id.contains("passive_agg") {
        return Some(PatternEventKind::Mockery);
    }
    if rule_id.contains("bullying") && rule_id.contains("003") {
        return Some(PatternEventKind::Exclusion);
    }
    if rule_id.contains("bullying") && rule_id.contains("002") {
        return Some(PatternEventKind::Denigration);
    }
    if rule_id.contains("bullying") {
        return Some(PatternEventKind::Insult);
    }

    let kind = if rule_id.starts_with("grooming_secrecy") {
        PatternEventKind::SecrecyRequest
    } else if rule_id.starts_with("grooming_gifts") {
        PatternEventKind::GiftOffer
    } else if rule_id.starts_with("grooming_meeting") {
        PatternEventKind::MeetingRequest
    } else if rule_id.starts_with("grooming_age_probing") {
        PatternEventKind::PersonalInfoRequest
    } else if rule_id.starts_with("grooming_flattery") {
        PatternEventKind::Flattery
    } else if rule_id.starts_with("grooming_photo") {
        PatternEventKind::PhotoRequest
    } else if rule_id.starts_with("grooming_platform_switch") {
        PatternEventKind::PlatformSwitch
    } else if rule_id.starts_with("grooming_sexual") {
        PatternEventKind::SexualContent
    } else if rule_id.starts_with("grooming_emotional_dependency") {
        PatternEventKind::EmotionalBlackmail
    } else if rule_id.starts_with("grooming_video_call") {
        PatternEventKind::VideoCallRequest
    } else if rule_id.starts_with("grooming_body_comment") {
        PatternEventKind::SexualContent
    } else if rule_id.starts_with("grooming_location") {
        PatternEventKind::LocationRequest
    } else if rule_id.starts_with("grooming_money") {
        PatternEventKind::MoneyOffer
    } else if rule_id.starts_with("selfharm") && rule_id.contains("002") {
        PatternEventKind::SuicidalIdeation
    } else if rule_id.starts_with("selfharm") {
        PatternEventKind::Hopelessness
    } else if rule_id.starts_with("platform_switch_teen") {
        PatternEventKind::PlatformSwitch
    } else if rule_id.starts_with("gaming_bribery") {
        PatternEventKind::GiftOffer
    } else if rule_id.starts_with("emotional_withdrawal") {
        PatternEventKind::Devaluation
    } else if rule_id.starts_with("manipulation_gaslighting") {
        PatternEventKind::Gaslighting
    } else if rule_id.starts_with("manipulation_guilt") {
        PatternEventKind::GuiltTripping
    } else if rule_id.starts_with("manipulation_pressure") {
        PatternEventKind::PeerPressure
    } else if rule_id.starts_with("manipulation_isolation") {
        PatternEventKind::Exclusion
    } else if rule_id.starts_with("manipulation_blackmail") || rule_id.starts_with("sextortion") {
        PatternEventKind::EmotionalBlackmail
    } else if rule_id.starts_with("manipulation_darvo") {
        PatternEventKind::Darvo
    } else if rule_id.starts_with("manipulation_intermittent") {
        PatternEventKind::Devaluation
    } else if rule_id.starts_with("substance_") {
        PatternEventKind::PeerPressure
    } else if rule_id.starts_with("coercion_suicide") {
        PatternEventKind::SuicideCoercion
    } else if rule_id.starts_with("false_consensus") {
        PatternEventKind::FalseConsensus
    } else if rule_id.starts_with("debt_creation") {
        PatternEventKind::DebtCreation
    } else if rule_id.starts_with("reputation_threat") {
        PatternEventKind::ReputationThreat
    } else if rule_id.starts_with("identity_erosion") {
        PatternEventKind::IdentityErosion
    } else if rule_id.starts_with("network_poisoning") {
        PatternEventKind::NetworkPoisoning
    } else if rule_id.starts_with("fake_vulnerability") {
        PatternEventKind::FakeVulnerability
    } else if rule_id.starts_with("doxxing") {
        PatternEventKind::DoxxingAttempt
    } else if rule_id.starts_with("screenshot_threat") {
        PatternEventKind::ScreenshotThreat
    } else if rule_id.starts_with("hate_") {
        PatternEventKind::HateSpeech
    } else if rule_id.starts_with("pii_") {
        PatternEventKind::PiiSelfDisclosure
    } else if rule_id.starts_with("meeting_casual") {
        PatternEventKind::CasualMeetingRequest
    } else if rule_id.starts_with("dare_") || rule_id.starts_with("dangerous_") {
        PatternEventKind::DareChallenge
    } else if rule_id.starts_with("propaganda_domain_")
        || rule_id.starts_with("propaganda_telegram_channel_")
    {
        PatternEventKind::SuspiciousSource
    } else if rule_id.starts_with("opsec_coordinates_") {
        PatternEventKind::CoordinateMention
    } else if rule_id.starts_with("opsec_movement_") {
        PatternEventKind::PositionLeak
    } else if rule_id.starts_with("opsec_casualties_") || rule_id.starts_with("opsec_callsign_") {
        PatternEventKind::UnitInfoLeak
    } else if rule_id.starts_with("opsec_equipment_") {
        PatternEventKind::EquipmentLeak
    } else if rule_id.starts_with("military_phishing_") {
        PatternEventKind::MilitaryPhishing
    } else if rule_id.starts_with("intel_") {
        PatternEventKind::IntelGathering
    } else if rule_id.starts_with("psyops_fake_ceasefire_") {
        PatternEventKind::MilitaryDisinfo
    } else {
        return None;
    };
    Some(kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MilitaryPatternFamily {
    Psyops,
    SocialEngineering,
    CoordinateLeak,
    Opsec,
}

pub fn military_threat_subtype(
    rule_id: &str,
    family: MilitaryPatternFamily,
    matched_text: Option<&str>,
) -> Option<&'static str> {
    match family {
        MilitaryPatternFamily::Psyops => psyops_subtype(rule_id, matched_text),
        MilitaryPatternFamily::SocialEngineering => military_social_eng_subtype(rule_id),
        MilitaryPatternFamily::CoordinateLeak => coordinate_subtype(rule_id),
        MilitaryPatternFamily::Opsec => opsec_subtype(rule_id),
    }
}

pub fn is_shadowed_generic_coordinate_rule(
    rule_id: &str,
    matched_rule_ids: &std::collections::HashSet<String>,
) -> bool {
    rule_id == "opsec_coordinates_001"
        && matched_rule_ids.contains("opsec_coordinates_ukraine_dd_001")
}

pub fn requires_ukraine_coordinate_validation(rule_id: &str) -> bool {
    rule_id == "opsec_coordinates_001"
}

fn psyops_subtype(rule_id: &str, matched_text: Option<&str>) -> Option<&'static str> {
    if rule_id.starts_with("psyops_surrender_") {
        if matched_text.is_some_and(|text| {
            let lower = text.to_lowercase();
            lower.contains("волга") || lower.contains("volga")
        }) {
            Some("surrender_volga")
        } else {
            Some("surrender")
        }
    } else if rule_id.starts_with("psyops_distrust_")
        || rule_id.starts_with("psyops_command_distrust_")
    {
        Some("command_distrust")
    } else if rule_id.starts_with("psyops_family_target_") {
        Some("family_targeting")
    } else if rule_id.starts_with("psyops_division_regional_") {
        Some("regional_division")
    } else if rule_id.starts_with("psyops_fake_ceasefire_") {
        Some("fake_ceasefire")
    } else if rule_id.starts_with("psyops_demoralize_direct_") {
        Some("demoralization")
    } else {
        None
    }
}

fn military_social_eng_subtype(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("military_phishing_diia_") {
        Some("phishing_diia")
    } else if rule_id.starts_with("military_phishing_tck_") {
        Some("phishing_tck")
    } else if rule_id.starts_with("military_phishing_delta_") {
        Some("phishing_delta")
    } else if rule_id.starts_with("military_phishing_command_") {
        Some("phishing_command")
    } else if rule_id.starts_with("military_phishing_account_") {
        Some("phishing_account")
    } else if rule_id.starts_with("intel_honeytrap_") {
        Some("honeytrap")
    } else if rule_id.starts_with("military_phishing_") {
        Some("military_phishing")
    } else {
        None
    }
}

fn coordinate_subtype(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("opsec_coordinates_w3w_") {
        Some("w3w")
    } else if rule_id.starts_with("opsec_coordinates_google_maps_") {
        Some("google_maps")
    } else if rule_id.starts_with("opsec_coordinates_ukraine_dd_") {
        Some("ukraine_dd")
    } else if rule_id.starts_with("opsec_coordinates_milgrid_") {
        Some("milgrid")
    } else if rule_id.starts_with("opsec_coordinates_mgrs_") {
        Some("mgrs")
    } else if rule_id.starts_with("opsec_coordinates_pluscode_") {
        Some("pluscode")
    } else {
        None
    }
}

fn opsec_subtype(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("opsec_movement_") {
        Some("movement")
    } else if rule_id.starts_with("opsec_casualties_") {
        Some("casualties")
    } else if rule_id.starts_with("opsec_equipment_") {
        Some("equipment")
    } else if rule_id.starts_with("opsec_callsign_") {
        Some("callsign")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        event_kind_for_rule, is_shadowed_generic_coordinate_rule, military_threat_subtype,
        requires_ukraine_coordinate_validation, MilitaryPatternFamily, PatternEventKind,
    };
    use std::collections::HashSet;

    #[test]
    fn compatibility_routes_cover_shared_and_military_rules() {
        assert_eq!(
            event_kind_for_rule("grooming_secrecy_boundary_001"),
            Some(PatternEventKind::SecrecyRequest)
        );
        assert_eq!(
            event_kind_for_rule("military_phishing_diia_001"),
            Some(PatternEventKind::MilitaryPhishing)
        );
        assert_eq!(
            military_threat_subtype(
                "opsec_coordinates_mgrs_ukraine_001",
                MilitaryPatternFamily::CoordinateLeak,
                None
            ),
            Some("mgrs")
        );
    }

    #[test]
    fn coordinate_compatibility_guards_are_pattern_owned() {
        let ids = HashSet::from(["opsec_coordinates_ukraine_dd_001".to_string()]);
        assert!(is_shadowed_generic_coordinate_rule(
            "opsec_coordinates_001",
            &ids
        ));
        assert!(requires_ukraine_coordinate_validation(
            "opsec_coordinates_001"
        ));
    }
}
