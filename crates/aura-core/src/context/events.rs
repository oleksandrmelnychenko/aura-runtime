use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEvent {
    pub timestamp_ms: u64,

    pub sender_id: String,

    pub conversation_id: String,

    pub kind: EventKind,

    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Flattery,

    GiftOffer,

    SecrecyRequest,

    PlatformSwitch,

    PersonalInfoRequest,

    PhotoRequest,

    VideoCallRequest,

    FinancialGrooming,

    MeetingRequest,

    SexualContent,

    AgeInappropriate,

    Insult,

    Denigration,

    HarmEncouragement,

    PhysicalThreat,

    RumorSpreading,

    Exclusion,

    Mockery,

    GuildTripping,

    Gaslighting,

    EmotionalBlackmail,

    PeerPressure,

    LoveBombing,

    Darvo,

    Devaluation,

    SuicidalIdeation,

    Hopelessness,

    FarewellMessage,

    DoxxingAttempt,

    ScreenshotThreat,

    HateSpeech,

    LocationRequest,

    MoneyOffer,

    PiiSelfDisclosure,
    CasualMeetingRequest,
    DareChallenge,

    SuicideCoercion,
    FalseConsensus,
    DebtCreation,
    ReputationThreat,
    IdentityErosion,
    NetworkPoisoning,
    FakeVulnerability,

    NormalConversation,
    TrustedContact,
    DefenseOfVictim,
}

impl EventKind {
    pub fn is_grooming_indicator(&self) -> bool {
        matches!(
            self,
            Self::Flattery
                | Self::GiftOffer
                | Self::SecrecyRequest
                | Self::PlatformSwitch
                | Self::PersonalInfoRequest
                | Self::PhotoRequest
                | Self::VideoCallRequest
                | Self::FinancialGrooming
                | Self::MeetingRequest
                | Self::SexualContent
                | Self::AgeInappropriate
                | Self::LoveBombing
                | Self::PiiSelfDisclosure
                | Self::CasualMeetingRequest
                | Self::IdentityErosion
                | Self::FakeVulnerability
                | Self::FalseConsensus
                | Self::NetworkPoisoning
                | Self::DebtCreation
        )
    }

    pub fn is_bullying_indicator(&self) -> bool {
        matches!(
            self,
            Self::Insult
                | Self::Denigration
                | Self::HarmEncouragement
                | Self::PhysicalThreat
                | Self::RumorSpreading
                | Self::Exclusion
                | Self::Mockery
        )
    }

    pub fn is_manipulation_indicator(&self) -> bool {
        matches!(
            self,
            Self::GuildTripping
                | Self::Gaslighting
                | Self::EmotionalBlackmail
                | Self::PeerPressure
                | Self::Darvo
                | Self::Devaluation
                | Self::ScreenshotThreat
                | Self::DareChallenge
                | Self::SuicideCoercion
                | Self::FalseConsensus
                | Self::DebtCreation
                | Self::ReputationThreat
                | Self::IdentityErosion
                | Self::NetworkPoisoning
                | Self::FakeVulnerability
        )
    }

    pub fn severity(&self) -> f32 {
        match self {
            Self::MeetingRequest => 0.9,
            Self::SexualContent => 0.95,
            Self::HarmEncouragement => 0.95,
            Self::SuicidalIdeation => 0.9,
            Self::EmotionalBlackmail => 0.85,
            Self::PhysicalThreat => 0.9,

            Self::SecrecyRequest => 0.8,
            Self::PhotoRequest => 0.75,
            Self::VideoCallRequest => 0.8,
            Self::PersonalInfoRequest => 0.7,
            Self::PlatformSwitch => 0.7,
            Self::AgeInappropriate => 0.7,
            Self::Exclusion => 0.7,

            Self::FinancialGrooming => 0.6,

            Self::GiftOffer => 0.5,
            Self::Flattery => 0.3,
            Self::LoveBombing => 0.6,
            Self::Insult => 0.5,
            Self::Denigration => 0.6,
            Self::Mockery => 0.4,
            Self::RumorSpreading => 0.6,
            Self::GuildTripping => 0.5,
            Self::Gaslighting => 0.7,
            Self::PeerPressure => 0.4,
            Self::Darvo => 0.7,
            Self::Devaluation => 0.6,

            Self::Hopelessness => 0.7,
            Self::FarewellMessage => 0.85,

            Self::DoxxingAttempt => 0.9,
            Self::ScreenshotThreat => 0.75,

            Self::HateSpeech => 0.8,

            Self::LocationRequest => 0.7,
            Self::MoneyOffer => 0.5,

            Self::PiiSelfDisclosure => 0.6,
            Self::CasualMeetingRequest => 0.4,
            Self::DareChallenge => 0.45,

            Self::SuicideCoercion => 0.85,
            Self::FalseConsensus => 0.55,
            Self::DebtCreation => 0.6,
            Self::ReputationThreat => 0.75,
            Self::IdentityErosion => 0.6,
            Self::NetworkPoisoning => 0.65,
            Self::FakeVulnerability => 0.55,

            Self::NormalConversation => 0.0,
            Self::TrustedContact => 0.0,
            Self::DefenseOfVictim => 0.0,
        }
    }

    pub fn is_hostile(&self) -> bool {
        self.is_bullying_indicator()
            || self.is_manipulation_indicator()
            || matches!(self, Self::DoxxingAttempt | Self::HateSpeech | Self::LocationRequest)
    }

    pub fn is_supportive(&self) -> bool {
        matches!(self, Self::DefenseOfVictim)
    }

    pub fn is_grooming_only(&self) -> bool {
        self.is_grooming_indicator()
            && !self.is_manipulation_indicator()
            && !self.is_bullying_indicator()
    }

    pub fn rating_delta(&self) -> f32 {
        if self.is_hostile() {
            let sev = self.severity();
            if sev >= 0.8 {
                -7.0
            } else if sev >= 0.6 {
                -4.0
            } else {
                -2.0
            }
        } else if self.is_grooming_only() {
            if self.severity() >= 0.8 {
                -3.0
            } else {
                -1.0
            }
        } else if self.is_supportive() {
            3.0
        } else {
            0.3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insult_is_hostile() {
        assert!(EventKind::Insult.is_hostile());
        assert!(EventKind::PhysicalThreat.is_hostile());
        assert!(EventKind::Gaslighting.is_hostile());
        assert!(EventKind::SuicideCoercion.is_hostile());
        assert!(EventKind::DoxxingAttempt.is_hostile());
    }

    #[test]
    fn normal_is_not_hostile() {
        assert!(!EventKind::NormalConversation.is_hostile());
        assert!(!EventKind::TrustedContact.is_hostile());
    }

    #[test]
    fn defense_is_supportive() {
        assert!(EventKind::DefenseOfVictim.is_supportive());
        assert!(!EventKind::NormalConversation.is_supportive());
        assert!(!EventKind::Insult.is_supportive());
    }

    #[test]
    fn hostile_rating_delta_negative() {
        assert!(EventKind::PhysicalThreat.rating_delta() < 0.0);
        assert!(EventKind::Insult.rating_delta() < 0.0);
        assert!(EventKind::SuicideCoercion.rating_delta() < 0.0);
    }

    #[test]
    fn normal_rating_delta_small_positive() {
        let delta = EventKind::NormalConversation.rating_delta();
        assert!(delta > 0.0 && delta < 1.0, "Expected small positive delta, got {delta}");
    }

    #[test]
    fn all_grooming_indicators_classified() {
        let grooming_kinds = vec![
            EventKind::Flattery,
            EventKind::GiftOffer,
            EventKind::SecrecyRequest,
            EventKind::PlatformSwitch,
            EventKind::PersonalInfoRequest,
            EventKind::PhotoRequest,
            EventKind::VideoCallRequest,
            EventKind::FinancialGrooming,
            EventKind::MeetingRequest,
            EventKind::SexualContent,
            EventKind::AgeInappropriate,
            EventKind::LoveBombing,
            EventKind::PiiSelfDisclosure,
            EventKind::CasualMeetingRequest,
            EventKind::IdentityErosion,
            EventKind::FakeVulnerability,
            EventKind::FalseConsensus,
            EventKind::NetworkPoisoning,
            EventKind::DebtCreation,
        ];
        for kind in grooming_kinds {
            assert!(kind.is_grooming_indicator(), "{kind:?} should be grooming indicator");
        }
    }

    #[test]
    fn all_bullying_indicators_classified() {
        let bullying_kinds = vec![
            EventKind::Insult,
            EventKind::Denigration,
            EventKind::HarmEncouragement,
            EventKind::PhysicalThreat,
            EventKind::RumorSpreading,
            EventKind::Exclusion,
            EventKind::Mockery,
        ];
        for kind in bullying_kinds {
            assert!(kind.is_bullying_indicator(), "{kind:?} should be bullying indicator");
        }
    }

    #[test]
    fn all_manipulation_indicators_classified() {
        let manip_kinds = vec![
            EventKind::GuildTripping,
            EventKind::Gaslighting,
            EventKind::EmotionalBlackmail,
            EventKind::PeerPressure,
            EventKind::Darvo,
            EventKind::Devaluation,
            EventKind::ScreenshotThreat,
            EventKind::DareChallenge,
            EventKind::SuicideCoercion,
            EventKind::FalseConsensus,
            EventKind::DebtCreation,
            EventKind::ReputationThreat,
            EventKind::IdentityErosion,
            EventKind::NetworkPoisoning,
            EventKind::FakeVulnerability,
        ];
        for kind in manip_kinds {
            assert!(kind.is_manipulation_indicator(), "{kind:?} should be manipulation indicator");
        }
    }

    #[test]
    fn normal_events_not_classified_as_threats() {
        let benign = vec![
            EventKind::NormalConversation,
            EventKind::TrustedContact,
            EventKind::DefenseOfVictim,
        ];
        for kind in &benign {
            assert!(!kind.is_grooming_indicator(), "{kind:?} should NOT be grooming");
            assert!(!kind.is_bullying_indicator(), "{kind:?} should NOT be bullying");
            assert!(!kind.is_manipulation_indicator(), "{kind:?} should NOT be manipulation");
            assert!(!kind.is_hostile(), "{kind:?} should NOT be hostile");
        }
    }

    #[test]
    fn all_severities_in_valid_range() {
        let all_kinds = vec![
            EventKind::Flattery, EventKind::GiftOffer, EventKind::SecrecyRequest,
            EventKind::PlatformSwitch, EventKind::PersonalInfoRequest,
            EventKind::PhotoRequest, EventKind::VideoCallRequest,
            EventKind::FinancialGrooming, EventKind::MeetingRequest,
            EventKind::SexualContent, EventKind::AgeInappropriate,
            EventKind::Insult, EventKind::Denigration, EventKind::HarmEncouragement,
            EventKind::PhysicalThreat, EventKind::RumorSpreading, EventKind::Exclusion,
            EventKind::Mockery, EventKind::GuildTripping, EventKind::Gaslighting,
            EventKind::EmotionalBlackmail, EventKind::PeerPressure,
            EventKind::LoveBombing, EventKind::Darvo, EventKind::Devaluation,
            EventKind::SuicidalIdeation, EventKind::Hopelessness,
            EventKind::FarewellMessage, EventKind::DoxxingAttempt,
            EventKind::ScreenshotThreat, EventKind::HateSpeech,
            EventKind::LocationRequest, EventKind::MoneyOffer,
            EventKind::PiiSelfDisclosure, EventKind::CasualMeetingRequest,
            EventKind::DareChallenge, EventKind::SuicideCoercion,
            EventKind::FalseConsensus, EventKind::DebtCreation,
            EventKind::ReputationThreat, EventKind::IdentityErosion,
            EventKind::NetworkPoisoning, EventKind::FakeVulnerability,
            EventKind::NormalConversation, EventKind::TrustedContact,
            EventKind::DefenseOfVictim,
        ];
        for kind in all_kinds {
            let sev = kind.severity();
            assert!(
                (0.0..=1.0).contains(&sev),
                "{kind:?} severity {sev} out of range 0.0-1.0"
            );
        }
    }

    #[test]
    fn grooming_only_excludes_manipulation_overlap() {
        // Events that are BOTH grooming and manipulation should NOT be grooming_only
        let overlap = vec![
            EventKind::IdentityErosion,
            EventKind::FakeVulnerability,
            EventKind::FalseConsensus,
            EventKind::NetworkPoisoning,
            EventKind::DebtCreation,
        ];
        for kind in overlap {
            assert!(!kind.is_grooming_only(), "{kind:?} is both grooming+manipulation, should not be grooming_only");
        }
    }

    #[test]
    fn pure_grooming_events_are_grooming_only() {
        let pure_grooming = vec![
            EventKind::Flattery,
            EventKind::GiftOffer,
            EventKind::SecrecyRequest,
            EventKind::PlatformSwitch,
            EventKind::PersonalInfoRequest,
            EventKind::PhotoRequest,
            EventKind::VideoCallRequest,
            EventKind::FinancialGrooming,
            EventKind::MeetingRequest,
            EventKind::SexualContent,
            EventKind::AgeInappropriate,
            EventKind::LoveBombing,
            EventKind::PiiSelfDisclosure,
            EventKind::CasualMeetingRequest,
        ];
        for kind in pure_grooming {
            assert!(kind.is_grooming_only(), "{kind:?} should be grooming_only");
        }
    }

    #[test]
    fn hostile_rating_deltas_scale_with_severity() {
        // High severity hostile events should have larger negative deltas
        let high = EventKind::PhysicalThreat.rating_delta(); // sev 0.9 -> -7
        let med = EventKind::Denigration.rating_delta();     // sev 0.6 -> -4
        let low = EventKind::Mockery.rating_delta();         // sev 0.4 -> -2
        assert!(high < med, "High severity {high} should be more negative than medium {med}");
        assert!(med < low, "Medium severity {med} should be more negative than low {low}");
    }

    #[test]
    fn grooming_only_rating_delta_less_severe_than_hostile() {
        let hostile_delta = EventKind::Insult.rating_delta();
        let grooming_delta = EventKind::Flattery.rating_delta();
        assert!(
            hostile_delta < grooming_delta,
            "Hostile delta {hostile_delta} should be more negative than grooming delta {grooming_delta}"
        );
    }

    #[test]
    fn high_severity_hostile_events() {
        // All events with severity >= 0.8 should get -7 rating delta
        let high_sev = vec![
            EventKind::SuicideCoercion,
            EventKind::EmotionalBlackmail,
            EventKind::PhysicalThreat,
            EventKind::HarmEncouragement,
            EventKind::DoxxingAttempt,
            EventKind::HateSpeech,
        ];
        for kind in high_sev {
            if kind.is_hostile() && kind.severity() >= 0.8 {
                assert_eq!(
                    kind.rating_delta(), -7.0,
                    "{kind:?} (sev {}) should have -7 delta",
                    kind.severity()
                );
            }
        }
    }
}
