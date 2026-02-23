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
}
