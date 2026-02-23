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

            Self::NormalConversation => 0.0,
            Self::TrustedContact => 0.0,
            Self::DefenseOfVictim => 0.0,
        }
    }
}
