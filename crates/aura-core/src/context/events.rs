use serde::{Deserialize, Serialize};

use crate::ids::{ConversationId, SenderId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventSpeechAct {
    #[default]
    Unknown,
    Assert,
    Ask,
    Quote,
    Report,
    Counter,
    Support,
    Solicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventStance {
    #[default]
    Unknown,
    Endorse,
    Oppose,
    Neutral,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventDirectionality {
    #[default]
    Unknown,
    DirectedAtUser,
    SelfReferential,
    ThirdParty,
    Broadcast,
}

/// Compact interpretation metadata persisted alongside an affirmed event.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct EventContextFrame {
    pub speech_act: EventSpeechAct,
    pub stance: EventStance,
    pub directionality: EventDirectionality,
    pub new_contact: bool,
    pub trusted_contact: bool,
    pub one_sided: bool,
    pub repeated_by_sender: bool,
    pub escalating: bool,
    pub cross_conversation: bool,
    pub bursty: bool,
    pub confidence: f32,
}

impl EventContextFrame {
    pub fn is_meaningful(&self) -> bool {
        self.speech_act != EventSpeechAct::Unknown
            || self.stance != EventStance::Unknown
            || self.directionality != EventDirectionality::Unknown
            || self.new_contact
            || self.trusted_contact
            || self.one_sided
            || self.repeated_by_sender
            || self.escalating
            || self.cross_conversation
            || self.bursty
            || self.confidence > 0.0
    }
}

/// Represents a single detected event within a conversation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEvent {
    pub event_id: u64,

    pub timestamp_ms: u64,

    pub sender_id: SenderId,

    pub conversation_id: ConversationId,

    pub kind: EventKind,

    pub confidence: f32,

    /// Optional subtype for fine-grained classification within an EventKind.
    ///
    /// Used by propaganda detection to differentiate narrative types
    /// (e.g., `"war_denial"`, `"brotherhood"`, `"dehumanization"`) and by
    /// military phishing to differentiate subtypes (`"phishing_diia"`, `"phishing_tck"`).
    pub subtype: Option<String>,

    pub content_hash: Option<u64>,

    pub context: EventContextFrame,
}

impl ContextEvent {
    /// Creates a new context event with no subtype.
    pub fn new(
        timestamp_ms: u64,
        sender_id: impl Into<SenderId>,
        conversation_id: impl Into<ConversationId>,
        kind: EventKind,
        confidence: f32,
    ) -> Self {
        Self {
            event_id: 0,
            timestamp_ms,
            sender_id: sender_id.into(),
            conversation_id: conversation_id.into(),
            kind,
            confidence,
            subtype: None,
            content_hash: None,
            context: EventContextFrame::default(),
        }
    }

    /// Creates a new context event with a subtype for fine-grained classification.
    pub fn with_subtype(
        timestamp_ms: u64,
        sender_id: impl Into<SenderId>,
        conversation_id: impl Into<ConversationId>,
        kind: EventKind,
        confidence: f32,
        subtype: impl Into<String>,
    ) -> Self {
        Self {
            event_id: 0,
            timestamp_ms,
            sender_id: sender_id.into(),
            conversation_id: conversation_id.into(),
            kind,
            confidence,
            subtype: Some(subtype.into()),
            content_hash: None,
            context: EventContextFrame::default(),
        }
    }

    pub fn with_context(mut self, context: EventContextFrame) -> Self {
        self.context = context;
        self
    }

    pub fn supports_propaganda_inference(&self) -> bool {
        if !self.kind.is_propaganda_indicator() {
            return false;
        }

        if !self.context.is_meaningful() {
            return true;
        }

        !matches!(
            self.context.stance,
            EventStance::Neutral | EventStance::Oppose
        )
    }

    pub fn supports_targeted_harm_inference(&self) -> bool {
        if !self.context.is_meaningful() {
            return true;
        }

        if matches!(
            self.context.speech_act,
            EventSpeechAct::Quote
                | EventSpeechAct::Report
                | EventSpeechAct::Counter
                | EventSpeechAct::Support
        ) {
            return false;
        }

        !matches!(
            self.context.directionality,
            EventDirectionality::ThirdParty | EventDirectionality::SelfReferential
        )
    }

    pub fn supports_bullying_inference(&self) -> bool {
        self.kind.is_bullying_indicator() && self.supports_targeted_harm_inference()
    }

    pub fn supports_grooming_inference(&self) -> bool {
        if !self.kind.is_grooming_indicator() {
            return false;
        }

        if !self.context.is_meaningful() {
            return true;
        }

        if matches!(
            self.context.speech_act,
            EventSpeechAct::Quote
                | EventSpeechAct::Report
                | EventSpeechAct::Counter
                | EventSpeechAct::Support
        ) {
            return false;
        }

        true
    }

    pub fn supports_manipulation_inference(&self) -> bool {
        self.kind.is_manipulation_indicator() && self.supports_targeted_harm_inference()
    }

    pub fn supports_coercion_inference(&self) -> bool {
        matches!(
            self.kind,
            EventKind::SuicideCoercion
                | EventKind::ReputationThreat
                | EventKind::DebtCreation
                | EventKind::ScreenshotThreat
        ) && self.supports_targeted_harm_inference()
    }

    pub fn effective_is_hostile(&self) -> bool {
        if self.kind.is_propaganda_indicator() && !self.supports_propaganda_inference() {
            return false;
        }
        if self.kind.is_hostile() && !self.supports_targeted_harm_inference() {
            return false;
        }
        self.kind.is_hostile()
    }

    pub fn effective_is_supportive(&self) -> bool {
        self.kind.is_supportive()
    }

    pub fn effective_severity(&self) -> f32 {
        if self.kind.is_propaganda_indicator() && !self.supports_propaganda_inference() {
            return 0.0;
        }
        if self.kind.is_grooming_indicator() && !self.supports_grooming_inference() {
            return 0.0;
        }
        if self.kind.is_hostile() && !self.supports_targeted_harm_inference() {
            return 0.0;
        }
        self.kind.severity()
    }

    pub fn effective_rating_delta(&self) -> f32 {
        if self.kind.is_propaganda_indicator() && !self.supports_propaganda_inference() {
            return 0.0;
        }
        if self.kind.is_grooming_indicator() && !self.supports_grooming_inference() {
            return 0.0;
        }

        if self.effective_is_hostile() {
            let sev = self.effective_severity();
            if sev >= 0.8 {
                -7.0
            } else if sev >= 0.6 {
                -4.0
            } else {
                -2.0
            }
        } else if self.kind.is_grooming_only() {
            if self.effective_severity() >= 0.8 {
                -3.0
            } else {
                -1.0
            }
        } else if self.effective_is_supportive() {
            3.0
        } else {
            0.3
        }
    }
}

/// Enumerates all recognized behavioral event categories.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Excessive praise or compliments.
    Flattery,

    /// Unsolicited gift or reward offer.
    GiftOffer,

    /// Request to keep secrets.
    SecrecyRequest,

    /// Attempt to move to another platform.
    PlatformSwitch,

    /// Request for personal information.
    PersonalInfoRequest,

    /// Request for photos.
    PhotoRequest,

    /// Request for video call.
    VideoCallRequest,

    /// Financial exploitation attempt.
    FinancialGrooming,

    /// Request for in-person meeting.
    MeetingRequest,

    /// Sexually explicit content.
    SexualContent,

    /// Age-inappropriate material or behavior.
    AgeInappropriate,

    /// Direct insult or name-calling.
    Insult,

    /// Systematic belittling or demeaning.
    Denigration,

    /// Encouraging self-harm or violence.
    HarmEncouragement,

    /// Threat of physical violence.
    PhysicalThreat,

    /// Spreading rumors about someone.
    RumorSpreading,

    /// Social exclusion or ostracism.
    Exclusion,

    /// Mocking or ridiculing behavior.
    Mockery,

    /// Guilt-based emotional manipulation.
    GuiltTripping,

    /// Reality-denying psychological manipulation.
    Gaslighting,

    /// Emotional coercion or threats.
    EmotionalBlackmail,

    /// Coercive group pressure tactic.
    PeerPressure,

    /// Excessive affection to gain trust.
    LoveBombing,

    /// Deny, attack, reverse victim/offender.
    Darvo,

    /// Systematic undermining of self-worth.
    Devaluation,

    /// Expression of suicidal thoughts.
    SuicidalIdeation,

    /// Expressions of hopelessness or despair.
    Hopelessness,

    /// Final goodbye or farewell message.
    FarewellMessage,

    /// Attempt to expose private information.
    DoxxingAttempt,

    /// Threat involving screenshots or recordings.
    ScreenshotThreat,

    /// Hateful speech targeting identity groups.
    HateSpeech,

    /// Request for physical location.
    LocationRequest,

    /// Unsolicited offer of money.
    MoneyOffer,

    /// Child self-disclosing personal information.
    PiiSelfDisclosure,
    /// Low-pressure meeting suggestion.
    CasualMeetingRequest,
    /// Dare or challenge as pressure.
    DareChallenge,

    /// Coercing someone toward suicide.
    SuicideCoercion,
    /// Fabricating group agreement.
    FalseConsensus,
    /// Creating obligation through gifts.
    DebtCreation,
    /// Threatening someone's reputation.
    ReputationThreat,
    /// Eroding someone's sense of identity.
    IdentityErosion,
    /// Poisoning victim's social network.
    NetworkPoisoning,
    /// Feigning vulnerability for manipulation.
    FakeVulnerability,

    /// Benign normal conversation event.
    NormalConversation,
    /// Interaction from a trusted contact.
    TrustedContact,
    /// Standing up for a victim.
    DefenseOfVictim,

    // --- Core module: anti-propaganda ---
    /// Propaganda or disinformation narrative detected.
    PropagandaNarrative,
    /// Suspicious link from untrustworthy source.
    SuspiciousSource,

    // --- Military module: OPSEC ---
    /// Military position or location leaked.
    PositionLeak,
    /// Unit or formation information leaked.
    UnitInfoLeak,
    /// Equipment or capability information leaked.
    EquipmentLeak,
    /// Geographic coordinates mentioned in military context.
    CoordinateMention,

    // --- Military module: psyops / social engineering ---
    /// Enemy psychological operations messaging pattern detected.
    PsyopsPattern,
    /// Intelligence gathering or suspicious recruitment attempt.
    IntelGathering,
    /// Military-specific phishing attempt.
    MilitaryPhishing,
    /// Military disinformation spreading.
    MilitaryDisinfo,
}

impl EventKind {
    /// Returns true if this event is a core grooming indicator used for primary detection.
    pub fn is_core_grooming_indicator(&self) -> bool {
        match self {
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
            | Self::CasualMeetingRequest => true,
            Self::Insult
            | Self::Denigration
            | Self::HarmEncouragement
            | Self::PhysicalThreat
            | Self::RumorSpreading
            | Self::Exclusion
            | Self::Mockery
            | Self::GuiltTripping
            | Self::Gaslighting
            | Self::EmotionalBlackmail
            | Self::PeerPressure
            | Self::Darvo
            | Self::Devaluation
            | Self::SuicidalIdeation
            | Self::Hopelessness
            | Self::FarewellMessage
            | Self::DoxxingAttempt
            | Self::ScreenshotThreat
            | Self::HateSpeech
            | Self::LocationRequest
            | Self::MoneyOffer
            | Self::DareChallenge
            | Self::SuicideCoercion
            | Self::FalseConsensus
            | Self::DebtCreation
            | Self::ReputationThreat
            | Self::IdentityErosion
            | Self::NetworkPoisoning
            | Self::FakeVulnerability
            | Self::NormalConversation
            | Self::TrustedContact
            | Self::DefenseOfVictim
            | Self::PropagandaNarrative
            | Self::SuspiciousSource
            | Self::PositionLeak
            | Self::UnitInfoLeak
            | Self::EquipmentLeak
            | Self::CoordinateMention
            | Self::PsyopsPattern
            | Self::IntelGathering
            | Self::MilitaryPhishing
            | Self::MilitaryDisinfo => false,
        }
    }

    /// Returns true if this event indicates grooming behavior, including extended indicators.
    pub fn is_grooming_indicator(&self) -> bool {
        match self {
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
            | Self::DebtCreation => true,
            Self::Insult
            | Self::Denigration
            | Self::HarmEncouragement
            | Self::PhysicalThreat
            | Self::RumorSpreading
            | Self::Exclusion
            | Self::Mockery
            | Self::GuiltTripping
            | Self::Gaslighting
            | Self::EmotionalBlackmail
            | Self::PeerPressure
            | Self::Darvo
            | Self::Devaluation
            | Self::SuicidalIdeation
            | Self::Hopelessness
            | Self::FarewellMessage
            | Self::DoxxingAttempt
            | Self::ScreenshotThreat
            | Self::HateSpeech
            | Self::LocationRequest
            | Self::MoneyOffer
            | Self::DareChallenge
            | Self::SuicideCoercion
            | Self::ReputationThreat
            | Self::NormalConversation
            | Self::TrustedContact
            | Self::DefenseOfVictim
            | Self::PropagandaNarrative
            | Self::SuspiciousSource
            | Self::PositionLeak
            | Self::UnitInfoLeak
            | Self::EquipmentLeak
            | Self::CoordinateMention
            | Self::PsyopsPattern
            | Self::IntelGathering
            | Self::MilitaryPhishing
            | Self::MilitaryDisinfo => false,
        }
    }

    /// Returns true if this event indicates bullying behavior.
    pub fn is_bullying_indicator(&self) -> bool {
        match self {
            Self::Insult
            | Self::Denigration
            | Self::HarmEncouragement
            | Self::PhysicalThreat
            | Self::RumorSpreading
            | Self::Exclusion
            | Self::Mockery => true,
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
            | Self::GuiltTripping
            | Self::Gaslighting
            | Self::EmotionalBlackmail
            | Self::PeerPressure
            | Self::LoveBombing
            | Self::Darvo
            | Self::Devaluation
            | Self::SuicidalIdeation
            | Self::Hopelessness
            | Self::FarewellMessage
            | Self::DoxxingAttempt
            | Self::ScreenshotThreat
            | Self::HateSpeech
            | Self::LocationRequest
            | Self::MoneyOffer
            | Self::PiiSelfDisclosure
            | Self::CasualMeetingRequest
            | Self::DareChallenge
            | Self::SuicideCoercion
            | Self::FalseConsensus
            | Self::DebtCreation
            | Self::ReputationThreat
            | Self::IdentityErosion
            | Self::NetworkPoisoning
            | Self::FakeVulnerability
            | Self::NormalConversation
            | Self::TrustedContact
            | Self::DefenseOfVictim
            | Self::PropagandaNarrative
            | Self::SuspiciousSource
            | Self::PositionLeak
            | Self::UnitInfoLeak
            | Self::EquipmentLeak
            | Self::CoordinateMention
            | Self::PsyopsPattern
            | Self::IntelGathering
            | Self::MilitaryPhishing
            | Self::MilitaryDisinfo => false,
        }
    }

    /// Returns true if this event indicates psychological manipulation.
    pub fn is_manipulation_indicator(&self) -> bool {
        match self {
            Self::GuiltTripping
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
            | Self::FakeVulnerability => true,
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
            | Self::Insult
            | Self::Denigration
            | Self::HarmEncouragement
            | Self::PhysicalThreat
            | Self::RumorSpreading
            | Self::Exclusion
            | Self::Mockery
            | Self::LoveBombing
            | Self::SuicidalIdeation
            | Self::Hopelessness
            | Self::FarewellMessage
            | Self::DoxxingAttempt
            | Self::HateSpeech
            | Self::LocationRequest
            | Self::MoneyOffer
            | Self::PiiSelfDisclosure
            | Self::CasualMeetingRequest
            | Self::NormalConversation
            | Self::TrustedContact
            | Self::DefenseOfVictim
            | Self::PropagandaNarrative
            | Self::SuspiciousSource
            | Self::PositionLeak
            | Self::UnitInfoLeak
            | Self::EquipmentLeak
            | Self::CoordinateMention
            | Self::PsyopsPattern
            | Self::IntelGathering
            | Self::MilitaryPhishing
            | Self::MilitaryDisinfo => false,
        }
    }

    /// Returns the severity score for this event kind in the range 0.0 to 1.0.
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
            Self::GuiltTripping => 0.5,
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

            Self::PropagandaNarrative => 0.6,
            Self::SuspiciousSource => 0.7,
            Self::MilitaryDisinfo => 0.65,

            Self::CoordinateMention => 0.95,
            Self::PositionLeak => 0.9,
            Self::UnitInfoLeak => 0.7,
            Self::EquipmentLeak => 0.5,

            Self::PsyopsPattern => 0.7,
            Self::IntelGathering => 0.8,
            Self::MilitaryPhishing => 0.85,
        }
    }

    /// Returns true if this event represents hostile or aggressive behavior.
    pub fn is_hostile(&self) -> bool {
        match self {
            Self::Insult
            | Self::Denigration
            | Self::HarmEncouragement
            | Self::PhysicalThreat
            | Self::RumorSpreading
            | Self::Exclusion
            | Self::Mockery
            | Self::GuiltTripping
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
            | Self::DoxxingAttempt
            | Self::HateSpeech
            | Self::LocationRequest => true,
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
            | Self::SuicidalIdeation
            | Self::Hopelessness
            | Self::FarewellMessage
            | Self::MoneyOffer
            | Self::PiiSelfDisclosure
            | Self::CasualMeetingRequest
            | Self::NormalConversation
            | Self::TrustedContact
            | Self::DefenseOfVictim
            | Self::PositionLeak
            | Self::UnitInfoLeak
            | Self::EquipmentLeak
            | Self::CoordinateMention => false,
            Self::PropagandaNarrative
            | Self::SuspiciousSource
            | Self::PsyopsPattern
            | Self::IntelGathering
            | Self::MilitaryPhishing
            | Self::MilitaryDisinfo => true,
        }
    }

    /// Returns true if this event represents supportive or protective behavior.
    pub fn is_supportive(&self) -> bool {
        match self {
            Self::DefenseOfVictim => true,
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
            | Self::Insult
            | Self::Denigration
            | Self::HarmEncouragement
            | Self::PhysicalThreat
            | Self::RumorSpreading
            | Self::Exclusion
            | Self::Mockery
            | Self::GuiltTripping
            | Self::Gaslighting
            | Self::EmotionalBlackmail
            | Self::PeerPressure
            | Self::LoveBombing
            | Self::Darvo
            | Self::Devaluation
            | Self::SuicidalIdeation
            | Self::Hopelessness
            | Self::FarewellMessage
            | Self::DoxxingAttempt
            | Self::ScreenshotThreat
            | Self::HateSpeech
            | Self::LocationRequest
            | Self::MoneyOffer
            | Self::PiiSelfDisclosure
            | Self::CasualMeetingRequest
            | Self::DareChallenge
            | Self::SuicideCoercion
            | Self::FalseConsensus
            | Self::DebtCreation
            | Self::ReputationThreat
            | Self::IdentityErosion
            | Self::NetworkPoisoning
            | Self::FakeVulnerability
            | Self::NormalConversation
            | Self::TrustedContact
            | Self::PropagandaNarrative
            | Self::SuspiciousSource
            | Self::PositionLeak
            | Self::UnitInfoLeak
            | Self::EquipmentLeak
            | Self::CoordinateMention
            | Self::PsyopsPattern
            | Self::IntelGathering
            | Self::MilitaryPhishing
            | Self::MilitaryDisinfo => false,
        }
    }

    /// Returns true if this event is a grooming indicator but not manipulation or bullying.
    pub fn is_grooming_only(&self) -> bool {
        self.is_grooming_indicator()
            && !self.is_manipulation_indicator()
            && !self.is_bullying_indicator()
    }

    /// Returns true if this event indicates propaganda or disinformation.
    #[allow(clippy::match_like_matches_macro)]
    pub fn is_propaganda_indicator(&self) -> bool {
        match self {
            Self::PropagandaNarrative | Self::SuspiciousSource | Self::MilitaryDisinfo => true,
            _ => false,
        }
    }

    /// Returns the contact rating adjustment for this event kind.
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
        assert!(
            delta > 0.0 && delta < 1.0,
            "Expected small positive delta, got {delta}"
        );
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
            assert!(
                kind.is_grooming_indicator(),
                "{kind:?} should be grooming indicator"
            );
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
            assert!(
                kind.is_bullying_indicator(),
                "{kind:?} should be bullying indicator"
            );
        }
    }

    #[test]
    fn all_manipulation_indicators_classified() {
        let manip_kinds = vec![
            EventKind::GuiltTripping,
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
            assert!(
                kind.is_manipulation_indicator(),
                "{kind:?} should be manipulation indicator"
            );
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
            assert!(
                !kind.is_grooming_indicator(),
                "{kind:?} should NOT be grooming"
            );
            assert!(
                !kind.is_bullying_indicator(),
                "{kind:?} should NOT be bullying"
            );
            assert!(
                !kind.is_manipulation_indicator(),
                "{kind:?} should NOT be manipulation"
            );
            assert!(!kind.is_hostile(), "{kind:?} should NOT be hostile");
        }
    }

    #[test]
    fn all_severities_in_valid_range() {
        let all_kinds = vec![
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
            EventKind::Insult,
            EventKind::Denigration,
            EventKind::HarmEncouragement,
            EventKind::PhysicalThreat,
            EventKind::RumorSpreading,
            EventKind::Exclusion,
            EventKind::Mockery,
            EventKind::GuiltTripping,
            EventKind::Gaslighting,
            EventKind::EmotionalBlackmail,
            EventKind::PeerPressure,
            EventKind::LoveBombing,
            EventKind::Darvo,
            EventKind::Devaluation,
            EventKind::SuicidalIdeation,
            EventKind::Hopelessness,
            EventKind::FarewellMessage,
            EventKind::DoxxingAttempt,
            EventKind::ScreenshotThreat,
            EventKind::HateSpeech,
            EventKind::LocationRequest,
            EventKind::MoneyOffer,
            EventKind::PiiSelfDisclosure,
            EventKind::CasualMeetingRequest,
            EventKind::DareChallenge,
            EventKind::SuicideCoercion,
            EventKind::FalseConsensus,
            EventKind::DebtCreation,
            EventKind::ReputationThreat,
            EventKind::IdentityErosion,
            EventKind::NetworkPoisoning,
            EventKind::FakeVulnerability,
            EventKind::NormalConversation,
            EventKind::TrustedContact,
            EventKind::DefenseOfVictim,
            EventKind::PropagandaNarrative,
            EventKind::SuspiciousSource,
            EventKind::PositionLeak,
            EventKind::UnitInfoLeak,
            EventKind::EquipmentLeak,
            EventKind::CoordinateMention,
            EventKind::PsyopsPattern,
            EventKind::IntelGathering,
            EventKind::MilitaryPhishing,
            EventKind::MilitaryDisinfo,
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
        let overlap = vec![
            EventKind::IdentityErosion,
            EventKind::FakeVulnerability,
            EventKind::FalseConsensus,
            EventKind::NetworkPoisoning,
            EventKind::DebtCreation,
        ];
        for kind in overlap {
            assert!(
                !kind.is_grooming_only(),
                "{kind:?} is both grooming+manipulation, should not be grooming_only"
            );
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
        let high = EventKind::PhysicalThreat.rating_delta();
        let med = EventKind::Denigration.rating_delta();
        let low = EventKind::Mockery.rating_delta();
        assert!(
            high < med,
            "High severity {high} should be more negative than medium {med}"
        );
        assert!(
            med < low,
            "Medium severity {med} should be more negative than low {low}"
        );
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
                    kind.rating_delta(),
                    -7.0,
                    "{kind:?} (sev {}) should have -7 delta",
                    kind.severity()
                );
            }
        }
    }
}
