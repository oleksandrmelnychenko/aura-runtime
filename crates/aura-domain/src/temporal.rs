use serde::{Deserialize, Serialize};

use crate::{DomainAction, DomainConversationType, DomainEventKind, DomainSignal};

/// Role assigned to an actor inside a content-free temporal projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalActorRole {
    ProtectedAccount,
    External,
}

/// Interpreted speech act carried by a confirmed temporal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalSpeechAct {
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

/// Interpreted stance carried by a confirmed temporal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalStance {
    #[default]
    Unknown,
    Endorse,
    Oppose,
    Neutral,
    Ambiguous,
}

/// Direction assigned to a confirmed temporal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalDirectionality {
    #[default]
    Unknown,
    DirectedAtUser,
    SelfReferential,
    ThirdParty,
    Broadcast,
}

/// Minimal interpreted context required for conservative temporal inference.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct DomainTemporalContext {
    pub speech_act: DomainTemporalSpeechAct,
    pub stance: DomainTemporalStance,
    pub directionality: DomainTemporalDirectionality,
    pub trusted_contact: bool,
    pub confidence: f32,
}

impl DomainTemporalContext {
    /// Returns whether the event has enough affirmative context to contribute.
    pub fn supports_temporal_inference(self) -> bool {
        self.confidence > 0.0
            && !self.trusted_contact
            && matches!(
                self.speech_act,
                DomainTemporalSpeechAct::Assert
                    | DomainTemporalSpeechAct::Ask
                    | DomainTemporalSpeechAct::Solicit
            )
            && matches!(
                self.stance,
                DomainTemporalStance::Endorse | DomainTemporalStance::Ambiguous
            )
    }
}

/// One interpreter-confirmed event projected without text or stable identifiers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainTemporalEvent {
    pub event_id: u64,
    pub timestamp_ms: u64,
    pub actor_id: u32,
    pub actor_role: DomainTemporalActorRole,
    pub kind: DomainEventKind,
    pub confidence: f32,
    pub content_hash: Option<u64>,
    pub context: DomainTemporalContext,
}

/// Bounded, content-free conversation view supplied to a domain module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainTemporalInput {
    pub as_of_ms: u64,
    pub current_actor_id: u32,
    pub current_content_hash: Option<u64>,
    pub conversation_type: DomainConversationType,
    pub events: Vec<DomainTemporalEvent>,
}

/// Derived domain signals that must not be written back as source events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DomainTemporalOutput {
    pub signals: Vec<DomainSignal>,
    pub action: Option<DomainAction>,
}

#[cfg(test)]
mod tests {
    use super::{
        DomainTemporalContext, DomainTemporalDirectionality, DomainTemporalSpeechAct,
        DomainTemporalStance,
    };

    fn context(
        speech_act: DomainTemporalSpeechAct,
        stance: DomainTemporalStance,
    ) -> DomainTemporalContext {
        DomainTemporalContext {
            speech_act,
            stance,
            directionality: DomainTemporalDirectionality::DirectedAtUser,
            trusted_contact: false,
            confidence: 0.9,
        }
    }

    #[test]
    fn affirmative_solicitation_supports_temporal_inference() {
        let context = context(
            DomainTemporalSpeechAct::Solicit,
            DomainTemporalStance::Endorse,
        );

        assert!(context.supports_temporal_inference());
    }

    #[test]
    fn counter_speech_does_not_support_temporal_inference() {
        let context = context(
            DomainTemporalSpeechAct::Counter,
            DomainTemporalStance::Oppose,
        );

        assert!(!context.supports_temporal_inference());
    }

    #[test]
    fn trusted_contact_does_not_enter_initial_temporal_release() {
        let mut context = context(
            DomainTemporalSpeechAct::Assert,
            DomainTemporalStance::Endorse,
        );
        context.trusted_contact = true;

        assert!(!context.supports_temporal_inference());
    }
}
