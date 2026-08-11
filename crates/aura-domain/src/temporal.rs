use serde::{Deserialize, Serialize};

use crate::{DomainAction, DomainConversationType, DomainEventKind, DomainSignal};

/// Role assigned to an actor inside a content-free temporal projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalActorRole {
    /// The locally protected account.
    ProtectedAccount,
    /// Any other participant.
    External,
}

/// Interpreted speech act carried by a confirmed temporal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalSpeechAct {
    /// Speech act could not be established.
    #[default]
    Unknown,
    /// Declarative assertion.
    Assert,
    /// Question or request for information.
    Ask,
    /// Quoted content rather than the speaker's own assertion.
    Quote,
    /// Report about another statement or event.
    Report,
    /// Counter-speech or rebuttal.
    Counter,
    /// Supportive statement.
    Support,
    /// Active solicitation or request for action.
    Solicit,
}

/// Interpreted stance carried by a confirmed temporal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalStance {
    /// Stance could not be established.
    #[default]
    Unknown,
    /// Speaker endorses the semantic content.
    Endorse,
    /// Speaker opposes the semantic content.
    Oppose,
    /// Speaker is neutral toward the semantic content.
    Neutral,
    /// Available evidence supports more than one stance.
    Ambiguous,
}

/// Direction assigned to a confirmed temporal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainTemporalDirectionality {
    /// Direction could not be established.
    #[default]
    Unknown,
    /// Content is directed at the protected user.
    DirectedAtUser,
    /// Content refers to the speaker themself.
    SelfReferential,
    /// Content concerns a third party.
    ThirdParty,
    /// Content addresses a group or public audience.
    Broadcast,
}

/// Minimal interpreted context required for conservative temporal inference.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct DomainTemporalContext {
    /// Interpreted speech act.
    pub speech_act: DomainTemporalSpeechAct,
    /// Interpreted stance.
    pub stance: DomainTemporalStance,
    /// Interpreted target direction.
    pub directionality: DomainTemporalDirectionality,
    /// Whether local trust policy marks the contact as trusted.
    pub trusted_contact: bool,
    /// Normalized confidence of the context interpretation.
    pub confidence: f32,
}

impl DomainTemporalContext {
    /// Returns whether the event has enough affirmative context to contribute.
    #[must_use]
    pub fn supports_temporal_inference(self) -> bool {
        self.supports_temporal_inference_at(0.0)
    }

    /// Applies the common context guards at a caller-selected confidence floor.
    #[must_use]
    pub fn supports_temporal_inference_at(self, minimum_confidence: f32) -> bool {
        minimum_confidence.is_finite()
            && (0.0..=1.0).contains(&minimum_confidence)
            && self.confidence.is_finite()
            && self.confidence > 0.0
            && self.confidence >= minimum_confidence
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
    /// Ephemeral event identity within the local projection.
    pub event_id: u64,
    /// Event time in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Ephemeral actor identity within the local projection.
    pub actor_id: u32,
    /// Protected or external actor role.
    pub actor_role: DomainTemporalActorRole,
    /// Domain-owned semantic event kind.
    pub kind: DomainEventKind,
    /// Normalized confidence of the source event.
    pub confidence: f32,
    /// Optional local content digest used only for deduplication.
    pub content_hash: Option<u64>,
    /// Interpreter-confirmed context associated with the event.
    pub context: DomainTemporalContext,
}

/// Bounded, content-free conversation view supplied to a domain module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainTemporalInput {
    /// Inclusive analysis cutoff in Unix milliseconds.
    pub as_of_ms: u64,
    /// Actor responsible for the current event.
    pub current_actor_id: u32,
    /// Digest of the current event, if content was available.
    pub current_content_hash: Option<u64>,
    /// Direct or group conversation topology.
    pub conversation_type: DomainConversationType,
    /// Bounded confirmed history; implementations must not persist derivatives.
    pub events: Vec<DomainTemporalEvent>,
}

/// Derived domain signals that must not be written back as source events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DomainTemporalOutput {
    /// Derived temporal signals; these are not source events.
    pub signals: Vec<DomainSignal>,
    /// Strongest action recommended by temporal fusion.
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

    #[test]
    fn context_below_required_confidence_does_not_support_inference() {
        let mut context = context(
            DomainTemporalSpeechAct::Assert,
            DomainTemporalStance::Endorse,
        );
        context.confidence = 0.2;

        assert!(!context.supports_temporal_inference_at(0.8));
    }

    #[test]
    fn non_finite_context_confidence_does_not_support_inference() {
        let mut context = context(
            DomainTemporalSpeechAct::Assert,
            DomainTemporalStance::Endorse,
        );
        context.confidence = f32::NAN;

        assert!(!context.supports_temporal_inference());
    }
}
