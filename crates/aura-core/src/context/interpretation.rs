use std::sync::Arc;

use crate::context::events::{
    ContextEvent, EventContextFrame, EventDirectionality, EventKind, EventSpeechAct, EventStance,
};
use crate::context::observation::{
    materialize_event_hints, split_observations, RawEventHint, RawObservation,
};
use crate::context::rules::{
    builtin_context_rule_packs, ContextRuleError, ContextRulePacks, EventSelector,
    InterpretationCondition, InterpretationEffect, InterpretationRule, MemoryCondition, MemoryRule,
    PolicyCondition, PolicyRule, SignalSelector,
};
use crate::context::tracker::ConversationTimeline;
use crate::types::{
    AccountType, AnalysisContextSummary, BehavioralTrend, CircleTier, Confidence, ContactSnapshot,
    ContextDirectionality, ContextReciprocity, ContextRelationshipSummary, ContextSpeechAct,
    ContextStance, ContextTrajectorySummary, ConversationType, DetectionLayer, DetectionSignal,
    MessageInput, RelationshipTrustSource, SenderRelationship, ThreatType,
};
use aura_patterns::TextNormalizer;

/// Interpreter-approved event that may be persisted by the conversation tracker.
///
/// The inner event is intentionally private: detector output must pass through
/// [`ContextInterpreter`] before it can cross the tracker boundary.
#[derive(Debug, Clone)]
pub struct ConfirmedEvent(ContextEvent);

impl ConfirmedEvent {
    fn new(event: ContextEvent) -> Self {
        Self(event)
    }

    pub(super) fn into_event(self) -> ContextEvent {
        self.0
    }
}

impl std::ops::Deref for ConfirmedEvent {
    type Target = ContextEvent;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl From<ContextEvent> for ConfirmedEvent {
    fn from(event: ContextEvent) -> Self {
        Self::new(event)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeechAct {
    Assert,
    Ask,
    Quote,
    Report,
    Counter,
    Support,
    Solicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stance {
    Endorse,
    Oppose,
    Neutral,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directionality {
    DirectedAtUser,
    SelfReferential,
    ThirdParty,
    Broadcast,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reciprocity {
    OneSided,
    Mutual,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RelationshipContext {
    pub is_new_contact: bool,
    pub is_trusted: bool,
    pub circle_tier: CircleTier,
    pub trust_level: f32,
    pub prior_conversation_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrajectoryContext {
    pub repeated_by_sender: bool,
    pub escalating: bool,
    pub cross_conversation: bool,
    pub bursty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThreatContextFrame {
    pub speech_act: SpeechAct,
    pub stance: Stance,
    pub directionality: Directionality,
    pub reciprocity: Reciprocity,
    pub relationship: RelationshipContext,
    pub trajectory: TrajectoryContext,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct ContextInterpretation {
    pub frame: ThreatContextFrame,
    pub adjusted_signals: Vec<DetectionSignal>,
    pub confirmed_events: Vec<ConfirmedEvent>,
    pub suppressed_reason_codes: Vec<String>,
    pub(crate) signal_adjustments: ContextSignalAdjustments,
}

/// Semantic calibration decisions owned by the context interpreter.
///
/// The analyzer may apply this value after tracker-derived signals and
/// contact/escalation calibration have been staged, but it cannot re-derive
/// context semantics from the public summary.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContextSignalAdjustments {
    effects: Vec<InterpretationEffect>,
}

impl ContextSignalAdjustments {
    fn from_frame(frame: &ThreatContextFrame, rules: &[InterpretationRule]) -> Self {
        Self {
            effects: rules
                .iter()
                .filter(|rule| interpretation_frame_condition_matches(rule.condition, frame))
                .map(|rule| rule.effect.clone())
                .collect(),
        }
    }

    pub(crate) fn apply_calibration(self, signals: &mut Vec<DetectionSignal>) {
        for effect in self.effects {
            match effect {
                InterpretationEffect::SuppressSignals { selectors } => {
                    apply_signal_suppression(&selectors, signals);
                }
                InterpretationEffect::CorroborationBoost {
                    threat_type,
                    pattern_reason_prefix,
                    ml_reason_code,
                    score_add,
                    score_cap,
                } => {
                    let has_pattern = signals.iter().any(|signal| {
                        signal.threat_type == threat_type
                            && signal.layer == DetectionLayer::PatternMatching
                            && signal.reason_code.starts_with(&pattern_reason_prefix)
                    });
                    let has_ml = signals.iter().any(|signal| {
                        signal.threat_type == threat_type
                            && signal.layer == DetectionLayer::MlClassification
                            && signal.reason_code == ml_reason_code
                    });
                    if !(has_pattern && has_ml) {
                        continue;
                    }

                    for signal in &mut *signals {
                        let corroborated = signal.threat_type == threat_type
                            && match signal.layer {
                                DetectionLayer::PatternMatching => {
                                    signal.reason_code.starts_with(&pattern_reason_prefix)
                                }
                                DetectionLayer::MlClassification => {
                                    signal.reason_code == ml_reason_code
                                }
                                DetectionLayer::ContextAnalysis => false,
                            };
                        if corroborated {
                            signal.score = (signal.score + score_add).min(score_cap);
                            signal.confidence = confidence_from_score(signal.score);
                        }
                    }
                }
            }
        }
    }
}

fn interpretation_frame_condition_matches(
    condition: InterpretationCondition,
    frame: &ThreatContextFrame,
) -> bool {
    match condition {
        InterpretationCondition::SupportiveNeutralOrOpposed => {
            matches!(frame.speech_act, SpeechAct::Support)
                && matches!(frame.stance, Stance::Neutral | Stance::Oppose)
        }
        InterpretationCondition::DirectedNewContactOneSided => {
            frame.directionality == Directionality::DirectedAtUser
                && frame.relationship.is_new_contact
                && frame.reciprocity == Reciprocity::OneSided
        }
        InterpretationCondition::Defender
        | InterpretationCondition::SafeMediaContext
        | InterpretationCondition::FriendlyTiming
        | InterpretationCondition::SafeGamingBanter
        | InterpretationCondition::DeescalatingPeerConflict
        | InterpretationCondition::FriendlyPlayfulBanter => false,
    }
}

fn apply_signal_suppression(selectors: &[SignalSelector], signals: &mut Vec<DetectionSignal>) {
    signals.retain(|signal| {
        !selectors.iter().any(|selector| {
            selector.matches(signal)
                && !(selector.unless_high_risk_grooming && is_high_risk_grooming_signal(signal))
        })
    });
}

#[derive(Debug, Clone)]
pub struct ContextInterpreter {
    rules: Arc<ContextRulePacks>,
}

impl Default for ContextInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextInterpreter {
    /// Creates an interpreter using the bundled, validated context rule packs.
    ///
    /// # Panics
    ///
    /// Panics when a bundled pack is invalid. Release initialization should use
    /// [`Self::try_new`] to surface the typed error instead.
    pub fn new() -> Self {
        match Self::try_new() {
            Ok(interpreter) => interpreter,
            Err(error) => panic!("bundled context rule packs failed validation: {error}"),
        }
    }

    pub fn try_new() -> Result<Self, ContextRuleError> {
        Ok(Self {
            rules: builtin_context_rule_packs()?,
        })
    }

    pub fn interpret_observations(
        &self,
        input: &MessageInput,
        text: Option<&str>,
        timestamp_ms: Option<u64>,
        timeline: Option<&ConversationTimeline>,
        mut observations: Vec<RawObservation>,
        snapshot: Option<&ContactSnapshot>,
    ) -> ContextInterpretation {
        if let (Some(text), Some(timestamp_ms)) = (text, timestamp_ms) {
            apply_contextual_observation_filters(
                input,
                text,
                timestamp_ms,
                timeline,
                snapshot,
                self.rules.memory_rules(),
                &mut observations,
            );
        }
        let (signals, event_hints) = split_observations(observations);
        self.interpret_raw(
            input,
            text,
            timestamp_ms,
            timeline,
            signals,
            event_hints,
            snapshot,
        )
    }

    pub(crate) fn apply_downstream_signal_semantics(
        &self,
        input: &MessageInput,
        text: &str,
        timestamp_ms: u64,
        timeline: Option<&ConversationTimeline>,
        snapshot: Option<&ContactSnapshot>,
        signals: &mut Vec<DetectionSignal>,
    ) {
        apply_downstream_context_signal_filters(
            input,
            text,
            timestamp_ms,
            timeline,
            snapshot,
            self.rules.interpretation_rules(),
            signals,
        );
    }

    pub(crate) fn apply_relationship_metadata(
        &self,
        input: &MessageInput,
        account_type: AccountType,
        signals: &mut [DetectionSignal],
    ) -> RelationshipMetadataContext {
        apply_relationship_metadata_context(input, account_type, self.rules.policy_rules(), signals)
    }

    #[allow(clippy::too_many_arguments)]
    fn interpret_raw(
        &self,
        input: &MessageInput,
        text: Option<&str>,
        timestamp_ms: Option<u64>,
        timeline: Option<&ConversationTimeline>,
        signals: Vec<DetectionSignal>,
        event_hints: Vec<RawEventHint>,
        snapshot: Option<&ContactSnapshot>,
    ) -> ContextInterpretation {
        let frame = self.derive_frame(
            input,
            text,
            timestamp_ms,
            timeline,
            &signals,
            &event_hints,
            snapshot,
        );
        let signal_adjustments =
            ContextSignalAdjustments::from_frame(&frame, self.rules.interpretation_rules());
        let Some(text) = text else {
            let confirmed_events =
                materialize_confirmed_events(event_hints, timestamp_ms, input, &frame);
            return ContextInterpretation {
                frame,
                adjusted_signals: signals,
                confirmed_events,
                suppressed_reason_codes: Vec::new(),
                signal_adjustments,
            };
        };

        let lower = text.to_lowercase();
        let mut adjusted_signals = Vec::with_capacity(signals.len());
        let mut suppressed_reason_codes = Vec::new();
        for mut signal in signals {
            if self.should_suppress_signal(&frame, &signal, &lower) {
                if !signal.reason_code.is_empty() {
                    suppressed_reason_codes.push(signal.reason_code.clone());
                }
                continue;
            }

            if let Some(multiplier) = self.signal_multiplier(&frame, &signal, &lower) {
                signal.score = (signal.score * multiplier).clamp(0.0, 1.0);
                signal.confidence = confidence_from_score(signal.score);
            }

            adjusted_signals.push(signal);
        }

        let mut confirmed_event_hints = Vec::with_capacity(event_hints.len());
        for event_hint in event_hints {
            if self.should_suppress_event_kind(&frame, &event_hint.kind, &lower) {
                continue;
            }
            confirmed_event_hints.push(event_hint);
        }
        let confirmed_events =
            materialize_confirmed_events(confirmed_event_hints, timestamp_ms, input, &frame);

        ContextInterpretation {
            frame,
            adjusted_signals,
            confirmed_events,
            suppressed_reason_codes,
            signal_adjustments,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_frame(
        &self,
        input: &MessageInput,
        text: Option<&str>,
        timestamp_ms: Option<u64>,
        timeline: Option<&ConversationTimeline>,
        signals: &[DetectionSignal],
        event_hints: &[RawEventHint],
        snapshot: Option<&ContactSnapshot>,
    ) -> ThreatContextFrame {
        let lower = text.unwrap_or_default().to_lowercase();
        let cue_lower = normalize_context_cues(&lower);
        let is_support = looks_like_support_context(&cue_lower);
        let is_counter = looks_like_counter_context(&cue_lower);
        let is_quote = looks_like_quote_context(&cue_lower);
        let is_report =
            looks_like_report_context(&cue_lower) || looks_like_opsec_warning(&cue_lower);
        let is_solicit = looks_like_distribution_or_coordination(&cue_lower);
        let speech_act = if is_support {
            SpeechAct::Support
        } else if is_counter {
            SpeechAct::Counter
        } else if is_quote {
            SpeechAct::Quote
        } else if is_report {
            SpeechAct::Report
        } else if is_solicit {
            SpeechAct::Solicit
        } else if lower.contains('?') {
            SpeechAct::Ask
        } else {
            SpeechAct::Assert
        };

        let stance = if is_counter {
            Stance::Oppose
        } else if is_support || is_quote || is_report {
            Stance::Neutral
        } else if is_solicit || matches!(speech_act, SpeechAct::Assert) {
            Stance::Endorse
        } else {
            Stance::Ambiguous
        };

        let directionality = if is_self_referential_distress(&cue_lower) {
            Directionality::SelfReferential
        } else if looks_like_third_party_reference(&cue_lower) || is_quote || is_report {
            Directionality::ThirdParty
        } else if looks_like_directed_at_user(&cue_lower) {
            Directionality::DirectedAtUser
        } else if input.conversation_type != ConversationType::Direct {
            Directionality::Broadcast
        } else {
            Directionality::Unknown
        };

        let relationship = RelationshipContext {
            is_new_contact: snapshot.map(|s| s.is_new_contact).unwrap_or(true),
            is_trusted: snapshot.map(|s| s.is_trusted).unwrap_or(false),
            circle_tier: snapshot.map(|s| s.circle_tier).unwrap_or_default(),
            trust_level: snapshot.map(|s| s.trust_level).unwrap_or(0.0),
            prior_conversation_count: snapshot.map(|s| s.conversation_count).unwrap_or(0),
        };

        let reciprocity = if input.conversation_type != ConversationType::Direct {
            Reciprocity::Unknown
        } else if !relationship.is_new_contact
            && (relationship.is_trusted
                || relationship.prior_conversation_count > 0
                || relationship.trust_level >= 0.60
                || relationship.circle_tier != CircleTier::New)
        {
            Reciprocity::Mutual
        } else {
            Reciprocity::OneSided
        };

        let trajectory = derive_trajectory(
            input,
            timestamp_ms,
            timeline,
            signals,
            event_hints,
            snapshot,
        );

        ThreatContextFrame {
            speech_act,
            stance,
            directionality,
            reciprocity,
            relationship,
            trajectory,
            confidence: if is_support || is_counter || is_quote || is_report {
                0.80
            } else if is_solicit {
                0.70
            } else if matches!(speech_act, SpeechAct::Ask) {
                0.60
            } else {
                0.50
            },
        }
    }

    fn should_suppress_signal(
        &self,
        frame: &ThreatContextFrame,
        signal: &DetectionSignal,
        lower: &str,
    ) -> bool {
        if signal.reason_code == "ml.uncertainty.guardian_review"
            && (matches!(
                frame.speech_act,
                SpeechAct::Support | SpeechAct::Counter | SpeechAct::Quote | SpeechAct::Report
            ) || looks_like_opsec_warning_context(lower)
                || looks_like_trusted_logistics_context(frame, lower))
        {
            return true;
        }

        if looks_like_opsec_warning_context(lower)
            && matches!(
                signal.threat_type,
                ThreatType::CoordinateLeak | ThreatType::OpsecViolation
            )
        {
            return true;
        }

        if looks_like_trusted_logistics_context(frame, lower)
            && signal.reason_code.starts_with("ml.intent.media")
            && looks_like_documentary_media_request(lower)
        {
            return true;
        }

        if looks_like_trusted_logistics_context(frame, lower)
            && signal.threat_type == ThreatType::Grooming
            && signal.score <= 0.55
            && !is_high_risk_grooming_reason(&signal.reason_code)
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Support)
            && !is_self_referential_distress(lower)
            && signal.threat_type == ThreatType::SelfHarm
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Support)
            && signal.reason_code == "conversation.timing.late_night_minor_contact"
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Counter)
            && matches!(
                signal.threat_type,
                ThreatType::Propaganda
                    | ThreatType::HateSpeech
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
            )
            && !looks_like_direct_military_social_eng_pretext(signal, lower)
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Quote | SpeechAct::Report)
            && matches!(
                signal.threat_type,
                ThreatType::Threat
                    | ThreatType::Bullying
                    | ThreatType::HateSpeech
                    | ThreatType::Propaganda
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak
                    | ThreatType::OpsecViolation
            )
            && !looks_like_direct_military_social_eng_pretext(signal, lower)
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Quote | SpeechAct::Report)
            && signal.threat_type == ThreatType::SelfHarm
            && !is_self_referential_distress(lower)
        {
            return true;
        }

        false
    }

    fn signal_multiplier(
        &self,
        frame: &ThreatContextFrame,
        signal: &DetectionSignal,
        lower: &str,
    ) -> Option<f32> {
        let mut multiplier = 1.0_f32;

        if matches!(frame.speech_act, SpeechAct::Support)
            && signal.layer == DetectionLayer::ContextAnalysis
            && signal.threat_type == ThreatType::Manipulation
            && looks_like_support_context(lower)
        {
            multiplier = multiplier.min(0.35);
        }

        if looks_like_trusted_logistics_context(frame, lower)
            && signal.threat_type == ThreatType::Grooming
            && signal.score <= 0.75
            && !is_high_risk_grooming_reason(&signal.reason_code)
        {
            multiplier = multiplier.min(0.45);
        }

        if frame.relationship.is_new_contact
            && matches!(
                frame.reciprocity,
                Reciprocity::OneSided | Reciprocity::Unknown
            )
            && matches!(
                frame.speech_act,
                SpeechAct::Ask | SpeechAct::Solicit | SpeechAct::Assert
            )
            && matches!(
                signal.threat_type,
                ThreatType::Grooming | ThreatType::Manipulation
            )
            && (frame.trajectory.repeated_by_sender
                || frame.trajectory.cross_conversation
                || frame.trajectory.escalating)
        {
            multiplier = multiplier.max(
                if frame.trajectory.cross_conversation || frame.trajectory.escalating {
                    1.22
                } else {
                    1.12
                },
            );
        }

        if frame.directionality == Directionality::DirectedAtUser
            && matches!(
                signal.threat_type,
                ThreatType::Bullying | ThreatType::Threat | ThreatType::HateSpeech
            )
            && (frame.trajectory.repeated_by_sender
                || frame.trajectory.bursty
                || frame.trajectory.escalating)
        {
            multiplier = multiplier.max(if frame.trajectory.bursty { 1.20 } else { 1.12 });
        }

        if frame.stance == Stance::Endorse
            && matches!(
                signal.threat_type,
                ThreatType::Propaganda | ThreatType::Psyops | ThreatType::MilitarySocialEng
            )
            && (frame.trajectory.repeated_by_sender
                || frame.trajectory.cross_conversation
                || frame.trajectory.bursty)
        {
            multiplier = multiplier.max(
                if frame.trajectory.cross_conversation || frame.trajectory.bursty {
                    1.25
                } else {
                    1.15
                },
            );
        }

        if matches!(
            frame.speech_act,
            SpeechAct::Assert | SpeechAct::Solicit | SpeechAct::Ask
        ) && matches!(
            signal.threat_type,
            ThreatType::CoordinateLeak | ThreatType::OpsecViolation
        ) && (frame.trajectory.repeated_by_sender || frame.trajectory.bursty)
        {
            multiplier = multiplier.max(1.12);
        }

        if (multiplier - 1.0).abs() < f32::EPSILON {
            None
        } else {
            Some(multiplier)
        }
    }

    fn should_suppress_event_kind(
        &self,
        frame: &ThreatContextFrame,
        kind: &EventKind,
        lower: &str,
    ) -> bool {
        if looks_like_opsec_warning_context(lower)
            && matches!(
                kind,
                EventKind::CoordinateMention
                    | EventKind::PositionLeak
                    | EventKind::UnitInfoLeak
                    | EventKind::EquipmentLeak
            )
        {
            return true;
        }

        if looks_like_trusted_logistics_context(frame, lower)
            && matches!(
                kind,
                EventKind::PersonalInfoRequest
                    | EventKind::LocationRequest
                    | EventKind::CasualMeetingRequest
                    | EventKind::MeetingRequest
            )
        {
            return true;
        }

        if looks_like_trusted_logistics_context(frame, lower)
            && looks_like_documentary_media_request(lower)
            && *kind == EventKind::PhotoRequest
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Support)
            && !is_self_referential_distress(lower)
            && matches!(
                kind,
                EventKind::SuicidalIdeation | EventKind::Hopelessness | EventKind::FarewellMessage
            )
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Counter)
            && matches!(
                kind,
                EventKind::PropagandaNarrative
                    | EventKind::SuspiciousSource
                    | EventKind::MilitaryDisinfo
                    | EventKind::HateSpeech
                    | EventKind::PsyopsPattern
            )
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Quote | SpeechAct::Report)
            && matches!(
                kind,
                EventKind::Insult
                    | EventKind::Denigration
                    | EventKind::Mockery
                    | EventKind::HarmEncouragement
                    | EventKind::PhysicalThreat
                    | EventKind::HateSpeech
                    | EventKind::PropagandaNarrative
                    | EventKind::SuspiciousSource
                    | EventKind::MilitaryDisinfo
                    | EventKind::PsyopsPattern
                    | EventKind::IntelGathering
                    | EventKind::MilitaryPhishing
                    | EventKind::CoordinateMention
                    | EventKind::PositionLeak
                    | EventKind::UnitInfoLeak
                    | EventKind::EquipmentLeak
            )
        {
            return true;
        }

        if matches!(frame.speech_act, SpeechAct::Quote | SpeechAct::Report)
            && !is_self_referential_distress(lower)
            && matches!(
                kind,
                EventKind::SuicidalIdeation | EventKind::Hopelessness | EventKind::FarewellMessage
            )
        {
            return true;
        }

        false
    }
}

impl ContextInterpretation {
    pub fn analysis_context_summary(&self) -> AnalysisContextSummary {
        AnalysisContextSummary {
            speech_act: match self.frame.speech_act {
                SpeechAct::Assert => ContextSpeechAct::Assert,
                SpeechAct::Ask => ContextSpeechAct::Ask,
                SpeechAct::Quote => ContextSpeechAct::Quote,
                SpeechAct::Report => ContextSpeechAct::Report,
                SpeechAct::Counter => ContextSpeechAct::Counter,
                SpeechAct::Support => ContextSpeechAct::Support,
                SpeechAct::Solicit => ContextSpeechAct::Solicit,
            },
            stance: match self.frame.stance {
                Stance::Endorse => ContextStance::Endorse,
                Stance::Oppose => ContextStance::Oppose,
                Stance::Neutral => ContextStance::Neutral,
                Stance::Ambiguous => ContextStance::Ambiguous,
            },
            directionality: match self.frame.directionality {
                Directionality::DirectedAtUser => ContextDirectionality::DirectedAtUser,
                Directionality::SelfReferential => ContextDirectionality::SelfReferential,
                Directionality::ThirdParty => ContextDirectionality::ThirdParty,
                Directionality::Broadcast => ContextDirectionality::Broadcast,
                Directionality::Unknown => ContextDirectionality::Unknown,
            },
            reciprocity: match self.frame.reciprocity {
                Reciprocity::OneSided => ContextReciprocity::OneSided,
                Reciprocity::Mutual => ContextReciprocity::Mutual,
                Reciprocity::Unknown => ContextReciprocity::Unknown,
            },
            relationship: ContextRelationshipSummary {
                is_new_contact: self.frame.relationship.is_new_contact,
                is_trusted: self.frame.relationship.is_trusted,
                circle_tier: self.frame.relationship.circle_tier,
                trust_level: self.frame.relationship.trust_level,
                prior_conversation_count: self.frame.relationship.prior_conversation_count,
            },
            trajectory: ContextTrajectorySummary {
                repeated_by_sender: self.frame.trajectory.repeated_by_sender,
                escalating: self.frame.trajectory.escalating,
                cross_conversation: self.frame.trajectory.cross_conversation,
                bursty: self.frame.trajectory.bursty,
            },
            filter_applied: !self.suppressed_reason_codes.is_empty(),
            confidence: self.frame.confidence,
        }
    }

    pub fn diagnostic_reason_codes(&self) -> Vec<String> {
        self.analysis_context_summary().context_markers()
    }
}

fn apply_contextual_observation_filters(
    input: &MessageInput,
    text: &str,
    timestamp_ms: u64,
    timeline: Option<&ConversationTimeline>,
    snapshot: Option<&ContactSnapshot>,
    rules: &[MemoryRule],
    observations: &mut Vec<RawObservation>,
) {
    let has_friendly_context =
        has_recent_playful_reciprocity(timeline, &input.sender_id, timestamp_ms)
            || snapshot.is_some_and(is_established_friendly_contact);

    for rule in rules {
        if memory_condition_matches(
            rule.condition,
            input,
            text,
            timestamp_ms,
            timeline,
            has_friendly_context,
            observations,
        ) {
            observations.retain(|observation| !memory_rule_suppresses(rule, observation));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn memory_condition_matches(
    condition: MemoryCondition,
    input: &MessageInput,
    text: &str,
    timestamp_ms: u64,
    timeline: Option<&ConversationTimeline>,
    has_friendly_context: bool,
    observations: &[RawObservation],
) -> bool {
    match condition {
        MemoryCondition::Always => true,
        MemoryCondition::SubstancePressureContext => observations.iter().any(|observation| {
            observation.signal_matches(|signal| {
                signal.reason_code.starts_with("pattern.substance_")
                    || signal.reason_code == "pattern.manipulation_pressure_uk"
                    || signal.reason_code == "pattern.manipulation_pressure_en"
                    || signal.reason_code == "pattern.false_consensus_uk"
                    || signal.reason_code == "pattern.false_consensus_en"
            })
        }),
        MemoryCondition::SelfReferentialDistressProfanity => {
            is_self_referential_distress_profanity_message(text)
        }
        MemoryCondition::DeescalatingPeerConflict => is_deescalating_peer_conflict_message(text),
        MemoryCondition::PlainPeerCompliment => {
            let has_high_risk_grooming = observations
                .iter()
                .any(|observation| observation.signal_matches(is_high_risk_grooming_signal));
            input.conversation_type == ConversationType::Direct
                && (has_friendly_context || is_casual_appearance_compliment_message(text))
                && is_plain_peer_compliment_message(text)
                && !has_high_risk_grooming
        }
        MemoryCondition::NonRomanticGroupPraise => {
            let has_high_risk_grooming = observations
                .iter()
                .any(|observation| observation.signal_matches(is_high_risk_grooming_signal));
            input.conversation_type != ConversationType::Direct
                && is_non_romantic_group_praise_message(text)
                && !has_high_risk_grooming
        }
        MemoryCondition::CompetitiveGamingBanter => {
            let has_high_threat_or_hate = observations.iter().any(|observation| {
                observation.signal_matches(|signal| {
                    matches!(
                        signal.threat_type,
                        ThreatType::Threat | ThreatType::HateSpeech
                    ) && signal.score >= 0.75
                })
            });
            input.conversation_type != ConversationType::Direct
                && (is_competitive_gaming_banter_message(text)
                    || is_lightweight_competitive_banter_message(text))
                && !has_high_threat_or_hate
        }
        MemoryCondition::CasualMediaShare => is_casual_media_share_message(text),
        MemoryCondition::PlayfulBanter => {
            is_playful_banter_message(input, text, timestamp_ms, timeline)
        }
    }
}

fn memory_rule_suppresses(rule: &MemoryRule, observation: &RawObservation) -> bool {
    let protected_high_risk = observation.signal_matches(is_high_risk_grooming_signal);
    let suppresses_signal = rule.signal_selectors.iter().any(|selector| {
        observation.signal_matches(|signal| {
            selector.matches(signal)
                && !(selector.unless_high_risk_grooming && is_high_risk_grooming_signal(signal))
        })
    });
    let suppresses_event = rule.event_selectors.iter().any(|selector| {
        event_selector_matches(selector, observation)
            && !(selector.unless_high_risk_grooming && protected_high_risk)
    });

    suppresses_signal || suppresses_event
}

fn event_selector_matches(selector: &EventSelector, observation: &RawObservation) -> bool {
    observation.event_kind_matches(|kind| kind == &selector.kind)
}

#[derive(Debug, Default)]
pub(crate) struct RelationshipMetadataContext {
    pub(crate) context_markers: Vec<String>,
    pub(crate) reason_codes: Vec<String>,
}

fn apply_relationship_metadata_context(
    input: &MessageInput,
    account_type: AccountType,
    rules: &[PolicyRule],
    signals: &mut [DetectionSignal],
) -> RelationshipMetadataContext {
    if input.sender_relationship == SenderRelationship::Unknown {
        return RelationshipMetadataContext::default();
    }

    let mut context = RelationshipMetadataContext::default();
    context.context_markers.push(format!(
        "context.relationship.sender.{}",
        sender_relationship_marker(input.sender_relationship)
    ));
    context.context_markers.push(format!(
        "context.relationship.source.{}",
        relationship_trust_source_marker(input.relationship_trust_source)
    ));

    for rule in rules {
        if !policy_condition_matches(rule.condition, input, account_type) {
            continue;
        }

        if let Some(context_marker) = &rule.effect.context_marker {
            context.context_markers.push(context_marker.clone());
        }

        let has_relevant_signal = signals.iter().any(|signal| {
            signal.score > 0.0 && rule.effect.threat_types.contains(&signal.threat_type)
        });
        if has_relevant_signal {
            if let Some(reason_code) = &rule.effect.reason_code {
                context.reason_codes.push(reason_code.clone());
            }
            if rule.effect.score_add > 0.0 {
                for signal in &mut *signals {
                    if signal.score > 0.0 && rule.effect.threat_types.contains(&signal.threat_type)
                    {
                        signal.score = (signal.score + rule.effect.score_add).min(1.0);
                    }
                }
            }
        }
    }

    context
}

fn policy_condition_matches(
    condition: PolicyCondition,
    input: &MessageInput,
    account_type: AccountType,
) -> bool {
    let minor_account = matches!(account_type, AccountType::Child | AccountType::Teen);
    match condition {
        PolicyCondition::UnknownAdultMinor => {
            minor_account && input.sender_relationship == SenderRelationship::UnknownAdult
        }
        PolicyCondition::SelfDeclared => {
            input.relationship_trust_source == RelationshipTrustSource::SelfDeclared
        }
        PolicyCondition::SelfDeclaredPrivileged => {
            input.relationship_trust_source == RelationshipTrustSource::SelfDeclared
                && privileged_relationship_claim(input.sender_relationship)
        }
        PolicyCondition::SelfDeclaredPrivilegedMinor => {
            minor_account
                && input.relationship_trust_source == RelationshipTrustSource::SelfDeclared
                && privileged_relationship_claim(input.sender_relationship)
        }
        PolicyCondition::VerifiedFamily => {
            verified_relationship_source(input.relationship_trust_source)
                && trusted_family_or_guardian_relationship(input.sender_relationship)
        }
    }
}

fn apply_downstream_context_signal_filters(
    input: &MessageInput,
    text: &str,
    timestamp_ms: u64,
    timeline: Option<&ConversationTimeline>,
    snapshot: Option<&ContactSnapshot>,
    rules: &[InterpretationRule],
    signals: &mut Vec<DetectionSignal>,
) {
    let sender_is_defender = timeline.is_some_and(|timeline| {
        timeline.all_events().iter().any(|event| {
            event.sender_id == input.sender_id && event.kind == EventKind::DefenseOfVictim
        })
    });
    let friendly_context = has_recent_playful_reciprocity(timeline, &input.sender_id, timestamp_ms)
        || snapshot.is_some_and(is_established_friendly_contact);

    for rule in rules {
        let condition_matches = match rule.condition {
            InterpretationCondition::Defender => sender_is_defender,
            InterpretationCondition::SafeMediaContext => {
                is_casual_media_share_message(text)
                    || is_non_romantic_group_praise_message(text)
                    || (friendly_context && is_lightweight_media_banter_message(text))
            }
            InterpretationCondition::FriendlyTiming => {
                friendly_context && !signals.iter().any(is_high_risk_grooming_signal)
            }
            InterpretationCondition::SafeGamingBanter => {
                input.conversation_type != ConversationType::Direct
                    && is_lightweight_competitive_banter_message(text)
            }
            InterpretationCondition::DeescalatingPeerConflict => {
                is_deescalating_peer_conflict_message(text)
            }
            InterpretationCondition::FriendlyPlayfulBanter => {
                friendly_context && is_playful_banter_message(input, text, timestamp_ms, timeline)
            }
            InterpretationCondition::SupportiveNeutralOrOpposed
            | InterpretationCondition::DirectedNewContactOneSided => false,
        };
        if !condition_matches {
            continue;
        }
        if let InterpretationEffect::SuppressSignals { selectors } = &rule.effect {
            apply_signal_suppression(selectors, signals);
        }
    }
}

fn privileged_relationship_claim(relationship: SenderRelationship) -> bool {
    matches!(
        relationship,
        SenderRelationship::Parent
            | SenderRelationship::Guardian
            | SenderRelationship::Teacher
            | SenderRelationship::Coach
            | SenderRelationship::Authority
    )
}

fn trusted_family_or_guardian_relationship(relationship: SenderRelationship) -> bool {
    matches!(
        relationship,
        SenderRelationship::Parent
            | SenderRelationship::Guardian
            | SenderRelationship::Family
            | SenderRelationship::Sibling
    )
}

fn verified_relationship_source(source: RelationshipTrustSource) -> bool {
    matches!(
        source,
        RelationshipTrustSource::UserVerified
            | RelationshipTrustSource::GuardianVerified
            | RelationshipTrustSource::PlatformVerified
            | RelationshipTrustSource::AddressBook
            | RelationshipTrustSource::SchoolDirectory
    )
}

fn sender_relationship_marker(relationship: SenderRelationship) -> &'static str {
    match relationship {
        SenderRelationship::Unknown => "unknown",
        SenderRelationship::Parent => "parent",
        SenderRelationship::Guardian => "guardian",
        SenderRelationship::Family => "family",
        SenderRelationship::Sibling => "sibling",
        SenderRelationship::Peer => "peer",
        SenderRelationship::Teacher => "teacher",
        SenderRelationship::Coach => "coach",
        SenderRelationship::Authority => "authority",
        SenderRelationship::Service => "service",
        SenderRelationship::UnknownAdult => "unknown_adult",
        SenderRelationship::UnknownPeer => "unknown_peer",
    }
}

fn relationship_trust_source_marker(source: RelationshipTrustSource) -> &'static str {
    match source {
        RelationshipTrustSource::Unknown => "unknown",
        RelationshipTrustSource::UserVerified => "user_verified",
        RelationshipTrustSource::GuardianVerified => "guardian_verified",
        RelationshipTrustSource::PlatformVerified => "platform_verified",
        RelationshipTrustSource::AddressBook => "address_book",
        RelationshipTrustSource::SchoolDirectory => "school_directory",
        RelationshipTrustSource::ServerReputation => "server_reputation",
        RelationshipTrustSource::LocalHeuristic => "local_heuristic",
        RelationshipTrustSource::SelfDeclared => "self_declared",
    }
}

fn is_established_friendly_contact(snapshot: &ContactSnapshot) -> bool {
    !snapshot.is_new_contact
        && snapshot.conversation_count > 0
        && (snapshot.is_trusted
            || snapshot.trust_level >= 0.60
            || snapshot.circle_tier != CircleTier::New)
}

fn has_recent_playful_reciprocity(
    timeline: Option<&ConversationTimeline>,
    sender_id: &str,
    now_ms: u64,
) -> bool {
    let Some(timeline) = timeline else {
        return false;
    };
    let since = now_ms.saturating_sub(15 * 60 * 1000);
    let recent = timeline.events_since(since);
    let sender_has_prior = recent.iter().any(|event| event.sender_id == sender_id);
    let other_sender_replied = recent
        .iter()
        .any(|event| event.sender_id != sender_id && event.kind == EventKind::NormalConversation);

    sender_has_prior && other_sender_replied
}

fn is_playful_banter_message(
    input: &MessageInput,
    text: &str,
    timestamp_ms: u64,
    timeline: Option<&ConversationTimeline>,
) -> bool {
    let lower = text.to_lowercase();
    let joke_disclaimer = contains_any(
        &lower,
        &["жартую", "jk", "just kidding", "just kiddin", "kidding"],
    );
    let playful_marker = contains_any(
        &lower,
        &[
            "ахаха",
            "хаха",
            "😂",
            "🤣",
            "😜",
            "😈",
            "💀",
            "рофл",
            "лол",
            "мем",
            "bro",
            "бро",
        ],
    );
    let mild_teasing_marker = contains_any(
        &lower,
        &[
            "дурень",
            "дурна",
            "дебіли",
            "дебіли",
            "кринж",
            "заткнись",
            "ненавіджу вас",
            "сук!",
            "сук ",
        ],
    );
    let silly_object = contains_any(
        &lower,
        &[
            "бутерброд",
            "бутік",
            "обід",
            "снідан",
            "піц",
            "pizza",
            "sandwich",
            "lunch",
            "мем",
        ],
    );
    let media_marker = contains_any(
        &lower,
        &[
            "тікток",
            "tiktok",
            "мем",
            "відео",
            "video",
            "пост",
            "інста",
            "instagram",
            "селфі",
            "selfie",
            "скетч",
            "зошит",
        ],
    );
    let gaming_marker = contains_any(
        &lower,
        &[
            "катк",
            "лобі",
            "клатч",
            "кіл",
            "кіли",
            "сервер",
            "хіліл",
            "rank",
            "рейд",
            "матч",
            "game",
            "гру",
            "катку",
        ],
    );
    let crush_marker = contains_any(
        &lower,
        &[
            "подобається",
            "краш",
            "подобаєшся",
            "ти думаєш",
            "😳",
            "🥺",
            "😍",
            "💕",
        ],
    );
    let exam_marker = contains_any(
        &lower,
        &["контрольн", "матеш", "урок", "екзам", "школи", "дз"],
    );
    let goodnight_marker = contains_any(
        &lower,
        &[
            "на добраніч",
            "добраніч",
            "goodnight",
            "gn",
            "не проспи",
            "соня",
        ],
    );
    let reciprocal_play = has_recent_playful_reciprocity(timeline, &input.sender_id, timestamp_ms);

    if looks_like_unresolved_future_violence(&lower) {
        return false;
    }

    let self_nullified_teasing = joke_disclaimer && (playful_marker || reciprocal_play);
    let playful_hyperbole = lower.contains("я тебе вб'ю за")
        || lower.contains("kill you for")
        || lower.contains("помру від сміх")
        || lower.contains("здохну від")
        || lower.contains("dying from laughing")
        || lower.contains("dead from laughing")
        || (lower.contains("монстр") && (playful_marker || reciprocal_play))
        || ((lower.contains("вбивця") || lower.contains("знищ") || lower.contains("тікайте"))
            && silly_object
            && playful_marker);
    let casual_death_hyperbole = contains_any(
        &lower,
        &[
            "я здохла",
            "я здох",
            "я мертва",
            "я мертвий",
            "я помру",
            "ми всі здохнемо",
            "не здохніть",
            "ледь жива",
            "ледь живий",
            "i'm dead",
            "im dead",
            "literally died",
            "i died",
        ],
    ) && (playful_marker
        || reciprocal_play
        || media_marker
        || gaming_marker
        || crush_marker
        || exam_marker);
    let conditional_mock_threat = reciprocal_play
        && (lower.contains("я тебе вб'ю якщо") || lower.contains("kill you if you"))
        && !contains_any(
            &lower,
            &[
                "знаю де ти живеш",
                "i know where you live",
                "школ",
                "поб'ю",
                "beat you",
                "заріжу",
                "збро",
                "knife",
            ],
        );
    let joking_mild_teasing = mild_teasing_marker
        && (playful_marker || joke_disclaimer || reciprocal_play)
        && !contains_any(
            &lower,
            &[
                "(ні)",
                "не жарт",
                "не шучу",
                "всі знають",
                "найтуп",
                "ніхто",
            ],
        );
    let friendly_goodnight_teasing = goodnight_marker
        && reciprocal_play
        && (playful_marker || mild_teasing_marker || lower.contains("не проспи"));

    self_nullified_teasing
        || playful_hyperbole
        || casual_death_hyperbole
        || conditional_mock_threat
        || joking_mild_teasing
        || friendly_goodnight_teasing
}

fn looks_like_unresolved_future_violence(lower: &str) -> bool {
    if unresolved_future_violence_in(lower) {
        return true;
    }

    let normalized = TextNormalizer::new().normalize(lower);
    normalized != lower && unresolved_future_violence_in(&normalized)
}

fn unresolved_future_violence_in(lower: &str) -> bool {
    let violent_action = contains_any(
        lower,
        &[
            "kill u",
            "kill you",
            "hurt you",
            "shoot you",
            "stab you",
            "beat you",
            "break your",
            "gonna kill",
            "going to kill",
            "wont make it",
            "won't make it",
        ],
    );
    let future_or_ambiguous = contains_any(
        lower,
        &[
            "tmrw",
            "tomorrow",
            "tonight",
            "next week",
            "after school",
            "unless",
            "outside",
            "come out",
            "waiting",
        ],
    );

    violent_action && future_or_ambiguous
}

fn is_deescalating_peer_conflict_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    if is_deescalating_peer_conflict_text(&lower) {
        return true;
    }

    let normalizer = TextNormalizer::new();
    normalizer
        .normalize_cyrillic_leet_variants(text, "uk")
        .iter()
        .any(|normalized| normalized != &lower && is_deescalating_peer_conflict_text(normalized))
}

fn is_deescalating_peer_conflict_text(lower: &str) -> bool {
    if contains_any(
        lower,
        &[
            "здох",
            "вбий",
            "убей",
            "kill yourself",
            "nobody wants",
            "nobody likes",
            "everyone hates",
            "worthless",
            "pathetic",
            "нікому не",
            "никому не",
            "ніхто тебе",
            "никто тебя",
            "потвор",
            "урод",
            "ненавид",
        ],
    ) {
        return false;
    }

    let deescalation = contains_any(
        lower,
        &[
            "без сварок",
            "без ссор",
            "не свар",
            "не ссор",
            "не треба кричати",
            "не надо кричать",
            "не треба свар",
            "не надо ссор",
            "lets not fight",
            "let's not fight",
            "dont fight",
            "don't fight",
            "stop fighting",
            "calm down",
            "i disagree but",
            "я не згоден, але",
            "я не согласен, но",
        ],
    );
    let repair_context = contains_any(
        lower,
        &[
            "переробимо",
            "переделаем",
            "fix the project",
            "fix the slides",
            "слайд",
            "slides",
            "презентац",
            "presentation",
            "проєкт",
            "проект",
            "project",
            "тактик",
            "tactic",
            "розберемо",
            "розберем",
            "review the play",
            "review the game",
            "момент",
            "match",
            "матч",
            "тренув",
            "training",
            "after class",
            "після урок",
            "после урок",
        ],
    );

    deescalation && repair_context
}

fn is_plain_peer_compliment_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let compliment_markers = [
        "beautiful",
        "pretty",
        "gorgeous",
        "cute",
        "amazing",
        "perfect",
        "incredible",
        "special",
        "wonderful",
        "lovely",
        "adorable",
        "sweet",
        "таланов",
        "гарн",
        "крас",
        "подобає",
        "зачіск",
        "найкращ",
        "чудов",
        "мила",
        "крутан",
        "талант",
        "ідеаль",
        "неймовірн",
        "особлив",
        "чарівн",
    ];
    let grooming_anchors = [
        "for your age",
        "для свого віку",
        "special connection",
        "особливий зв'язок",
        "не кажи",
        "secret",
        "секрет",
        "зустрінем",
        "meet",
        "photo",
        "фото",
        "selfie",
        "camera",
        "камера",
        "parents",
        "батьк",
        "where do you live",
        "де ти живеш",
        "gift",
        "подар",
        "money",
        "грош",
    ];

    let compliment_count = count_contains(&lower, &compliment_markers);
    compliment_count > 0 && compliment_count <= 2 && !contains_any(&lower, &grooming_anchors)
}

fn is_casual_appearance_compliment_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_any(
        &lower,
        &[
            "гарна сьогодні",
            "гарно сьогодні",
            "красива сьогодні",
            "pretty today",
            "look nice today",
            "look good today",
            "класна зачіска",
            "класний лук",
            "nice haircut",
            "nice outfit",
        ],
    )
}

fn is_non_romantic_group_praise_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let praise_markers = [
        "ти бог",
        "you are god",
        "ти топ",
        "рятівниц",
        "шедевр",
        "легенда",
        "неймовірна",
        "неймовірний",
        "найкраща",
        "найкращий",
    ];
    let context_markers = [
        "катк",
        "лобі",
        "клатч",
        "кіл",
        "сервер",
        "дз",
        "зошит",
        "проект",
        "скетч",
        "портрет",
        "селфі",
        "групове",
        "фотограф",
    ];
    contains_any(&lower, &praise_markers)
        && contains_any(&lower, &context_markers)
        && !contains_any(
            &lower,
            &[
                "секрет",
                "батьк",
                "мама",
                "купальник",
                "гола",
                "тіло",
                "адрес",
            ],
        )
}

fn is_casual_media_share_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let char_len = lower.chars().count();
    let media_markers = [
        "тікток",
        "tiktok",
        "мем",
        "відео",
        "video",
        "пост",
        "запостив",
        "інста",
        "instagram",
        "селфі",
        "selfie",
        "скетч",
        "зошит",
        "проект",
        "фотку зошита",
        "групове селфі",
        "фотограф",
    ];
    let share_markers = ["скинь", "покажи", "дивись", "кидаю", "покажи", "сфотк"];
    let curiosity_markers = [
        "який",
        "шо там",
        "що там",
        "ні шо там",
        "нi шо там",
        "не покажу нікому",
        "не скажу нікому",
        "тільки не показуй нікому",
        "клянусь",
    ];
    let risky_markers = [
        "купальник",
        "ліфчик",
        "гола",
        "голий",
        "тіло",
        "огол",
        "камера",
        "адрес",
        "локац",
        "де ти живеш",
        "батьк",
        "мама",
        "зустрінем",
    ];

    (contains_any(&lower, &media_markers)
        || (contains_any(&lower, &share_markers)
            && (contains_any(
                &lower,
                &["мем", "відео", "тікток", "зошит", "селфі", "пост"],
            ) || char_len <= 40))
        || (contains_any(&lower, &curiosity_markers)
            && (contains_any(&lower, &media_markers)
                || contains_any(
                    &lower,
                    &["😂", "🤣", "💀", "😭", "кринж", "тіпа", "ахаха", "хахах"],
                )
                || char_len <= 14)))
        && !contains_any(&lower, &risky_markers)
}

fn is_lightweight_media_banter_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_any(
        &lower,
        &[
            "помирала від",
            "помираю від цього",
            "я мертва",
            "який скинь",
            "ні шо там",
            "що там",
            "покажи я помру",
            "покажи я здохну",
            "не скажу нікому",
            "не покажу нікому",
            "це реально він",
            "групове селфі",
        ],
    ) && contains_any(
        &lower,
        &["😂", "🤣", "💀", "😭", "тікток", "мем", "відео", "селфі"],
    )
}

fn is_high_risk_grooming_signal(signal: &DetectionSignal) -> bool {
    signal.threat_type == ThreatType::Grooming
        && (signal.score > 0.55
            || contains_any(
                &signal.reason_code,
                &[
                    "secrecy",
                    "gift",
                    "money",
                    "photo",
                    "meeting",
                    "platform",
                    "sexual",
                    "location",
                    "personal_info",
                    "identity_erosion",
                ],
            ))
}

fn is_lightweight_competitive_banter_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_any(
        &lower,
        &[
            "ти шо робиш там",
            "ти шо робиш",
            "мене вбили через",
            "ти бог",
            "ти топ",
            "ми мусор",
            "минулі 10 каток",
            "ще катку",
            "ненавіджу (жарт)",
            "ненавіджу жарт",
        ],
    ) || (contains_any(&lower, &["😂", "🤣", "💀", "😤"])
        && contains_any(&lower, &["катк", "лобі", "клатч", "кіл", "хіліл"]))
}

fn is_self_referential_distress_profanity_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_any(
        &lower,
        &[
            "мені мама дала",
            "мене мама",
            "мені пздц",
            "мені пізда",
            "мені п*зда",
            "мені хана",
            "ми в сраці",
            "я в сраці",
            "я в жопі",
        ],
    ) && !contains_any(
        &lower,
        &[
            "тобі",
            "тобе",
            "ти ",
            "тебе",
            "він ",
            "вона ",
            "вони ",
            "з тобою",
        ],
    )
}

fn is_competitive_gaming_banter_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let gaming_markers = [
        "катк",
        "лобі",
        "клатч",
        "кіл",
        "кіли",
        "хіліл",
        "сервер",
        "game",
        "гру",
        "катку",
        "матч",
    ];
    let banter_markers = [
        "лол",
        "ахах",
        "😂",
        "🤣",
        "💀",
        "😤",
        "го",
        "рілі",
        "бог",
        "топ",
        "мусор",
    ];
    let severe_abuse = [
        "потвора",
        "шмара",
        "урод",
        "здохни",
        "нехай здохне",
        "нікому не потрібна",
        "всі тебе ненавидять",
    ];

    contains_any(&lower, &gaming_markers)
        && (contains_any(&lower, &banter_markers)
            || lower.contains("ти шо робиш")
            || lower.contains("ще катку"))
        && !contains_any(&lower, &severe_abuse)
}

fn count_contains(text: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter(|needle| text.contains(**needle))
        .count()
}

fn strip_redundant_normal_events(mut events: Vec<ContextEvent>) -> Vec<ContextEvent> {
    let mut has_non_normal = false;
    for event in &events {
        if event.kind != EventKind::NormalConversation {
            has_non_normal = true;
            break;
        }
    }
    if has_non_normal {
        events.retain(|event| event.kind != EventKind::NormalConversation);
    }
    events
}

fn materialize_confirmed_events(
    event_hints: Vec<RawEventHint>,
    timestamp_ms: Option<u64>,
    input: &MessageInput,
    frame: &ThreatContextFrame,
) -> Vec<ConfirmedEvent> {
    let events = materialize_event_hints(
        event_hints,
        timestamp_ms,
        &input.sender_id,
        &input.conversation_id,
    );
    with_event_context(strip_redundant_normal_events(events), frame)
}

fn with_event_context(
    events: Vec<ContextEvent>,
    frame: &ThreatContextFrame,
) -> Vec<ConfirmedEvent> {
    let context = compact_event_context(frame);
    let mut decorated = Vec::with_capacity(events.len());
    for event in events {
        let event = if event.kind == EventKind::NormalConversation {
            event
        } else {
            event.with_context(context)
        };
        decorated.push(ConfirmedEvent::new(event));
    }
    decorated
}

fn compact_event_context(frame: &ThreatContextFrame) -> EventContextFrame {
    EventContextFrame {
        speech_act: match frame.speech_act {
            SpeechAct::Assert => EventSpeechAct::Assert,
            SpeechAct::Ask => EventSpeechAct::Ask,
            SpeechAct::Quote => EventSpeechAct::Quote,
            SpeechAct::Report => EventSpeechAct::Report,
            SpeechAct::Counter => EventSpeechAct::Counter,
            SpeechAct::Support => EventSpeechAct::Support,
            SpeechAct::Solicit => EventSpeechAct::Solicit,
        },
        stance: match frame.stance {
            Stance::Endorse => EventStance::Endorse,
            Stance::Oppose => EventStance::Oppose,
            Stance::Neutral => EventStance::Neutral,
            Stance::Ambiguous => EventStance::Ambiguous,
        },
        directionality: match frame.directionality {
            Directionality::DirectedAtUser => EventDirectionality::DirectedAtUser,
            Directionality::SelfReferential => EventDirectionality::SelfReferential,
            Directionality::ThirdParty => EventDirectionality::ThirdParty,
            Directionality::Broadcast => EventDirectionality::Broadcast,
            Directionality::Unknown => EventDirectionality::Unknown,
        },
        new_contact: frame.relationship.is_new_contact,
        trusted_contact: frame.relationship.is_trusted,
        one_sided: matches!(frame.reciprocity, Reciprocity::OneSided),
        repeated_by_sender: frame.trajectory.repeated_by_sender,
        escalating: frame.trajectory.escalating,
        cross_conversation: frame.trajectory.cross_conversation,
        bursty: frame.trajectory.bursty,
        confidence: frame.confidence,
    }
}

fn confidence_from_score(score: f32) -> Confidence {
    if score >= 0.8 {
        Confidence::High
    } else if score >= 0.5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn contains_any_token(text: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|token| contains_token(text, token))
}

fn contains_token(text: &str, token: &str) -> bool {
    let mut search_from = 0;
    while let Some(pos) = text[search_from..].find(token) {
        let start = search_from + pos;
        let end = start + token.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();

        if before.is_none_or(is_token_boundary) && after.is_none_or(is_token_boundary) {
            return true;
        }

        search_from = end;
    }
    false
}

fn is_token_boundary(c: char) -> bool {
    !c.is_alphanumeric() && c != '_'
}

fn normalize_context_cues(lower: &str) -> String {
    let chars: Vec<char> = lower.chars().map(fold_fullwidth_context_char).collect();
    let mut result = String::with_capacity(lower.len());
    let mut last_was_space = false;

    for (idx, c) in chars.iter().enumerate() {
        if is_zero_width_context_noise(*c) || is_context_combining_mark(*c) {
            continue;
        }
        if is_contextual_interstitial(&chars, idx) {
            continue;
        }
        if is_emoji_context_noise(*c) {
            if !last_was_space {
                result.push(' ');
                last_was_space = true;
            }
            continue;
        }

        let normalized = match *c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            other => other,
        };
        result.push(normalized);
        last_was_space = normalized.is_whitespace();
    }

    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn fold_fullwidth_context_char(c: char) -> char {
    match c {
        '\u{3000}' => ' ',
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
        other => other,
    }
}

fn is_contextual_interstitial(chars: &[char], idx: usize) -> bool {
    if !matches!(
        chars[idx],
        '*' | '.'
            | '-'
            | '_'
            | '~'
            | '`'
            | '|'
            | '/'
            | '\\'
            | '#'
            | '^'
            | '&'
            | '='
            | ':'
            | ';'
            | '·'
            | '•'
            | '‧'
            | '∙'
            | '⋅'
            | '˙'
            | '⁄'
            | '∕'
    ) {
        return false;
    }

    let prev_letter = idx > 0 && chars[idx - 1].is_alphabetic();
    let next_letter = idx + 1 < chars.len() && chars[idx + 1].is_alphabetic();
    prev_letter && next_letter
}

fn is_zero_width_context_noise(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{FEFF}'
            | '\u{00AD}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2060}'
            | '\u{2061}'
            | '\u{2062}'
            | '\u{2063}'
            | '\u{2064}'
            | '\u{034F}'
    )
}

fn is_emoji_context_noise(c: char) -> bool {
    let cp = c as u32;
    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || (0xFE00..=0xFE0F).contains(&cp)
        || cp == 0x20E3
}

fn is_context_combining_mark(c: char) -> bool {
    let cp = c as u32;
    (0x0300..=0x036F).contains(&cp)
        || (0x1AB0..=0x1AFF).contains(&cp)
        || (0x1DC0..=0x1DFF).contains(&cp)
        || (0xFE20..=0xFE2F).contains(&cp)
}

fn looks_like_quote_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "he said",
            "she said",
            "they said",
            "someone said",
            "he wrote",
            "she wrote",
            "they wrote",
            "he texted",
            "she texted",
            "they texted",
            "he messaged",
            "she messaged",
            "they messaged",
            "court read",
            "defendant's text",
            "defendants text",
            "the text said",
            "message read",
            "message said",
            "evidence that",
            "quoted",
            "quote:",
            "quoted:",
            "він сказав",
            "вона сказала",
            "вони сказали",
            "хтось сказав",
            "він написав",
            "вона написала",
            "вони написали",
            "цитата",
            "цитую",
            "он сказал",
            "она сказала",
            "они сказали",
            "кто-то сказал",
            "он написал",
            "она написала",
            "они написали",
            "цитирую",
            "переслали",
            "forwarded",
        ],
    ) || contains_any(lower, &["\"", "«", "»", "“", "”"])
}

fn looks_like_report_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "reporting this",
            "i'm reporting",
            "im reporting",
            "reported this",
            "sending this to",
            "forwarding this",
            "forwarding it",
            "forwarding the screenshot",
            "i m forwarding",
            "for context",
            "for the report",
            "поскаржуся",
            "скаржуся",
            "для контексту",
            "для звіту",
            "це мені скинули",
            "це переслали",
            "я жалуюсь",
            "я пожалуюсь",
            "для отчёта",
            "для отчета",
            "мне это скинули",
            "это переслали",
        ],
    )
}

fn looks_like_direct_military_social_eng_pretext(signal: &DetectionSignal, lower: &str) -> bool {
    if signal.threat_type != ThreatType::MilitarySocialEng {
        return false;
    }

    let has_pretext_role = contains_any(
        lower,
        &[
            "я з відділу комплектування",
            "я журналіст",
            "я кореспондент",
            "я фельдшер",
            "я медик",
            "капелан",
            "фонду ветеранів",
            "районного штабу",
            "volunteer fund",
            "hq here",
        ],
    );
    let has_sensitive_request = contains_any(
        lower,
        &[
            "підтвердіть",
            "підтв",
            "поділіться",
            "дайте",
            "скажіть",
            "скинь",
            "позицію",
            "координати",
            "номер частини",
            "ваше звання",
            "unit id",
            "current position",
            "відсканьте qr",
            "з паспортом",
        ],
    );

    has_pretext_role && has_sensitive_request
}

fn looks_like_counter_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "this is false",
            "this is fake",
            "fake news",
            "debunk",
            "debunking",
            "factcheck",
            "fact-check",
            "це брехня",
            "це фейк",
            "спростування",
            "ворожа пропаганда",
            "это ложь",
            "это фейк",
            "опровержение",
            "вражеская пропаганда",
            "enemy propaganda",
            "don't believe this propaganda",
            "dont believe this propaganda",
            "do not believe this propaganda",
            "не вірте цій пропаганді",
            "не вір цій пропаганді",
            "не верьте этой пропаганде",
            "не верь этой пропаганде",
            "don't post coordinates",
            "dont post coordinates",
            "don't share coordinates",
            "dont share coordinates",
            "do not post coordinates",
            "do not share coordinates",
            "do not publish coordinates",
            "dont publish coordinates",
            "не публікуй координати",
            "не публікувати координати",
            "не публікувати в чатах",
            "не публікувти в чатах",
            "не публікуйте координати",
            "не кидай координати",
            "не скидай координати",
            "не постити координати",
            "не публикуй координаты",
            "не публиковать координаты",
            "не публикуйте координаты",
            "не кидай координаты",
            "не скидывай координаты",
        ],
    )
}

fn looks_like_support_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "i'm here with you",
            "im here with you",
            "i'm here for you",
            "im here for you",
            "i care about you",
            "thank you for telling me",
            "you don't have to handle this alone",
            "you dont have to handle this alone",
            "you dont have to do this alone",
            "you don't have to do this alone",
            "lets tell your parents",
            "let's tell your parents",
            "lets tell your counselor",
            "let's tell your counselor",
            "we can get help",
            "we can find help",
            "you're not alone",
            "youre not alone",
            "i'm calling the counselor",
            "im calling the counselor",
            "staying with you",
            "let's leave this chat",
            "lets leave this chat",
            "get help from adults",
            "help from adults",
            "we're with you",
            "were with you",
            "я поруч",
            "я з тобою",
            "ми з тобою",
            "дякую що сказала",
            "дякую що сказав",
            "дякую що розказала",
            "дякую що розказав",
            "не треба це ховати",
            "давай скажемо батькам",
            "давай скажемо психологу",
            "можемо знайти допомогу",
            "ти не один",
            "ты не один",
            "мы с тобой",
            "я рядом",
            "спасибо что сказал",
            "спасибо что сказала",
            "давай скажем родителям",
            "давай скажем психологу",
            "можем найти помощь",
        ],
    )
}

fn looks_like_distribution_or_coordination(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "share this",
            "forward this",
            "send this to everyone",
            "join the channel",
            "follow this channel",
            "subscribe here",
            "пошир це",
            "перешли це",
            "скинь всім",
            "підпишись",
            "заходь в канал",
            "подпишись",
            "перешли это",
            "скинь всем",
            "заходи в канал",
        ],
    )
}

fn looks_like_directed_at_user(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "you ",
            "your ",
            "u ",
            "ur ",
            "ти ",
            "тобі ",
            "тебе ",
            "твій ",
            "твоя ",
            "твое ",
            "твоя ",
            "ты ",
            "тебе ",
            "твой ",
            "твоя ",
        ],
    )
}

fn looks_like_third_party_reference(lower: &str) -> bool {
    contains_any_token(
        lower,
        &[
            "he",
            "she",
            "they",
            "my friend",
            "his",
            "her",
            "their",
            "він",
            "вона",
            "вони",
            "мій друг",
            "моя подруга",
            "його",
            "її",
            "їх",
            "он",
            "она",
            "они",
            "мой друг",
            "моя подруга",
            "его",
            "ее",
            "их",
        ],
    )
}

fn is_self_referential_distress(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "i want to die",
            "i wanna die",
            "i will kill myself",
            "i'll kill myself",
            "im going to kill myself",
            "i'm going to kill myself",
            "i want to end it",
            "i cant go on",
            "i can't go on",
            "i feel hopeless",
            "i feel like there's no reason to live",
            "there's no reason for me to live",
            "there is no reason for me to live",
            "хочу померти",
            "хочу вмерти",
            "я вб'ю себе",
            "я убью себя",
            "я не хочу жити",
            "я не хочу жить",
            "мені нема сенсу жити",
            "мне нет смысла жить",
            "хочу померти",
            "покончить с собой",
        ],
    )
}

fn looks_like_opsec_warning(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "don't post coordinates",
            "dont post coordinates",
            "don't share coordinates",
            "dont share coordinates",
            "do not post coordinates",
            "do not share coordinates",
            "do not publish coordinates",
            "dont publish coordinates",
            "delete the coordinates",
            "remove the coordinates",
            "не пиши координати",
            "не публікуй координати",
            "не публікувати координати",
            "не публікувати в чатах",
            "не публікувти в чатах",
            "не публікуйте координати",
            "не кидай координати",
            "не скидай координати",
            "не постити координати",
            "видали координати",
            "не публикуй координаты",
            "не публиковать координаты",
            "не публикуйте координаты",
            "не кидай координаты",
            "не скидывай координаты",
            "удали координаты",
        ],
    )
}

fn looks_like_opsec_warning_context(lower: &str) -> bool {
    looks_like_opsec_warning(lower) || looks_like_opsec_warning(&normalize_context_cues(lower))
}

fn looks_like_trusted_logistics_context(frame: &ThreatContextFrame, lower: &str) -> bool {
    let institutional_logistics = contains_any(
        lower,
        &[
            "parent chat",
            "parents chat",
            "parent group",
            "guardian group",
            "guardian copy",
            "permission slip",
            "signed form",
            "signed permission",
            "permission form",
            "team bus",
            "group reminder",
            "application form",
            "family chat",
            "батьківський чат",
            "чат батьків",
            "батьківська група",
            "дозвіл",
            "заява",
            "підписан",
            "батьківську групу",
            "родительский чат",
            "чат родителей",
            "разрешение",
            "заявлен",
            "подписан",
        ],
    );
    let trusted_relationship = !frame.relationship.is_new_contact
        && (frame.relationship.is_trusted
            || frame.relationship.prior_conversation_count > 0
            || frame.relationship.trust_level >= 0.60
            || frame.relationship.circle_tier != CircleTier::New);
    (trusted_relationship || institutional_logistics)
        && contains_any(
            lower,
            &[
                "after class",
                "after school",
                "pickup",
                "pick you up",
                "classroom",
                "room ",
                "homework",
                "teacher",
                "counselor",
                "school gate",
                "parent",
                "parents",
                "після уроків",
                "після школи",
                "заберу",
                "кабінет",
                "клас",
                "домашк",
                "вчитель",
                "психолог",
                "батьк",
                "після занять",
                "после уроков",
                "после школы",
                "заберу тебя",
                "кабинет",
                "класс",
                "домашк",
                "учитель",
                "психолог",
                "родител",
                "дозвіл",
                "заява",
            ],
        )
}

fn looks_like_documentary_media_request(lower: &str) -> bool {
    let documentary_cue = contains_any(
        lower,
        &[
            "photo of the signed",
            "photo of signed",
            "picture of the signed",
            "picture of signed",
            "signed form",
            "signed permission",
            "permission slip",
            "permission form",
            "photo of the form",
            "picture of the form",
            "підписаної заяви",
            "підписану заяву",
            "підписаний дозвіл",
            "фото заяви",
            "фото дозволу",
            "подписанного заявления",
            "подписанное разрешение",
            "фото заявления",
            "фото разрешения",
        ],
    );
    let administrative_share = contains_any(
        lower,
        &[
            "parent chat",
            "parents chat",
            "parent group",
            "guardian group",
            "guardian copy",
            "family chat",
            "to confirm permission",
            "so i can see the permission",
            "so i can confirm permission",
            "so i can see the signed form",
            "батьківський чат",
            "чат батьків",
            "батьківська група",
            "щоб я бачив дозвіл",
            "щоб я бачила дозвіл",
            "родительский чат",
            "чат родителей",
            "чтобы я видел разрешение",
        ],
    );

    documentary_cue && administrative_share
}

fn derive_trajectory(
    input: &MessageInput,
    timestamp_ms: Option<u64>,
    timeline: Option<&ConversationTimeline>,
    signals: &[DetectionSignal],
    event_hints: &[RawEventHint],
    snapshot: Option<&ContactSnapshot>,
) -> TrajectoryContext {
    const RECENT_WINDOW_MS: u64 = 12 * 60 * 60 * 1000;
    const BURST_WINDOW_MS: u64 = 10 * 60 * 1000;

    let current_harmful =
        has_current_harmful_signal(signals) || has_current_harmful_event_hint(event_hints);
    let current_threat_diversity = current_relevant_threat_diversity(signals);
    let worsening_trend = snapshot.is_some_and(|snapshot| {
        matches!(
            snapshot.trend,
            BehavioralTrend::GradualWorsening
                | BehavioralTrend::RapidWorsening
                | BehavioralTrend::RoleReversal
        )
    });

    let history_recent_count = match (timestamp_ms, timeline) {
        (Some(now_ms), Some(timeline)) => timeline
            .events_from_sender(&input.sender_id, now_ms.saturating_sub(RECENT_WINDOW_MS))
            .into_iter()
            .filter(|event| is_harmful_event_kind(&event.kind))
            .count(),
        _ => 0,
    };

    let burst_history_count = match (timestamp_ms, timeline) {
        (Some(now_ms), Some(timeline)) => timeline
            .events_from_sender(&input.sender_id, now_ms.saturating_sub(BURST_WINDOW_MS))
            .into_iter()
            .filter(|event| is_harmful_event_kind(&event.kind))
            .count(),
        _ => 0,
    };

    let repeated_by_sender = (history_recent_count >= 1 && current_harmful)
        || snapshot.is_some_and(|snapshot| snapshot.total_threat_events >= 2);
    let bursty = burst_history_count >= 2 && current_harmful;
    let cross_conversation = snapshot.is_some_and(|snapshot| {
        snapshot.conversation_count >= 2 && (snapshot.total_threat_events >= 1 || worsening_trend)
    });
    let escalating = worsening_trend
        || (history_recent_count >= 1 && current_threat_diversity >= 2)
        || (bursty && current_harmful);

    TrajectoryContext {
        repeated_by_sender,
        escalating,
        cross_conversation,
        bursty,
    }
}

fn has_current_harmful_signal(signals: &[DetectionSignal]) -> bool {
    signals.iter().any(is_trajectory_relevant_signal)
}

fn current_relevant_threat_diversity(signals: &[DetectionSignal]) -> usize {
    let mut threats = Vec::new();
    for signal in signals {
        if is_trajectory_relevant_signal(signal) && !threats.contains(&signal.threat_type) {
            threats.push(signal.threat_type);
        }
    }
    threats.len()
}

fn is_trajectory_relevant_signal(signal: &DetectionSignal) -> bool {
    matches!(
        signal.threat_type,
        ThreatType::Grooming
            | ThreatType::Bullying
            | ThreatType::Manipulation
            | ThreatType::Threat
            | ThreatType::HateSpeech
            | ThreatType::Propaganda
            | ThreatType::Psyops
            | ThreatType::MilitarySocialEng
            | ThreatType::CoordinateLeak
            | ThreatType::OpsecViolation
    ) && signal.score >= 0.40
}

fn has_current_harmful_event_hint(event_hints: &[RawEventHint]) -> bool {
    event_hints
        .iter()
        .any(|event_hint| is_harmful_event_kind(&event_hint.kind))
}

fn is_harmful_event_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::SecrecyRequest
            | EventKind::PlatformSwitch
            | EventKind::PersonalInfoRequest
            | EventKind::PhotoRequest
            | EventKind::VideoCallRequest
            | EventKind::FinancialGrooming
            | EventKind::MeetingRequest
            | EventKind::SexualContent
            | EventKind::AgeInappropriate
            | EventKind::Insult
            | EventKind::Denigration
            | EventKind::HarmEncouragement
            | EventKind::PhysicalThreat
            | EventKind::RumorSpreading
            | EventKind::Exclusion
            | EventKind::Mockery
            | EventKind::GuiltTripping
            | EventKind::Gaslighting
            | EventKind::EmotionalBlackmail
            | EventKind::PeerPressure
            | EventKind::Darvo
            | EventKind::Devaluation
            | EventKind::HateSpeech
            | EventKind::LocationRequest
            | EventKind::MoneyOffer
            | EventKind::SuicideCoercion
            | EventKind::FalseConsensus
            | EventKind::DebtCreation
            | EventKind::ReputationThreat
            | EventKind::IdentityErosion
            | EventKind::NetworkPoisoning
            | EventKind::FakeVulnerability
            | EventKind::PropagandaNarrative
            | EventKind::SuspiciousSource
            | EventKind::PositionLeak
            | EventKind::UnitInfoLeak
            | EventKind::EquipmentLeak
            | EventKind::CoordinateMention
            | EventKind::PsyopsPattern
            | EventKind::IntelGathering
            | EventKind::MilitaryPhishing
            | EventKind::MilitaryDisinfo
    )
}

fn is_high_risk_grooming_reason(reason_code: &str) -> bool {
    contains_any(
        reason_code,
        &[
            "secrecy",
            "gift",
            "money",
            "photo",
            "meeting",
            "platform",
            "sexual",
            "identity_erosion",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::events::EventSpeechAct;
    use crate::context::observation::RawObservation;
    use crate::ids::{ConversationId, SenderId};
    use crate::types::{ContentType, ConversationType, DetectionSignal, ThreatType};

    fn input(text: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: SenderId::from("sender"),
            conversation_id: ConversationId::from("conv"),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        }
    }

    fn signal(threat_type: ThreatType, reason_code: &str, score: f32) -> DetectionSignal {
        DetectionSignal::pattern(
            threat_type,
            score,
            confidence_from_score(score),
            reason_code,
            "test signal",
        )
    }

    fn event(kind: EventKind) -> ContextEvent {
        ContextEvent::new(1_000, "sender", "conv", kind, 0.8)
    }

    fn timeline_with(events: Vec<ContextEvent>) -> ConversationTimeline {
        let mut timeline = ConversationTimeline::new(ConversationId::from("conv"), 32);
        for event in events {
            timeline.push(event);
        }
        timeline
    }

    fn trusted_snapshot() -> ContactSnapshot {
        ContactSnapshot {
            sender_id: SenderId::from("sender"),
            rating: 72.0,
            trust_level: 0.82,
            circle_tier: CircleTier::Regular,
            trend: crate::types::BehavioralTrend::Stable,
            is_trusted: false,
            is_new_contact: false,
            first_seen_ms: 0,
            last_seen_ms: 1_000,
            conversation_count: 4,
            grooming_event_count: 0,
            bullying_event_count: 0,
            manipulation_event_count: 0,
            total_threat_events: 0,
        }
    }

    #[test]
    fn contextual_observation_filter_blocks_safe_gaming_banter_memory() {
        let interpreter = ContextInterpreter::new();
        let text = "ти шо робиш там 😂 ще катку";
        let mut group_input = input(text);
        group_input.conversation_type = ConversationType::Group;
        let result = interpreter.interpret_observations(
            &group_input,
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Bullying, "pattern.bullying_test", 0.55),
                EventKind::Insult,
                0.55,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty(), "{result:?}");
        assert!(result.confirmed_events.is_empty(), "{result:?}");
    }

    #[test]
    fn interpreter_owned_calibration_boosts_only_corroborated_grooming_pair() {
        let interpreter = ContextInterpreter::new();
        let text = "you are beautiful";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![
                RawObservation::signal(signal(
                    ThreatType::Grooming,
                    "pattern.grooming_flattery_001",
                    0.30,
                )),
                RawObservation::signal(DetectionSignal::ml(
                    ThreatType::Grooming,
                    0.50,
                    Confidence::Medium,
                    "ml.safety.grooming",
                    "test ml signal",
                )),
                RawObservation::signal(signal(
                    ThreatType::Grooming,
                    "pattern.grooming_secrecy_001",
                    0.70,
                )),
            ],
            None,
        );
        let adjustments = result.signal_adjustments;
        let mut signals = result.adjusted_signals;

        adjustments.apply_calibration(&mut signals);

        assert!((signals[0].score - 0.42).abs() < f32::EPSILON);
        assert!((signals[1].score - 0.62).abs() < f32::EPSILON);
        assert!((signals[2].score - 0.70).abs() < f32::EPSILON);
        assert_eq!(signals[0].confidence, Confidence::Low);
        assert_eq!(signals[1].confidence, Confidence::Medium);
    }

    #[test]
    fn interpreter_owned_calibration_removes_supportive_timing_signal() {
        let interpreter = ContextInterpreter::new();
        let text = "I'm here with you. Let's tell your parents and get help.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            Vec::new(),
            None,
        );
        let mut signals = vec![signal(
            ThreatType::Grooming,
            "conversation.timing.late_night_minor_contact",
            0.40,
        )];

        result.signal_adjustments.apply_calibration(&mut signals);

        assert!(signals.is_empty());
    }

    #[test]
    fn counter_speech_suppresses_propaganda_signal_and_event() {
        let interpreter = ContextInterpreter::new();
        let result = interpreter.interpret_observations(
            &input("This is fake news, don't believe this propaganda."),
            Some("This is fake news, don't believe this propaganda."),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Propaganda, "pattern.propaganda_test", 0.86),
                EventKind::PropagandaNarrative,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn support_context_suppresses_selfharm_signal_and_event() {
        let interpreter = ContextInterpreter::new();
        let text = "I'm here with you. Let's tell your parents together and get help tonight.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::SelfHarm, "ml.safety.selfharm", 0.78),
                EventKind::Hopelessness,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn opsec_warning_suppresses_coordinate_leak() {
        let interpreter = ContextInterpreter::new();
        let text = "Don't post coordinates like 48.4500, 35.0000 in chat. Remove them now.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(
                    ThreatType::CoordinateLeak,
                    "pattern.opsec_coordinates_001",
                    0.92,
                ),
                EventKind::CoordinateMention,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn ukrainian_opsec_warning_suppresses_coordinate_leak() {
        let interpreter = ContextInterpreter::new();
        let text = "Нагадую: не публікувати в чатах координати типу 48.5928 38.0061.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(
                    ThreatType::CoordinateLeak,
                    "pattern.opsec_coordinates_001",
                    0.92,
                ),
                EventKind::CoordinateMention,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn interstitial_ukrainian_opsec_warning_suppresses_coordinate_leak() {
        let interpreter = ContextInterpreter::new();
        let text = "Нагадую: не п·у·б·л·і·к·у·в·а·т·и в чатах координати типу 48.5928 38.0061.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(
                    ThreatType::CoordinateLeak,
                    "pattern.opsec_coordinates_001",
                    0.92,
                ),
                EventKind::CoordinateMention,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn quote_context_suppresses_direct_threat() {
        let interpreter = ContextInterpreter::new();
        let text = r#"He said "I will kill you", and I'm reporting it."#;
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Threat, "pattern.threat_test", 0.90),
                EventKind::PhysicalThreat,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn punctuation_stripped_report_context_suppresses_direct_threat() {
        let interpreter = ContextInterpreter::new();
        let text = "He texted I will hurt you tomorrow I m forwarding the screenshot";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Threat, "pattern.threat_test", 0.90),
                EventKind::PhysicalThreat,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
        assert!(result
            .diagnostic_reason_codes()
            .iter()
            .any(|code| code == "context.speech_act.quote"));
    }

    #[test]
    fn fullwidth_quote_context_suppresses_direct_threat() {
        let interpreter = ContextInterpreter::new();
        let text = "Ｈｅ ｔｅｘｔｅｄ ＂Ｉ ｗｉｌｌ ｈｕｒｔ ｙｏｕ ｔｏｍｏｒｒｏｗ＂ － Ｉ＇ｍ ｆｏｒｗａｒｄｉｎｇ ｔｈｅ ｓｃｒｅｅｎｓｈｏｔ．";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Threat, "pattern.threat_test", 0.90),
                EventKind::PhysicalThreat,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn combining_mark_quote_context_suppresses_direct_threat() {
        let interpreter = ContextInterpreter::new();
        let text = "Cọúrt read tḥe defendánt's text 'Í wi̇ḷl k̇ill yoụ ṭomoṙroẇ' aloud.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Threat, "pattern.threat_test", 0.90),
                EventKind::PhysicalThreat,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn leetspeak_quote_context_suppresses_direct_threat() {
        let interpreter = ContextInterpreter::new();
        let text = "C0ur7 r34d 7h3 d3f3nd4n7's 73x7 '1 w1ll k1ll y0u 70m0rr0w' aloud";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Threat, "pattern.threat_test", 0.90),
                EventKind::PhysicalThreat,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
        assert!(result
            .diagnostic_reason_codes()
            .iter()
            .any(|code| code == "context.speech_act.quote"));
    }

    #[test]
    fn trusted_logistics_suppresses_low_risk_grooming_probe() {
        let interpreter = ContextInterpreter::new();
        let text = "Which classroom are you in after school? Your teacher asked me to pick you up.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(
                    ThreatType::Grooming,
                    "pattern.grooming_personal_info_001",
                    0.42,
                ),
                EventKind::PersonalInfoRequest,
                0.8,
                None,
                None,
            )],
            Some(&trusted_snapshot()),
        );

        assert!(result.adjusted_signals.is_empty());
        assert!(result.confirmed_events.is_empty());
    }

    #[test]
    fn trusted_logistics_suppresses_documentary_media_request() {
        let interpreter = ContextInterpreter::new();
        let text =
            "Send a photo of the signed permission slip to the parent chat so I can confirm it.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Grooming, "ml.intent.media", 0.71),
                EventKind::PhotoRequest,
                0.8,
                None,
                None,
            )],
            Some(&trusted_snapshot()),
        );

        assert!(result.adjusted_signals.is_empty(), "{result:?}");
        assert!(result.confirmed_events.is_empty(), "{result:?}");
    }

    #[test]
    fn third_party_reference_uses_token_boundaries() {
        assert!(!looks_like_third_party_reference(
            "you're the most incredible person"
        ));
        assert!(looks_like_third_party_reference(
            "he asked me to send a photo"
        ));
    }

    #[test]
    fn repeated_sender_trajectory_upweights_new_contact_grooming() {
        let interpreter = ContextInterpreter::new();
        let text = "What school do you go to, and where do you live?";
        let mut prior = event(EventKind::PersonalInfoRequest);
        prior.timestamp_ms = 700;
        let timeline = timeline_with(vec![prior]);
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            Some(&timeline),
            vec![RawObservation::signal_with_event(
                signal(
                    ThreatType::Grooming,
                    "pattern.grooming_personal_info_001",
                    0.50,
                ),
                EventKind::PersonalInfoRequest,
                0.8,
                None,
                None,
            )],
            None,
        );

        assert_eq!(result.adjusted_signals.len(), 1);
        assert_eq!(result.confirmed_events.len(), 1);
        assert!(result.frame.trajectory.repeated_by_sender);
        assert!(
            result.adjusted_signals[0].score > 0.50,
            "expected repeated trajectory to upweight signal, got {:?}",
            result.adjusted_signals
        );
        assert!(result.confirmed_events[0].context.repeated_by_sender);
        assert!(result.confirmed_events[0].context.new_contact);
        assert_eq!(
            result.confirmed_events[0].context.speech_act,
            EventSpeechAct::Ask
        );
    }

    #[test]
    fn diagnostics_include_filter_and_context_markers() {
        let interpreter = ContextInterpreter::new();
        let text = r#"He said "I will kill you", and I'm reporting it."#;
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Threat, "pattern.threat_test", 0.90),
                EventKind::PhysicalThreat,
                0.8,
                None,
                None,
            )],
            None,
        );
        let codes = result.diagnostic_reason_codes();

        assert!(codes.iter().any(|code| code == "context.speech_act.quote"));
        assert!(codes.iter().any(|code| code == "context.filter.applied"));
        assert!(codes
            .iter()
            .any(|code| code == "context.direction.third_party"));
    }

    #[test]
    fn raw_observation_counter_speech_suppresses_before_materialization() {
        let interpreter = ContextInterpreter::new();
        let text = "This is fake news, don't believe this propaganda.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::signal_with_event(
                signal(ThreatType::Propaganda, "pattern.propaganda_test", 0.86),
                EventKind::PropagandaNarrative,
                0.86,
                None,
                Some(42),
            )],
            None,
        );

        assert!(result.adjusted_signals.is_empty(), "{result:?}");
        assert!(result.confirmed_events.is_empty(), "{result:?}");
    }

    #[test]
    fn normal_observation_crosses_confirmed_boundary_without_state_semantic_drift() {
        let interpreter = ContextInterpreter::new();
        let text = "Sounds good, see you tomorrow.";
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            None,
            vec![RawObservation::event(
                EventKind::NormalConversation,
                1.0,
                None,
                Some(7),
            )],
            None,
        );

        assert_eq!(result.confirmed_events.len(), 1);
        assert_eq!(
            result.confirmed_events[0].kind,
            EventKind::NormalConversation
        );
        assert_eq!(result.confirmed_events[0].content_hash, Some(7));
        assert_eq!(
            result.confirmed_events[0].context,
            EventContextFrame::default()
        );
    }

    #[test]
    fn raw_observation_repeated_sender_materializes_confirmed_event_with_context() {
        let interpreter = ContextInterpreter::new();
        let text = "What school do you go to, and where do you live?";
        let mut prior = event(EventKind::PersonalInfoRequest);
        prior.timestamp_ms = 700;
        let timeline = timeline_with(vec![prior]);
        let result = interpreter.interpret_observations(
            &input(text),
            Some(text),
            Some(1_000),
            Some(&timeline),
            vec![RawObservation::signal_with_event(
                signal(
                    ThreatType::Grooming,
                    "pattern.grooming_personal_info_001",
                    0.50,
                ),
                EventKind::PersonalInfoRequest,
                0.80,
                None,
                Some(99),
            )],
            None,
        );

        assert_eq!(result.adjusted_signals.len(), 1);
        assert_eq!(result.confirmed_events.len(), 1);
        assert!(result.frame.trajectory.repeated_by_sender);
        assert_eq!(result.confirmed_events[0].content_hash, Some(99));
        assert!(result.confirmed_events[0].context.repeated_by_sender);
        assert_eq!(
            result.confirmed_events[0].context.speech_act,
            EventSpeechAct::Ask
        );
    }
}
