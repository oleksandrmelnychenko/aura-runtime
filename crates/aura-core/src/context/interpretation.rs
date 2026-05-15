use crate::context::events::{
    ContextEvent, EventContextFrame, EventDirectionality, EventKind, EventSpeechAct, EventStance,
};
use crate::context::observation::{
    materialize_event_hints, split_observations, RawEventHint, RawObservation,
};
use crate::context::tracker::ConversationTimeline;
use crate::types::{
    AnalysisContextSummary, BehavioralTrend, CircleTier, Confidence, ContactSnapshot,
    ContextDirectionality, ContextReciprocity, ContextRelationshipSummary, ContextSpeechAct,
    ContextStance, ContextTrajectorySummary, ConversationType, DetectionLayer, DetectionSignal,
    MessageInput, ThreatType,
};

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
    pub confirmed_events: Vec<ContextEvent>,
    pub suppressed_reason_codes: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ContextInterpreter;

impl ContextInterpreter {
    pub fn new() -> Self {
        Self
    }

    pub fn interpret_observations(
        &self,
        input: &MessageInput,
        text: Option<&str>,
        timestamp_ms: Option<u64>,
        timeline: Option<&ConversationTimeline>,
        observations: Vec<RawObservation>,
        snapshot: Option<&ContactSnapshot>,
    ) -> ContextInterpretation {
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
        let Some(text) = text else {
            let confirmed_events =
                materialize_confirmed_events(event_hints, timestamp_ms, input, &frame);
            return ContextInterpretation {
                frame,
                adjusted_signals: signals,
                confirmed_events,
                suppressed_reason_codes: Vec::new(),
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
        let mut codes = Vec::new();

        match self.frame.speech_act {
            SpeechAct::Assert => {}
            SpeechAct::Ask => codes.push("context.speech_act.ask".to_string()),
            SpeechAct::Quote => codes.push("context.speech_act.quote".to_string()),
            SpeechAct::Report => codes.push("context.speech_act.report".to_string()),
            SpeechAct::Counter => codes.push("context.speech_act.counter".to_string()),
            SpeechAct::Support => codes.push("context.speech_act.support".to_string()),
            SpeechAct::Solicit => codes.push("context.speech_act.solicit".to_string()),
        }

        match self.frame.stance {
            Stance::Endorse => {}
            Stance::Oppose => codes.push("context.stance.oppose".to_string()),
            Stance::Neutral => codes.push("context.stance.neutral".to_string()),
            Stance::Ambiguous => codes.push("context.stance.ambiguous".to_string()),
        }

        match self.frame.directionality {
            Directionality::DirectedAtUser => {
                codes.push("context.direction.directed_at_user".to_string())
            }
            Directionality::SelfReferential => {
                codes.push("context.direction.self_referential".to_string())
            }
            Directionality::ThirdParty => codes.push("context.direction.third_party".to_string()),
            Directionality::Broadcast | Directionality::Unknown => {}
        }

        if self.frame.relationship.is_new_contact
            && matches!(
                self.frame.speech_act,
                SpeechAct::Ask | SpeechAct::Solicit | SpeechAct::Assert
            )
        {
            codes.push("context.relationship.new_contact".to_string());
        }

        if (self.frame.relationship.is_trusted || self.frame.relationship.trust_level >= 0.80)
            && matches!(
                self.frame.speech_act,
                SpeechAct::Support
                    | SpeechAct::Report
                    | SpeechAct::Ask
                    | SpeechAct::Quote
                    | SpeechAct::Counter
            )
        {
            codes.push("context.relationship.trusted".to_string());
        }

        if self.frame.relationship.is_new_contact && self.frame.reciprocity == Reciprocity::OneSided
        {
            codes.push("context.reciprocity.one_sided".to_string());
        }

        if self.frame.trajectory.repeated_by_sender {
            codes.push("context.trajectory.repeated_sender".to_string());
        }
        if self.frame.trajectory.escalating {
            codes.push("context.trajectory.escalating".to_string());
        }
        if self.frame.trajectory.cross_conversation {
            codes.push("context.trajectory.cross_conversation".to_string());
        }
        if self.frame.trajectory.bursty {
            codes.push("context.trajectory.bursty".to_string());
        }

        if !self.suppressed_reason_codes.is_empty() {
            codes.push("context.filter.applied".to_string());
        }

        dedupe_codes(codes)
    }
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
) -> Vec<ContextEvent> {
    let events = materialize_event_hints(
        event_hints,
        timestamp_ms,
        &input.sender_id,
        &input.conversation_id,
    );
    with_event_context(strip_redundant_normal_events(events), frame)
}

fn with_event_context(events: Vec<ContextEvent>, frame: &ThreatContextFrame) -> Vec<ContextEvent> {
    let context = compact_event_context(frame);
    let mut decorated = Vec::with_capacity(events.len());
    for event in events {
        decorated.push(event.with_context(context));
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

fn dedupe_codes(codes: Vec<String>) -> Vec<String> {
    let mut unique = Vec::with_capacity(codes.len());
    for code in codes {
        if !unique.iter().any(|existing| existing == &code) {
            unique.push(code);
        }
    }
    unique
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
    if !(signal.reason_code.contains("military.social_eng.")
        || signal.reason_code.starts_with("pattern.intel_honeytrap_")
        || signal.reason_code.starts_with("pattern.intel_probing_"))
    {
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
            server_sender_risk_hint: None,
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
