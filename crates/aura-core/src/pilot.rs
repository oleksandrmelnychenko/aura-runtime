use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::audit::{
    tokenize_identifier, AuditRecord, AuditThreatScore, ProtectedIdentifier,
    AUDIT_IDENTIFIER_SCHEME,
};
use crate::context::tracker::TRACKER_STATE_VERSION;
use crate::product::{build_product_decision_surface, ProductDecisionSurface, ProductRolloutMode};
use crate::{
    Action, AlertPriority, AnalysisResult, BehavioralTrend, CircleTier, Confidence,
    ConversationType, FollowUpAction, InferenceSummary, ProtectionLevel, RiskBreakdown, ThreatType,
    UiAction,
};

pub const SHADOW_MODE_BUNDLE_SCHEMA_VERSION: &str = "aura.shadow_mode_bundle.v1";
pub const SHADOW_MODE_WIRE_PACKAGE: &str = "aura.messenger.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeBundle {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub source_kind: String,
    pub source_label: String,
    pub source_input: String,
    pub owner_token: ProtectedIdentifier,
    pub runtime_version: String,
    pub wire_package: String,
    pub state_schema_version: u32,
    pub protection_level: ProtectionLevel,
    pub privacy: ShadowModePrivacy,
    pub summary: ShadowModeSummary,
    pub findings: Vec<ShadowModeFinding>,
    pub events: Vec<ShadowModeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModePrivacy {
    pub identifier_scheme: String,
    pub raw_text_present: bool,
    pub raw_identifier_fields_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeSummary {
    pub total_events: usize,
    pub threat_events: usize,
    pub blocked_events: usize,
    pub action_counts: BTreeMap<String, usize>,
    pub threat_counts: BTreeMap<String, usize>,
    pub alert_counts: BTreeMap<String, usize>,
    pub finding_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeEvent {
    pub request_id: String,
    pub sequence: usize,
    pub timestamp_ms: u64,
    pub sender_token: ProtectedIdentifier,
    pub conversation_token: ProtectedIdentifier,
    pub language: String,
    pub conversation_type: ConversationType,
    pub member_count: Option<u32>,
    pub expectation: Option<ShadowModeExpectation>,
    pub audit_record: AuditRecord,
    pub decision: ShadowModeDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeExpectation {
    pub expect_threat: Option<ThreatType>,
    pub expect_min_action: Option<Action>,
    pub expect_min_alert: Option<AlertPriority>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeDecision {
    pub threat_type: ThreatType,
    pub confidence: Confidence,
    pub action: Action,
    pub score: f32,
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub context_markers: Vec<String>,
    pub top_threat_scores: Vec<AuditThreatScore>,
    pub risk_breakdown: RiskBreakdown,
    pub inference: InferenceSummary,
    pub parent_alert: AlertPriority,
    pub follow_ups: Vec<FollowUpAction>,
    pub crisis_resources: bool,
    pub ui_actions: Vec<UiAction>,
    pub contact: Option<ShadowModeContactSummary>,
    pub mirror: ShadowModeMirror,
    pub product_surface: ProductDecisionSurface,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeContactSummary {
    pub sender_token: ProtectedIdentifier,
    pub rating: f32,
    pub trust_level: f32,
    pub circle_tier: CircleTier,
    pub trend: BehavioralTrend,
    pub is_trusted: bool,
    pub is_new_contact: bool,
    pub conversation_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeMirror {
    pub would_surface_to_child: bool,
    pub would_alert_guardian: bool,
    pub would_open_review: bool,
    pub would_block_message: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowModeFinding {
    pub severity: String,
    pub event_sequence: usize,
    pub request_id: String,
    pub timestamp_ms: u64,
    pub message: String,
}

pub struct ShadowModeEventInput<'a> {
    pub request_id: &'a str,
    pub sequence: usize,
    pub timestamp_ms: u64,
    pub sender_id: &'a str,
    pub conversation_id: &'a str,
    pub language: &'a str,
    pub conversation_type: ConversationType,
    pub member_count: Option<u32>,
    pub expectation: Option<ShadowModeExpectation>,
    pub protection_level: ProtectionLevel,
    pub result: &'a AnalysisResult,
}

impl ShadowModeBundle {
    pub fn from_events(
        source_kind: impl Into<String>,
        source_label: impl Into<String>,
        source_input: impl Into<String>,
        owner_id: &str,
        protection_level: ProtectionLevel,
        findings: Vec<ShadowModeFinding>,
        events: Vec<ShadowModeEvent>,
    ) -> Self {
        Self {
            schema_version: SHADOW_MODE_BUNDLE_SCHEMA_VERSION.to_string(),
            generated_at_utc: Utc::now().to_rfc3339(),
            source_kind: source_kind.into(),
            source_label: source_label.into(),
            source_input: source_input.into(),
            owner_token: tokenize_identifier(owner_id),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
            wire_package: SHADOW_MODE_WIRE_PACKAGE.to_string(),
            state_schema_version: TRACKER_STATE_VERSION,
            protection_level,
            privacy: ShadowModePrivacy {
                identifier_scheme: AUDIT_IDENTIFIER_SCHEME.to_string(),
                raw_text_present: false,
                raw_identifier_fields_present: false,
            },
            summary: summarize_shadow_events(&events, findings.len()),
            findings,
            events,
        }
    }
}

pub fn build_shadow_mode_event(input: ShadowModeEventInput<'_>) -> ShadowModeEvent {
    let audit_record = AuditRecord::from_analysis_result(
        input.request_id,
        input.timestamp_ms,
        env!("CARGO_PKG_VERSION"),
        SHADOW_MODE_WIRE_PACKAGE,
        TRACKER_STATE_VERSION,
        input.protection_level,
        Some(input.sender_id),
        Some(input.conversation_id),
        input.result,
    );
    let recommendation = input.result.recommended_action.as_ref();
    let top_threat_scores = audit_record.top_threat_scores.clone();
    let context_markers = audit_record.context_markers.clone();
    let product_surface = build_product_decision_surface(input.result, ProductRolloutMode::Shadow);

    ShadowModeEvent {
        request_id: input.request_id.to_string(),
        sequence: input.sequence,
        timestamp_ms: input.timestamp_ms,
        sender_token: tokenize_identifier(input.sender_id),
        conversation_token: tokenize_identifier(input.conversation_id),
        language: input.language.to_string(),
        conversation_type: input.conversation_type,
        member_count: input.member_count,
        expectation: input.expectation,
        audit_record,
        decision: ShadowModeDecision {
            threat_type: input.result.threat_type,
            confidence: input.result.confidence,
            action: input.result.action,
            score: input.result.score,
            reason_codes: input.result.reason_codes.clone(),
            context_markers,
            top_threat_scores,
            risk_breakdown: input.result.risk_breakdown.clone(),
            inference: input.result.inference.clone(),
            parent_alert: recommendation
                .map(|recommendation| recommendation.parent_alert)
                .unwrap_or(AlertPriority::None),
            follow_ups: recommendation
                .map(|recommendation| recommendation.follow_ups.clone())
                .unwrap_or_default(),
            crisis_resources: recommendation
                .map(|recommendation| recommendation.crisis_resources)
                .unwrap_or(false),
            ui_actions: recommendation
                .map(|recommendation| recommendation.ui_actions.clone())
                .unwrap_or_default(),
            contact: input.result.contact_snapshot.as_ref().map(|snapshot| {
                ShadowModeContactSummary {
                    sender_token: tokenize_identifier(snapshot.sender_id.as_ref()),
                    rating: snapshot.rating,
                    trust_level: snapshot.trust_level,
                    circle_tier: snapshot.circle_tier,
                    trend: snapshot.trend,
                    is_trusted: snapshot.is_trusted,
                    is_new_contact: snapshot.is_new_contact,
                    conversation_count: snapshot.conversation_count,
                }
            }),
            mirror: ShadowModeMirror {
                would_surface_to_child: product_surface.child.visible,
                would_alert_guardian: product_surface.guardian.notify,
                would_open_review: product_surface.review.open_review,
                would_block_message: input.result.action == Action::Block,
            },
            product_surface,
        },
    }
}

fn summarize_shadow_events(events: &[ShadowModeEvent], finding_count: usize) -> ShadowModeSummary {
    let mut action_counts = BTreeMap::new();
    let mut threat_counts = BTreeMap::new();
    let mut alert_counts = BTreeMap::new();
    let mut threat_events = 0usize;
    let mut blocked_events = 0usize;

    for event in events {
        bump_count(&mut action_counts, enum_key(&event.decision.action));
        if event.decision.threat_type != ThreatType::None {
            threat_events += 1;
            bump_count(&mut threat_counts, enum_key(&event.decision.threat_type));
        }
        if event.decision.action == Action::Block {
            blocked_events += 1;
        }
        bump_count(&mut alert_counts, enum_key(&event.decision.parent_alert));
    }

    ShadowModeSummary {
        total_events: events.len(),
        threat_events,
        blocked_events,
        action_counts,
        threat_counts,
        alert_counts,
        finding_count,
    }
}

fn bump_count(map: &mut BTreeMap<String, usize>, key: String) {
    *map.entry(key).or_default() += 1;
}

fn enum_key<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .expect("serializable enum")
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionRecommendation, AnalysisContextSummary, BehavioralTrend, CircleTier, ContactSnapshot,
        DetectionSignal, FollowUpAction, RiskBreakdown, UiAction,
    };

    fn sample_result() -> AnalysisResult {
        AnalysisResult {
            threat_type: ThreatType::Grooming,
            confidence: Confidence::High,
            action: Action::Warn,
            score: 0.91,
            explanation: "detected grooming pattern".to_string(),
            detected_threats: vec![
                (ThreatType::Grooming, 0.91),
                (ThreatType::Manipulation, 0.72),
            ],
            signals: vec![DetectionSignal::pattern(
                ThreatType::Grooming,
                0.91,
                Confidence::High,
                "conversation.grooming.stage_sequence",
                "stage sequence",
            )],
            recommended_action: Some(ActionRecommendation {
                parent_alert: AlertPriority::High,
                follow_ups: vec![FollowUpAction::MonitorConversation],
                crisis_resources: false,
                ui_actions: vec![UiAction::SuggestBlockContact, UiAction::SuggestReport],
                reason_codes: vec!["conversation.grooming.stage_sequence".to_string()],
            }),
            risk_breakdown: RiskBreakdown {
                content: 0.3,
                conversation: 0.8,
                link: 0.0,
                abuse: 0.1,
            },
            contact_snapshot: Some(ContactSnapshot {
                sender_id: "coach_realistic".into(),
                rating: 14.0,
                trust_level: 0.2,
                circle_tier: CircleTier::New,
                trend: BehavioralTrend::RapidWorsening,
                is_trusted: false,
                is_new_contact: true,
                first_seen_ms: 1_000,
                last_seen_ms: 2_000,
                conversation_count: 1,
                grooming_event_count: 0,
                bullying_event_count: 0,
                manipulation_event_count: 0,
                total_threat_events: 0,
            }),
            reason_codes: vec![
                "conversation.grooming.stage_sequence".to_string(),
                "conversation.grooming.new_contact_flattery".to_string(),
            ],
            context_markers: vec![
                "context.relationship.new_contact".to_string(),
                "context.trajectory.repeated_sender".to_string(),
            ],
            context_summary: AnalysisContextSummary::from_markers(&[
                "context.relationship.new_contact".to_string(),
                "context.trajectory.repeated_sender".to_string(),
            ]),
            inference: InferenceSummary::default(),
            analysis_time_us: 420,
        }
    }

    #[test]
    fn shadow_mode_event_omits_plaintext_and_identifiers() {
        let event = build_shadow_mode_event(ShadowModeEventInput {
            request_id: "shadow_req_1",
            sequence: 1,
            timestamp_ms: 1_000,
            sender_id: "coach_realistic",
            conversation_id: "conv_secret",
            language: "uk",
            conversation_type: ConversationType::Direct,
            member_count: None,
            expectation: Some(ShadowModeExpectation {
                expect_threat: Some(ThreatType::Grooming),
                expect_min_action: Some(Action::Warn),
                expect_min_alert: Some(AlertPriority::High),
            }),
            protection_level: ProtectionLevel::High,
            result: &sample_result(),
        });

        let json = serde_json::to_string(&event).expect("serialize shadow mode event");
        assert!(!json.contains("coach_realistic"));
        assert!(!json.contains("conv_secret"));
        assert!(!json.contains("detected grooming pattern"));
        assert!(!json.contains("stage sequence"));
        assert_eq!(
            event.decision.product_surface.rollout_mode,
            ProductRolloutMode::Shadow
        );
        assert_eq!(
            event.decision.product_surface.child.delivery_mode,
            crate::ProductDeliveryMode::MirrorOnly
        );
        assert_eq!(
            event.decision.context_markers,
            vec![
                "context.relationship.new_contact".to_string(),
                "context.trajectory.repeated_sender".to_string(),
            ]
        );
    }

    #[test]
    fn shadow_mode_bundle_tracks_summary_without_raw_text() {
        let event = build_shadow_mode_event(ShadowModeEventInput {
            request_id: "shadow_req_1",
            sequence: 1,
            timestamp_ms: 1_000,
            sender_id: "coach_realistic",
            conversation_id: "conv_secret",
            language: "uk",
            conversation_type: ConversationType::Direct,
            member_count: None,
            expectation: None,
            protection_level: ProtectionLevel::High,
            result: &sample_result(),
        });
        let bundle = ShadowModeBundle::from_events(
            "world_sim",
            "demo",
            "crates/aura-core/data/world_sim_demo.json",
            "olena_owner",
            ProtectionLevel::High,
            vec![ShadowModeFinding {
                severity: "warning".to_string(),
                event_sequence: 1,
                request_id: "shadow_req_1".to_string(),
                timestamp_ms: 1_000,
                message: "expected threat did not match".to_string(),
            }],
            vec![event],
        );

        assert_eq!(bundle.summary.total_events, 1);
        assert_eq!(bundle.summary.threat_events, 1);
        assert_eq!(bundle.summary.finding_count, 1);
        assert!(!bundle.privacy.raw_text_present);
        assert!(!bundle.privacy.raw_identifier_fields_present);

        let json = serde_json::to_string(&bundle).expect("serialize shadow mode bundle");
        assert!(!json.contains("olena_owner"));
        assert!(!json.contains("coach_realistic"));
        assert!(!json.contains("conv_secret"));
    }

    #[test]
    fn shadow_mode_mirror_respects_context_softened_product_surface() {
        let mut result = sample_result();
        result.context_summary = AnalysisContextSummary {
            speech_act: crate::ContextSpeechAct::Quote,
            stance: crate::ContextStance::Oppose,
            filter_applied: true,
            ..AnalysisContextSummary::default()
        };
        result.context_markers = Vec::new();
        result.recommended_action.as_mut().unwrap().parent_alert = AlertPriority::None;

        let event = build_shadow_mode_event(ShadowModeEventInput {
            request_id: "shadow_req_2",
            sequence: 2,
            timestamp_ms: 2_000,
            sender_id: "coach_realistic",
            conversation_id: "conv_secret",
            language: "uk",
            conversation_type: ConversationType::Direct,
            member_count: None,
            expectation: None,
            protection_level: ProtectionLevel::High,
            result: &result,
        });

        assert!(event.decision.mirror.would_surface_to_child);
        assert!(!event.decision.mirror.would_alert_guardian);
        assert!(!event.decision.mirror.would_open_review);
        assert!(!event.decision.product_surface.guardian.notify);
        assert!(!event.decision.product_surface.review.open_review);
        assert_eq!(
            event.decision.context_markers,
            vec![
                "context.speech_act.quote".to_string(),
                "context.stance.oppose".to_string(),
                "context.filter.applied".to_string(),
            ]
        );
    }
}
