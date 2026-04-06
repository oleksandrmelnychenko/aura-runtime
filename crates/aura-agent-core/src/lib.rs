//! On-device Agent runtime for AURA.
//!
//! This crate is the first extraction step away from the mixed `aura-core`
//! runtime. For now it wraps the existing analyzer, but it already speaks in
//! terms of Agent/Relay contracts:
//!
//! - local analysis remains on device
//! - relay escalation is an explicit policy decision
//! - relay requests are built from typed shared contracts

// ── Transitional re-exports ─────────────────────────────────────────
// These allow downstream crates (aura-agent-ffi) to depend solely on
// aura-agent-core instead of reaching into aura-core directly.
// Types will migrate to their final homes (aura-contracts,
// aura-agent-policy) in subsequent phases.

pub use aura_core::action;
pub use aura_core::analyzer;
pub use aura_core::audit;
pub use aura_core::config;
pub use aura_core::context;
pub use aura_core::domain_runtime;
pub use aura_core::error;
pub use aura_core::ids;
pub use aura_core::pilot;
pub use aura_core::pilot_gate;
pub use aura_core::product;
pub use aura_core::types;

// Re-export the same root-level convenience aliases that aura-core provides.
pub use aura_core::{
    Action, AccountType, AlertPriority, AnalysisContextSummary, AnalysisMode,
    AnalysisResult, ActionRecommendation, AuraDomainModule, AuraDomainRuntime,
    AuraConfig, AuraError, Analyzer,
    BehavioralTrend, CircleTier, Confidence, ContactSnapshot, ContentType,
    ContextDirectionality, ContextReciprocity, ContextSpeechAct, ContextStance,
    ConversationTracker, ConversationType,
    DetectionLayer, DetectionSignal, DomainMode,
    FollowUpAction,
    InferenceSummary,
    LatentStateEvidence, LatentStateKind,
    MessageInput,
    ProtectionLevel,
    RiskBreakdown, RiskHorizon,
    SenderId, ConversationId, ReasonCode,
    SignalFamily,
    ThreatType,
    UiAction, UncertaintyLevel,
};

// Product surface
pub use aura_core::{
    build_product_decision_surface,
    ProductChildIntervention, ProductChildSurface, ProductDecisionSurface,
    ProductDeliveryMode, ProductGuardianSurface, ProductReviewSurface,
    ProductReviewUrgency, ProductRolloutMode, ProductUncertaintyDisposition,
    PRODUCT_DECISION_SURFACE_SCHEMA_VERSION,
};

// Audit
pub use aura_core::{
    AuditRecord, AuditThreatScore, ProtectedIdentifier,
    tokenize_identifier, current_salt_epoch, rotate_audit_salt,
    AUDIT_IDENTIFIER_SCHEME, AUDIT_SCHEMA_VERSION,
};

// Shadow / pilot
pub use aura_core::{
    build_shadow_mode_event,
    ShadowModeBundle, ShadowModeContactSummary, ShadowModeDecision,
    ShadowModeEvent, ShadowModeEventInput, ShadowModeExpectation,
    ShadowModeFinding, ShadowModeMirror, ShadowModePrivacy,
    ShadowModeSummary,
    SHADOW_MODE_BUNDLE_SCHEMA_VERSION, SHADOW_MODE_WIRE_PACKAGE,
};

// Re-export contracts for relay-aware consumers
pub use aura_contracts;

// Domain packs (transitional: FFI needs direct access to kids pipeline)
pub use aura_kids;

// ── Internal imports for this crate's own code ──────────────────────

use aura_contracts::{
    default_relay_schema_version,
    AgentAnalyzeRequest, AgentCapabilities, DetectionLayer as ContractDetectionLayer,
    LocalContextSummary, MessageWindowEntry,
    RawObservation, RelayPrivacyMode, RelationshipTag, SpeechAct, Stance, ThreatContextFrame,
    TrajectoryTag,
};
use aura_core::context::tracker::TrackerWireState;
use aura_patterns::PatternDatabase;

#[derive(Debug, Clone)]
pub struct AgentRelayPolicy {
    pub enabled: bool,
    pub score_threshold: f32,
    pub send_on_high_uncertainty: bool,
    pub send_on_new_contact: bool,
    pub send_on_repeated_sender: bool,
    pub privacy_mode: RelayPrivacyMode,
    pub max_recent_window_messages: usize,
    pub deadline_ms: Option<u32>,
}

impl Default for AgentRelayPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            score_threshold: 0.70,
            send_on_high_uncertainty: true,
            send_on_new_contact: true,
            send_on_repeated_sender: true,
            privacy_mode: RelayPrivacyMode::MessageOnly,
            max_recent_window_messages: 0,
            deadline_ms: Some(300),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentAnalysisEnvelope {
    pub local_result: AnalysisResult,
    pub relay_request: Option<AgentAnalyzeRequest>,
}

pub struct AgentRuntime {
    analyzer: Analyzer,
    relay_policy: AgentRelayPolicy,
}

impl AgentRuntime {
    pub fn new(config: AuraConfig, pattern_db: &PatternDatabase) -> Self {
        Self {
            analyzer: Analyzer::new(config, pattern_db),
            relay_policy: AgentRelayPolicy::default(),
        }
    }

    pub fn with_relay_policy(mut self, relay_policy: AgentRelayPolicy) -> Self {
        self.relay_policy = relay_policy;
        self
    }

    pub fn relay_policy(&self) -> &AgentRelayPolicy {
        &self.relay_policy
    }

    pub fn relay_policy_mut(&mut self) -> &mut AgentRelayPolicy {
        &mut self.relay_policy
    }

    pub fn analyze_local(&mut self, input: &MessageInput) -> AnalysisResult {
        self.analyzer.analyze(input)
    }

    pub fn analyze_local_with_context(
        &mut self,
        input: &MessageInput,
        timestamp_ms: u64,
    ) -> AnalysisResult {
        self.analyzer.analyze_with_context(input, timestamp_ms)
    }

    pub fn analyze_for_relay(
        &mut self,
        input: &MessageInput,
        timestamp_ms: u64,
    ) -> AgentAnalysisEnvelope {
        let local_result = self.analyze_local_with_context(input, timestamp_ms);
        let relay_request = self
            .should_query_relay(&local_result)
            .then(|| self.build_relay_request(input, timestamp_ms, &local_result));

        AgentAnalysisEnvelope {
            local_result,
            relay_request,
        }
    }

    pub fn build_relay_request(
        &self,
        input: &MessageInput,
        timestamp_ms: u64,
        local_result: &AnalysisResult,
    ) -> AgentAnalyzeRequest {
        let local_observations = local_result
            .signals
            .iter()
            .map(map_detection_signal)
            .collect();
        let local_context = local_result
            .context_summary
            .is_meaningful()
            .then(|| map_context_summary(&local_result.context_summary));

        AgentAnalyzeRequest {
            schema_version: default_relay_schema_version(),
            request_id: format!(
                "{}:{}:{}",
                input.conversation_id.as_ref(),
                input.sender_id.as_ref(),
                timestamp_ms
            ),
            message_id: format!(
                "{}:{}",
                input.conversation_id.as_ref(),
                timestamp_ms
            ),
            account_type: self.analyzer_config_account_type(),
            protection_level: self.analyzer.protection_level(),
            conversation_type: input.conversation_type,
            language: input.language.clone(),
            text: input.text.clone().unwrap_or_default(),
            local_observations,
            local_context,
            local_context_summary: LocalContextSummary {
                context_markers: local_result.context_markers.clone(),
                recent_observations: Vec::new(),
                recent_confirmed_events: Vec::new(),
            },
            recent_message_window: bounded_recent_window(
                self.relay_policy.max_recent_window_messages,
                timestamp_ms,
            ),
            server_sender_risk_hint: input.server_sender_risk_hint,
            privacy_mode: self.relay_policy.privacy_mode,
            capabilities: AgentCapabilities {
                local_context_interpreter: true,
                local_tracker: true,
                supports_remote_correlation: true,
                relay_timeout_ms: self.relay_policy.deadline_ms,
            },
            deadline_ms: self.relay_policy.deadline_ms,
        }
    }

    pub fn should_query_relay(&self, local_result: &AnalysisResult) -> bool {
        if !self.relay_policy.enabled {
            return false;
        }

        if local_result.score >= self.relay_policy.score_threshold {
            return true;
        }

        if self.relay_policy.send_on_high_uncertainty
            && local_result.inference.uncertainty == aura_core::UncertaintyLevel::High
        {
            return true;
        }

        if self.relay_policy.send_on_new_contact && local_result.context_summary.relationship.is_new_contact
        {
            return true;
        }

        if self.relay_policy.send_on_repeated_sender
            && local_result.context_summary.trajectory.repeated_by_sender
        {
            return true;
        }

        needs_relay_due_to_inference(&local_result.inference)
    }

    pub fn protection_level(&self) -> ProtectionLevel {
        self.analyzer.protection_level()
    }

    pub fn context_tracker(&self) -> &aura_core::ConversationTracker {
        self.analyzer.context_tracker()
    }

    pub fn export_context_state(&self) -> TrackerWireState {
        self.analyzer.export_context_state()
    }

    pub fn import_context_state(
        &mut self,
        state: TrackerWireState,
    ) -> Result<(), aura_core::AuraError> {
        self.analyzer.import_context_state(state)
    }

    pub fn cleanup_context(&mut self, now_ms: u64) {
        self.analyzer.cleanup_context(now_ms);
    }

    pub fn mark_contact_trusted(&mut self, sender_id: &str) {
        self.analyzer.mark_contact_trusted(sender_id);
    }

    pub fn update_config(&mut self, config: AuraConfig, pattern_db: &PatternDatabase) {
        self.analyzer.update_config(config, pattern_db);
    }

    pub fn reload_patterns(&mut self, pattern_db: &PatternDatabase) {
        self.analyzer.reload_patterns(pattern_db);
    }

    fn analyzer_config_account_type(&self) -> AccountType {
        match self.analyzer.protection_level() {
            ProtectionLevel::High => AccountType::Child,
            ProtectionLevel::Medium | ProtectionLevel::Low | ProtectionLevel::Off => {
                AccountType::Adult
            }
        }
    }
}

fn bounded_recent_window(max_messages: usize, timestamp_ms: u64) -> Vec<MessageWindowEntry> {
    if max_messages == 0 {
        return Vec::new();
    }

    vec![MessageWindowEntry {
        sender_id: "current_sender".to_string(),
        text: String::new(),
        timestamp_ms,
    }]
}

fn needs_relay_due_to_inference(inference: &InferenceSummary) -> bool {
    inference.escalation_likelihood_24h >= 0.75
        || matches!(inference.risk_horizon, RiskHorizon::Immediate | RiskHorizon::ShortTerm)
}

fn map_detection_layer(value: DetectionLayer) -> ContractDetectionLayer {
    match value {
        DetectionLayer::PatternMatching => ContractDetectionLayer::PatternMatching,
        DetectionLayer::MlClassification => ContractDetectionLayer::MlClassification,
        DetectionLayer::ContextAnalysis => ContractDetectionLayer::ContextAnalysis,
    }
}

fn map_detection_signal(signal: &aura_core::DetectionSignal) -> RawObservation {
    RawObservation {
        threat_type: signal.threat_type,
        threat_subtype: signal.threat_subtype.clone(),
        layer: map_detection_layer(signal.layer),
        score: signal.score,
        confidence: signal.confidence,
        reason_code: signal.reason_code.clone(),
        explanation: signal.explanation.clone(),
    }
}

fn map_context_summary(summary: &AnalysisContextSummary) -> ThreatContextFrame {
    let speech_act = match summary.speech_act {
        ContextSpeechAct::Unknown => SpeechAct::Assert,
        ContextSpeechAct::Assert => SpeechAct::Assert,
        ContextSpeechAct::Ask => SpeechAct::Ask,
        ContextSpeechAct::Quote => SpeechAct::Quote,
        ContextSpeechAct::Report => SpeechAct::Report,
        ContextSpeechAct::Counter => SpeechAct::Counter,
        ContextSpeechAct::Support => SpeechAct::Support,
        ContextSpeechAct::Solicit => SpeechAct::Solicit,
    };

    let stance = match summary.stance {
        ContextStance::Unknown => Stance::Ambiguous,
        ContextStance::Endorse => Stance::Endorse,
        ContextStance::Oppose => Stance::Oppose,
        ContextStance::Neutral => Stance::Neutral,
        ContextStance::Ambiguous => Stance::Ambiguous,
    };

    let directionality = match summary.directionality {
        ContextDirectionality::Unknown => aura_contracts::Directionality::Unknown,
        ContextDirectionality::DirectedAtUser => aura_contracts::Directionality::DirectedAtUser,
        ContextDirectionality::SelfReferential => aura_contracts::Directionality::SelfReferential,
        ContextDirectionality::ThirdParty => aura_contracts::Directionality::ThirdParty,
        ContextDirectionality::Broadcast => aura_contracts::Directionality::Broadcast,
    };

    let mut relationship = Vec::new();
    if summary.relationship.is_new_contact {
        relationship.push(RelationshipTag::NewContact);
    }
    if summary.relationship.is_trusted {
        relationship.push(RelationshipTag::Trusted);
    }

    let mut trajectory = Vec::new();
    if summary.trajectory.repeated_by_sender {
        trajectory.push(TrajectoryTag::RepeatedSender);
    }
    if summary.trajectory.escalating {
        trajectory.push(TrajectoryTag::Escalating);
    }
    if summary.trajectory.cross_conversation {
        trajectory.push(TrajectoryTag::CrossConversation);
    }
    if summary.trajectory.bursty {
        trajectory.push(TrajectoryTag::Bursty);
    }

    let _ = ContextReciprocity::Unknown;

    ThreatContextFrame {
        speech_act,
        stance,
        directionality,
        relationship,
        trajectory,
        confidence: summary.confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_core::{ContentType, ConversationType};

    fn make_input(text: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: "sender_1".into(),
            conversation_id: "conv_1".into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            server_sender_risk_hint: Some(0.2),
        }
    }

    #[test]
    fn relay_request_is_emitted_for_high_risk_local_result() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let mut runtime = AgentRuntime::new(config, &pattern_db).with_relay_policy(
            AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.5,
                ..AgentRelayPolicy::default()
            },
        );

        let envelope = runtime.analyze_for_relay(
            &make_input("i will kill you"),
            1_700_000_000_000,
        );

        assert!(envelope.local_result.score > 0.0);
        assert!(envelope.relay_request.is_some());
    }

    #[test]
    fn relay_request_contains_local_observations() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let mut runtime = AgentRuntime::new(config, &pattern_db).with_relay_policy(
            AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.01,
                ..AgentRelayPolicy::default()
            },
        );

        let input = make_input("i will kill you");
        let local_result = runtime.analyze_local_with_context(&input, 123);
        let request = runtime.build_relay_request(&input, 123, &local_result);

        assert_eq!(request.schema_version, aura_contracts::AURA_RELAY_SCHEMA_VERSION);
        assert!(!request.local_observations.is_empty());
        assert_eq!(request.text, "i will kill you");
    }
}
