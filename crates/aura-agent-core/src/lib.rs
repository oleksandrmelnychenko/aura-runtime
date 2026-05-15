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
    AccountType, Action, ActionRecommendation, AlertPriority, AnalysisContextSummary, AnalysisMode,
    AnalysisResult, Analyzer, AuraConfig, AuraDomainModule, AuraDomainRuntime, AuraError,
    BehavioralTrend, CircleTier, Confidence, ContactSnapshot, ContentType, ContextDirectionality,
    ContextReciprocity, ContextSpeechAct, ContextStance, ConversationId, ConversationTracker,
    ConversationType, DetectionLayer, DetectionSignal, DomainMode, FollowUpAction,
    InferenceSummary, LatentStateEvidence, LatentStateKind, MessageInput, ProtectionLevel,
    ReasonCode, RiskBreakdown, RiskHorizon, SenderId, SignalFamily, ThreatType, UiAction,
    UncertaintyLevel,
};

// Product surface
pub use aura_core::{
    build_product_decision_surface, ProductChildIntervention, ProductChildSurface,
    ProductDecisionSurface, ProductDeliveryMode, ProductGuardianSurface, ProductReviewSurface,
    ProductReviewUrgency, ProductRolloutMode, ProductUncertaintyDisposition,
    PRODUCT_DECISION_SURFACE_SCHEMA_VERSION,
};

// Audit
pub use aura_core::{
    current_salt_epoch, rotate_audit_salt, tokenize_identifier, AuditRecord, AuditThreatScore,
    ProtectedIdentifier, AUDIT_IDENTIFIER_SCHEME, AUDIT_SCHEMA_VERSION,
};

// Shadow / pilot
pub use aura_core::{
    build_shadow_mode_event, ShadowModeBundle, ShadowModeContactSummary, ShadowModeDecision,
    ShadowModeEvent, ShadowModeEventInput, ShadowModeExpectation, ShadowModeFinding,
    ShadowModeMirror, ShadowModePrivacy, ShadowModeSummary, SHADOW_MODE_BUNDLE_SCHEMA_VERSION,
    SHADOW_MODE_WIRE_PACKAGE,
};

// Re-export contracts for relay-aware consumers
pub use aura_contracts;

// Domain packs (transitional: FFI needs direct access to kids pipeline)
pub use aura_kids;

// ── Internal imports for this crate's own code ──────────────────────

use std::collections::HashMap;

use aura_contracts::{
    default_relay_schema_version, sign_relay_request_auth, verify_relay_response_auth,
    AgentAnalyzeRequest, AgentCapabilities, ClientSafetyTelemetryEvent,
    DetectionLayer as ContractDetectionLayer, LocalContextSummary, MessageWindowEntry,
    ProtectedAccountTokenAttestation, RawObservation, RelayAnalyzeResponse, RelayPrivacyMode,
    SafetyTelemetryAction, SafetyTelemetrySeverity, SafetyTelemetrySurface,
};
use aura_core::context::tracker::TrackerWireState;
use aura_patterns::PatternDatabase;

const DEFAULT_RELAY_SENDER_HINT_TTL_MS: u64 = 6 * 60 * 60 * 1_000;
const DEFAULT_PENDING_RELAY_RESPONSE_TTL_MS: u64 = 5 * 60 * 1_000;
const MAX_PENDING_RELAY_REQUESTS: usize = 1024;

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
    pub emit_local_safety_telemetry: bool,
    pub protected_account_id: Option<String>,
    pub protected_account_attestation: Option<ProtectedAccountTokenAttestation>,
    pub require_protected_account_attestation: bool,
    pub require_relay_auth: bool,
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
            emit_local_safety_telemetry: true,
            protected_account_id: None,
            protected_account_attestation: None,
            require_protected_account_attestation: false,
            require_relay_auth: false,
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
    relay_sender_hints: HashMap<SenderId, CachedRelaySenderHint>,
    pending_relay_requests: HashMap<String, PendingRelayRequest>,
    relay_request_auth_key: Option<RelayRequestAuthKey>,
    relay_response_auth_keys: Vec<RelayResponseAuthKey>,
}

#[derive(Debug, Clone)]
pub struct RelayRequestAuthKey {
    pub key_id: String,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RelayResponseAuthKey {
    pub key_id: String,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CachedRelaySenderHint {
    hint: f32,
    expires_at_ms: u64,
}

#[derive(Debug, Clone)]
struct PendingRelayRequest {
    sender_id: SenderId,
    sender_token: Option<String>,
    expires_at_ms: u64,
}

impl AgentRuntime {
    pub fn new(config: AuraConfig, pattern_db: &PatternDatabase) -> Self {
        Self {
            analyzer: Analyzer::new(config, pattern_db),
            relay_policy: AgentRelayPolicy::default(),
            relay_sender_hints: HashMap::new(),
            pending_relay_requests: HashMap::new(),
            relay_request_auth_key: None,
            relay_response_auth_keys: Vec::new(),
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

    pub fn set_protected_account_attestation(
        &mut self,
        attestation: ProtectedAccountTokenAttestation,
    ) {
        self.relay_policy.protected_account_attestation = Some(attestation);
    }

    pub fn clear_protected_account_attestation(&mut self) {
        self.relay_policy.protected_account_attestation = None;
    }

    pub fn with_relay_request_auth_key(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.set_relay_request_auth_key(key_id, secret);
        self
    }

    pub fn set_relay_request_auth_key(
        &mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) {
        self.relay_request_auth_key = Some(RelayRequestAuthKey {
            key_id: key_id.into(),
            secret: secret.into(),
        });
    }

    pub fn clear_relay_request_auth_key(&mut self) {
        self.relay_request_auth_key = None;
    }

    pub fn with_relay_response_auth_key(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.set_relay_response_auth_key(key_id, secret);
        self
    }

    pub fn set_relay_response_auth_key(
        &mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) {
        self.relay_response_auth_keys = vec![RelayResponseAuthKey {
            key_id: key_id.into(),
            secret: secret.into(),
        }];
    }

    pub fn set_relay_response_auth_keys(&mut self, keys: Vec<RelayResponseAuthKey>) {
        self.relay_response_auth_keys = keys;
    }

    pub fn add_accepted_relay_response_auth_key(
        &mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) {
        self.relay_response_auth_keys.push(RelayResponseAuthKey {
            key_id: key_id.into(),
            secret: secret.into(),
        });
    }

    pub fn clear_relay_response_auth_key(&mut self) {
        self.relay_response_auth_keys.clear();
    }

    pub fn analyze_local(&mut self, input: &MessageInput) -> AnalysisResult {
        let now_ms = current_unix_ms();
        let input = self.input_with_cached_relay_hint(input, now_ms);
        self.analyzer.analyze(&input)
    }

    pub fn analyze_local_with_context(
        &mut self,
        input: &MessageInput,
        timestamp_ms: u64,
    ) -> AnalysisResult {
        let input = self.input_with_cached_relay_hint(input, timestamp_ms);
        self.analyzer.analyze_with_context(&input, timestamp_ms)
    }

    pub fn analyze_for_relay(
        &mut self,
        input: &MessageInput,
        timestamp_ms: u64,
    ) -> AgentAnalysisEnvelope {
        let input = self.input_with_cached_relay_hint(input, timestamp_ms);
        let local_result = self.analyzer.analyze_with_context(&input, timestamp_ms);
        let relay_request = if self.should_query_relay(&local_result) {
            let request = self.build_relay_request(&input, timestamp_ms, &local_result);
            if self.relay_policy.require_protected_account_attestation
                && request.protected_account_attestation.is_none()
            {
                return AgentAnalysisEnvelope {
                    local_result,
                    relay_request: None,
                };
            }
            self.remember_pending_relay_request(&input.sender_id, &request, timestamp_ms);
            Some(request)
        } else {
            None
        };

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
            .map(|signal| map_detection_signal(signal, self.relay_policy.privacy_mode))
            .collect();
        let text = match self.relay_policy.privacy_mode {
            RelayPrivacyMode::MetadataOnly => String::new(),
            RelayPrivacyMode::MessageOnly | RelayPrivacyMode::MessageAndWindow => {
                input.text.clone().unwrap_or_default()
            }
        };
        let protected_account_token = self
            .relay_policy
            .protected_account_id
            .as_deref()
            .map(|account_id| prefixed_token("acct", account_id));

        let mut request = AgentAnalyzeRequest {
            schema_version: default_relay_schema_version(),
            request_id: prefixed_token(
                "req",
                &format!(
                    "{}:{}:{}",
                    input.conversation_id.as_ref(),
                    input.sender_id.as_ref(),
                    timestamp_ms
                ),
            ),
            message_id: prefixed_token(
                "msg",
                &format!("{}:{}", input.conversation_id.as_ref(), timestamp_ms),
            ),
            sender_token: Some(prefixed_token("snd", input.sender_id.as_ref())),
            protected_account_token: protected_account_token.clone(),
            conversation_token: Some(prefixed_token("conv", input.conversation_id.as_ref())),
            account_type: self.analyzer_config_account_type(),
            protection_level: self.analyzer.protection_level(),
            conversation_type: input.conversation_type,
            language: input.language.clone(),
            text,
            local_observations,
            // The current protobuf relay request carries the summary markers,
            // not the typed context frame. Keep signed requests wire-stable.
            local_context: None,
            local_context_summary: LocalContextSummary {
                context_markers: local_result.context_markers.clone(),
                recent_observations: Vec::new(),
                recent_confirmed_events: Vec::new(),
            },
            local_safety_telemetry: self.build_local_safety_telemetry(
                input,
                timestamp_ms,
                local_result,
            ),
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
            protected_account_attestation: self.protected_account_attestation_for_request(
                protected_account_token.as_deref(),
                timestamp_ms,
            ),
            auth: None,
        };
        self.sign_relay_request_if_configured(&mut request);
        request
    }

    fn sign_relay_request_if_configured(&self, request: &mut AgentAnalyzeRequest) {
        let Some(key) = self.relay_request_auth_key.as_ref() else {
            return;
        };
        request.auth = sign_relay_request_auth(request, &key.key_id, &key.secret);
    }

    fn protected_account_attestation_for_request(
        &self,
        protected_account_token: Option<&str>,
        timestamp_ms: u64,
    ) -> Option<ProtectedAccountTokenAttestation> {
        let protected_account_token = protected_account_token?;
        let attestation = self.relay_policy.protected_account_attestation.as_ref()?;
        if attestation.protected_account_token == protected_account_token
            && attestation.expires_at_ms > timestamp_ms
        {
            Some(attestation.clone())
        } else {
            None
        }
    }

    fn build_local_safety_telemetry(
        &self,
        input: &MessageInput,
        timestamp_ms: u64,
        local_result: &AnalysisResult,
    ) -> Vec<ClientSafetyTelemetryEvent> {
        if !self.relay_policy.emit_local_safety_telemetry
            || local_result.threat_type == ThreatType::None
            || local_result.score <= 0.0
        {
            return Vec::new();
        }

        let Some(protected_account_id) = self.relay_policy.protected_account_id.as_deref() else {
            return Vec::new();
        };

        let event_source = format!(
            "{}:{}:{}",
            input.conversation_id.as_ref(),
            input.sender_id.as_ref(),
            timestamp_ms
        );
        let event = ClientSafetyTelemetryEvent {
            event_id: prefixed_token("evt", &event_source),
            sender_token: prefixed_token("snd", input.sender_id.as_ref()),
            protected_account_token: prefixed_token("acct", protected_account_id),
            conversation_token: Some(prefixed_token("conv", input.conversation_id.as_ref())),
            surface: map_safety_surface(input.conversation_type),
            threat_type: local_result.threat_type,
            severity: map_safety_severity(local_result.score, local_result.action),
            confidence: local_result.confidence,
            action: map_safety_action(local_result.action),
            timestamp_bucket_ms: timestamp_ms - (timestamp_ms % 3_600_000),
            reason_family: safety_reason_family(local_result.threat_type).map(str::to_string),
        };

        event.privacy_safe().then_some(event).into_iter().collect()
    }

    pub fn record_relay_response_for_sender(
        &mut self,
        sender_id: &SenderId,
        response: &RelayAnalyzeResponse,
        received_at_ms: u64,
    ) -> bool {
        let Some(pending) =
            self.matching_pending_relay_request(sender_id, &response.request_id, received_at_ms)
        else {
            return false;
        };

        if !self.relay_response_auth_valid(response, &pending) {
            return false;
        }

        let Some(hint) = sanitize_sender_reputation_hint(response.sender_reputation_hint) else {
            return false;
        };
        let expires_at_ms = response
            .expires_at_ms
            .unwrap_or_else(|| received_at_ms.saturating_add(DEFAULT_RELAY_SENDER_HINT_TTL_MS));
        if expires_at_ms <= received_at_ms {
            self.relay_sender_hints.remove(sender_id);
            return false;
        }

        self.pending_relay_requests.remove(&response.request_id);
        self.relay_sender_hints.insert(
            sender_id.clone(),
            CachedRelaySenderHint {
                hint,
                expires_at_ms,
            },
        );
        true
    }

    pub fn relay_sender_hint(&self, sender_id: &SenderId, now_ms: u64) -> Option<f32> {
        self.relay_sender_hints
            .get(sender_id)
            .filter(|hint| hint.expires_at_ms > now_ms)
            .map(|hint| hint.hint)
    }

    pub fn cleanup_relay_hints(&mut self, now_ms: u64) {
        self.relay_sender_hints
            .retain(|_, hint| hint.expires_at_ms > now_ms);
        self.cleanup_pending_relay_requests(now_ms);
    }

    fn remember_pending_relay_request(
        &mut self,
        sender_id: &SenderId,
        request: &AgentAnalyzeRequest,
        requested_at_ms: u64,
    ) {
        if request.request_id.trim().is_empty() {
            return;
        }
        self.cleanup_pending_relay_requests(requested_at_ms);
        if self.pending_relay_requests.len() >= MAX_PENDING_RELAY_REQUESTS {
            if let Some(oldest_request_id) = self
                .pending_relay_requests
                .iter()
                .min_by_key(|(_, pending)| pending.expires_at_ms)
                .map(|(request_id, _)| request_id.clone())
            {
                self.pending_relay_requests.remove(&oldest_request_id);
            }
        }

        self.pending_relay_requests.insert(
            request.request_id.clone(),
            PendingRelayRequest {
                sender_id: sender_id.clone(),
                sender_token: request.privacy_safe_sender_token().map(str::to_string),
                expires_at_ms: requested_at_ms
                    .saturating_add(DEFAULT_PENDING_RELAY_RESPONSE_TTL_MS),
            },
        );
    }

    fn matching_pending_relay_request(
        &mut self,
        sender_id: &SenderId,
        request_id: &str,
        received_at_ms: u64,
    ) -> Option<PendingRelayRequest> {
        self.cleanup_pending_relay_requests(received_at_ms);
        if request_id.trim().is_empty() {
            return None;
        }
        let Some(pending) = self.pending_relay_requests.get(request_id) else {
            return None;
        };
        (pending.sender_id == *sender_id && pending.expires_at_ms > received_at_ms)
            .then(|| pending.clone())
    }

    fn relay_response_auth_valid(
        &self,
        response: &RelayAnalyzeResponse,
        pending: &PendingRelayRequest,
    ) -> bool {
        if self.relay_response_auth_keys.is_empty() {
            return true;
        }
        let Some(sender_token) = pending.sender_token.as_deref() else {
            return false;
        };
        self.relay_response_auth_keys
            .iter()
            .any(|key| verify_relay_response_auth(response, sender_token, &key.key_id, &key.secret))
    }

    fn cleanup_pending_relay_requests(&mut self, now_ms: u64) {
        self.pending_relay_requests
            .retain(|_, pending| pending.expires_at_ms > now_ms);
    }

    fn input_with_cached_relay_hint(&self, input: &MessageInput, now_ms: u64) -> MessageInput {
        let direct_hint = sanitize_sender_reputation_hint(input.server_sender_risk_hint);
        let cached_hint = self.relay_sender_hint(&input.sender_id, now_ms);
        let effective_hint = match (direct_hint, cached_hint) {
            (Some(direct), Some(cached)) => Some(direct.max(cached)),
            (Some(direct), None) => Some(direct),
            (None, Some(cached)) => Some(cached),
            (None, None) => None,
        };

        if effective_hint == input.server_sender_risk_hint {
            return input.clone();
        }

        let mut input = input.clone();
        input.server_sender_risk_hint = effective_hint;
        input
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

        if self.relay_policy.send_on_new_contact
            && local_result.context_summary.relationship.is_new_contact
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

    pub fn export_kids_memory_state(&self) -> aura_kids::pipeline::ExportedKidsMemoryState {
        self.analyzer.export_kids_memory_state()
    }

    pub fn import_context_state(
        &mut self,
        state: TrackerWireState,
    ) -> Result<(), aura_core::AuraError> {
        self.analyzer.import_context_state(state)
    }

    pub fn import_kids_memory_state(
        &mut self,
        state: &aura_kids::pipeline::ExportedKidsMemoryState,
    ) {
        self.analyzer.import_kids_memory_state(state);
    }

    pub fn clear_kids_memory_state(&mut self) {
        self.analyzer.clear_kids_memory_state();
    }

    pub fn cleanup_context(&mut self, now_ms: u64) {
        self.analyzer.cleanup_context(now_ms);
        self.cleanup_relay_hints(now_ms);
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

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn sanitize_sender_reputation_hint(value: Option<f32>) -> Option<f32> {
    let value = value?;
    value.is_finite().then(|| value.clamp(0.0, 1.0))
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
        || matches!(
            inference.risk_horizon,
            RiskHorizon::Immediate | RiskHorizon::ShortTerm
        )
}

fn prefixed_token(prefix: &str, raw_identifier: &str) -> String {
    format!("{prefix}_{}", tokenize_identifier(raw_identifier).token)
}

fn map_safety_surface(conversation_type: ConversationType) -> SafetyTelemetrySurface {
    match conversation_type {
        ConversationType::Direct => SafetyTelemetrySurface::DirectMessage,
        ConversationType::Group => SafetyTelemetrySurface::GroupChat,
    }
}

fn map_safety_action(action: Action) -> SafetyTelemetryAction {
    match action {
        Action::Allow => SafetyTelemetryAction::None,
        Action::Mark => SafetyTelemetryAction::Mark,
        Action::Blur => SafetyTelemetryAction::Blur,
        Action::Warn => SafetyTelemetryAction::Warn,
        Action::Block => SafetyTelemetryAction::Block,
    }
}

fn map_safety_severity(score: f32, action: Action) -> SafetyTelemetrySeverity {
    if action == Action::Block || score >= 0.9 {
        SafetyTelemetrySeverity::Critical
    } else if matches!(action, Action::Warn | Action::Blur) || score >= 0.7 {
        SafetyTelemetrySeverity::High
    } else if action == Action::Mark || score >= 0.4 {
        SafetyTelemetrySeverity::Medium
    } else {
        SafetyTelemetrySeverity::Low
    }
}

fn safety_reason_family(threat_type: ThreatType) -> Option<&'static str> {
    match threat_type {
        ThreatType::None => None,
        ThreatType::Bullying => Some("bullying"),
        ThreatType::Grooming => Some("grooming"),
        ThreatType::Explicit => Some("explicit"),
        ThreatType::Threat => Some("threat"),
        ThreatType::SelfHarm => Some("self_harm"),
        ThreatType::Spam => Some("spam"),
        ThreatType::Scam => Some("scam"),
        ThreatType::Phishing => Some("phishing"),
        ThreatType::Manipulation => Some("manipulation"),
        ThreatType::Nsfw => Some("nsfw"),
        ThreatType::HateSpeech => Some("hate_speech"),
        ThreatType::Doxxing => Some("doxxing"),
        ThreatType::PiiLeakage => Some("pii_leakage"),
        ThreatType::Propaganda => Some("propaganda"),
        ThreatType::OpsecViolation => Some("opsec_violation"),
        ThreatType::Psyops => Some("psyops"),
        ThreatType::MilitarySocialEng => Some("military_social_eng"),
        ThreatType::CoordinateLeak => Some("coordinate_leak"),
    }
}

fn map_detection_layer(value: DetectionLayer) -> ContractDetectionLayer {
    match value {
        DetectionLayer::PatternMatching => ContractDetectionLayer::PatternMatching,
        DetectionLayer::MlClassification => ContractDetectionLayer::MlClassification,
        DetectionLayer::ContextAnalysis => ContractDetectionLayer::ContextAnalysis,
    }
}

fn map_detection_signal(
    signal: &aura_core::DetectionSignal,
    privacy_mode: RelayPrivacyMode,
) -> RawObservation {
    RawObservation {
        threat_type: signal.threat_type,
        threat_subtype: signal.threat_subtype.clone(),
        layer: map_detection_layer(signal.layer),
        score: signal.score,
        confidence: signal.confidence,
        reason_code: signal.reason_code.clone(),
        explanation: match privacy_mode {
            RelayPrivacyMode::MetadataOnly => String::new(),
            RelayPrivacyMode::MessageOnly | RelayPrivacyMode::MessageAndWindow => {
                signal.explanation.clone()
            }
        },
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

    fn make_child_input(text: &str, sender_id: &str, conversation_id: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: sender_id.into(),
            conversation_id: conversation_id.into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            server_sender_risk_hint: None,
        }
    }

    fn child_kids_config() -> AuraConfig {
        AuraConfig {
            account_type: AccountType::Child,
            protection_level: ProtectionLevel::High,
            domain_mode: DomainMode::Kids,
            language: "en".to_string(),
            ..AuraConfig::default()
        }
    }

    #[test]
    fn relay_request_is_emitted_for_high_risk_local_result() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let mut runtime =
            AgentRuntime::new(config, &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.5,
                ..AgentRelayPolicy::default()
            });

        let envelope = runtime.analyze_for_relay(&make_input("i will kill you"), 1_700_000_000_000);

        assert!(envelope.local_result.score > 0.0);
        assert!(envelope.relay_request.is_some());
    }

    #[test]
    fn kids_domain_memory_exports_and_imports_with_agent_runtime_state() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = child_kids_config();
        let mut runtime = AgentRuntime::new(config.clone(), &pattern_db);
        let seed = make_child_input(
            "our little secret. don't tell your parents.",
            "runtime_memory_sender",
            "runtime_memory_conv",
        );
        let followup = make_child_input(
            "you can only trust me. do it now or i post everything.",
            "runtime_memory_sender",
            "runtime_memory_conv",
        );

        let _ = runtime.analyze_local_with_context(&seed, 1_778_652_000_000);
        let core_state = runtime.export_context_state();
        let kids_state = runtime.export_kids_memory_state();
        assert!(
            !kids_state.conversations.is_empty(),
            "agent runtime should export instance-owned kids memory"
        );

        let mut restored = AgentRuntime::new(config, &pattern_db);
        restored
            .import_context_state(core_state)
            .expect("core context should import");
        restored.import_kids_memory_state(&kids_state);

        let result = restored.analyze_local_with_context(&followup, 1_778_652_045_000);

        assert!(
            result
                .reason_codes
                .iter()
                .any(|code| code == "domain.kids.memory.grooming_progression"),
            "imported kids memory should affect post-restore analysis, got {:?}",
            result.reason_codes
        );
    }

    #[test]
    fn relay_request_contains_local_observations() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let mut runtime =
            AgentRuntime::new(config, &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.01,
                ..AgentRelayPolicy::default()
            });

        let input = make_input("i will kill you");
        let local_result = runtime.analyze_local_with_context(&input, 123);
        let request = runtime.build_relay_request(&input, 123, &local_result);

        assert_eq!(
            request.schema_version,
            aura_contracts::AURA_RELAY_SCHEMA_VERSION
        );
        assert!(!request.local_observations.is_empty());
        assert_eq!(request.text, "i will kill you");
        assert!(request.local_safety_telemetry.is_empty());
        assert!(request.request_id.starts_with("req_"));
        assert!(request.message_id.starts_with("msg_"));
        assert!(request
            .sender_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("snd_"));
        assert!(request
            .conversation_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("conv_"));
        assert!(!request.request_id.contains("sender_1"));
        assert!(!request.message_id.contains("conv_1"));
        assert_ne!(request.sender_token.as_deref(), Some("sender_1"));
        assert_ne!(request.conversation_token.as_deref(), Some("conv_1"));
    }

    #[test]
    fn relay_request_emits_privacy_safe_local_safety_telemetry_when_configured() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let mut runtime =
            AgentRuntime::new(config, &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.01,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                ..AgentRelayPolicy::default()
            });

        let input = make_input("i will kill you");
        let local_result = runtime.analyze_local_with_context(&input, 1_700_000_123_456);
        let request = runtime.build_relay_request(&input, 1_700_000_123_456, &local_result);

        assert!(request.text.is_empty());
        assert!(!request.local_observations.is_empty());
        assert!(request
            .local_observations
            .iter()
            .all(|observation| observation.explanation.is_empty()));
        assert!(request.request_id.starts_with("req_"));
        assert!(request.message_id.starts_with("msg_"));
        assert!(request
            .sender_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("snd_"));
        assert!(request
            .protected_account_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("acct_"));
        assert!(request
            .conversation_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("conv_"));
        assert!(!request.request_id.contains("sender_1"));
        assert!(!request.message_id.contains("conv_1"));
        assert_ne!(request.sender_token.as_deref(), Some("sender_1"));
        assert_ne!(
            request.protected_account_token.as_deref(),
            Some("child_account_1")
        );
        assert_ne!(request.conversation_token.as_deref(), Some("conv_1"));
        assert_eq!(request.local_safety_telemetry.len(), 1);
        let telemetry = &request.local_safety_telemetry[0];
        assert!(telemetry.privacy_safe());
        assert!(telemetry.event_id.starts_with("evt_"));
        assert!(telemetry.sender_token.starts_with("snd_"));
        assert!(telemetry.protected_account_token.starts_with("acct_"));
        assert!(telemetry
            .conversation_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("conv_"));
        assert_eq!(telemetry.surface, SafetyTelemetrySurface::DirectMessage);
        assert_eq!(telemetry.threat_type, local_result.threat_type);
        assert_eq!(
            telemetry.timestamp_bucket_ms,
            1_700_000_123_456 - (1_700_000_123_456 % 3_600_000)
        );
        assert_ne!(telemetry.sender_token, "sender_1");
        assert_ne!(telemetry.protected_account_token, "child_account_1");
    }

    #[test]
    fn relay_request_includes_subject_tokens_even_without_safety_telemetry() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let mut runtime =
            AgentRuntime::new(config, &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.0,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                emit_local_safety_telemetry: true,
                ..AgentRelayPolicy::default()
            });

        let envelope = runtime.analyze_for_relay(&make_input("hello there"), 1_700_000_123_456);
        let request = envelope
            .relay_request
            .expect("relay request should be emitted");

        assert_eq!(request.local_safety_telemetry.len(), 0);
        assert!(request.text.is_empty());
        assert!(request
            .sender_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("snd_"));
        assert!(request
            .protected_account_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("acct_"));
        assert!(request
            .conversation_token
            .as_deref()
            .unwrap_or_default()
            .starts_with("conv_"));
        assert_ne!(request.sender_token.as_deref(), Some("sender_1"));
        assert_ne!(
            request.protected_account_token.as_deref(),
            Some("child_account_1")
        );
        assert_ne!(request.conversation_token.as_deref(), Some("conv_1"));
    }

    #[test]
    fn relay_request_auth_key_signs_requests_and_binds_payload() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let mut runtime = AgentRuntime::new(config, &pattern_db)
            .with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.0,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                ..AgentRelayPolicy::default()
            })
            .with_relay_request_auth_key(
                "relay-req-key-1",
                b"relay request auth test secret".to_vec(),
            );

        let request = runtime
            .analyze_for_relay(&make_input("hello there"), 1_700_000_123_456)
            .relay_request
            .expect("relay request should be emitted");

        assert!(request.auth.is_some());
        assert!(aura_contracts::verify_relay_request_auth(
            &request,
            "relay-req-key-1",
            b"relay request auth test secret"
        ));

        let mut tampered = request.clone();
        tampered.sender_token = Some("snd_01H00000000000000000000001".to_string());
        assert!(!aura_contracts::verify_relay_request_auth(
            &tampered,
            "relay-req-key-1",
            b"relay request auth test secret"
        ));
    }

    #[test]
    fn relay_request_includes_matching_protected_account_attestation_before_signing() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let protected_account_token = prefixed_token("acct", "child_account_1");
        let attestation_secret = b"protected account attestation secret";
        let request_secret = b"relay request auth test secret";
        let mut runtime = AgentRuntime::new(config, &pattern_db)
            .with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.0,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                protected_account_attestation:
                    aura_contracts::sign_protected_account_token_attestation(
                        &protected_account_token,
                        1_800_000_000_000,
                        "acct-attest-key-1",
                        attestation_secret,
                    ),
                ..AgentRelayPolicy::default()
            })
            .with_relay_request_auth_key("relay-req-key-1", request_secret.to_vec());

        let request = runtime
            .analyze_for_relay(&make_input("hello there"), 1_700_000_123_456)
            .relay_request
            .expect("relay request should be emitted");

        let attestation = request
            .protected_account_attestation
            .as_ref()
            .expect("matching non-expired account attestation should be included");
        assert_eq!(attestation.protected_account_token, protected_account_token);
        assert!(aura_contracts::verify_protected_account_token_attestation(
            attestation,
            &protected_account_token,
            1_700_000_123_456,
            "acct-attest-key-1",
            attestation_secret,
        ));
        assert!(aura_contracts::verify_relay_request_auth(
            &request,
            "relay-req-key-1",
            request_secret,
        ));

        let mut tampered = request.clone();
        tampered
            .protected_account_attestation
            .as_mut()
            .expect("attestation should exist")
            .tag = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string();
        assert!(!aura_contracts::verify_relay_request_auth(
            &tampered,
            "relay-req-key-1",
            request_secret,
        ));
    }

    #[test]
    fn relay_request_omits_mismatched_or_expired_protected_account_attestation() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let attestation_secret = b"protected account attestation secret";
        let mismatched_attestation = aura_contracts::sign_protected_account_token_attestation(
            &prefixed_token("acct", "other_child"),
            1_800_000_000_000,
            "acct-attest-key-1",
            attestation_secret,
        );
        let mut runtime =
            AgentRuntime::new(config.clone(), &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.0,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                protected_account_attestation: mismatched_attestation,
                ..AgentRelayPolicy::default()
            });

        let mismatched_request = runtime
            .analyze_for_relay(&make_input("hello there"), 1_700_000_123_456)
            .relay_request
            .expect("relay request should be emitted");
        assert!(mismatched_request.protected_account_attestation.is_none());

        let expired_attestation = aura_contracts::sign_protected_account_token_attestation(
            &prefixed_token("acct", "child_account_1"),
            1_600_000_000_000,
            "acct-attest-key-1",
            attestation_secret,
        );
        let mut runtime =
            AgentRuntime::new(config, &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.0,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                protected_account_attestation: expired_attestation,
                ..AgentRelayPolicy::default()
            });

        let expired_request = runtime
            .analyze_for_relay(&make_input("hello there"), 1_700_000_123_456)
            .relay_request
            .expect("relay request should be emitted");
        assert!(expired_request.protected_account_attestation.is_none());
    }

    #[test]
    fn relay_request_is_suppressed_when_required_account_attestation_is_invalid() {
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig::default();
        let attestation_secret = b"protected account attestation secret";
        let expired_attestation = aura_contracts::sign_protected_account_token_attestation(
            &prefixed_token("acct", "child_account_1"),
            1_600_000_000_000,
            "acct-attest-key-1",
            attestation_secret,
        );
        let mut runtime =
            AgentRuntime::new(config, &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.0,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                protected_account_attestation: expired_attestation,
                require_protected_account_attestation: true,
                ..AgentRelayPolicy::default()
            });

        let envelope = runtime.analyze_for_relay(&make_input("hello there"), 1_700_000_123_456);

        assert!(envelope.relay_request.is_none());
    }

    #[test]
    fn relay_response_hint_is_cached_and_applied_to_future_analysis() {
        aura_kids::pipeline::clear_kids_memory();
        let pattern_db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            protection_level: ProtectionLevel::High,
            domain_mode: DomainMode::Kids,
            language: "en".to_string(),
            ..AuraConfig::default()
        };
        let mut runtime = AgentRuntime::new(config, &pattern_db);
        let sender_id: SenderId = "server_hint_sender".into();
        let now_ms = 1_778_652_000_000;
        runtime.relay_policy_mut().enabled = true;
        runtime.relay_policy_mut().score_threshold = 0.0;
        let pending_input = MessageInput {
            content_type: ContentType::Text,
            text: Some("hello there".to_string()),
            image_data: None,
            sender_id: sender_id.clone(),
            conversation_id: "conv_pending_hint".into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            server_sender_risk_hint: None,
        };
        let request_id = runtime
            .analyze_for_relay(&pending_input, now_ms)
            .relay_request
            .expect("pending relay request should be emitted")
            .request_id;

        let response = RelayAnalyzeResponse {
            request_id,
            sender_reputation_hint: Some(0.9),
            expires_at_ms: Some(now_ms + 60_000),
            correlation_findings: vec![
                "relay.context.cross_conversation_safety_telemetry".to_string()
            ],
            ..RelayAnalyzeResponse::default()
        };

        assert!(runtime.record_relay_response_for_sender(&sender_id, &response, now_ms));
        assert_eq!(runtime.relay_sender_hint(&sender_id, now_ms + 1), Some(0.9));

        let result = runtime.analyze_local_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("our little secret".to_string()),
                image_data: None,
                sender_id,
                conversation_id: "conv_server_hint".into(),
                language: Some("en".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
                server_sender_risk_hint: None,
            },
            now_ms + 1,
        );

        assert!(
            result
                .reason_codes
                .iter()
                .any(|code| code == "domain.kids.memory.sender_risk_accumulation"),
            "cached relay reputation hint should feed kids sender-risk memory, got {:?}",
            result.reason_codes
        );
    }

    #[test]
    fn relay_response_hint_expires_and_clamps_invalid_values() {
        let pattern_db = PatternDatabase::default_mvp();
        let mut runtime = AgentRuntime::new(AuraConfig::default(), &pattern_db);
        let sender_id: SenderId = "sender_1".into();
        let now_ms = 1_778_652_000_000;
        runtime.relay_policy_mut().enabled = true;
        runtime.relay_policy_mut().score_threshold = 0.0;
        let request_id = runtime
            .analyze_for_relay(&make_input("hello there"), now_ms)
            .relay_request
            .expect("pending relay request should be emitted")
            .request_id;

        assert!(runtime.record_relay_response_for_sender(
            &sender_id,
            &RelayAnalyzeResponse {
                request_id,
                sender_reputation_hint: Some(2.0),
                expires_at_ms: Some(now_ms + 10),
                ..RelayAnalyzeResponse::default()
            },
            now_ms,
        ));
        assert_eq!(runtime.relay_sender_hint(&sender_id, now_ms + 1), Some(1.0));
        assert_eq!(runtime.relay_sender_hint(&sender_id, now_ms + 10), None);

        let nan_request_id = runtime
            .analyze_for_relay(&make_input("hello again"), now_ms + 20)
            .relay_request
            .expect("pending relay request should be emitted")
            .request_id;
        assert!(!runtime.record_relay_response_for_sender(
            &sender_id,
            &RelayAnalyzeResponse {
                request_id: nan_request_id,
                sender_reputation_hint: Some(f32::NAN),
                expires_at_ms: Some(now_ms + 60_000),
                ..RelayAnalyzeResponse::default()
            },
            now_ms,
        ));
    }

    #[test]
    fn relay_response_hint_requires_matching_pending_request() {
        let pattern_db = PatternDatabase::default_mvp();
        let mut runtime = AgentRuntime::new(AuraConfig::default(), &pattern_db);
        runtime.relay_policy_mut().enabled = true;
        runtime.relay_policy_mut().score_threshold = 0.0;
        let sender_id: SenderId = "sender_1".into();
        let now_ms = 1_778_652_000_000;
        let request_id = runtime
            .analyze_for_relay(&make_input("hello there"), now_ms)
            .relay_request
            .expect("pending relay request should be emitted")
            .request_id;
        let response = RelayAnalyzeResponse {
            request_id: request_id.clone(),
            sender_reputation_hint: Some(0.8),
            expires_at_ms: Some(now_ms + 60_000),
            ..RelayAnalyzeResponse::default()
        };

        assert!(!runtime.record_relay_response_for_sender(
            &"sender_2".into(),
            &response,
            now_ms + 1
        ));
        assert!(runtime.record_relay_response_for_sender(&sender_id, &response, now_ms + 1));
        assert_eq!(runtime.relay_sender_hint(&sender_id, now_ms + 2), Some(0.8));
        assert!(!runtime.record_relay_response_for_sender(&sender_id, &response, now_ms + 2));
    }

    #[test]
    fn relay_response_auth_key_rejects_missing_replayed_or_tampered_auth() {
        let pattern_db = PatternDatabase::default_mvp();
        let mut runtime = AgentRuntime::new(AuraConfig::default(), &pattern_db)
            .with_relay_response_auth_key(
                "relay-key-1",
                b"relay response auth test secret".to_vec(),
            );
        runtime.relay_policy_mut().enabled = true;
        runtime.relay_policy_mut().score_threshold = 0.0;
        let sender_id: SenderId = "sender_1".into();
        let now_ms = 1_778_652_000_000;
        let request = runtime
            .analyze_for_relay(&make_input("hello there"), now_ms)
            .relay_request
            .expect("pending relay request should be emitted");
        let sender_token = request
            .sender_token
            .as_deref()
            .expect("relay request should bind a sender token")
            .to_string();
        let response = RelayAnalyzeResponse {
            request_id: request.request_id,
            sender_reputation_hint: Some(0.8),
            expires_at_ms: Some(now_ms + 60_000),
            ..RelayAnalyzeResponse::default()
        };

        assert!(!runtime.record_relay_response_for_sender(&sender_id, &response, now_ms + 1));

        let mut signed_response = response.clone();
        signed_response.auth = aura_contracts::sign_relay_response_auth(
            &signed_response,
            &sender_token,
            "relay-key-1",
            b"relay response auth test secret",
        );
        let mut tampered_response = signed_response.clone();
        tampered_response.sender_reputation_hint = Some(0.1);

        assert!(!runtime.record_relay_response_for_sender(
            &sender_id,
            &tampered_response,
            now_ms + 1
        ));
        assert!(runtime.record_relay_response_for_sender(&sender_id, &signed_response, now_ms + 1));
        assert_eq!(runtime.relay_sender_hint(&sender_id, now_ms + 2), Some(0.8));
        assert!(!runtime.record_relay_response_for_sender(
            &sender_id,
            &signed_response,
            now_ms + 2
        ));
    }

    #[test]
    fn relay_response_auth_accepts_rotation_key_set() {
        let pattern_db = PatternDatabase::default_mvp();
        let mut runtime = AgentRuntime::new(AuraConfig::default(), &pattern_db);
        runtime.set_relay_response_auth_keys(vec![
            RelayResponseAuthKey {
                key_id: "relay-key-current".to_string(),
                secret: b"relay response current secret".to_vec(),
            },
            RelayResponseAuthKey {
                key_id: "relay-key-previous".to_string(),
                secret: b"relay response previous secret".to_vec(),
            },
        ]);
        runtime.relay_policy_mut().enabled = true;
        runtime.relay_policy_mut().score_threshold = 0.0;
        let sender_id: SenderId = "sender_1".into();
        let now_ms = 1_778_652_000_000;
        let request = runtime
            .analyze_for_relay(&make_input("hello there"), now_ms)
            .relay_request
            .expect("pending relay request should be emitted");
        let sender_token = request
            .sender_token
            .as_deref()
            .expect("relay request should bind a sender token")
            .to_string();
        let mut response = RelayAnalyzeResponse {
            request_id: request.request_id,
            sender_reputation_hint: Some(0.8),
            expires_at_ms: Some(now_ms + 60_000),
            ..RelayAnalyzeResponse::default()
        };
        response.auth = aura_contracts::sign_relay_response_auth(
            &response,
            &sender_token,
            "relay-key-previous",
            b"relay response previous secret",
        );

        assert!(runtime.record_relay_response_for_sender(&sender_id, &response, now_ms + 1));
        assert_eq!(runtime.relay_sender_hint(&sender_id, now_ms + 2), Some(0.8));
    }
}
