//! On-device Agent runtime for AURA.
//!
//! The runtime keeps message analysis on device and projects canonical source
//! events into instance-local longitudinal safety cases.

/// Account-scoped signed execution policy and monotonic native floor.
pub mod execution_policy;
/// Instance-local longitudinal safety-case projection and deduplication.
pub mod safety_case_runtime;

// ── Agent runtime API ────────────────────────────────────────────────
// The FFI depends on one on-device runtime crate instead of coupling directly
// to its implementation crates.

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
pub use aura_core::runtime_capabilities;
pub use aura_core::types;

// Re-export the same root-level convenience aliases that aura-core provides.
pub use aura_core::{
    AccountType, Action, ActionRecommendation, AlertPriority, AnalysisContextSummary, AnalysisMode,
    AnalysisResult, Analyzer, AuraConfig, AuraDomainModule, AuraDomainRuntime, AuraError,
    BehavioralTrend, CircleTier, Confidence, ContactSnapshot, ContentType, ContextDirectionality,
    ContextReciprocity, ContextSpeechAct, ContextStance, ConversationId, ConversationTracker,
    ConversationType, DetectionLayer, DetectionSignal, DomainMode, FollowUpAction,
    InferenceSummary, LanguageCandidate, LanguageEvidence, LanguageEvidenceError,
    LanguageEvidenceSource, LanguageScript, LanguageSpan, LanguageTag, LatentStateEvidence,
    LatentStateKind, MessageInput, ProtectionLevel, ReasonCode, RelationshipTrustSource,
    RiskBreakdown, RiskHorizon, SenderId, SenderRelationship, SignalFamily, ThreatType, UiAction,
    UncertaintyLevel, MAX_DOMAIN_TEXT_BYTES, MAX_LANGUAGE_CANDIDATES, MAX_LANGUAGE_SPANS,
};

pub use aura_agent_policy::safety_case::{
    ConversationEventKey, GuardianDeliveryClass, GuardianExecutionMode, GuardianExecutionPolicy,
    GuardianExecutionRule, GuardianReport, GuardianReportExecutionBinding, GuardianReportKey,
    GuardianReportObservationVolumeBand, GuardianReportTrigger, SafetyCase, SafetyCaseCommand,
    SafetyCaseDecision, SafetyCaseEvent, SafetyCaseId, SafetyCaseSeverity, SafetyCaseStatus,
    SafetyCaseSubjectKey, SafetyReasonCode, SourceEventId, SourceEventKey,
};
pub use execution_policy::{
    NativeExecutionMode, NativeExecutionPolicy, NativeExecutionPolicyApplicationReceipt,
    NativeExecutionPolicyApplyDisposition, NativeExecutionPolicyError, NativeExecutionPolicyState,
};
pub use safety_case_runtime::{
    ExportedSafetyCaseRuntimeState, SafetyAccountKey, SafetyAccountKeyError,
    SafetyCaseAccountRemoval, SafetyCaseGeneration, SafetyCaseIgnoredReason,
    SafetyCaseIngestIdentity, SafetyCaseIngestOutcome, SafetyCaseRuntime, SafetyCaseRuntimeConfig,
    SafetyCaseRuntimeError, SafetyCaseSourceCheckpointDisposition, SafetyCaseSourcePreflight,
    SafetyCaseSourceReceipt, SafetyCaseSuccessorActivationDisposition,
    SafetyCaseSuccessorActivationOutcome, SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES,
    SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION,
};

// Product surface
pub use aura_core::{
    build_product_decision_surface, ProductChildIntervention, ProductChildSurface,
    ProductDecisionSurface, ProductDeliveryMode, ProductGuardianSurface, ProductReviewSurface,
    ProductReviewUrgency, ProductRolloutMode, ProductUncertaintyDisposition,
    PRODUCT_DECISION_SURFACE_SCHEMA_VERSION, PRODUCT_POLICY_SCHEMA_VERSION,
};

// Runtime capability surface
pub use aura_core::{
    RuntimeBackend, RuntimeCapabilities, RuntimeModality, RuntimeModelIdentity,
    RUNTIME_CAPABILITIES_SCHEMA_VERSION,
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

// Domain packs used by the FFI state boundary.
pub use aura_kids;

// ── Internal imports for this crate's own code ──────────────────────

use aura_core::context::tracker::TrackerWireState;
use aura_patterns::PatternDatabase;

/// Exactly-once output from canonical local analysis and case projection.
#[derive(Debug, Clone)]
pub enum CanonicalSafetyAnalysisOutcome {
    /// This source revision was analyzed for the first time.
    Processed {
        /// Case projection result for the first processing attempt.
        safety_case: Result<SafetyCaseIngestOutcome, SafetyCaseRuntimeError>,
    },
    /// The source revision was already processed, so analysis was skipped.
    DuplicateIgnored {
        /// Content-free receipt from the first processing attempt.
        receipt: SafetyCaseSourceReceipt,
    },
    /// A newer edit was already processed, so analysis was skipped.
    StaleIgnored {
        /// Highest processed revision for the canonical source event.
        latest_revision: u32,
    },
}

/// Exactly-once output that exposes a product decision only for a committed
/// first analysis attempt.
#[derive(Debug, Clone)]
pub enum CanonicalLocalDecisionAnalysisOutcome {
    /// This source revision was analyzed for the first time.
    Processed {
        /// The local result is present only when case projection and the
        /// supplied persistence postcondition both succeeded.
        local_result: Option<Box<AnalysisResult>>,
        /// Case projection result for the first processing attempt.
        safety_case: Result<SafetyCaseIngestOutcome, SafetyCaseRuntimeError>,
    },
    /// The source revision was already processed, so analysis was skipped.
    DuplicateIgnored {
        /// Content-free receipt from the first processing attempt.
        receipt: SafetyCaseSourceReceipt,
    },
    /// A newer edit was already processed, so analysis was skipped.
    StaleIgnored {
        /// Highest processed revision for the canonical source event.
        latest_revision: u32,
    },
}

pub struct AgentRuntime {
    analyzer: Analyzer,
    safety_cases: SafetyCaseRuntime,
}

impl AgentRuntime {
    /// Creates a runtime after validating configuration and bundled rule packs.
    pub fn try_new(config: AuraConfig, pattern_db: &PatternDatabase) -> Result<Self, AuraError> {
        Ok(Self {
            analyzer: Analyzer::try_new(config, pattern_db)?,
            safety_cases: SafetyCaseRuntime::default(),
        })
    }

    /// Creates a runtime with a configuration that must be valid.
    ///
    /// # Panics
    ///
    /// Panics if configuration or bundled context rule-pack validation fails.
    pub fn new(config: AuraConfig, pattern_db: &PatternDatabase) -> Self {
        match Self::try_new(config, pattern_db) {
            Ok(runtime) => runtime,
            Err(error) => panic!("AURA agent runtime initialization failed: {error}"),
        }
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

    /// Analyzes and projects one canonical event exactly once.
    ///
    /// Duplicate source revisions return a content-free receipt without calling
    /// the analyzer, so tracker and Kids context cannot be mutated twice. The
    /// first attempt exposes only its safety-case projection.
    pub fn analyze_local_with_canonical_safety_case(
        &mut self,
        input: &MessageInput,
        identity: &SafetyCaseIngestIdentity,
    ) -> Result<CanonicalSafetyAnalysisOutcome, SafetyCaseRuntimeError> {
        self.analyze_local_with_canonical_safety_case_guarded(input, identity, |_| Ok(()))
    }

    /// Canonically analyzes one event and rolls back all persisted analyzer
    /// state when the supplied host-persistence postcondition fails.
    ///
    /// A failed first attempt still records a rejected source receipt after
    /// rollback, preserving exactly-once behavior without retaining the event's
    /// context or case mutation.
    pub fn analyze_local_with_canonical_safety_case_guarded<F>(
        &mut self,
        input: &MessageInput,
        identity: &SafetyCaseIngestIdentity,
        persistence_guard: F,
    ) -> Result<CanonicalSafetyAnalysisOutcome, SafetyCaseRuntimeError>
    where
        F: FnOnce(&Self) -> Result<(), SafetyCaseRuntimeError>,
    {
        let outcome = self.analyze_local_decision_with_canonical_safety_case_guarded(
            input,
            identity,
            |runtime, _| persistence_guard(runtime),
        )?;
        Ok(match outcome {
            CanonicalLocalDecisionAnalysisOutcome::Processed { safety_case, .. } => {
                CanonicalSafetyAnalysisOutcome::Processed { safety_case }
            }
            CanonicalLocalDecisionAnalysisOutcome::DuplicateIgnored { receipt } => {
                CanonicalSafetyAnalysisOutcome::DuplicateIgnored { receipt }
            }
            CanonicalLocalDecisionAnalysisOutcome::StaleIgnored { latest_revision } => {
                CanonicalSafetyAnalysisOutcome::StaleIgnored { latest_revision }
            }
        })
    }

    /// Canonically analyzes one event and exposes a product result only after
    /// case projection and the supplied persistence postcondition succeed.
    ///
    /// Duplicate and stale revisions never invoke the analyzer. Projection or
    /// persistence failures restore conversation and KIDS context before a
    /// durable rejected receipt is recorded.
    pub fn analyze_local_decision_with_canonical_safety_case_guarded<F>(
        &mut self,
        input: &MessageInput,
        identity: &SafetyCaseIngestIdentity,
        persistence_guard: F,
    ) -> Result<CanonicalLocalDecisionAnalysisOutcome, SafetyCaseRuntimeError>
    where
        F: FnOnce(&Self, &AnalysisResult) -> Result<(), SafetyCaseRuntimeError>,
    {
        self.safety_cases
            .require_active_execution_policy(identity.account_key(), identity.observed_at_ms())?;
        match self.safety_cases.preflight_source(identity)? {
            SafetyCaseSourcePreflight::Duplicate(receipt) => {
                return Ok(CanonicalLocalDecisionAnalysisOutcome::DuplicateIgnored { receipt });
            }
            SafetyCaseSourcePreflight::Stale { latest_revision } => {
                return Ok(CanonicalLocalDecisionAnalysisOutcome::StaleIgnored { latest_revision });
            }
            SafetyCaseSourcePreflight::Ready => {}
        }

        let context_snapshot = self.analyzer.export_context_state();
        let kids_snapshot = self.analyzer.export_kids_memory_state();
        let safety_case_snapshot = self.safety_cases.clone();
        let timestamp_ms = identity.observed_at_ms();
        let local_result = self.analyzer.analyze_with_context(input, timestamp_ms);
        let safety_case = self.safety_cases.ingest_analysis(identity, &local_result);
        if safety_case.is_err() {
            self.analyzer.reset_runtime_state();
            self.safety_cases = safety_case_snapshot;
            let context_restored = self.analyzer.import_context_state(context_snapshot).is_ok();
            let kids_restored = self.analyzer.import_kids_memory_state(&kids_snapshot);
            self.safety_cases.remember_rejected_source(identity)?;
            if !context_restored || !kids_restored {
                return Err(SafetyCaseRuntimeError::CanonicalContextRollbackFailed);
            }
            return Ok(CanonicalLocalDecisionAnalysisOutcome::Processed {
                local_result: None,
                safety_case,
            });
        }
        if let Err(persistence_error) = persistence_guard(self, &local_result) {
            self.analyzer.reset_runtime_state();
            self.safety_cases = safety_case_snapshot;
            let context_restored = self.analyzer.import_context_state(context_snapshot).is_ok();
            let kids_restored = self.analyzer.import_kids_memory_state(&kids_snapshot);
            self.safety_cases.remember_rejected_source(identity)?;
            if !context_restored || !kids_restored {
                return Err(SafetyCaseRuntimeError::CanonicalContextRollbackFailed);
            }
            return Ok(CanonicalLocalDecisionAnalysisOutcome::Processed {
                local_result: None,
                safety_case: Err(persistence_error),
            });
        }
        Ok(CanonicalLocalDecisionAnalysisOutcome::Processed {
            local_result: Some(Box::new(local_result)),
            safety_case,
        })
    }

    /// Returns this runtime's instance-local safety-case state.
    pub const fn safety_cases(&self) -> &SafetyCaseRuntime {
        &self.safety_cases
    }

    /// Returns mutable safety-case state for explicit lifecycle commands.
    pub fn safety_cases_mut(&mut self) -> &mut SafetyCaseRuntime {
        &mut self.safety_cases
    }

    /// Applies an account-scoped lifecycle command transactionally against a
    /// host persistence postcondition.
    pub fn apply_safety_case_lifecycle_guarded<F>(
        &mut self,
        account_key: &SafetyAccountKey,
        case_id: &SafetyCaseId,
        command: SafetyCaseCommand,
        persistence_guard: F,
    ) -> Result<SafetyCaseDecision, SafetyCaseRuntimeError>
    where
        F: FnOnce(&Self) -> Result<(), SafetyCaseRuntimeError>,
    {
        let snapshot = self.safety_cases.clone();
        let decision =
            self.safety_cases
                .apply_account_lifecycle_command(account_key, case_id, command)?;
        if let Err(error) = persistence_guard(self) {
            self.safety_cases = snapshot;
            return Err(error);
        }
        Ok(decision)
    }

    /// Explicitly activates one successor generation transactionally against a
    /// host persistence postcondition. No ingestion path calls this automatically.
    pub fn activate_safety_case_successor_guarded<F>(
        &mut self,
        account_key: &SafetyAccountKey,
        predecessor_case_id: &SafetyCaseId,
        expected_generation: SafetyCaseGeneration,
        expected_case_revision: u64,
        activated_at_ms: u64,
        persistence_guard: F,
    ) -> Result<SafetyCaseSuccessorActivationOutcome, SafetyCaseRuntimeError>
    where
        F: FnOnce(&Self) -> Result<(), SafetyCaseRuntimeError>,
    {
        let snapshot = self.safety_cases.clone();
        let outcome = self.safety_cases.activate_successor(
            account_key,
            predecessor_case_id,
            expected_generation,
            expected_case_revision,
            activated_at_ms,
        )?;
        if let Err(error) = persistence_guard(self) {
            self.safety_cases = snapshot;
            return Err(error);
        }
        Ok(outcome)
    }

    /// Replaces the empty/default safety-case runtime with host configuration.
    pub fn with_safety_case_runtime(mut self, safety_cases: SafetyCaseRuntime) -> Self {
        self.safety_cases = safety_cases;
        self
    }

    pub fn protection_level(&self) -> ProtectionLevel {
        self.analyzer.protection_level()
    }

    pub fn product_rollout_mode(&self) -> ProductRolloutMode {
        self.analyzer.product_rollout_mode()
    }

    pub fn account_type(&self) -> AccountType {
        self.analyzer.account_type()
    }

    pub fn effective_domain_mode(&self) -> DomainMode {
        self.analyzer.effective_domain_mode()
    }

    pub fn language(&self) -> &str {
        self.analyzer.language()
    }

    pub fn runtime_capabilities(&self) -> RuntimeCapabilities {
        self.analyzer.runtime_capabilities()
    }

    /// Returns the digest of the exact model manifest active in this handle.
    pub fn model_manifest_digest(&self) -> [u8; 32] {
        self.analyzer.model_manifest_digest()
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
    ) -> bool {
        self.analyzer.import_kids_memory_state(state)
    }

    pub fn clear_kids_memory_state(&mut self) {
        self.analyzer.clear_kids_memory_state();
    }

    pub fn kids_conversation_risk_score(&self, conversation_id: &str) -> f32 {
        self.analyzer.kids_conversation_risk_score(conversation_id)
    }

    pub fn kids_conversation_escalation_message_count(&self, conversation_id: &str) -> u32 {
        self.analyzer
            .kids_conversation_escalation_message_count(conversation_id)
    }

    pub fn kids_sender_cross_risk_score(&self, sender_id: &str) -> f32 {
        self.analyzer.kids_sender_cross_risk_score(sender_id)
    }

    pub fn apply_kids_guardian_feedback(
        &mut self,
        sender_id: &str,
        conversation_id: &str,
        verdict: aura_kids::pipeline::GuardianVerdict,
    ) {
        self.analyzer
            .apply_kids_guardian_feedback(sender_id, conversation_id, verdict);
    }

    pub fn cleanup_context(&mut self, now_ms: u64) {
        self.analyzer.cleanup_context(now_ms);
    }

    pub fn mark_contact_trusted(&mut self, sender_id: &str) {
        self.analyzer.mark_contact_trusted(sender_id);
    }

    /// Binds the protected sender identity after its account authority has
    /// been authenticated. A different identity cannot replace the binding.
    pub fn bind_protected_account_id(
        &mut self,
        protected_account_id: String,
    ) -> Result<(), AuraError> {
        self.analyzer
            .bind_protected_account_id(protected_account_id)
    }

    /// Validates an authenticated account binding without mutating runtime state.
    pub fn validate_protected_account_id_binding(
        &self,
        protected_account_id: &str,
    ) -> Result<(), AuraError> {
        self.analyzer
            .validate_protected_account_id_binding(protected_account_id)
    }

    pub fn update_config(
        &mut self,
        config: AuraConfig,
        pattern_db: &PatternDatabase,
    ) -> Result<(), AuraError> {
        self.analyzer.update_config(config, pattern_db)?;
        self.safety_cases.deactivate_execution_policies();
        Ok(())
    }

    pub fn reload_patterns(&mut self, pattern_db: &PatternDatabase) {
        self.analyzer.reload_patterns(pattern_db);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_core::{ContentType, ConversationType};

    fn test_execution_policy() -> NativeExecutionPolicy {
        let policy_wire_digest = [1; 32];
        let runtime_capabilities_digest = [2; 32];
        let model_manifest_digest = [3; 32];
        let execution_policy_trust_keyring_digest = [4; 32];
        NativeExecutionPolicy {
            account_key: "account".to_string(),
            protected_account_id: [5; 16],
            authority_lineage_id: "test-authority".to_string(),
            issuer_key_id: "test-issuer".to_string(),
            policy_epoch: 1,
            revoked_through_policy_epoch: 0,
            state: NativeExecutionPolicyState::Enabled,
            execution_mode: NativeExecutionMode::ShadowCases,
            policy_wire_digest,
            signed_policy_digest: [6; 32],
            runtime_capabilities_digest,
            model_manifest_digest,
            execution_policy_trust_keyring_digest,
            valid_from_ms: 1,
            valid_until_ms: 1_000_000,
            maximum_case_observations: 128,
            maximum_case_reason_codes: 16,
            guardian_policy: Some(GuardianExecutionPolicy {
                authority_lineage_id: "test-authority".to_string(),
                policy_epoch: 1,
                policy_version: "test-v1".to_string(),
                policy_assertion_digest: policy_wire_digest,
                runtime_capabilities_digest,
                model_manifest_digest,
                execution_policy_trust_keyring_digest,
                valid_from_ms: 1,
                valid_until_ms: 1_000_000,
                execution_mode: GuardianExecutionMode::ShadowCases,
                rules: Vec::new(),
            }),
            active_for_runtime: false,
        }
    }

    fn test_identity() -> SafetyCaseIngestIdentity {
        SafetyCaseIngestIdentity::new(
            SafetyAccountKey::new("account").expect("account key"),
            SafetyCaseSubjectKey::new("subject").expect("subject key"),
            ConversationEventKey::new("conversation").expect("conversation key"),
            SourceEventId::new("event").expect("event id"),
            1,
            1_000,
            1_000,
        )
    }

    fn make_child_input(text: &str, sender_id: &str, conversation_id: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: sender_id.into(),
            conversation_id: conversation_id.into(),
            language: Some("en".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
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
    fn canonical_local_decision_rolls_back_before_exposing_failed_attempt() {
        let pattern_db = PatternDatabase::default_mvp();
        let mut runtime = AgentRuntime::new(child_kids_config(), &pattern_db);
        let identity = test_identity();
        runtime
            .safety_cases_mut()
            .apply_execution_policy(identity.account_key(), test_execution_policy())
            .expect("test policy must apply");
        let input = make_child_input(
            "don't tell your parents, it's our secret",
            "sender",
            "conversation",
        );
        assert!(runtime.export_context_state().timelines.is_empty());
        assert!(runtime.export_kids_memory_state().conversations.is_empty());

        let first = runtime
            .analyze_local_decision_with_canonical_safety_case_guarded(&input, &identity, |_, _| {
                Err(SafetyCaseRuntimeError::StateSerialization(
                    "simulated host commit failure".to_string(),
                ))
            })
            .expect("failed commit must return a rejected canonical outcome");

        match first {
            CanonicalLocalDecisionAnalysisOutcome::Processed {
                local_result,
                safety_case,
            } => {
                assert!(local_result.is_none());
                assert!(matches!(
                    safety_case,
                    Err(SafetyCaseRuntimeError::StateSerialization(_))
                ));
            }
            _ => panic!("first attempt must be processed exactly once"),
        }
        assert!(runtime.export_context_state().timelines.is_empty());
        assert!(runtime
            .export_context_state()
            .contact_profiler
            .profiles
            .is_empty());
        assert!(runtime.export_kids_memory_state().conversations.is_empty());
        assert!(runtime.export_kids_memory_state().senders.is_empty());
        assert!(matches!(
            runtime
                .safety_cases()
                .preflight_source(&identity)
                .expect("rejected receipt preflight"),
            SafetyCaseSourcePreflight::Duplicate(SafetyCaseSourceReceipt::Rejected)
        ));

        let duplicate = runtime
            .analyze_local_decision_with_canonical_safety_case_guarded(&input, &identity, |_, _| {
                Ok(())
            })
            .expect("duplicate must be returned without analysis");
        assert!(matches!(
            duplicate,
            CanonicalLocalDecisionAnalysisOutcome::DuplicateIgnored {
                receipt: SafetyCaseSourceReceipt::Rejected
            }
        ));
        assert!(runtime.export_context_state().timelines.is_empty());
        assert!(runtime.export_kids_memory_state().conversations.is_empty());
    }
}
