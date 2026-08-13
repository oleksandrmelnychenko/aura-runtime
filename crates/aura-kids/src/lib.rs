pub mod detectors;
mod lexicon;
pub mod pipeline;
pub mod policy;
mod routing;

use aura_domain::{
    validate_domain_study_independent_recomputation, validate_domain_study_preregistration,
    validate_domain_study_recomputation_registry, validate_domain_study_reproduction_manifest,
    validate_domain_study_result_evidence, DomainConfirmedOutput, DomainInput, DomainModule,
    DomainModuleEvidence, DomainModuleId, DomainOutput, DomainSignal, DomainStudyBinding,
    DomainStudyBuildProvenance, DomainStudyError, DomainStudyRecomputationError,
    DomainStudyRecomputationRegistryAcceptedAnchor, DomainStudyRecomputationRegistryError,
    DomainStudyRecomputationRegistryReport, DomainStudyRecomputationRegistryTrustPolicy,
    DomainStudyRecomputationReport, DomainStudyRecomputationTrustPolicy,
    DomainStudyReproductionError, DomainStudyReproductionReport, DomainStudyResultError,
    DomainStudyResultReport, DomainStudyTrustPolicy, DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
};

#[derive(Default)]
pub struct KidsModule {
    memory: pipeline::KidsPipelineMemory,
}

impl KidsModule {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn export_memory(&self) -> pipeline::ExportedKidsMemoryState {
        pipeline::export_kids_memory_from(&self.memory)
    }

    pub fn import_memory(&self, state: &pipeline::ExportedKidsMemoryState) -> bool {
        pipeline::import_kids_memory_into(&self.memory, state)
    }

    pub fn clear_memory(&self) {
        pipeline::clear_kids_memory_in(&self.memory);
    }

    pub fn conversation_risk_score(&self, conversation_id: &str) -> f32 {
        pipeline::conversation_risk_score_from(&self.memory, conversation_id)
    }

    pub fn conversation_escalation_message_count(&self, conversation_id: &str) -> u32 {
        pipeline::conversation_escalation_message_count_from(&self.memory, conversation_id)
    }

    pub fn sender_cross_risk_score(&self, sender_id: &str) -> f32 {
        pipeline::sender_cross_risk_score_from(&self.memory, sender_id)
    }

    pub fn apply_guardian_feedback(
        &self,
        sender_id: &str,
        conversation_id: &str,
        verdict: pipeline::GuardianVerdict,
    ) {
        pipeline::apply_guardian_feedback_to(&self.memory, sender_id, conversation_id, verdict);
    }
}

/// Returns the exact Kids policy and state identity used by release evidence.
#[must_use]
pub fn domain_evidence() -> DomainModuleEvidence {
    DomainModuleEvidence {
        schema_version: DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
        module_id: DomainModuleId::Kids,
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        stateful: true,
        state_schema_version: Some(pipeline::KIDS_MEMORY_STATE_VERSION),
        lexical_policy: lexicon::evidence(),
        temporal_policy: None,
    }
}

/// Validates a Kids study against the exact policy pack and memory schema in this build.
///
/// `expected_build_provenance` must describe the actual evaluated binary.
/// Repository seeds are injected automatically; private synthetic and tuning
/// corpus digests must be supplied so they cannot be relabeled as external.
pub fn validate_independent_study_preregistration(
    preregistration_json: &str,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
) -> Result<DomainStudyBinding, DomainStudyError> {
    validate_domain_study_preregistration(
        preregistration_json,
        &domain_evidence(),
        expected_build_provenance,
        additional_known_seed_sha256,
    )
}

/// Validates a signed Kids result chain against this exact policy and state schema.
///
/// A successful return is a content-free evidence report, not production
/// activation authority or proof of universal real-world effectiveness.
pub fn validate_independent_study_result(
    preregistration_json: &str,
    evidence_json: &str,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    trust_policy: &DomainStudyTrustPolicy,
) -> Result<DomainStudyResultReport, DomainStudyResultError> {
    validate_domain_study_result_evidence(
        preregistration_json,
        evidence_json,
        &domain_evidence(),
        expected_build_provenance,
        additional_known_seed_sha256,
        trust_policy,
    )
}

/// Validates a private Kids reproduction manifest against this exact build.
///
/// The returned status proves manifest consistency only. It is neither a
/// completed independent rerun nor authority to export private child data.
pub fn validate_independent_study_reproduction_manifest(
    preregistration_json: &str,
    evidence_json: &str,
    reproduction_manifest_json: &str,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    trust_policy: &DomainStudyTrustPolicy,
) -> Result<DomainStudyReproductionReport, DomainStudyReproductionError> {
    validate_domain_study_reproduction_manifest(
        preregistration_json,
        evidence_json,
        reproduction_manifest_json,
        &domain_evidence(),
        expected_build_provenance,
        additional_known_seed_sha256,
        trust_policy,
    )
}

/// Validates one signed Kids aggregate-recomputation attempt against this build.
///
/// An exact match is bounded to independent same-data computational
/// reproduction. It is not a new-sample scientific replication, does not
/// activate child-safety policy, and never authorizes private-data disclosure.
#[expect(
    clippy::too_many_arguments,
    reason = "the public boundary keeps every independently governed evidence input explicit"
)]
pub fn validate_independent_study_recomputation(
    preregistration_json: &str,
    result_evidence_json: &str,
    reproduction_manifest_json: &str,
    recomputation_evidence_json: &str,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    original_trust_policy: &DomainStudyTrustPolicy,
    recomputation_trust_policy: &DomainStudyRecomputationTrustPolicy,
) -> Result<DomainStudyRecomputationReport, DomainStudyRecomputationError> {
    validate_domain_study_independent_recomputation(
        preregistration_json,
        result_evidence_json,
        reproduction_manifest_json,
        recomputation_evidence_json,
        &domain_evidence(),
        expected_build_provenance,
        additional_known_seed_sha256,
        original_trust_policy,
        recomputation_trust_policy,
    )
}

/// Validates a witnessed Kids recomputation registry through one checkpoint.
///
/// Success establishes local integrity, prefix-state completeness, and
/// append-only continuity only for the submitted registry view relative to
/// `previous_anchor`. The caller must compare-and-swap durably persist the
/// report's `next_accepted_anchor` before relying on the report or processing
/// another extension. Success does not prove that no off-ledger attempt,
/// competing successor, or split view exists. Operational reliance requires an
/// externally witnessed, durable append-only publication channel.
#[expect(
    clippy::too_many_arguments,
    reason = "the public boundary keeps every independently governed evidence input explicit"
)]
pub fn validate_independent_study_recomputation_registry(
    preregistration_json: &str,
    result_evidence_json: &str,
    reproduction_manifest_json: &str,
    recomputation_evidence_json: &str,
    registry_evidence_json: &str,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    original_trust_policy: &DomainStudyTrustPolicy,
    recomputation_trust_policy: &DomainStudyRecomputationTrustPolicy,
    registry_trust_policy: &DomainStudyRecomputationRegistryTrustPolicy,
    previous_anchor: &DomainStudyRecomputationRegistryAcceptedAnchor,
) -> Result<DomainStudyRecomputationRegistryReport, DomainStudyRecomputationRegistryError> {
    validate_domain_study_recomputation_registry(
        preregistration_json,
        result_evidence_json,
        reproduction_manifest_json,
        recomputation_evidence_json,
        registry_evidence_json,
        &domain_evidence(),
        expected_build_provenance,
        additional_known_seed_sha256,
        original_trust_policy,
        recomputation_trust_policy,
        registry_trust_policy,
        previous_anchor,
    )
}

impl DomainModule for KidsModule {
    fn id(&self) -> DomainModuleId {
        DomainModuleId::Kids
    }

    fn evidence(&self) -> DomainModuleEvidence {
        domain_evidence()
    }

    fn detect(&self, input: &DomainInput) -> DomainOutput {
        pipeline::detect_kids_pipeline(input)
    }

    fn analyze(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_kids_pipeline_with_memory(input, &self.memory)
    }

    fn commit_confirmed(
        &self,
        input: &DomainInput,
        confirmed_signals: &[DomainSignal],
    ) -> DomainConfirmedOutput {
        pipeline::commit_confirmed_kids_pipeline(input, confirmed_signals, &self.memory)
    }
}

#[cfg(test)]
mod tests {
    use super::{domain_evidence, KidsModule};
    use crate::pipeline::GuardianVerdict;
    use aura_domain::{
        DomainConversationType, DomainInput, DomainModule, DomainRiskProfile, DomainSignal,
    };

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    #[test]
    fn domain_evidence_declares_stateful_kids_contract() {
        let evidence = domain_evidence();

        assert!(evidence.stateful);
        assert_eq!(
            evidence.state_schema_version,
            Some(crate::pipeline::KIDS_MEMORY_STATE_VERSION)
        );
        assert!(evidence.temporal_policy.is_none());
    }

    fn risky_input(sender_id: &str, conversation_id: &str) -> DomainInput {
        DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some(sender_id.to_string()),
            conversation_id: Some(conversation_id.to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    fn safe_input(sender_id: &str, conversation_id: &str) -> DomainInput {
        DomainInput {
            text: Some("hello, how are you?".to_string()),
            language: None,
            sender_id: Some(sender_id.to_string()),
            conversation_id: Some(conversation_id.to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    fn has_reason(signals: &[DomainSignal], reason: &str) -> bool {
        signals.iter().any(|signal| signal.reason_code == reason)
    }

    fn tracked_sender_conversation_pairs(module: &KidsModule) -> Vec<(String, Option<String>)> {
        let mut pairs = Vec::new();
        for conversation in module.export_memory().conversations {
            for entry in conversation.entries {
                pairs.push((conversation.conversation_id.clone(), entry.sender_id));
            }
        }
        pairs.sort();
        pairs
    }

    #[test]
    fn module_instances_keep_memory_isolated() {
        let first = KidsModule::new();
        let second = KidsModule::new();
        let seed = input("our little secret. don't tell your parents.");
        let followup = input("you can only trust me. do it now or i post everything.");

        let _ = first.analyze(&seed);
        let first_output = first.analyze(&followup);
        let second_output = second.analyze(&followup);

        assert!(has_reason(
            &first_output.signals,
            "kids.memory.grooming_progression"
        ));
        assert!(!has_reason(
            &second_output.signals,
            "kids.memory.grooming_progression"
        ));
    }

    #[test]
    fn candidate_detection_does_not_mutate_module_memory() {
        let module = KidsModule::new();
        let candidate = input("our little secret. don't tell your parents.");

        let output = module.detect(&candidate);
        let state = module.export_memory();

        assert!(!output.signals.is_empty());
        assert!(state.conversations.is_empty());
        assert!(state.senders.is_empty());
    }

    #[test]
    fn confirmation_commit_records_only_the_confirmed_projection() {
        let module = KidsModule::new();
        let candidate = input("our little secret. don't tell your parents.");

        let detected = module.detect(&candidate);
        assert!(!detected.signals.is_empty());
        let committed = module.commit_confirmed(&candidate, &[]);
        let state = module.export_memory();

        assert!(committed.confirmed_signals.is_empty());
        assert!(committed.derived_signals.is_empty());
        assert_eq!(state.conversations.len(), 1);
        assert_eq!(state.conversations[0].entries.len(), 1);
        let snapshot = &state.conversations[0].entries[0];
        assert!(!snapshot.has_grooming);
        assert!(!snapshot.has_manipulation);
        assert!(!snapshot.has_bullying);
        assert!(!snapshot.has_self_harm);
    }

    #[test]
    fn guardian_feedback_and_explainability_stay_instance_isolated() {
        let first = KidsModule::new();
        let second = KidsModule::new();

        first.apply_guardian_feedback("s1", "conv_mem_gp", GuardianVerdict::Block);

        assert_eq!(
            (
                first.sender_cross_risk_score("s1"),
                second.sender_cross_risk_score("s1"),
            ),
            (5.0, 0.0),
        );
    }

    #[test]
    fn trusted_feedback_removes_sender_evidence_from_every_conversation() {
        let module = KidsModule::new();
        let trusted_sender = "trusted_sender";
        let other_sender = "other_sender";
        let shared_conversation = "shared_conversation";
        let second_conversation = "second_conversation";

        let _ = module.analyze(&risky_input(trusted_sender, shared_conversation));
        let _ = module.analyze(&risky_input(trusted_sender, second_conversation));
        let _ = module.analyze(&risky_input(other_sender, shared_conversation));

        module.apply_guardian_feedback(
            trusted_sender,
            shared_conversation,
            GuardianVerdict::Trusted,
        );

        let state = module.export_memory();
        assert_eq!(module.sender_cross_risk_score(trusted_sender), 0.0);
        assert!(state.conversations.iter().all(|conversation| {
            conversation
                .entries
                .iter()
                .all(|entry| entry.sender_id.as_deref() != Some(trusted_sender))
        }));
        assert!(state.conversations.iter().any(|conversation| {
            conversation.conversation_id == shared_conversation
                && conversation
                    .entries
                    .iter()
                    .any(|entry| entry.sender_id.as_deref() == Some(other_sender))
        }));
    }

    #[test]
    fn false_positive_feedback_only_removes_the_sender_conversation_pair() {
        let module = KidsModule::new();
        let corrected_sender = "corrected_sender";
        let other_sender = "other_sender";
        let corrected_conversation = "corrected_conversation";
        let unaffected_conversation = "unaffected_conversation";

        let _ = module.analyze(&risky_input(corrected_sender, corrected_conversation));
        let _ = module.analyze(&risky_input(corrected_sender, unaffected_conversation));
        let _ = module.analyze(&risky_input(other_sender, corrected_conversation));

        module.apply_guardian_feedback(
            corrected_sender,
            corrected_conversation,
            GuardianVerdict::FalsePositive,
        );

        let state = module.export_memory();
        let corrected = state
            .senders
            .iter()
            .find(|sender| sender.sender_id == corrected_sender)
            .expect("the sender still has risk evidence in another conversation");
        assert_eq!(
            corrected.recent_high_risk_conversations,
            vec![unaffected_conversation.to_string()]
        );
        assert!(state.conversations.iter().any(|conversation| {
            conversation.conversation_id == corrected_conversation
                && conversation
                    .entries
                    .iter()
                    .any(|entry| entry.sender_id.as_deref() == Some(other_sender))
                && conversation
                    .entries
                    .iter()
                    .all(|entry| entry.sender_id.as_deref() != Some(corrected_sender))
        }));
        assert!(state.conversations.iter().any(|conversation| {
            conversation.conversation_id == unaffected_conversation
                && conversation
                    .entries
                    .iter()
                    .any(|entry| entry.sender_id.as_deref() == Some(corrected_sender))
        }));
    }

    #[test]
    fn blocked_feedback_does_not_forge_conversation_history() {
        let module = KidsModule::new();
        let blocked_sender = "blocked_sender";

        module.apply_guardian_feedback(
            blocked_sender,
            "reviewed_conversation",
            GuardianVerdict::Block,
        );

        let state = module.export_memory();
        let blocked = state
            .senders
            .iter()
            .find(|sender| sender.sender_id == blocked_sender)
            .expect("blocked sender state");
        assert!(blocked.guardian_blocked);
        assert!(blocked.recent_high_risk_conversations.is_empty());

        let output = module.analyze(&safe_input(blocked_sender, "new_conversation"));
        assert_eq!(output.action, Some(aura_domain::DomainAction::Block));
        assert!(has_reason(
            &output.signals,
            "kids.memory.guardian_blocked_sender"
        ));
    }

    #[test]
    fn guardian_feedback_scope_preserves_every_unrelated_pair() {
        let senders = ["scope_sender_a", "scope_sender_b", "scope_sender_c"];
        let conversations = ["scope_conv_a", "scope_conv_b", "scope_conv_c"];
        let trusted_sender = senders[1];
        let corrected_conversation = conversations[2];

        let trusted_module = KidsModule::new();
        let false_positive_module = KidsModule::new();
        for sender in senders {
            for conversation in conversations {
                let input = risky_input(sender, conversation);
                let _ = trusted_module.analyze(&input);
                let _ = false_positive_module.analyze(&input);
            }
        }

        let before = tracked_sender_conversation_pairs(&trusted_module);
        trusted_module.apply_guardian_feedback(
            trusted_sender,
            corrected_conversation,
            GuardianVerdict::Trusted,
        );
        let mut expected_after_trusted = Vec::new();
        for pair in &before {
            if pair.1.as_deref() != Some(trusted_sender) {
                expected_after_trusted.push(pair.clone());
            }
        }
        assert_eq!(
            tracked_sender_conversation_pairs(&trusted_module),
            expected_after_trusted
        );

        false_positive_module.apply_guardian_feedback(
            trusted_sender,
            corrected_conversation,
            GuardianVerdict::FalsePositive,
        );
        let mut expected_after_false_positive = Vec::new();
        for pair in before {
            if pair.0 != corrected_conversation || pair.1.as_deref() != Some(trusted_sender) {
                expected_after_false_positive.push(pair);
            }
        }
        assert_eq!(
            tracked_sender_conversation_pairs(&false_positive_module),
            expected_after_false_positive
        );
    }
}
