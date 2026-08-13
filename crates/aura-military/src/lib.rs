pub mod detectors;
mod lexicon;
pub mod pipeline;
pub mod policy;
mod routing;
mod temporal;
mod text;

#[cfg(feature = "evaluation")]
pub mod temporal_eval;
#[cfg(feature = "evaluation")]
pub mod temporal_review;
#[cfg(feature = "evaluation")]
pub mod temporal_review_packet;
#[cfg(feature = "shadow-telemetry")]
pub mod temporal_shadow_telemetry;
#[cfg(feature = "evaluation")]
pub mod temporal_study;

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
    DomainStudyResultReport, DomainStudyTrustPolicy, DomainTemporalInput, DomainTemporalOutput,
    DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
};

#[derive(Default)]
pub struct MilitaryModule;

/// Returns the exact Military policy identity without enabling temporal actions.
#[must_use]
pub fn domain_evidence() -> DomainModuleEvidence {
    DomainModuleEvidence {
        schema_version: DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
        module_id: DomainModuleId::Military,
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        stateful: false,
        state_schema_version: None,
        lexical_policy: lexicon::evidence(),
        temporal_policy: Some(temporal::evidence()),
    }
}

/// Validates a Military study against the exact policy packs in this build.
///
/// The shared validator rejects the preregistration unless the temporal pack
/// remains runtime-disabled, non-executable, and declared `shadow_only`.
/// `expected_build_provenance` must describe the actual evaluated binary;
/// repository seeds are injected before private seed digests are added.
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

/// Validates a signed Military result chain without enabling temporal actions.
///
/// The complete evidence chain is re-bound to this exact lexical and temporal
/// policy. The shared validator rejects any temporal runtime or action enablement.
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

/// Validates a private Military reproduction manifest without enabling policy.
///
/// The complete signed result chain is revalidated under this exact disabled
/// shadow policy. Success proves manifest consistency, not a completed rerun.
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

/// Validates one signed Military aggregate-recomputation attempt.
///
/// The original temporal policy remains disabled and shadow-only. No status
/// returned by this validator can enable runtime actions, establish a
/// new-sample scientific replication, or authorize private-data disclosure.
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

/// Validates a witnessed Military recomputation registry through one checkpoint.
///
/// The original temporal policy remains disabled and shadow-only. Success
/// establishes local integrity, prefix-state completeness, and append-only
/// continuity only for the submitted view. The caller must compare-and-swap
/// durably persist the report's `next_accepted_anchor` before relying on the
/// report or accepting another extension. Validation cannot rule out off-ledger
/// attempts, competing successors, or a split view. External witness publication
/// and durable retention remain operational gates.
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

impl DomainModule for MilitaryModule {
    fn id(&self) -> DomainModuleId {
        DomainModuleId::Military
    }

    fn evidence(&self) -> DomainModuleEvidence {
        domain_evidence()
    }

    fn detect(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_military_pipeline(input)
    }

    fn analyze(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_military_pipeline(input)
    }

    fn commit_confirmed(
        &self,
        _input: &DomainInput,
        confirmed_signals: &[DomainSignal],
    ) -> DomainConfirmedOutput {
        pipeline::commit_confirmed_military_pipeline(confirmed_signals)
    }

    fn temporal_enabled(&self) -> bool {
        temporal::temporal_enabled()
    }

    fn analyze_temporal(&self, input: &DomainTemporalInput) -> DomainTemporalOutput {
        temporal::run_military_temporal_pipeline(input)
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::domain_evidence;

    #[test]
    fn domain_evidence_keeps_temporal_policy_non_executable() {
        let evidence = domain_evidence();
        let temporal = evidence.temporal_policy.expect("military temporal policy");

        assert!(!evidence.stateful);
        assert_eq!(temporal.pack.rule_count, 3);
        assert_eq!(
            temporal.pack.sha256,
            "664830faa36ec2cf9846d612c02cb14d159a4a75ee925a3664f6147da0cc7348"
        );
        assert!(!temporal.runtime_enabled);
        assert!(!temporal.action_execution_configured);
    }
}
