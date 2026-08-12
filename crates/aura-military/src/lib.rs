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
    validate_domain_study_preregistration, DomainConfirmedOutput, DomainInput, DomainModule,
    DomainModuleEvidence, DomainModuleId, DomainOutput, DomainSignal, DomainStudyBinding,
    DomainStudyBuildProvenance, DomainStudyError, DomainTemporalInput, DomainTemporalOutput,
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
