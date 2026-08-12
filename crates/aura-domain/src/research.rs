//! Fail-closed preregistration for independent domain evaluation.
//!
//! This module binds a fixed corpus and analysis plan to the exact domain
//! policy evidence under study. Validation produces a pending binding, never a
//! claim that independent evidence already exists.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    is_canonical_sha256, validate_domain_module_evidence, DomainModuleEvidence, DomainModuleId,
};

/// Supported schema for independent-domain evaluation preregistrations.
pub const DOMAIN_STUDY_PREREGISTRATION_SCHEMA_VERSION: &str =
    "aura.domain.independent_evaluation_preregistration.v1";

/// Exact repository corpus digests that can never be claimed as independent.
///
/// The list covers the bundled curated, realistic, pilot, world-simulation,
/// lifecycle, and Military temporal seed corpora. Tests bind every entry to
/// its current source bytes.
pub const AURA_REPOSITORY_SEED_SHA256: &[&str] = &[
    "0ff33f84d723f8c1728f9b76598737e876bb30e7d01f3e47a0062c242832a73c",
    "1729afffd49482aa9aa9d663ede8983db2ef05164cc74771bfba5e2086f4cb21",
    "21932ea0c99cea71db60a46894c42d4d35eb155c5b1d62c57059e002668a291b",
    "236ad7b753343e964c6c49ad317b51c8f72113a6087f70cb2cf4f352bc3af736",
    "25ff98e4a8b71d6ae07b89131939b3c0df72e4f5ce59f7820a0a27f3ce85e64a",
    "346d58a06969978692295d168c85048400b0b3b03ce50ac6d91ee10ea907aadb",
    "3b84180a146435be7f7d6f42733df562c4d24a31acb7ec9f5a14483125d172ca",
    "3c7b5987ed4575365bb0dd16e6e73c56f4b23c808090e94f065f48fc95017430",
    "5762322c9e8a80bb18c28e8d7d9a791466b363e91b687975b247b97b57b61d1a",
    "6203fd2fd3f571c7a021e450e677d46eba5decea13db46bf8587752716a0f8d5",
    "7a758e34b77d6a2c999f8766aa52d127d71ddaaceb746b490a30953144511412",
    "83da53961b5ff1dc0e370343599a2bcf2a36562abe09620ab405f358a39c2498",
    "8533f2b56ce036cef4e305cc4275b2b45e4a813931f662c8e52c5875d15605f5",
    "8e520bb7eb7c88c1bb4a1f26cc2d6b5026a60b3440adc839a0e1ae3f06449045",
    "8fa24d71baf90edd6adeccb977a2a9052fe10cc562e146f109eff9fbc53a19c1",
    "9a7a864c523eea9b8459f3cadc39e03a29659c836983b073ecb617e7808fa882",
    "9dcb82d726e6fda878fb0e6c6699b553ccced4cfcf6c4b18792326d037710297",
    "a4d61c99d8a55f8a825ad1095987d7874d32a83db7344b8198902b3bea097396",
    "a588ecf6e0e077999755efea4464c669f2c591f33e61e019ef517f24d594d909",
    "b89c36e8a15d9082eb3bf53316399d897d22ae4f2cf39145f0e12eec84cdf5af",
    "b92df9b98fc13815a72f8129fc35b382869231c86ee0e93d3b15ab728d644fef",
    "c82c9e9f0b5a9d2d323f1b411f28707894555b9a028b74d8c133bc551667d8c8",
    "ca502f671dccaa6d712751c71d6b77a12e7b8c1ad88613a4e9f4fc83afba3d2d",
    "cce2c696d776bfd6ab6ee84591699a37d3efaaf1df3e090fc172643c062adc26",
    "e81a7fcf819c6208e871120289ce20fd012a6d11a32ef1a829521deb94d6c01c",
    "f503181000062caaa39d1af07729d31aa0f73eb77a802697ff683b893faefc4b",
];

/// Error returned when an independent-domain preregistration is not admissible.
#[derive(Debug, Error)]
pub enum DomainStudyError {
    /// The supplied document is not valid JSON for the strict schema.
    #[error("invalid domain-study preregistration JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// The parsed document violates a preregistered-study invariant.
    #[error("invalid domain-study preregistration: {0}")]
    InvalidPreregistration(String),
}

/// Provenance class declared for the fixed evaluation corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyCorpusClass {
    /// Public or repository-owned material used only for engineering checks.
    RepositorySeed,
    /// Internally curated material that cannot establish independent validity.
    CuratedInternal,
    /// Material sampled and governed outside the implementation team.
    IndependentExternal,
}

/// Fixed temporal-policy operating mode for the study.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyTemporalMode {
    /// The evaluated module has no temporal policy.
    NotApplicable,
    /// Temporal decisions may be measured but cannot execute product actions.
    ShadowOnly,
}

/// Confirmatory outcome families that must be fixed before labels are seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyPrimaryOutcome {
    /// Macro-averaged F1 across prespecified threat families.
    MacroF1,
    /// Recall reported for every prespecified threat family.
    PerThreatRecall,
    /// False-positive rate on prespecified safe-boundary cases.
    SafeBoundaryFalsePositiveRate,
    /// Decision consistency across prespecified attack variants.
    AttackVariantConsistencyRate,
}

/// Prespecified handling of incomplete review decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyMissingDataRule {
    /// Do not impute; publish incomplete counts and keep the study non-passing.
    NoImputationReportIncomplete,
}

/// Ceiling on the claim supported immediately after preregistration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyReadiness {
    /// The corpus can support only deterministic engineering regression claims.
    EngineeringOnly,
    /// The external protocol is bound, but independent evidence is still absent.
    IndependentEvidencePending,
}

/// One falsifiable hypothesis fixed before evaluation labels are collected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyHypothesis {
    /// Stable ASCII identifier sorted with the other hypotheses.
    pub hypothesis_id: String,
    /// Human-readable, testable prediction.
    pub statement: String,
}

/// Immutable source and binary provenance for the executable under study.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyBuildProvenance {
    /// Full lowercase Git commit identity.
    pub git_revision: String,
    /// Deterministic digest of the evaluated source tree.
    pub source_tree_sha256: String,
    /// Digest of the exact Cargo.lock used for the build.
    pub cargo_lock_sha256: String,
    /// Digest of the pinned Rust toolchain manifest or descriptor.
    pub rust_toolchain_sha256: String,
    /// Rust target triple used for evaluation.
    pub target_triple: String,
    /// Cargo profile used for evaluation.
    pub cargo_profile: String,
    /// Exact enabled feature set; values must be unique and sorted.
    pub feature_set: Vec<String>,
    /// Digest of the exact executable or linked library under evaluation.
    pub binary_sha256: String,
    /// Must be true: confirmatory builds cannot contain uncommitted sources.
    pub source_tree_clean: bool,
}

/// Identity, provenance, and privacy constraints for the frozen corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyDatasetPlan {
    /// Stable dataset identity.
    pub dataset_id: String,
    /// Declared corpus provenance class.
    pub corpus_class: DomainStudyCorpusClass,
    /// SHA-256 of the exact canonical corpus bytes.
    pub corpus_sha256: String,
    /// Number of cases fixed before evaluation begins.
    pub fixed_case_count: usize,
    /// SHA-256 of the frozen inclusion criteria.
    pub inclusion_criteria_sha256: String,
    /// SHA-256 of the frozen exclusion criteria.
    pub exclusion_criteria_sha256: String,
    /// SHA-256 of the frozen threat-label ontology and decision rules.
    pub label_ontology_sha256: String,
    /// SHA-256 of the frozen safe-boundary definition and examples policy.
    pub safe_boundary_definition_sha256: String,
    /// Threat families whose recall must be reported; sorted and unique.
    pub required_threat_families: Vec<String>,
    /// Minimum labeled cases required for every threat family.
    pub minimum_cases_per_threat_family: usize,
    /// Minimum prespecified safe-boundary controls.
    pub minimum_safe_boundary_cases: usize,
    /// Prespecified strata; values must be unique and sorted.
    pub required_strata: Vec<String>,
    /// Prospective sample-size or precision rationale.
    pub a_priori_sample_size_rationale: String,
    /// Whether the sampling frame is governed outside the implementation team.
    pub independent_sampling_frame: bool,
    /// Whether identities or trajectories are disjoint across evaluation splits.
    pub identity_disjoint_splits: bool,
    /// Whether implementers are denied confirmatory labels until policy freeze.
    pub labels_hidden_from_implementers_until_policy_freeze: bool,
    /// Must remain false for public/release evidence artifacts.
    pub raw_content_exported_in_public_evidence: bool,
    /// Digest of the repository and caller-supplied known-seed registry.
    pub known_seed_registry_sha256: String,
}

/// Fixed attack-variation coverage for robustness evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAttackPlan {
    /// Prespecified attack families; values must be unique and sorted.
    pub attack_families: Vec<String>,
    /// Exact total number of variants to be evaluated.
    pub fixed_variant_count: usize,
    /// Minimum support required for every attack family.
    pub minimum_variants_per_family: usize,
    /// SHA-256 of the frozen generator or construction manifest.
    pub construction_manifest_sha256: String,
    /// Whether variants remain in the split of their source trajectory.
    pub source_case_split_locked: bool,
}

/// Independence and privacy requirements for human review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReviewPlan {
    /// Minimum independent reviewers required for every case.
    pub minimum_reviewers_per_case: usize,
    /// Maximum reviewers permitted for one case.
    pub maximum_reviewers_per_case: usize,
    /// Whether reviewers must come from distinct affiliations.
    pub distinct_reviewer_affiliations: bool,
    /// Whether adjudication must be performed by a separate person.
    pub independent_adjudicator: bool,
    /// Whether reviewers are blinded to machine outputs and seed labels.
    pub machine_output_and_seed_label_blinding: bool,
    /// Whether reviewer decisions are frozen before adjudication.
    pub labels_frozen_before_adjudication: bool,
    /// Whether inter-rater agreement must be reported.
    pub inter_rater_agreement_reported: bool,
    /// Must remain false for public aggregate evidence.
    pub reviewer_identifiers_exported: bool,
}

/// Fixed outcome thresholds and anti-bias analysis decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAnalysisPlan {
    /// Exact required primary outcomes in enum order.
    pub primary_outcomes: Vec<DomainStudyPrimaryOutcome>,
    /// Minimum acceptable macro F1.
    pub minimum_macro_f1: f64,
    /// Minimum acceptable recall for every required threat family.
    pub minimum_per_threat_recall: f64,
    /// Maximum acceptable safe-boundary false-positive rate.
    pub maximum_safe_boundary_false_positive_rate: f64,
    /// Minimum acceptable consistency across attack variants.
    pub minimum_attack_variant_consistency_rate: f64,
    /// Minimum acceptable inter-rater agreement for confirmatory review.
    pub minimum_inter_rater_agreement: f64,
    /// Prespecified handling of incomplete review decisions.
    pub missing_data_rule: DomainStudyMissingDataRule,
    /// Whether exploratory analyses are explicitly separated from confirmation.
    pub exploratory_analyses_reported_separately: bool,
    /// Whether every exclusion and protocol deviation is reported.
    pub all_exclusions_and_deviations_reported: bool,
    /// Must be true: the fixed corpus cannot grow until a threshold passes.
    pub fixed_corpus_no_optional_stopping: bool,
}

/// Strict preregistration bound to one exact domain implementation and corpus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyPreregistration {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Declared registration time in Unix milliseconds.
    pub registered_at_ms: u64,
    /// Domain under study.
    pub domain: DomainModuleId,
    /// Exact release evidence returned by the domain implementation under test.
    pub policy_evidence: DomainModuleEvidence,
    /// Exact source, toolchain, and binary identity under test.
    pub build_provenance: DomainStudyBuildProvenance,
    /// Temporal execution boundary for the study.
    pub temporal_mode: DomainStudyTemporalMode,
    /// Falsifiable confirmatory hypotheses sorted by identifier.
    pub confirmatory_hypotheses: Vec<DomainStudyHypothesis>,
    /// Frozen dataset plan.
    pub dataset: DomainStudyDatasetPlan,
    /// Frozen adversarial-variation plan.
    pub attacks: DomainStudyAttackPlan,
    /// Frozen human-review plan.
    pub review: DomainStudyReviewPlan,
    /// Frozen analysis plan.
    pub analysis: DomainStudyAnalysisPlan,
}

/// Content-free identity emitted after a preregistration passes validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyBinding {
    /// Stable study identity.
    pub study_id: String,
    /// Declared registration time in Unix milliseconds.
    pub registered_at_ms: u64,
    /// Domain under study.
    pub domain: DomainModuleId,
    /// Declared corpus provenance class.
    pub corpus_class: DomainStudyCorpusClass,
    /// SHA-256 of the canonical parsed preregistration.
    pub preregistration_canonical_sha256: String,
    /// SHA-256 of the exact corpus.
    pub corpus_sha256: String,
    /// SHA-256 of the canonical exact domain policy evidence.
    pub policy_evidence_canonical_sha256: String,
    /// SHA-256 of the canonical exact build provenance.
    pub build_provenance_canonical_sha256: String,
    /// SHA-256 of the complete known-seed registry used by validation.
    pub known_seed_registry_sha256: String,
    /// Fixed temporal execution boundary.
    pub temporal_mode: DomainStudyTemporalMode,
    /// Maximum claim supported before review results are supplied.
    pub readiness: DomainStudyReadiness,
}

/// Validates and binds one preregistration to the exact domain policy evidence.
///
/// Repository seeds are always included. `additional_known_seed_sha256` adds
/// private synthetic, pilot-tuning, or prior evaluation corpora. The exact
/// combined registry is bound into the preregistration, and an
/// `independent_external` corpus is rejected if it matches any entry. The
/// returned readiness is never a passing research result.
pub fn validate_domain_study_preregistration(
    preregistration_json: &str,
    expected_policy_evidence: &DomainModuleEvidence,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
) -> Result<DomainStudyBinding, DomainStudyError> {
    let preregistration: DomainStudyPreregistration = serde_json::from_str(preregistration_json)?;
    validate_preregistration(
        &preregistration,
        expected_policy_evidence,
        expected_build_provenance,
        additional_known_seed_sha256,
    )?;

    Ok(DomainStudyBinding {
        study_id: preregistration.study_id.clone(),
        registered_at_ms: preregistration.registered_at_ms,
        domain: preregistration.domain,
        corpus_class: preregistration.dataset.corpus_class,
        preregistration_canonical_sha256: canonical_sha256(&preregistration)?,
        corpus_sha256: preregistration.dataset.corpus_sha256.clone(),
        policy_evidence_canonical_sha256: canonical_sha256(expected_policy_evidence)?,
        build_provenance_canonical_sha256: canonical_sha256(expected_build_provenance)?,
        known_seed_registry_sha256: preregistration.dataset.known_seed_registry_sha256.clone(),
        temporal_mode: preregistration.temporal_mode,
        readiness: match preregistration.dataset.corpus_class {
            DomainStudyCorpusClass::IndependentExternal => {
                DomainStudyReadiness::IndependentEvidencePending
            }
            DomainStudyCorpusClass::RepositorySeed | DomainStudyCorpusClass::CuratedInternal => {
                DomainStudyReadiness::EngineeringOnly
            }
        },
    })
}

fn validate_preregistration(
    preregistration: &DomainStudyPreregistration,
    expected_policy_evidence: &DomainModuleEvidence,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
) -> Result<(), DomainStudyError> {
    if preregistration.schema_version != DOMAIN_STUDY_PREREGISTRATION_SCHEMA_VERSION {
        return invalid("preregistration schema is unsupported");
    }
    if !safe_token(&preregistration.study_id) || preregistration.registered_at_ms == 0 {
        return invalid("study identity fields are invalid");
    }
    validate_domain_module_evidence(expected_policy_evidence)
        .map_err(|error| DomainStudyError::InvalidPreregistration(error.to_string()))?;
    if preregistration.domain != expected_policy_evidence.module_id
        || preregistration.policy_evidence != *expected_policy_evidence
    {
        return invalid("preregistration is not bound to the exact domain policy evidence");
    }
    validate_build_provenance(expected_build_provenance)?;
    if preregistration.build_provenance != *expected_build_provenance {
        return invalid("preregistration is not bound to the exact executable build provenance");
    }
    validate_temporal_mode(preregistration)?;
    validate_hypotheses(&preregistration.confirmatory_hypotheses)?;
    validate_dataset(&preregistration.dataset, additional_known_seed_sha256)?;
    validate_attacks(&preregistration.attacks)?;
    validate_review(&preregistration.review)?;
    validate_analysis(&preregistration.analysis)
}

fn validate_build_provenance(
    provenance: &DomainStudyBuildProvenance,
) -> Result<(), DomainStudyError> {
    if !is_git_revision(&provenance.git_revision)
        || !is_canonical_sha256(&provenance.source_tree_sha256)
        || !is_canonical_sha256(&provenance.cargo_lock_sha256)
        || !is_canonical_sha256(&provenance.rust_toolchain_sha256)
        || !is_canonical_sha256(&provenance.binary_sha256)
        || !safe_token(&provenance.target_triple)
        || !safe_token(&provenance.cargo_profile)
        || !provenance.source_tree_clean
    {
        return invalid("build provenance identity or clean-source assurance is invalid");
    }
    validate_sorted_tokens("build feature", &provenance.feature_set, 1, 64)
}

fn validate_temporal_mode(
    preregistration: &DomainStudyPreregistration,
) -> Result<(), DomainStudyError> {
    match (
        preregistration.policy_evidence.temporal_policy.as_ref(),
        preregistration.temporal_mode,
    ) {
        (None, DomainStudyTemporalMode::NotApplicable) => Ok(()),
        (Some(temporal), DomainStudyTemporalMode::ShadowOnly)
            if !temporal.runtime_enabled && !temporal.action_execution_configured =>
        {
            Ok(())
        }
        (Some(_), DomainStudyTemporalMode::ShadowOnly) => {
            invalid("temporal study policy must remain runtime-disabled and non-executable")
        }
        _ => invalid("temporal mode does not match domain policy evidence"),
    }
}

fn validate_hypotheses(hypotheses: &[DomainStudyHypothesis]) -> Result<(), DomainStudyError> {
    if !(1..=16).contains(&hypotheses.len()) {
        return invalid("confirmatory hypothesis count must be within 1..=16");
    }
    let mut previous = None;
    for hypothesis in hypotheses {
        if !safe_token(&hypothesis.hypothesis_id)
            || !(16..=1_000).contains(&hypothesis.statement.trim().chars().count())
            || previous.is_some_and(|value: &str| value >= hypothesis.hypothesis_id.as_str())
        {
            return invalid("confirmatory hypotheses must be valid, unique, and sorted");
        }
        previous = Some(hypothesis.hypothesis_id.as_str());
    }
    Ok(())
}

fn validate_dataset(
    dataset: &DomainStudyDatasetPlan,
    additional_known_seed_sha256: &[&str],
) -> Result<(), DomainStudyError> {
    if !safe_token(&dataset.dataset_id)
        || !is_canonical_sha256(&dataset.corpus_sha256)
        || !is_canonical_sha256(&dataset.inclusion_criteria_sha256)
        || !is_canonical_sha256(&dataset.exclusion_criteria_sha256)
        || !is_canonical_sha256(&dataset.label_ontology_sha256)
        || !is_canonical_sha256(&dataset.safe_boundary_definition_sha256)
        || !(30..=1_000_000).contains(&dataset.fixed_case_count)
        || dataset.minimum_cases_per_threat_family < 5
        || dataset.minimum_cases_per_threat_family > dataset.fixed_case_count
        || dataset.minimum_safe_boundary_cases < 10
        || dataset.minimum_safe_boundary_cases > dataset.fixed_case_count
        || !(32..=2_000).contains(
            &dataset
                .a_priori_sample_size_rationale
                .trim()
                .chars()
                .count(),
        )
        || dataset.raw_content_exported_in_public_evidence
    {
        return invalid("dataset identity, size rationale, or privacy fields are invalid");
    }
    validate_sorted_tokens(
        "required threat family",
        &dataset.required_threat_families,
        2,
        64,
    )?;
    validate_sorted_tokens("required stratum", &dataset.required_strata, 2, 64)?;

    let expected_registry_sha256 = domain_study_seed_registry_sha256(additional_known_seed_sha256)?;
    if dataset.known_seed_registry_sha256 != expected_registry_sha256 {
        return invalid("known-seed registry does not match repository and supplied seed digests");
    }

    if dataset.corpus_class == DomainStudyCorpusClass::IndependentExternal {
        if AURA_REPOSITORY_SEED_SHA256
            .iter()
            .chain(additional_known_seed_sha256.iter())
            .any(|seed| *seed == dataset.corpus_sha256)
        {
            return invalid("independent external corpus matches a known seed corpus");
        }
        if !dataset.independent_sampling_frame
            || !dataset.identity_disjoint_splits
            || !dataset.labels_hidden_from_implementers_until_policy_freeze
        {
            return invalid("external corpus does not satisfy independence and leakage controls");
        }
    }
    Ok(())
}

fn validate_attacks(attacks: &DomainStudyAttackPlan) -> Result<(), DomainStudyError> {
    validate_sorted_tokens("attack family", &attacks.attack_families, 3, 32)?;
    if !is_canonical_sha256(&attacks.construction_manifest_sha256)
        || attacks.minimum_variants_per_family < 5
        || attacks.fixed_variant_count
            < attacks
                .attack_families
                .len()
                .saturating_mul(attacks.minimum_variants_per_family)
        || attacks.fixed_variant_count > 10_000_000
        || !attacks.source_case_split_locked
    {
        return invalid("attack-variation plan is incomplete or inconsistent");
    }
    Ok(())
}

fn validate_review(review: &DomainStudyReviewPlan) -> Result<(), DomainStudyError> {
    if !(2..=5).contains(&review.minimum_reviewers_per_case)
        || !(review.minimum_reviewers_per_case..=5).contains(&review.maximum_reviewers_per_case)
        || !review.distinct_reviewer_affiliations
        || !review.independent_adjudicator
        || !review.machine_output_and_seed_label_blinding
        || !review.labels_frozen_before_adjudication
        || !review.inter_rater_agreement_reported
        || review.reviewer_identifiers_exported
    {
        return invalid("human-review plan does not satisfy separation or privacy requirements");
    }
    Ok(())
}

fn validate_analysis(analysis: &DomainStudyAnalysisPlan) -> Result<(), DomainStudyError> {
    let required = [
        DomainStudyPrimaryOutcome::MacroF1,
        DomainStudyPrimaryOutcome::PerThreatRecall,
        DomainStudyPrimaryOutcome::SafeBoundaryFalsePositiveRate,
        DomainStudyPrimaryOutcome::AttackVariantConsistencyRate,
    ];
    if analysis.primary_outcomes != required
        || !high_assurance_floor(analysis.minimum_macro_f1)
        || !high_assurance_floor(analysis.minimum_per_threat_recall)
        || !low_false_positive_ceiling(analysis.maximum_safe_boundary_false_positive_rate)
        || !high_assurance_floor(analysis.minimum_attack_variant_consistency_rate)
        || !high_assurance_floor(analysis.minimum_inter_rater_agreement)
        || analysis.missing_data_rule != DomainStudyMissingDataRule::NoImputationReportIncomplete
        || !analysis.exploratory_analyses_reported_separately
        || !analysis.all_exclusions_and_deviations_reported
        || !analysis.fixed_corpus_no_optional_stopping
    {
        return invalid("analysis plan does not satisfy fixed high-assurance requirements");
    }
    Ok(())
}

fn validate_sorted_tokens(
    label: &str,
    values: &[String],
    minimum: usize,
    maximum: usize,
) -> Result<(), DomainStudyError> {
    if !(minimum..=maximum).contains(&values.len())
        || values.iter().any(|value| !safe_label_token(value))
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return invalid(format!("{label} values must be valid, unique, and sorted"));
    }
    Ok(())
}

/// Returns the canonical digest of all built-in and caller-supplied seed digests.
///
/// The order of caller input does not affect the result. Malformed digests are
/// rejected, and duplicates collapse to one registry entry.
pub fn domain_study_seed_registry_sha256(
    additional_known_seed_sha256: &[&str],
) -> Result<String, DomainStudyError> {
    if additional_known_seed_sha256
        .iter()
        .any(|digest| !is_canonical_sha256(digest))
    {
        return invalid("additional known-seed registry contains a malformed SHA-256 digest");
    }
    let registry = AURA_REPOSITORY_SEED_SHA256
        .iter()
        .copied()
        .chain(additional_known_seed_sha256.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    canonical_sha256(&registry)
}

fn high_assurance_floor(value: f64) -> bool {
    value.is_finite() && (0.8..=1.0).contains(&value)
}

fn low_false_positive_ceiling(value: f64) -> bool {
    value.is_finite() && (0.0..=0.1).contains(&value)
}

fn safe_token(value: &str) -> bool {
    let length = value.len();
    (1..=128).contains(&length)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn safe_label_token(value: &str) -> bool {
    safe_token(value) && value.len() <= 64
}

fn is_git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, DomainStudyError> {
    let digest = Sha256::digest(serde_json::to_vec(value)?);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DomainStudyError> {
    Err(DomainStudyError::InvalidPreregistration(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DomainPolicyPackEvidence, DomainTemporalPolicyEvidence,
        DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
    };

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SHA_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn evidence(module_id: DomainModuleId, temporal: bool) -> DomainModuleEvidence {
        DomainModuleEvidence {
            schema_version: DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
            module_id,
            module_version: "0.1.0".to_string(),
            stateful: module_id == DomainModuleId::Kids,
            state_schema_version: (module_id == DomainModuleId::Kids).then_some(2),
            lexical_policy: DomainPolicyPackEvidence {
                pack_id: "test.lexical.v1".to_string(),
                schema_version: 1,
                sha256: SHA_A.to_string(),
                rule_count: 12,
            },
            temporal_policy: temporal.then(|| DomainTemporalPolicyEvidence {
                pack: DomainPolicyPackEvidence {
                    pack_id: "test.temporal.v1".to_string(),
                    schema_version: 1,
                    sha256: SHA_B.to_string(),
                    rule_count: 3,
                },
                runtime_enabled: false,
                action_execution_configured: false,
            }),
        }
    }

    fn build_provenance() -> DomainStudyBuildProvenance {
        DomainStudyBuildProvenance {
            git_revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
            source_tree_sha256: SHA_A.to_string(),
            cargo_lock_sha256: SHA_B.to_string(),
            rust_toolchain_sha256: SHA_C.to_string(),
            target_triple: "aarch64-apple-ios".to_string(),
            cargo_profile: "release".to_string(),
            feature_set: vec!["default".to_string()],
            binary_sha256: SHA_D.to_string(),
            source_tree_clean: true,
        }
    }

    fn preregistration(
        policy: DomainModuleEvidence,
        build_provenance: DomainStudyBuildProvenance,
    ) -> DomainStudyPreregistration {
        DomainStudyPreregistration {
            schema_version: DOMAIN_STUDY_PREREGISTRATION_SCHEMA_VERSION.to_string(),
            study_id: "domain_study_2026_01".to_string(),
            registered_at_ms: 1_780_000_000_000,
            domain: policy.module_id,
            temporal_mode: if policy.temporal_policy.is_some() {
                DomainStudyTemporalMode::ShadowOnly
            } else {
                DomainStudyTemporalMode::NotApplicable
            },
            policy_evidence: policy,
            build_provenance,
            confirmatory_hypotheses: vec![DomainStudyHypothesis {
                hypothesis_id: "h1_primary".to_string(),
                statement: "The frozen domain policy meets every prespecified primary threshold."
                    .to_string(),
            }],
            dataset: DomainStudyDatasetPlan {
                dataset_id: "external_domain_corpus_2026_01".to_string(),
                corpus_class: DomainStudyCorpusClass::IndependentExternal,
                corpus_sha256: SHA_B.to_string(),
                fixed_case_count: 120,
                inclusion_criteria_sha256: SHA_C.to_string(),
                exclusion_criteria_sha256: SHA_D.to_string(),
                label_ontology_sha256: SHA_A.to_string(),
                safe_boundary_definition_sha256: SHA_B.to_string(),
                required_threat_families: vec!["grooming".to_string(), "self_harm".to_string()],
                minimum_cases_per_threat_family: 20,
                minimum_safe_boundary_cases: 20,
                required_strata: vec!["high_risk".to_string(), "safe_boundary".to_string()],
                a_priori_sample_size_rationale:
                    "Fixed precision target and per-threat minimum support were set before review."
                        .to_string(),
                independent_sampling_frame: true,
                identity_disjoint_splits: true,
                labels_hidden_from_implementers_until_policy_freeze: true,
                raw_content_exported_in_public_evidence: false,
                known_seed_registry_sha256: domain_study_seed_registry_sha256(&[])
                    .expect("built-in seed registry"),
            },
            attacks: DomainStudyAttackPlan {
                attack_families: vec![
                    "code_switching".to_string(),
                    "orthographic_noise".to_string(),
                    "paraphrase".to_string(),
                ],
                fixed_variant_count: 60,
                minimum_variants_per_family: 20,
                construction_manifest_sha256: SHA_C.to_string(),
                source_case_split_locked: true,
            },
            review: DomainStudyReviewPlan {
                minimum_reviewers_per_case: 2,
                maximum_reviewers_per_case: 5,
                distinct_reviewer_affiliations: true,
                independent_adjudicator: true,
                machine_output_and_seed_label_blinding: true,
                labels_frozen_before_adjudication: true,
                inter_rater_agreement_reported: true,
                reviewer_identifiers_exported: false,
            },
            analysis: DomainStudyAnalysisPlan {
                primary_outcomes: vec![
                    DomainStudyPrimaryOutcome::MacroF1,
                    DomainStudyPrimaryOutcome::PerThreatRecall,
                    DomainStudyPrimaryOutcome::SafeBoundaryFalsePositiveRate,
                    DomainStudyPrimaryOutcome::AttackVariantConsistencyRate,
                ],
                minimum_macro_f1: 0.8,
                minimum_per_threat_recall: 0.8,
                maximum_safe_boundary_false_positive_rate: 0.05,
                minimum_attack_variant_consistency_rate: 0.8,
                minimum_inter_rater_agreement: 0.8,
                missing_data_rule: DomainStudyMissingDataRule::NoImputationReportIncomplete,
                exploratory_analyses_reported_separately: true,
                all_exclusions_and_deviations_reported: true,
                fixed_corpus_no_optional_stopping: true,
            },
        }
    }

    fn json(value: &DomainStudyPreregistration) -> String {
        serde_json::to_string(value).expect("serialize preregistration")
    }

    #[test]
    fn external_preregistration_is_bound_but_evidence_remains_pending() {
        let policy = evidence(DomainModuleId::Kids, false);
        let build = build_provenance();
        let binding = validate_domain_study_preregistration(
            &json(&preregistration(policy.clone(), build.clone())),
            &policy,
            &build,
            &[],
        )
        .expect("valid external preregistration");

        assert_eq!(
            binding.readiness,
            DomainStudyReadiness::IndependentEvidencePending
        );
        assert_eq!(
            binding.temporal_mode,
            DomainStudyTemporalMode::NotApplicable
        );
        assert_eq!(binding.preregistration_canonical_sha256.len(), 64);
        assert_eq!(binding.build_provenance_canonical_sha256.len(), 64);
    }

    #[test]
    fn repository_seed_registry_is_bound_to_exact_source_bytes() {
        let sources: &[&[u8]] = &[
            include_bytes!("../../aura-core/data/corpus_curated_cases.json"),
            include_bytes!("../../aura-core/data/corpus_style_profiles.json"),
            include_bytes!("../../aura-core/data/external_curated_chat_cases.json"),
            include_bytes!("../../aura-core/data/pilot_simulation_regression_cases.json"),
            include_bytes!("../../aura-core/data/realistic_chat_cases.json"),
            include_bytes!("../../aura-core/data/world_sim_13yo_6mo.json"),
            include_bytes!("../../aura-core/data/world_sim_2k.json"),
            include_bytes!("../../aura-core/data/world_sim_demo.json"),
            include_bytes!("../../aura-core/data/world_sim_kids_memory_stress.json"),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/anastasia_12_to_14_clean_negative_2y.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/andrii_14_peer_blackmail_recovery_4mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/andrii_36_military_fake_recruiter_simple_4mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/denys_13_safe_adult_negative_5mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/dmytro_41_multi_vector_recruitment_network_6mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/ira_15_artist_slow_grooming_6mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/kateryna_16_recruitment_pressure_9mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/lev_10_gaming_scam_grooming_1y.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/liza_14_multilingual_creator_18mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/maksym_11_bullying_selfharm_4mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/maria_12_public_comments_phishing_pii_3mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/mykola_12_public_unknown_adult_network_1y.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/olena_09_game_3mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/olena_32_spec_service_recruitment_simple_4mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/serhiy_24_gang_recruitment_simple_3mo.json"
            ),
            include_bytes!(
                "../../aura-core/data/world_lifecycle_suite/sofia_13_to_15_dense_2y.json"
            ),
            include_bytes!("../../aura-military/data/temporal_shadow_corpus.json"),
        ];
        let mut actual = sources
            .iter()
            .map(|source| {
                Sha256::digest(source)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        actual.sort();

        assert_eq!(actual, AURA_REPOSITORY_SEED_SHA256);
    }

    #[test]
    fn caller_seed_registry_must_be_bound_into_preregistration() {
        let policy = evidence(DomainModuleId::Kids, false);
        let build = build_provenance();
        let error = validate_domain_study_preregistration(
            &json(&preregistration(policy.clone(), build.clone())),
            &policy,
            &build,
            &[SHA_C],
        )
        .expect_err("unbound additional seed registry must fail");

        assert!(error.to_string().contains("known-seed registry"));
    }

    #[test]
    fn executable_build_drift_invalidates_preregistration() {
        let policy = evidence(DomainModuleId::Kids, false);
        let registered_build = build_provenance();
        let mut actual_build = registered_build.clone();
        actual_build.binary_sha256 = SHA_A.to_string();

        let error = validate_domain_study_preregistration(
            &json(&preregistration(policy.clone(), registered_build)),
            &policy,
            &actual_build,
            &[],
        )
        .expect_err("binary drift must fail");

        assert!(error.to_string().contains("exact executable build"));
    }

    #[test]
    fn known_seed_cannot_be_declared_independent_external() {
        let policy = evidence(DomainModuleId::Kids, false);
        let build = build_provenance();
        let mut study = preregistration(policy.clone(), build.clone());
        study.dataset.corpus_sha256 = AURA_REPOSITORY_SEED_SHA256[0].to_string();
        let error = validate_domain_study_preregistration(&json(&study), &policy, &build, &[])
            .expect_err("known seed claim must fail");

        assert!(error.to_string().contains("known seed"));
    }

    #[test]
    fn policy_drift_invalidates_preregistration() {
        let policy = evidence(DomainModuleId::Kids, false);
        let build = build_provenance();
        let mut current = policy.clone();
        current.lexical_policy.sha256 = SHA_D.to_string();

        let error = validate_domain_study_preregistration(
            &json(&preregistration(policy, build.clone())),
            &current,
            &build,
            &[],
        )
        .expect_err("policy drift must fail");

        assert!(error.to_string().contains("exact domain policy evidence"));
    }

    #[test]
    fn military_temporal_policy_is_accepted_only_as_disabled_shadow() {
        let policy = evidence(DomainModuleId::Military, true);
        let build = build_provenance();
        validate_domain_study_preregistration(
            &json(&preregistration(policy.clone(), build.clone())),
            &policy,
            &build,
            &[],
        )
        .expect("disabled shadow temporal policy");

        let mut active_policy = policy.clone();
        active_policy
            .temporal_policy
            .as_mut()
            .expect("temporal evidence")
            .runtime_enabled = true;
        let error = validate_domain_study_preregistration(
            &json(&preregistration(active_policy.clone(), build.clone())),
            &active_policy,
            &build,
            &[],
        )
        .expect_err("active temporal runtime must fail");

        assert!(error.to_string().contains("runtime-disabled"));
    }

    #[test]
    fn optional_stopping_is_rejected() {
        let policy = evidence(DomainModuleId::Kids, false);
        let build = build_provenance();
        let mut study = preregistration(policy.clone(), build.clone());
        study.analysis.fixed_corpus_no_optional_stopping = false;

        let error = validate_domain_study_preregistration(&json(&study), &policy, &build, &[])
            .expect_err("optional stopping must fail");

        assert!(error.to_string().contains("analysis plan"));
    }

    #[test]
    fn internal_corpus_can_never_exceed_engineering_readiness() {
        let policy = evidence(DomainModuleId::Kids, false);
        let build = build_provenance();
        let mut study = preregistration(policy.clone(), build.clone());
        study.dataset.corpus_class = DomainStudyCorpusClass::CuratedInternal;
        study.dataset.independent_sampling_frame = false;
        study
            .dataset
            .labels_hidden_from_implementers_until_policy_freeze = false;

        let binding = validate_domain_study_preregistration(&json(&study), &policy, &build, &[])
            .expect("valid internal protocol");

        assert_eq!(binding.readiness, DomainStudyReadiness::EngineeringOnly);
    }
}
