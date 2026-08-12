//! Fail-closed preregistration for independent domain evaluation.
//!
//! This module binds a fixed corpus and analysis plan to the exact domain
//! policy evidence under study. Validation produces a pending binding, never a
//! claim that independent evidence already exists.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{DomainModuleEvidence, DomainModuleId, DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION};

/// Supported schema for independent-domain evaluation preregistrations.
pub const DOMAIN_STUDY_PREREGISTRATION_SCHEMA_VERSION: &str =
    "aura.domain.independent_evaluation_preregistration.v1";

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
    /// Fixed temporal execution boundary.
    pub temporal_mode: DomainStudyTemporalMode,
    /// Maximum claim supported before review results are supplied.
    pub readiness: DomainStudyReadiness,
}

/// Validates and binds one preregistration to the exact domain policy evidence.
///
/// `known_seed_sha256` contains repository, synthetic, or tuning-corpus
/// digests. An `independent_external` preregistration is rejected if its corpus
/// matches any known seed. The returned readiness is never a passing research
/// result.
pub fn validate_domain_study_preregistration(
    preregistration_json: &str,
    expected_policy_evidence: &DomainModuleEvidence,
    known_seed_sha256: &[&str],
) -> Result<DomainStudyBinding, DomainStudyError> {
    let preregistration: DomainStudyPreregistration = serde_json::from_str(preregistration_json)?;
    validate_preregistration(
        &preregistration,
        expected_policy_evidence,
        known_seed_sha256,
    )?;

    Ok(DomainStudyBinding {
        study_id: preregistration.study_id.clone(),
        registered_at_ms: preregistration.registered_at_ms,
        domain: preregistration.domain,
        corpus_class: preregistration.dataset.corpus_class,
        preregistration_canonical_sha256: canonical_sha256(&preregistration)?,
        corpus_sha256: preregistration.dataset.corpus_sha256.clone(),
        policy_evidence_canonical_sha256: canonical_sha256(expected_policy_evidence)?,
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
    known_seed_sha256: &[&str],
) -> Result<(), DomainStudyError> {
    if preregistration.schema_version != DOMAIN_STUDY_PREREGISTRATION_SCHEMA_VERSION {
        return invalid("preregistration schema is unsupported");
    }
    if !safe_token(&preregistration.study_id) || preregistration.registered_at_ms == 0 {
        return invalid("study identity fields are invalid");
    }
    validate_expected_policy(expected_policy_evidence)?;
    if preregistration.domain != expected_policy_evidence.module_id
        || preregistration.policy_evidence != *expected_policy_evidence
    {
        return invalid("preregistration is not bound to the exact domain policy evidence");
    }
    validate_temporal_mode(preregistration)?;
    validate_hypotheses(&preregistration.confirmatory_hypotheses)?;
    validate_dataset(&preregistration.dataset, known_seed_sha256)?;
    validate_attacks(&preregistration.attacks)?;
    validate_review(&preregistration.review)?;
    validate_analysis(&preregistration.analysis)
}

fn validate_expected_policy(evidence: &DomainModuleEvidence) -> Result<(), DomainStudyError> {
    if evidence.schema_version != DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION
        || evidence.module_version.trim().is_empty()
        || !safe_token(&evidence.lexical_policy.pack_id)
        || evidence.lexical_policy.schema_version == 0
        || evidence.lexical_policy.rule_count == 0
        || !is_sha256(&evidence.lexical_policy.sha256)
        || evidence.temporal_policy.as_ref().is_some_and(|temporal| {
            !safe_token(&temporal.pack.pack_id)
                || temporal.pack.schema_version == 0
                || temporal.pack.rule_count == 0
                || !is_sha256(&temporal.pack.sha256)
        })
    {
        return invalid("expected domain policy evidence is invalid");
    }
    Ok(())
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
    known_seed_sha256: &[&str],
) -> Result<(), DomainStudyError> {
    if !safe_token(&dataset.dataset_id)
        || !is_sha256(&dataset.corpus_sha256)
        || !is_sha256(&dataset.inclusion_criteria_sha256)
        || !is_sha256(&dataset.exclusion_criteria_sha256)
        || !(30..=1_000_000).contains(&dataset.fixed_case_count)
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
    validate_sorted_tokens("required stratum", &dataset.required_strata, 2, 64)?;

    if dataset.corpus_class == DomainStudyCorpusClass::IndependentExternal {
        if known_seed_sha256
            .iter()
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
    if !is_sha256(&attacks.construction_manifest_sha256)
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
    use crate::{DomainPolicyPackEvidence, DomainTemporalPolicyEvidence};

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

    fn preregistration(policy: DomainModuleEvidence) -> DomainStudyPreregistration {
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
                required_strata: vec!["high_risk".to_string(), "safe_boundary".to_string()],
                a_priori_sample_size_rationale:
                    "Fixed precision target and per-threat minimum support were set before review."
                        .to_string(),
                independent_sampling_frame: true,
                identity_disjoint_splits: true,
                labels_hidden_from_implementers_until_policy_freeze: true,
                raw_content_exported_in_public_evidence: false,
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
        let binding = validate_domain_study_preregistration(
            &json(&preregistration(policy.clone())),
            &policy,
            &[SHA_A],
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
    }

    #[test]
    fn known_seed_cannot_be_declared_independent_external() {
        let policy = evidence(DomainModuleId::Kids, false);
        let error = validate_domain_study_preregistration(
            &json(&preregistration(policy.clone())),
            &policy,
            &[SHA_B],
        )
        .expect_err("known seed claim must fail");

        assert!(error.to_string().contains("known seed"));
    }

    #[test]
    fn policy_drift_invalidates_preregistration() {
        let policy = evidence(DomainModuleId::Kids, false);
        let mut current = policy.clone();
        current.lexical_policy.sha256 = SHA_D.to_string();

        let error =
            validate_domain_study_preregistration(&json(&preregistration(policy)), &current, &[])
                .expect_err("policy drift must fail");

        assert!(error.to_string().contains("exact domain policy evidence"));
    }

    #[test]
    fn military_temporal_policy_is_accepted_only_as_disabled_shadow() {
        let policy = evidence(DomainModuleId::Military, true);
        validate_domain_study_preregistration(
            &json(&preregistration(policy.clone())),
            &policy,
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
            &json(&preregistration(active_policy.clone())),
            &active_policy,
            &[],
        )
        .expect_err("active temporal runtime must fail");

        assert!(error.to_string().contains("runtime-disabled"));
    }

    #[test]
    fn optional_stopping_is_rejected() {
        let policy = evidence(DomainModuleId::Kids, false);
        let mut study = preregistration(policy.clone());
        study.analysis.fixed_corpus_no_optional_stopping = false;

        let error = validate_domain_study_preregistration(&json(&study), &policy, &[])
            .expect_err("optional stopping must fail");

        assert!(error.to_string().contains("analysis plan"));
    }

    #[test]
    fn internal_corpus_can_never_exceed_engineering_readiness() {
        let policy = evidence(DomainModuleId::Kids, false);
        let mut study = preregistration(policy.clone());
        study.dataset.corpus_class = DomainStudyCorpusClass::CuratedInternal;
        study.dataset.independent_sampling_frame = false;
        study
            .dataset
            .labels_hidden_from_implementers_until_policy_freeze = false;

        let binding = validate_domain_study_preregistration(&json(&study), &policy, &[])
            .expect("valid internal protocol");

        assert_eq!(binding.readiness, DomainStudyReadiness::EngineeringOnly);
    }
}
