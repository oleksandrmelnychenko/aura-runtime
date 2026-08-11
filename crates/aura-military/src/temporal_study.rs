//! Preregistration contract for independent temporal-review studies.

use std::collections::{BTreeSet, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::temporal_eval::{
    embedded_temporal_review_target, temporal_review_target, TemporalReviewTarget,
    TemporalShadowError,
};

const PREREGISTRATION_SCHEMA_VERSION: &str = "aura.military.temporal_review_preregistration.v1";
const MIN_PREREGISTERED_NEGATIVE_CONTROLS: usize = 18;
const MIN_PREREGISTERED_POSITIVES_PER_REASON_CODE: usize = 4;

/// Error returned when a temporal-review preregistration is invalid.
#[derive(Debug, Error)]
pub enum TemporalStudyError {
    #[error("invalid temporal-review preregistration JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid temporal-review preregistration: {0}")]
    InvalidPreregistration(String),
    #[error("temporal review corpus is unavailable: {0}")]
    Corpus(#[from] TemporalShadowError),
}

/// Declared source class for the corpus under study.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalStudyCorpusClass {
    PublicSeed,
    EmbargoedExternal,
}

/// Confirmatory outcome fixed before labels are collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalPrimaryOutcome {
    AdjudicatedExactMatchRate,
    ExactSetPairAgreementRate,
    KrippendorffAlphaNominal,
}

/// Prespecified handling of incomplete reviewer decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalMissingDataRule {
    NoImputationReportIncomplete,
}

/// Prespecified handling of undefined agreement coefficients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalUndefinedAlphaRule {
    ReportNullWithCounts,
}

/// Prespecified multiplicity interpretation for per-label summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalMultiplicityRule {
    DescriptivePerLabelNoNullHypothesisTests,
}

/// One hypothesis declared before the review begins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalConfirmatoryHypothesis {
    pub hypothesis_id: String,
    pub statement: String,
}

/// Fixed sampling and coverage requirements for the study corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalStudySamplingPlan {
    pub fixed_case_count: usize,
    pub minimum_negative_controls: usize,
    pub minimum_positive_cases_per_reason_code: usize,
    pub required_coverage_tags: Vec<String>,
}

/// Reviewer-separation requirements fixed before labels are collected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalStudyReviewDesign {
    pub minimum_reviewers_per_case: usize,
    pub distinct_reviewer_affiliations: bool,
    pub independent_adjudicator: bool,
    pub labels_frozen_before_adjudication: bool,
}

/// Statistical decisions fixed before labels are collected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalStudyAnalysisPlan {
    pub missing_data_rule: TemporalMissingDataRule,
    pub undefined_alpha_rule: TemporalUndefinedAlphaRule,
    pub multiplicity_rule: TemporalMultiplicityRule,
    pub exploratory_analyses_reported_separately: bool,
    pub minimum_acceptable_exact_set_pair_agreement_rate: f64,
    pub minimum_acceptable_krippendorff_alpha: f64,
}

/// Canonical preregistration document bound to blind-review material.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalReviewPreregistration {
    pub schema_version: String,
    pub study_id: String,
    pub registered_at_ms: u64,
    pub corpus_class: TemporalStudyCorpusClass,
    pub research_question: String,
    pub confirmatory_hypotheses: Vec<TemporalConfirmatoryHypothesis>,
    pub primary_outcomes: Vec<TemporalPrimaryOutcome>,
    pub planned_subgroups: Vec<String>,
    pub sampling: TemporalStudySamplingPlan,
    pub review_design: TemporalStudyReviewDesign,
    pub analysis: TemporalStudyAnalysisPlan,
    pub fixed_corpus_no_optional_stopping: bool,
}

/// Public identity of a validated preregistration.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalPreregistrationBinding {
    pub study_id: String,
    pub registered_at_ms: u64,
    pub corpus_class: TemporalStudyCorpusClass,
    pub canonical_sha256: String,
    pub minimum_reviewers_per_case: usize,
    pub minimum_acceptable_exact_set_pair_agreement_rate: f64,
    pub minimum_acceptable_krippendorff_alpha: f64,
}

/// Validates a preregistration against a caller-supplied corpus.
pub fn validate_temporal_review_preregistration(
    corpus_json: &str,
    preregistration_json: &str,
) -> Result<TemporalPreregistrationBinding, TemporalStudyError> {
    let target = temporal_review_target(corpus_json)?;
    validate_preregistration_against_target(
        preregistration_json,
        &target,
        Some(TemporalStudyCorpusClass::EmbargoedExternal),
    )
}

pub(crate) fn validate_preregistration_against_target(
    preregistration_json: &str,
    target: &TemporalReviewTarget,
    expected_corpus_class: Option<TemporalStudyCorpusClass>,
) -> Result<TemporalPreregistrationBinding, TemporalStudyError> {
    let preregistration: TemporalReviewPreregistration =
        serde_json::from_str(preregistration_json)?;
    if expected_corpus_class == Some(TemporalStudyCorpusClass::EmbargoedExternal) {
        let embedded = embedded_temporal_review_target()?;
        if target.corpus_sha256 == embedded.corpus_sha256
            || target.dataset_id == embedded.dataset_id
        {
            return invalid_preregistration(
                "external study corpus must differ from the embedded public seed",
            );
        }
    }
    validate_preregistration(&preregistration, target, expected_corpus_class)?;
    Ok(TemporalPreregistrationBinding {
        study_id: preregistration.study_id.clone(),
        registered_at_ms: preregistration.registered_at_ms,
        corpus_class: preregistration.corpus_class,
        canonical_sha256: canonical_sha256(&preregistration)?,
        minimum_reviewers_per_case: preregistration.review_design.minimum_reviewers_per_case,
        minimum_acceptable_exact_set_pair_agreement_rate: preregistration
            .analysis
            .minimum_acceptable_exact_set_pair_agreement_rate,
        minimum_acceptable_krippendorff_alpha: preregistration
            .analysis
            .minimum_acceptable_krippendorff_alpha,
    })
}

fn validate_preregistration(
    preregistration: &TemporalReviewPreregistration,
    target: &TemporalReviewTarget,
    expected_corpus_class: Option<TemporalStudyCorpusClass>,
) -> Result<(), TemporalStudyError> {
    if preregistration.schema_version != PREREGISTRATION_SCHEMA_VERSION {
        return invalid_preregistration("preregistration schema is unsupported");
    }
    if !safe_token(&preregistration.study_id) || preregistration.registered_at_ms == 0 {
        return invalid_preregistration("study identity fields are invalid");
    }
    if expected_corpus_class.is_some_and(|expected| expected != preregistration.corpus_class) {
        return invalid_preregistration("declared corpus class does not match the review workflow");
    }
    let question_length = preregistration.research_question.trim().chars().count();
    if !(16..=1_000).contains(&question_length) {
        return invalid_preregistration("research question must contain 16..=1000 characters");
    }
    validate_hypotheses(&preregistration.confirmatory_hypotheses)?;
    validate_primary_outcomes(&preregistration.primary_outcomes)?;
    validate_tokens(
        "planned subgroup",
        &preregistration.planned_subgroups,
        1,
        64,
    )?;
    validate_review_design(&preregistration.review_design)?;
    validate_analysis_plan(&preregistration.analysis)?;
    if !preregistration.fixed_corpus_no_optional_stopping {
        return invalid_preregistration("fixed-corpus stopping must be declared");
    }
    validate_sampling_plan(
        &preregistration.sampling,
        &preregistration.planned_subgroups,
        target,
    )
}

fn validate_hypotheses(
    hypotheses: &[TemporalConfirmatoryHypothesis],
) -> Result<(), TemporalStudyError> {
    if hypotheses.is_empty() || hypotheses.len() > 16 {
        return invalid_preregistration("confirmatory hypothesis count must be within 1..=16");
    }
    let mut ids = HashSet::with_capacity(hypotheses.len());
    for hypothesis in hypotheses {
        if !safe_token(&hypothesis.hypothesis_id)
            || !ids.insert(hypothesis.hypothesis_id.as_str())
            || !(16..=1_000).contains(&hypothesis.statement.trim().chars().count())
        {
            return invalid_preregistration("confirmatory hypotheses are invalid or duplicated");
        }
    }
    Ok(())
}

fn validate_primary_outcomes(
    outcomes: &[TemporalPrimaryOutcome],
) -> Result<(), TemporalStudyError> {
    let required = BTreeSet::from([
        TemporalPrimaryOutcome::AdjudicatedExactMatchRate,
        TemporalPrimaryOutcome::ExactSetPairAgreementRate,
        TemporalPrimaryOutcome::KrippendorffAlphaNominal,
    ]);
    if outcomes.iter().copied().collect::<BTreeSet<_>>() != required
        || outcomes.len() != required.len()
    {
        return invalid_preregistration("primary outcomes must contain the exact required set");
    }
    Ok(())
}

fn validate_review_design(design: &TemporalStudyReviewDesign) -> Result<(), TemporalStudyError> {
    if !(2..=5).contains(&design.minimum_reviewers_per_case)
        || !design.distinct_reviewer_affiliations
        || !design.independent_adjudicator
        || !design.labels_frozen_before_adjudication
    {
        return invalid_preregistration("review design does not satisfy separation requirements");
    }
    Ok(())
}

fn validate_analysis_plan(plan: &TemporalStudyAnalysisPlan) -> Result<(), TemporalStudyError> {
    if plan.missing_data_rule != TemporalMissingDataRule::NoImputationReportIncomplete
        || plan.undefined_alpha_rule != TemporalUndefinedAlphaRule::ReportNullWithCounts
        || plan.multiplicity_rule
            != TemporalMultiplicityRule::DescriptivePerLabelNoNullHypothesisTests
        || !plan.exploratory_analyses_reported_separately
        || !valid_high_assurance_threshold(plan.minimum_acceptable_exact_set_pair_agreement_rate)
        || !valid_high_assurance_threshold(plan.minimum_acceptable_krippendorff_alpha)
    {
        return invalid_preregistration("analysis plan does not satisfy reporting requirements");
    }
    Ok(())
}

fn valid_high_assurance_threshold(value: f64) -> bool {
    value.is_finite() && (0.8..=1.0).contains(&value)
}

fn validate_sampling_plan(
    sampling: &TemporalStudySamplingPlan,
    planned_subgroups: &[String],
    target: &TemporalReviewTarget,
) -> Result<(), TemporalStudyError> {
    if sampling.fixed_case_count != target.cases.len()
        || !(1..=10_000).contains(&sampling.fixed_case_count)
        || sampling.minimum_negative_controls < MIN_PREREGISTERED_NEGATIVE_CONTROLS
        || sampling.minimum_positive_cases_per_reason_code
            < MIN_PREREGISTERED_POSITIVES_PER_REASON_CODE
    {
        return invalid_preregistration("sampling counts do not match the fixed corpus");
    }
    validate_tokens(
        "required coverage tag",
        &sampling.required_coverage_tags,
        1,
        128,
    )?;
    let negative_controls = target
        .expected_labels
        .values()
        .filter(|labels| labels.is_empty())
        .count();
    if negative_controls < sampling.minimum_negative_controls {
        return invalid_preregistration("corpus has too few negative controls");
    }
    let reason_codes = target
        .expected_labels
        .values()
        .flat_map(|labels| labels.iter())
        .collect::<BTreeSet<_>>();
    if reason_codes.is_empty()
        || reason_codes.iter().any(|reason_code| {
            target
                .expected_labels
                .values()
                .filter(|labels| labels.contains(*reason_code))
                .count()
                < sampling.minimum_positive_cases_per_reason_code
        })
    {
        return invalid_preregistration("corpus has too few positive cases for a reason code");
    }
    let available_tags = target
        .case_tags
        .values()
        .flat_map(|tags| tags.iter().map(String::as_str))
        .collect::<HashSet<_>>();
    if sampling
        .required_coverage_tags
        .iter()
        .chain(planned_subgroups)
        .any(|tag| !available_tags.contains(tag.as_str()))
    {
        return invalid_preregistration("a planned tag is absent from the fixed corpus");
    }
    Ok(())
}

fn validate_tokens(
    label: &str,
    tokens: &[String],
    minimum: usize,
    maximum: usize,
) -> Result<(), TemporalStudyError> {
    if !(minimum..=maximum).contains(&tokens.len())
        || tokens.iter().any(|token| !safe_label_token(token))
        || tokens.iter().collect::<HashSet<_>>().len() != tokens.len()
    {
        return invalid_preregistration(format!("{label} values are invalid or duplicated"));
    }
    Ok(())
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, TemporalStudyError> {
    let digest = Sha256::digest(serde_json::to_vec(value)?);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(encoded)
}

fn safe_token(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn safe_label_token(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn invalid_preregistration<T>(message: impl Into<String>) -> Result<T, TemporalStudyError> {
    Err(TemporalStudyError::InvalidPreregistration(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::temporal_eval::embedded_temporal_review_target;

    fn preregistration_value() -> serde_json::Value {
        let target = embedded_temporal_review_target().expect("embedded review target");
        serde_json::json!({
            "schema_version": PREREGISTRATION_SCHEMA_VERSION,
            "study_id": "temporal_seed_study_2026",
            "registered_at_ms": 1,
            "corpus_class": "public_seed",
            "research_question": "Do independent reviewers reproduce frozen labels from content-free temporal event chains?",
            "confirmatory_hypotheses": [{
                "hypothesis_id": "temporal_exact_match",
                "statement": "Adjudicated reason-code sets will exactly match the frozen corpus labels for all cases."
            }],
            "primary_outcomes": [
                "adjudicated_exact_match_rate",
                "exact_set_pair_agreement_rate",
                "krippendorff_alpha_nominal"
            ],
            "planned_subgroups": ["group"],
            "sampling": {
                "fixed_case_count": target.cases.len(),
                "minimum_negative_controls": 18,
                "minimum_positive_cases_per_reason_code": 4,
                "required_coverage_tags": ["positive", "negative_control"]
            },
            "review_design": {
                "minimum_reviewers_per_case": 2,
                "distinct_reviewer_affiliations": true,
                "independent_adjudicator": true,
                "labels_frozen_before_adjudication": true
            },
            "analysis": {
                "missing_data_rule": "no_imputation_report_incomplete",
                "undefined_alpha_rule": "report_null_with_counts",
                "multiplicity_rule": "descriptive_per_label_no_null_hypothesis_tests",
                "exploratory_analyses_reported_separately": true,
                "minimum_acceptable_exact_set_pair_agreement_rate": 0.8,
                "minimum_acceptable_krippendorff_alpha": 0.8
            },
            "fixed_corpus_no_optional_stopping": true
        })
    }

    #[test]
    fn valid_preregistration_binds_to_fixed_public_seed() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let binding = validate_preregistration_against_target(
            &preregistration_value().to_string(),
            &target,
            Some(TemporalStudyCorpusClass::PublicSeed),
        )
        .expect("valid preregistration");

        assert_eq!(binding.canonical_sha256.len(), 64);
    }

    #[test]
    fn preregistration_rejects_optional_stopping() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let mut value = preregistration_value();
        value["fixed_corpus_no_optional_stopping"] = serde_json::Value::Bool(false);

        let error = validate_preregistration_against_target(
            &value.to_string(),
            &target,
            Some(TemporalStudyCorpusClass::PublicSeed),
        )
        .expect_err("optional stopping");

        assert!(error.to_string().contains("stopping"));
    }

    #[test]
    fn preregistration_rejects_post_hoc_case_count_change() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let mut value = preregistration_value();
        value["sampling"]["fixed_case_count"] = serde_json::json!(target.cases.len() + 1);

        let error = validate_preregistration_against_target(
            &value.to_string(),
            &target,
            Some(TemporalStudyCorpusClass::PublicSeed),
        )
        .expect_err("changed case count");

        assert!(error.to_string().contains("fixed corpus"));
    }

    #[test]
    fn preregistration_rejects_weak_coverage_minimums() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let mut value = preregistration_value();
        value["sampling"]["minimum_negative_controls"] = serde_json::json!(1);

        let error = validate_preregistration_against_target(
            &value.to_string(),
            &target,
            Some(TemporalStudyCorpusClass::PublicSeed),
        )
        .expect_err("weak coverage minimum");

        assert!(error.to_string().contains("sampling counts"));
    }

    #[test]
    fn embedded_workflow_rejects_external_corpus_claim() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let mut value = preregistration_value();
        value["corpus_class"] = serde_json::Value::String("embargoed_external".to_string());

        let error = validate_preregistration_against_target(
            &value.to_string(),
            &target,
            Some(TemporalStudyCorpusClass::PublicSeed),
        )
        .expect_err("wrong corpus class");

        assert!(error.to_string().contains("corpus class"));
    }
}
