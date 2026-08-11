//! Validation of independently produced labels for the temporal Shadow corpus.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::temporal_eval::{
    embedded_temporal_review_target, temporal_review_target, TemporalReviewTarget,
    TemporalShadowError,
};
use crate::temporal_study::TemporalStudyCorpusClass;

const REVIEW_SCHEMA_VERSION: &str = "aura.military.temporal_independent_review.v1";
const REPORT_SCHEMA_VERSION: &str = "aura.military.temporal_review_report.v5";
const MIN_REVIEWERS_PER_CASE: usize = 2;
const MAX_REVIEWERS_PER_CASE: usize = 5;

/// Error returned when an independent-review bundle cannot be evaluated.
#[derive(Debug, Error)]
pub enum TemporalReviewError {
    #[error("invalid temporal independent-review JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid temporal independent-review bundle: {0}")]
    InvalidBundle(String),
    #[error("temporal Shadow corpus is unavailable: {0}")]
    Corpus(#[from] TemporalShadowError),
}

/// Aggregate review-readiness metrics without reviewer identities.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalReviewMetrics {
    pub corpus_cases: usize,
    pub submitted_cases: usize,
    pub cases_with_two_independent_reviews: usize,
    pub cases_with_complete_adjudication: usize,
    pub cases_with_adjudicator_separation: usize,
    pub cases_matching_adjudicated_corpus_label: usize,
    pub reviewer_registry_entries: usize,
    pub reviewer_affiliations: usize,
    pub direct_agreement_cases: usize,
    pub resolved_disagreement_cases: usize,
    pub reviewer_pair_comparisons: usize,
    pub exact_set_pair_agreements: usize,
    pub exact_set_pair_disagreements: usize,
    pub exact_set_pair_agreement_rate: Option<f64>,
    pub krippendorff_units: usize,
    pub krippendorff_reviewer_decisions: usize,
    pub krippendorff_alpha_nominal: Option<f64>,
    pub by_reason_code_agreement: Vec<TemporalReasonCodeAgreementMetrics>,
}

/// Inter-rater agreement for one binary reason-code decision.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalReasonCodeAgreementMetrics {
    pub reason_code: String,
    pub units_with_complete_reviews: usize,
    pub reviewer_decisions: usize,
    pub present_decisions: usize,
    pub absent_decisions: usize,
    pub observed_agreement: Option<f64>,
    pub krippendorff_alpha_nominal: Option<f64>,
}

/// One aggregated research-readiness assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalReviewCheck {
    pub name: String,
    pub requirement: String,
    pub actual: String,
    pub passed: bool,
}

/// Privacy properties of the review report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalReviewPrivacy {
    pub raw_text_present: bool,
    pub reviewer_tokens_exported: bool,
    pub affiliation_tokens_exported: bool,
    pub stable_actor_identifiers_present: bool,
    pub internal_case_ids_exported: bool,
}

/// Privacy-safe boundaries of the declared human-review timeline.
///
/// These values come from the review bundle. They support chronology checks,
/// but are not independently trusted timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalReviewChronology {
    pub decision_time_assurance: &'static str,
    pub declared_preregistration_at_ms: Option<u64>,
    pub earliest_annotation_completed_at_ms: Option<u64>,
    pub latest_annotation_completed_at_ms: Option<u64>,
    pub earliest_adjudication_completed_at_ms: Option<u64>,
    pub latest_adjudication_completed_at_ms: Option<u64>,
}

/// Machine-readable status of independent human review for the temporal corpus.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalReviewReport {
    pub schema_version: &'static str,
    pub overall_status: &'static str,
    pub dataset_id: String,
    pub corpus_sha256: String,
    pub review_bundle_id: String,
    pub review_bundle_canonical_sha256: Option<String>,
    pub label_blinding_declared: bool,
    pub blinding_assurance: &'static str,
    pub blind_packet_id: Option<String>,
    pub blind_packet_canonical_sha256: Option<String>,
    pub preregistration_assurance: &'static str,
    pub study_id: Option<String>,
    pub study_corpus_class: Option<TemporalStudyCorpusClass>,
    pub preregistration_canonical_sha256: Option<String>,
    pub study_commitment_canonical_sha256: Option<String>,
    pub chronology: TemporalReviewChronology,
    pub metrics: TemporalReviewMetrics,
    pub checks: Vec<TemporalReviewCheck>,
    pub privacy: TemporalReviewPrivacy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalReviewBundle {
    schema_version: String,
    review_bundle_id: String,
    dataset_id: String,
    corpus_sha256: String,
    protocol: TemporalReviewProtocol,
    #[serde(default)]
    reviewers: Vec<TemporalReviewer>,
    #[serde(default)]
    cases: Vec<TemporalReviewedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalReviewProtocol {
    label_blinding: bool,
    minimum_reviewers_per_case: usize,
    distinct_reviewer_affiliations: bool,
    independent_adjudicator: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TemporalReviewerRole {
    Reviewer,
    Adjudicator,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalReviewer {
    reviewer_token: String,
    affiliation_token: String,
    role: TemporalReviewerRole,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalReviewedCase {
    case_id: String,
    #[serde(default)]
    annotations: Vec<TemporalAnnotation>,
    adjudication: Option<TemporalAdjudication>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalAnnotation {
    reviewer_token: String,
    expected_reason_codes: Vec<String>,
    completed_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalAdjudication {
    adjudicator_token: String,
    expected_reason_codes: Vec<String>,
    completed_at_ms: u64,
}

#[derive(Debug, Default)]
struct NominalAgreementAccumulator {
    units: usize,
    decisions: usize,
    present_decisions: usize,
    absent_decisions: usize,
    observed_disagreement_coincidences: f64,
}

impl NominalAgreementAccumulator {
    fn observe_binary(&mut self, present_decisions: usize, total_decisions: usize) {
        if total_decisions < 2 || present_decisions > total_decisions {
            return;
        }
        let absent_decisions = total_decisions - present_decisions;
        self.units += 1;
        self.decisions += total_decisions;
        self.present_decisions += present_decisions;
        self.absent_decisions += absent_decisions;
        self.observed_disagreement_coincidences +=
            2.0 * present_decisions as f64 * absent_decisions as f64 / (total_decisions - 1) as f64;
    }

    fn observed_agreement(&self) -> Option<f64> {
        (self.decisions > 0)
            .then(|| 1.0 - self.observed_disagreement_coincidences / self.decisions as f64)
    }

    fn krippendorff_alpha_nominal(&self) -> Option<f64> {
        if self.decisions < 2 {
            return None;
        }
        let expected_disagreement =
            2.0 * self.present_decisions as f64 * self.absent_decisions as f64
                / (self.decisions as f64 * (self.decisions - 1) as f64);
        if expected_disagreement == 0.0 {
            return None;
        }
        let observed_disagreement = self.observed_disagreement_coincidences / self.decisions as f64;
        Some(1.0 - observed_disagreement / expected_disagreement)
    }
}

/// Evaluates a review bundle against the exact embedded temporal corpus.
///
/// A passing report requires two blinded reviewers from distinct affiliations
/// and a separate adjudicator for every case. Reviewer tokens never appear in
/// the generated report.
pub fn evaluate_embedded_temporal_review(
    json: &str,
) -> Result<TemporalReviewReport, TemporalReviewError> {
    let target = embedded_temporal_review_target()?;
    evaluate_temporal_review_against_target(json, &target)
}

/// Evaluates a review bundle against a caller-supplied content-free corpus.
pub fn evaluate_temporal_review(
    corpus_json: &str,
    review_json: &str,
) -> Result<TemporalReviewReport, TemporalReviewError> {
    let target = temporal_review_target(corpus_json)?;
    evaluate_temporal_review_against_target(review_json, &target)
}

pub(crate) fn evaluate_temporal_review_against_target(
    json: &str,
    target: &TemporalReviewTarget,
) -> Result<TemporalReviewReport, TemporalReviewError> {
    let bundle: TemporalReviewBundle = serde_json::from_str(json)?;
    validate_bundle_identity(&bundle)?;
    if bundle.dataset_id != target.dataset_id || bundle.corpus_sha256 != target.corpus_sha256 {
        return invalid_bundle("review bundle is not bound to the supplied corpus identity");
    }

    let reviewer_registry = validate_reviewer_registry(&bundle.reviewers)?;
    let submitted_cases = validate_case_registry(&bundle.cases, &target.expected_labels)?;
    let known_labels = target
        .expected_labels
        .values()
        .flat_map(|labels| labels.iter().cloned())
        .collect::<BTreeSet<_>>();

    let mut independent_review_cases = 0usize;
    let mut complete_adjudication_cases = 0usize;
    let mut adjudicator_separation_cases = 0usize;
    let mut matching_label_cases = 0usize;
    let mut direct_agreement_cases = 0usize;
    let mut resolved_disagreement_cases = 0usize;
    let mut reviewer_pair_comparisons = 0usize;
    let mut exact_set_pair_agreements = 0usize;
    let mut overall_agreement = NominalAgreementAccumulator::default();
    let mut agreement_by_reason_code = known_labels
        .iter()
        .cloned()
        .map(|reason_code| (reason_code, NominalAgreementAccumulator::default()))
        .collect::<BTreeMap<_, _>>();
    let required_reviewers = bundle.protocol.minimum_reviewers_per_case;
    let annotation_completion_times = bundle
        .cases
        .iter()
        .flat_map(|case| {
            case.annotations
                .iter()
                .map(|annotation| annotation.completed_at_ms)
        })
        .collect::<Vec<_>>();
    let adjudication_completion_times = bundle
        .cases
        .iter()
        .filter_map(|case| {
            case.adjudication
                .as_ref()
                .map(|adjudication| adjudication.completed_at_ms)
        })
        .collect::<Vec<_>>();

    for (case_id, expected_labels) in &target.expected_labels {
        let Some(reviewed_case) = submitted_cases.get(case_id.as_str()) else {
            continue;
        };
        validate_case_labels(reviewed_case, &known_labels)?;

        let valid_annotations = reviewed_case
            .annotations
            .iter()
            .map(|annotation| {
                let reviewer = reviewer_registry
                    .get(annotation.reviewer_token.as_str())
                    .ok_or_else(|| {
                        TemporalReviewError::InvalidBundle(format!(
                            "case {case_id} references an unknown reviewer"
                        ))
                    })?;
                if reviewer.role != TemporalReviewerRole::Reviewer {
                    return invalid_bundle(format!(
                        "case {case_id} annotation token does not have the reviewer role"
                    ));
                }
                Ok((annotation, *reviewer))
            })
            .collect::<Result<Vec<_>, TemporalReviewError>>()?;
        let reviewer_tokens = valid_annotations
            .iter()
            .map(|(annotation, _)| annotation.reviewer_token.as_str())
            .collect::<HashSet<_>>();
        let affiliations = valid_annotations
            .iter()
            .map(|(_, reviewer)| reviewer.affiliation_token.as_str())
            .collect::<HashSet<_>>();
        let annotations_are_complete = (required_reviewers..=MAX_REVIEWERS_PER_CASE)
            .contains(&valid_annotations.len())
            && reviewer_tokens.len() == valid_annotations.len()
            && affiliations.len() >= required_reviewers
            && valid_annotations
                .iter()
                .all(|(annotation, _)| annotation.completed_at_ms > 0);
        independent_review_cases += usize::from(annotations_are_complete);

        let annotation_labels = valid_annotations
            .iter()
            .map(|(annotation, _)| {
                annotation
                    .expected_reason_codes
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
            })
            .collect::<Vec<_>>();
        let direct_agreement = annotations_are_complete
            && annotation_labels
                .first()
                .is_some_and(|first| annotation_labels.iter().all(|labels| labels == first));
        direct_agreement_cases += usize::from(direct_agreement);
        if annotations_are_complete {
            for (index, left) in annotation_labels.iter().enumerate() {
                for right in annotation_labels.iter().skip(index + 1) {
                    reviewer_pair_comparisons += 1;
                    exact_set_pair_agreements += usize::from(left == right);
                }
            }
            for reason_code in &known_labels {
                let present_decisions = annotation_labels
                    .iter()
                    .filter(|labels| labels.contains(reason_code))
                    .count();
                let total_decisions = annotation_labels.len();
                overall_agreement.observe_binary(present_decisions, total_decisions);
                if let Some(accumulator) = agreement_by_reason_code.get_mut(reason_code) {
                    accumulator.observe_binary(present_decisions, total_decisions);
                }
            }
        }

        let Some(adjudication) = reviewed_case.adjudication.as_ref() else {
            continue;
        };
        let adjudicator = reviewer_registry
            .get(adjudication.adjudicator_token.as_str())
            .ok_or_else(|| {
                TemporalReviewError::InvalidBundle(format!(
                    "case {case_id} references an unknown adjudicator"
                ))
            })?;
        if adjudicator.role != TemporalReviewerRole::Adjudicator {
            return invalid_bundle(format!(
                "case {case_id} adjudication token does not have the adjudicator role"
            ));
        }
        let latest_review_ms = valid_annotations
            .iter()
            .map(|(annotation, _)| annotation.completed_at_ms)
            .max()
            .unwrap_or_default();
        let adjudication_is_complete =
            adjudication.completed_at_ms > latest_review_ms && adjudication.completed_at_ms > 0;
        complete_adjudication_cases += usize::from(adjudication_is_complete);

        let adjudicator_is_separate = adjudication_is_complete
            && !reviewer_tokens.contains(adjudication.adjudicator_token.as_str())
            && !affiliations.contains(adjudicator.affiliation_token.as_str());
        adjudicator_separation_cases += usize::from(adjudicator_is_separate);

        let adjudicated_labels = adjudication
            .expected_reason_codes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        matching_label_cases += usize::from(adjudicated_labels == *expected_labels);
        resolved_disagreement_cases +=
            usize::from(annotations_are_complete && !direct_agreement && adjudication_is_complete);
    }

    let corpus_cases = target.expected_labels.len();
    let exact_set_pair_disagreements =
        reviewer_pair_comparisons.saturating_sub(exact_set_pair_agreements);
    let exact_set_pair_agreement_rate = (reviewer_pair_comparisons > 0)
        .then(|| exact_set_pair_agreements as f64 / reviewer_pair_comparisons as f64);
    let by_reason_code_agreement = agreement_by_reason_code
        .into_iter()
        .map(
            |(reason_code, accumulator)| TemporalReasonCodeAgreementMetrics {
                reason_code,
                units_with_complete_reviews: accumulator.units,
                reviewer_decisions: accumulator.decisions,
                present_decisions: accumulator.present_decisions,
                absent_decisions: accumulator.absent_decisions,
                observed_agreement: accumulator.observed_agreement(),
                krippendorff_alpha_nominal: accumulator.krippendorff_alpha_nominal(),
            },
        )
        .collect();
    let metrics = TemporalReviewMetrics {
        corpus_cases,
        submitted_cases: submitted_cases.len(),
        cases_with_two_independent_reviews: independent_review_cases,
        cases_with_complete_adjudication: complete_adjudication_cases,
        cases_with_adjudicator_separation: adjudicator_separation_cases,
        cases_matching_adjudicated_corpus_label: matching_label_cases,
        reviewer_registry_entries: reviewer_registry.len(),
        reviewer_affiliations: reviewer_registry
            .values()
            .map(|reviewer| reviewer.affiliation_token.as_str())
            .collect::<HashSet<_>>()
            .len(),
        direct_agreement_cases,
        resolved_disagreement_cases,
        reviewer_pair_comparisons,
        exact_set_pair_agreements,
        exact_set_pair_disagreements,
        exact_set_pair_agreement_rate,
        krippendorff_units: overall_agreement.units,
        krippendorff_reviewer_decisions: overall_agreement.decisions,
        krippendorff_alpha_nominal: overall_agreement.krippendorff_alpha_nominal(),
        by_reason_code_agreement,
    };
    let checks = build_checks(&bundle.protocol, &metrics);
    let overall_status = if checks.iter().all(|check| check.passed) {
        "pass"
    } else if metrics.submitted_cases == metrics.corpus_cases
        && metrics.cases_with_complete_adjudication == metrics.corpus_cases
    {
        "fail"
    } else {
        "pending"
    };

    Ok(TemporalReviewReport {
        schema_version: REPORT_SCHEMA_VERSION,
        overall_status,
        dataset_id: target.dataset_id.clone(),
        corpus_sha256: target.corpus_sha256.clone(),
        review_bundle_id: bundle.review_bundle_id,
        review_bundle_canonical_sha256: None,
        label_blinding_declared: bundle.protocol.label_blinding,
        blinding_assurance: "declared_only",
        blind_packet_id: None,
        blind_packet_canonical_sha256: None,
        preregistration_assurance: "absent",
        study_id: None,
        study_corpus_class: None,
        preregistration_canonical_sha256: None,
        study_commitment_canonical_sha256: None,
        chronology: TemporalReviewChronology {
            decision_time_assurance: "bundle_declared",
            declared_preregistration_at_ms: None,
            earliest_annotation_completed_at_ms: annotation_completion_times.iter().copied().min(),
            latest_annotation_completed_at_ms: annotation_completion_times.iter().copied().max(),
            earliest_adjudication_completed_at_ms: adjudication_completion_times
                .iter()
                .copied()
                .min(),
            latest_adjudication_completed_at_ms: adjudication_completion_times
                .iter()
                .copied()
                .max(),
        },
        metrics,
        checks,
        privacy: TemporalReviewPrivacy {
            raw_text_present: false,
            reviewer_tokens_exported: false,
            affiliation_tokens_exported: false,
            stable_actor_identifiers_present: false,
            internal_case_ids_exported: false,
        },
    })
}

fn validate_bundle_identity(bundle: &TemporalReviewBundle) -> Result<(), TemporalReviewError> {
    if bundle.schema_version != REVIEW_SCHEMA_VERSION {
        return invalid_bundle(format!(
            "schema_version {} is unsupported; expected {REVIEW_SCHEMA_VERSION}",
            bundle.schema_version
        ));
    }
    if !safe_token(&bundle.review_bundle_id)
        || bundle.dataset_id.trim().is_empty()
        || bundle.corpus_sha256.len() != 64
        || !bundle
            .corpus_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return invalid_bundle("review bundle identity fields are invalid");
    }
    Ok(())
}

fn validate_reviewer_registry(
    reviewers: &[TemporalReviewer],
) -> Result<BTreeMap<&str, &TemporalReviewer>, TemporalReviewError> {
    if reviewers.len() > 100 {
        return invalid_bundle("reviewer registry exceeds 100 entries");
    }
    let mut registry = BTreeMap::new();
    for reviewer in reviewers {
        if !safe_token(&reviewer.reviewer_token) || !safe_token(&reviewer.affiliation_token) {
            return invalid_bundle("reviewer or affiliation token is invalid");
        }
        if registry
            .insert(reviewer.reviewer_token.as_str(), reviewer)
            .is_some()
        {
            return invalid_bundle("reviewer tokens must be unique");
        }
    }
    Ok(registry)
}

fn validate_case_registry<'a>(
    cases: &'a [TemporalReviewedCase],
    expected: &BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeMap<&'a str, &'a TemporalReviewedCase>, TemporalReviewError> {
    if cases.len() > expected.len() {
        return invalid_bundle("review bundle contains more cases than the corpus");
    }
    let mut registry = BTreeMap::new();
    for case in cases {
        if !expected.contains_key(&case.case_id) {
            return invalid_bundle(format!("unknown reviewed case {}", case.case_id));
        }
        if registry.insert(case.case_id.as_str(), case).is_some() {
            return invalid_bundle(format!("duplicate reviewed case {}", case.case_id));
        }
        if case.annotations.len() > MAX_REVIEWERS_PER_CASE {
            return invalid_bundle(format!(
                "case {} exceeds {MAX_REVIEWERS_PER_CASE} annotations",
                case.case_id
            ));
        }
    }
    Ok(registry)
}

fn validate_case_labels(
    case: &TemporalReviewedCase,
    known_labels: &BTreeSet<String>,
) -> Result<(), TemporalReviewError> {
    for labels in case
        .annotations
        .iter()
        .map(|annotation| &annotation.expected_reason_codes)
        .chain(
            case.adjudication
                .iter()
                .map(|adjudication| &adjudication.expected_reason_codes),
        )
    {
        let unique = labels.iter().collect::<HashSet<_>>();
        if unique.len() != labels.len() || labels.iter().any(|label| !known_labels.contains(label))
        {
            return invalid_bundle(format!(
                "case {} contains duplicate or unsupported reason codes",
                case.case_id
            ));
        }
    }
    Ok(())
}

fn build_checks(
    protocol: &TemporalReviewProtocol,
    metrics: &TemporalReviewMetrics,
) -> Vec<TemporalReviewCheck> {
    vec![
        boolean_check("label_blinding_declared", protocol.label_blinding),
        boolean_check(
            "minimum_reviewers_protocol",
            (MIN_REVIEWERS_PER_CASE..=MAX_REVIEWERS_PER_CASE)
                .contains(&protocol.minimum_reviewers_per_case),
        ),
        boolean_check(
            "distinct_reviewer_affiliations_protocol",
            protocol.distinct_reviewer_affiliations,
        ),
        boolean_check(
            "independent_adjudicator_protocol",
            protocol.independent_adjudicator,
        ),
        exact_count_check(
            "all_corpus_cases_submitted",
            metrics.submitted_cases,
            metrics.corpus_cases,
        ),
        exact_count_check(
            "all_cases_have_two_independent_reviews",
            metrics.cases_with_two_independent_reviews,
            metrics.corpus_cases,
        ),
        exact_count_check(
            "all_cases_have_complete_adjudication",
            metrics.cases_with_complete_adjudication,
            metrics.corpus_cases,
        ),
        exact_count_check(
            "all_adjudicators_are_separate",
            metrics.cases_with_adjudicator_separation,
            metrics.corpus_cases,
        ),
        exact_count_check(
            "all_adjudicated_labels_match_corpus",
            metrics.cases_matching_adjudicated_corpus_label,
            metrics.corpus_cases,
        ),
    ]
}

fn boolean_check(name: &str, actual: bool) -> TemporalReviewCheck {
    TemporalReviewCheck {
        name: name.to_string(),
        requirement: "true".to_string(),
        actual: actual.to_string(),
        passed: actual,
    }
}

fn exact_count_check(name: &str, actual: usize, expected: usize) -> TemporalReviewCheck {
    TemporalReviewCheck {
        name: name.to_string(),
        requirement: format!("={expected}"),
        actual: actual.to_string(),
        passed: actual == expected,
    }
}

fn safe_token(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn invalid_bundle<T>(message: impl Into<String>) -> Result<T, TemporalReviewError> {
    Err(TemporalReviewError::InvalidBundle(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_bundle() -> String {
        let target = embedded_temporal_review_target().expect("embedded review target");
        serde_json::json!({
            "schema_version": REVIEW_SCHEMA_VERSION,
            "review_bundle_id": "temporal_review_pending_v1",
            "dataset_id": target.dataset_id,
            "corpus_sha256": target.corpus_sha256,
            "protocol": {
                "label_blinding": true,
                "minimum_reviewers_per_case": 2,
                "distinct_reviewer_affiliations": true,
                "independent_adjudicator": true
            },
            "reviewers": [
                {
                    "reviewer_token": "reviewer_a_8f2c10",
                    "affiliation_token": "affiliation_a_8f2c10",
                    "role": "reviewer"
                },
                {
                    "reviewer_token": "reviewer_b_41ad22",
                    "affiliation_token": "affiliation_b_41ad22",
                    "role": "reviewer"
                },
                {
                    "reviewer_token": "adjudicator_c_77b901",
                    "affiliation_token": "affiliation_c_77b901",
                    "role": "adjudicator"
                }
            ],
            "cases": []
        })
        .to_string()
    }

    #[test]
    fn empty_review_bundle_remains_pending() {
        let report = evaluate_embedded_temporal_review(&pending_bundle())
            .expect("structurally valid pending review bundle");

        assert_eq!(report.overall_status, "pending");
    }

    #[test]
    fn corpus_digest_mismatch_is_rejected() {
        let raw = pending_bundle().replace(
            "ca502f671dccaa6d712751c71d6b77a12e7b8c1ad88613a4e9f4fc83afba3d2d",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let error = evaluate_embedded_temporal_review(&raw).expect_err("corpus mismatch");

        assert!(error.to_string().contains("supplied corpus identity"));
    }

    #[test]
    fn review_report_does_not_export_reviewer_tokens() {
        let report = evaluate_embedded_temporal_review(&pending_bundle())
            .expect("structurally valid pending review bundle");
        let json = serde_json::to_string(&report).expect("review report JSON");

        assert!(!json.contains("reviewer_a_8f2c10") && !json.contains("affiliation_a_8f2c10"));
    }

    #[test]
    fn unknown_annotation_reviewer_is_rejected() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let case_id = target.expected_labels.keys().next().expect("corpus case");
        let mut bundle: serde_json::Value =
            serde_json::from_str(&pending_bundle()).expect("pending bundle JSON");
        bundle["cases"] = serde_json::json!([{
            "case_id": case_id,
            "annotations": [{
                "reviewer_token": "unknown_reviewer_123",
                "expected_reason_codes": [],
                "completed_at_ms": 10
            }],
            "adjudication": null
        }]);

        let error = evaluate_embedded_temporal_review(&bundle.to_string())
            .expect_err("unknown reviewer reference");

        assert!(error.to_string().contains("unknown reviewer"));
    }

    #[test]
    fn adjudication_must_follow_all_reviews() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let (case_id, labels) = target.expected_labels.iter().next().expect("corpus case");
        let labels = labels.iter().collect::<Vec<_>>();
        let mut bundle: serde_json::Value =
            serde_json::from_str(&pending_bundle()).expect("pending bundle JSON");
        bundle["cases"] = serde_json::json!([{
            "case_id": case_id,
            "annotations": [
                {
                    "reviewer_token": "reviewer_a_8f2c10",
                    "expected_reason_codes": labels,
                    "completed_at_ms": 10
                },
                {
                    "reviewer_token": "reviewer_b_41ad22",
                    "expected_reason_codes": labels,
                    "completed_at_ms": 20
                }
            ],
            "adjudication": {
                "adjudicator_token": "adjudicator_c_77b901",
                "expected_reason_codes": labels,
                "completed_at_ms": 20
            }
        }]);

        let report = evaluate_embedded_temporal_review(&bundle.to_string())
            .expect("structurally valid review bundle");

        assert_eq!(report.metrics.cases_with_complete_adjudication, 0);
    }

    #[test]
    fn reviewer_agreement_is_reported_before_adjudication() {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let (case_id, labels) = target.expected_labels.iter().next().expect("corpus case");
        let labels = labels.iter().collect::<Vec<_>>();
        let mut bundle: serde_json::Value =
            serde_json::from_str(&pending_bundle()).expect("pending bundle JSON");
        bundle["cases"] = serde_json::json!([{
            "case_id": case_id,
            "annotations": [
                {
                    "reviewer_token": "reviewer_a_8f2c10",
                    "expected_reason_codes": labels,
                    "completed_at_ms": 10
                },
                {
                    "reviewer_token": "reviewer_b_41ad22",
                    "expected_reason_codes": labels,
                    "completed_at_ms": 20
                }
            ],
            "adjudication": null
        }]);

        let report = evaluate_embedded_temporal_review(&bundle.to_string())
            .expect("structurally valid review bundle");

        assert_eq!(report.overall_status, "pending");
        assert_eq!(report.metrics.reviewer_pair_comparisons, 1);
        assert_eq!(report.metrics.exact_set_pair_agreement_rate, Some(1.0));
    }

    #[test]
    fn nominal_alpha_is_one_for_perfect_binary_agreement_with_variation() {
        let mut accumulator = NominalAgreementAccumulator::default();
        accumulator.observe_binary(2, 2);
        accumulator.observe_binary(0, 2);

        assert_eq!(accumulator.krippendorff_alpha_nominal(), Some(1.0));
    }

    #[test]
    fn nominal_alpha_is_undefined_without_category_variation() {
        let mut accumulator = NominalAgreementAccumulator::default();
        accumulator.observe_binary(2, 2);
        accumulator.observe_binary(2, 2);

        assert_eq!(accumulator.krippendorff_alpha_nominal(), None);
    }

    #[test]
    fn nominal_alpha_reports_negative_systematic_disagreement() {
        let mut accumulator = NominalAgreementAccumulator::default();
        accumulator.observe_binary(1, 2);
        accumulator.observe_binary(1, 2);

        let alpha = accumulator
            .krippendorff_alpha_nominal()
            .expect("defined alpha");
        assert!((alpha + 0.5).abs() < f64::EPSILON);
    }
}
