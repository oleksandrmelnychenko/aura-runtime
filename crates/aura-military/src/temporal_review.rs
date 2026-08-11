//! Validation of independently produced labels for the temporal Shadow corpus.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::temporal_eval::{embedded_temporal_review_target, TemporalShadowError};

const REVIEW_SCHEMA_VERSION: &str = "aura.military.temporal_independent_review.v1";
const REPORT_SCHEMA_VERSION: &str = "aura.military.temporal_review_report.v2";
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// Machine-readable status of independent human review for the temporal corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalReviewReport {
    pub schema_version: &'static str,
    pub overall_status: &'static str,
    pub dataset_id: String,
    pub corpus_sha256: String,
    pub review_bundle_id: String,
    pub label_blinding_declared: bool,
    pub blinding_assurance: &'static str,
    pub blind_packet_id: Option<String>,
    pub blind_packet_canonical_sha256: Option<String>,
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

/// Evaluates a review bundle against the exact embedded temporal corpus.
///
/// A passing report requires two blinded reviewers from distinct affiliations
/// and a separate adjudicator for every case. Reviewer tokens never appear in
/// the generated report.
pub fn evaluate_embedded_temporal_review(
    json: &str,
) -> Result<TemporalReviewReport, TemporalReviewError> {
    let bundle: TemporalReviewBundle = serde_json::from_str(json)?;
    validate_bundle_identity(&bundle)?;
    let target = embedded_temporal_review_target()?;
    if bundle.dataset_id != target.dataset_id || bundle.corpus_sha256 != target.corpus_sha256 {
        return invalid_bundle("review bundle is not bound to the embedded corpus identity");
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
    let required_reviewers = bundle.protocol.minimum_reviewers_per_case;

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
        resolved_disagreement_cases +=
            usize::from(annotations_are_complete && !direct_agreement && adjudication_is_complete);
    }

    let corpus_cases = target.expected_labels.len();
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
        dataset_id: target.dataset_id,
        corpus_sha256: target.corpus_sha256,
        review_bundle_id: bundle.review_bundle_id,
        label_blinding_declared: bundle.protocol.label_blinding,
        blinding_assurance: "declared_only",
        blind_packet_id: None,
        blind_packet_canonical_sha256: None,
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

        assert!(error.to_string().contains("embedded corpus identity"));
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
}
