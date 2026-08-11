//! Packet-bound blinding for independent temporal-corpus review.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use aura_domain::{
    DomainConversationType, DomainEventKind, DomainTemporalActorRole, DomainTemporalDirectionality,
    DomainTemporalInput, DomainTemporalSpeechAct, DomainTemporalStance,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::temporal::temporal_event_evidence_threshold_met;
use crate::temporal_eval::{
    embedded_temporal_review_target, temporal_review_target, TemporalReviewTarget,
    TemporalShadowError,
};
use crate::temporal_review::{
    evaluate_temporal_review_against_target, TemporalReviewCheck, TemporalReviewError,
    TemporalReviewReport,
};
use crate::temporal_study::{
    validate_preregistration_against_target, TemporalPreregistrationBinding,
    TemporalStudyCorpusClass, TemporalStudyError,
};

const PACKET_SCHEMA_VERSION: &str = "aura.military.temporal_blind_review_packet.v2";
const COORDINATOR_MAP_SCHEMA_VERSION: &str = "aura.military.temporal_blind_coordinator_map.v2";
const REVIEW_SCHEMA_VERSION: &str = "aura.military.temporal_independent_review.v3";
const STUDY_COMMITMENT_SCHEMA_VERSION: &str = "aura.military.temporal_study_commitment.v1";
const BLINDING_ASSURANCE: &str = "packet_bound";
const TOKEN_DOMAIN: &[u8] = b"aura.temporal-review.blind-token.v1\0";
const ORDER_DOMAIN: &[u8] = b"aura.temporal-review.blind-order.v1\0";

type HmacSha256 = Hmac<Sha256>;

/// Error returned when blind review material is invalid or cannot be produced.
#[derive(Debug, Error)]
pub enum TemporalBlindReviewError {
    #[error("invalid temporal blind-review JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid temporal blind-review material: {0}")]
    InvalidMaterial(String),
    #[error("temporal Shadow corpus is unavailable: {0}")]
    Corpus(#[from] TemporalShadowError),
    #[error("temporal independent review is invalid: {0}")]
    Review(#[from] TemporalReviewError),
    #[error("temporal study preregistration is invalid: {0}")]
    Study(#[from] TemporalStudyError),
}

/// Content-free packet that can be distributed to blinded reviewers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalBlindReviewPacket {
    pub schema_version: String,
    pub study_id: String,
    pub preregistration_canonical_sha256: String,
    pub packet_id: String,
    pub blinding_assurance: String,
    pub reason_code_catalog: Vec<String>,
    pub cases: Vec<TemporalBlindReviewCase>,
}

/// One blinded temporal case without source identifiers or seed expectations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalBlindReviewCase {
    pub blind_case_token: String,
    pub current_actor_token: u32,
    pub current_content_token: Option<u64>,
    pub conversation_type: DomainConversationType,
    pub events: Vec<TemporalBlindReviewEvent>,
}

/// One locally remapped event in a blinded review case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalBlindReviewEvent {
    pub relative_to_current_ms: i64,
    pub actor_token: u32,
    pub actor_role: DomainTemporalActorRole,
    pub kind: DomainEventKind,
    pub event_evidence_threshold_met: bool,
    pub content_token: Option<u64>,
    pub context: TemporalBlindReviewContext,
}

/// Interpreted context without upstream machine-confidence values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalBlindReviewContext {
    pub speech_act: DomainTemporalSpeechAct,
    pub stance: DomainTemporalStance,
    pub directionality: DomainTemporalDirectionality,
    pub trusted_contact: bool,
    pub interpretation_evidence_present: bool,
}

/// Coordinator-only mapping that must never be distributed to reviewers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalBlindCoordinatorMap {
    pub schema_version: String,
    pub study_id: String,
    pub preregistration_canonical_sha256: String,
    pub packet_id: String,
    pub dataset_id: String,
    pub corpus_sha256: String,
    pub packet_canonical_sha256: String,
    pub cases: Vec<TemporalBlindCoordinatorCase>,
}

/// Mapping between one blinded token and its internal corpus case identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalBlindCoordinatorCase {
    pub blind_case_token: String,
    pub internal_case_id: String,
}

/// Empty packet-bound bundle that reviewers and the adjudicator can populate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalBlindReviewTemplate {
    pub schema_version: String,
    pub study_id: String,
    pub preregistration_canonical_sha256: String,
    pub review_bundle_id: String,
    pub packet_id: String,
    pub packet_canonical_sha256: String,
    pub protocol: TemporalBlindReviewTemplateProtocol,
    pub reviewers: Vec<serde_json::Value>,
    pub cases: Vec<TemporalBlindReviewTemplateCase>,
}

/// Prespecified protocol fields for a blind review template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TemporalBlindReviewTemplateProtocol {
    pub label_blinding: bool,
    pub minimum_reviewers_per_case: usize,
    pub distinct_reviewer_affiliations: bool,
    pub independent_adjudicator: bool,
}

/// Empty annotations for one blinded case token.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalBlindReviewTemplateCase {
    pub blind_case_token: String,
    pub annotations: Vec<serde_json::Value>,
    pub adjudication: Option<serde_json::Value>,
}

/// Complete output of a packet-generation round.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalBlindReviewMaterials {
    pub packet: TemporalBlindReviewPacket,
    pub coordinator_map: TemporalBlindCoordinatorMap,
    pub review_template: TemporalBlindReviewTemplate,
    pub study_commitment: TemporalStudyCommitment,
}

/// Public pre-review commitment suitable for detached institutional signing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalStudyCommitment {
    pub schema_version: String,
    pub study_id: String,
    pub registered_at_ms: u64,
    pub corpus_class: TemporalStudyCorpusClass,
    pub preregistration_canonical_sha256: String,
    pub dataset_id: String,
    pub corpus_sha256: String,
    pub packet_id: String,
    pub packet_canonical_sha256: String,
    pub case_count: usize,
    pub minimum_reviewers_per_case: usize,
    pub minimum_acceptable_exact_set_pair_agreement_rate: f64,
    pub minimum_acceptable_krippendorff_alpha: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalBlindReviewBundle {
    schema_version: String,
    study_id: String,
    preregistration_canonical_sha256: String,
    review_bundle_id: String,
    packet_id: String,
    packet_canonical_sha256: String,
    protocol: TemporalBlindReviewProtocol,
    #[serde(default)]
    reviewers: Vec<TemporalBlindReviewer>,
    #[serde(default)]
    cases: Vec<TemporalBlindReviewedCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalBlindReviewProtocol {
    label_blinding: bool,
    minimum_reviewers_per_case: usize,
    distinct_reviewer_affiliations: bool,
    independent_adjudicator: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalBlindReviewer {
    reviewer_token: String,
    affiliation_token: String,
    role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalBlindReviewedCase {
    blind_case_token: String,
    #[serde(default)]
    annotations: Vec<TemporalBlindAnnotation>,
    adjudication: Option<TemporalBlindAdjudication>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalBlindAnnotation {
    reviewer_token: String,
    expected_reason_codes: Vec<String>,
    completed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalBlindAdjudication {
    adjudicator_token: String,
    expected_reason_codes: Vec<String>,
    completed_at_ms: u64,
}

/// Generates a reviewer packet, coordinator-only map, blank v3 bundle, and commitment.
///
/// The 32-byte blinding key is used only to derive per-round HMAC tokens and
/// ordering. It is never included in any returned material.
pub fn generate_embedded_temporal_blind_review_materials(
    preregistration_json: &str,
    packet_id: &str,
    blinding_key: &[u8; 32],
) -> Result<TemporalBlindReviewMaterials, TemporalBlindReviewError> {
    let target = embedded_temporal_review_target()?;
    let preregistration = validate_preregistration_against_target(
        preregistration_json,
        &target,
        Some(TemporalStudyCorpusClass::PublicSeed),
    )?;
    generate_temporal_blind_review_materials_for_target(
        &target,
        &preregistration,
        packet_id,
        blinding_key,
    )
}

/// Generates blind-review material for a caller-supplied content-free corpus.
pub fn generate_temporal_blind_review_materials(
    corpus_json: &str,
    preregistration_json: &str,
    packet_id: &str,
    blinding_key: &[u8; 32],
) -> Result<TemporalBlindReviewMaterials, TemporalBlindReviewError> {
    let target = temporal_review_target(corpus_json)?;
    let preregistration = validate_preregistration_against_target(
        preregistration_json,
        &target,
        Some(TemporalStudyCorpusClass::EmbargoedExternal),
    )?;
    generate_temporal_blind_review_materials_for_target(
        &target,
        &preregistration,
        packet_id,
        blinding_key,
    )
}

fn generate_temporal_blind_review_materials_for_target(
    target: &TemporalReviewTarget,
    preregistration: &TemporalPreregistrationBinding,
    packet_id: &str,
    blinding_key: &[u8; 32],
) -> Result<TemporalBlindReviewMaterials, TemporalBlindReviewError> {
    if !safe_token(packet_id) {
        return invalid_material("packet_id must be an 8..=64 character safe token");
    }
    let mut generated = Vec::with_capacity(target.cases.len());
    let mut tokens = HashSet::with_capacity(target.cases.len());
    let mut case_shape_labels = HashMap::with_capacity(target.cases.len());

    for (case_id, input) in &target.cases {
        let token_digest = derive_case_digest(
            blinding_key,
            TOKEN_DOMAIN,
            packet_id,
            &preregistration.canonical_sha256,
            &target.corpus_sha256,
            case_id,
        )?;
        let blind_case_token = format!("blind_{}", hex(&token_digest[..16]));
        if !tokens.insert(blind_case_token.clone()) {
            return invalid_material("derived blind case token collision");
        }
        let order_digest = derive_case_digest(
            blinding_key,
            ORDER_DOMAIN,
            packet_id,
            &preregistration.canonical_sha256,
            &target.corpus_sha256,
            case_id,
        )?;
        let case = blind_case(&blind_case_token, input)?;
        let labels = target.expected_labels.get(case_id).ok_or_else(|| {
            TemporalBlindReviewError::InvalidMaterial(
                "blind corpus case is missing its expected labels".to_string(),
            )
        })?;
        if case_shape_labels
            .insert(blind_case_shape_sha256(&case)?, labels)
            .is_some_and(|existing| existing != labels)
        {
            return invalid_material("structurally identical blind cases have different labels");
        }
        generated.push((
            order_digest,
            case,
            TemporalBlindCoordinatorCase {
                blind_case_token,
                internal_case_id: case_id.clone(),
            },
        ));
    }
    generated.sort_by_key(|entry| entry.0);

    let reason_code_catalog = target
        .expected_labels
        .values()
        .flat_map(|labels| labels.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let packet = TemporalBlindReviewPacket {
        schema_version: PACKET_SCHEMA_VERSION.to_string(),
        study_id: preregistration.study_id.clone(),
        preregistration_canonical_sha256: preregistration.canonical_sha256.clone(),
        packet_id: packet_id.to_string(),
        blinding_assurance: BLINDING_ASSURANCE.to_string(),
        reason_code_catalog,
        cases: generated.iter().map(|(_, case, _)| case.clone()).collect(),
    };
    let packet_canonical_sha256 = canonical_sha256(&packet)?;
    let coordinator_map = TemporalBlindCoordinatorMap {
        schema_version: COORDINATOR_MAP_SCHEMA_VERSION.to_string(),
        study_id: preregistration.study_id.clone(),
        preregistration_canonical_sha256: preregistration.canonical_sha256.clone(),
        packet_id: packet_id.to_string(),
        dataset_id: target.dataset_id.clone(),
        corpus_sha256: target.corpus_sha256.clone(),
        packet_canonical_sha256: packet_canonical_sha256.clone(),
        cases: generated.into_iter().map(|(_, _, map)| map).collect(),
    };
    let review_template = TemporalBlindReviewTemplate {
        schema_version: REVIEW_SCHEMA_VERSION.to_string(),
        study_id: preregistration.study_id.clone(),
        preregistration_canonical_sha256: preregistration.canonical_sha256.clone(),
        review_bundle_id: packet_id.to_string(),
        packet_id: packet_id.to_string(),
        packet_canonical_sha256,
        protocol: TemporalBlindReviewTemplateProtocol {
            label_blinding: true,
            minimum_reviewers_per_case: preregistration.minimum_reviewers_per_case,
            distinct_reviewer_affiliations: true,
            independent_adjudicator: true,
        },
        reviewers: Vec::new(),
        cases: packet
            .cases
            .iter()
            .map(|case| TemporalBlindReviewTemplateCase {
                blind_case_token: case.blind_case_token.clone(),
                annotations: Vec::new(),
                adjudication: None,
            })
            .collect(),
    };
    let study_commitment =
        build_study_commitment(target, preregistration, &packet, &coordinator_map);

    Ok(TemporalBlindReviewMaterials {
        packet,
        coordinator_map,
        review_template,
        study_commitment,
    })
}

fn build_study_commitment(
    target: &TemporalReviewTarget,
    preregistration: &TemporalPreregistrationBinding,
    packet: &TemporalBlindReviewPacket,
    coordinator_map: &TemporalBlindCoordinatorMap,
) -> TemporalStudyCommitment {
    TemporalStudyCommitment {
        schema_version: STUDY_COMMITMENT_SCHEMA_VERSION.to_string(),
        study_id: preregistration.study_id.clone(),
        registered_at_ms: preregistration.registered_at_ms,
        corpus_class: preregistration.corpus_class,
        preregistration_canonical_sha256: preregistration.canonical_sha256.clone(),
        dataset_id: target.dataset_id.clone(),
        corpus_sha256: target.corpus_sha256.clone(),
        packet_id: packet.packet_id.clone(),
        packet_canonical_sha256: coordinator_map.packet_canonical_sha256.clone(),
        case_count: packet.cases.len(),
        minimum_reviewers_per_case: preregistration.minimum_reviewers_per_case,
        minimum_acceptable_exact_set_pair_agreement_rate: preregistration
            .minimum_acceptable_exact_set_pair_agreement_rate,
        minimum_acceptable_krippendorff_alpha: preregistration
            .minimum_acceptable_krippendorff_alpha,
    }
}

/// Validates that a reviewer packet and coordinator map bind the exact corpus.
pub fn validate_embedded_temporal_blind_review_binding(
    preregistration_json: &str,
    packet_json: &str,
    coordinator_map_json: &str,
) -> Result<(TemporalBlindReviewPacket, TemporalBlindCoordinatorMap), TemporalBlindReviewError> {
    let target = embedded_temporal_review_target()?;
    let preregistration = validate_preregistration_against_target(
        preregistration_json,
        &target,
        Some(TemporalStudyCorpusClass::PublicSeed),
    )?;
    validate_temporal_blind_review_binding_for_target(
        &target,
        &preregistration,
        packet_json,
        coordinator_map_json,
    )
}

/// Validates a reviewer packet and map against a caller-supplied corpus.
pub fn validate_temporal_blind_review_binding(
    corpus_json: &str,
    preregistration_json: &str,
    packet_json: &str,
    coordinator_map_json: &str,
) -> Result<(TemporalBlindReviewPacket, TemporalBlindCoordinatorMap), TemporalBlindReviewError> {
    let target = temporal_review_target(corpus_json)?;
    let preregistration = validate_preregistration_against_target(
        preregistration_json,
        &target,
        Some(TemporalStudyCorpusClass::EmbargoedExternal),
    )?;
    validate_temporal_blind_review_binding_for_target(
        &target,
        &preregistration,
        packet_json,
        coordinator_map_json,
    )
}

fn validate_temporal_blind_review_binding_for_target(
    target: &TemporalReviewTarget,
    preregistration: &TemporalPreregistrationBinding,
    packet_json: &str,
    coordinator_map_json: &str,
) -> Result<(TemporalBlindReviewPacket, TemporalBlindCoordinatorMap), TemporalBlindReviewError> {
    let packet: TemporalBlindReviewPacket = serde_json::from_str(packet_json)?;
    let coordinator_map: TemporalBlindCoordinatorMap = serde_json::from_str(coordinator_map_json)?;
    validate_packet_and_map(target, preregistration, &packet, &coordinator_map)?;
    Ok((packet, coordinator_map))
}

/// Evaluates a preregistered packet-bound v3 review without exporting blind mappings.
pub fn evaluate_embedded_temporal_blind_review(
    preregistration_json: &str,
    packet_json: &str,
    coordinator_map_json: &str,
    study_commitment_json: &str,
    review_bundle_json: &str,
) -> Result<TemporalReviewReport, TemporalBlindReviewError> {
    let target = embedded_temporal_review_target()?;
    let preregistration = validate_preregistration_against_target(
        preregistration_json,
        &target,
        Some(TemporalStudyCorpusClass::PublicSeed),
    )?;
    evaluate_temporal_blind_review_for_target(
        &target,
        &preregistration,
        packet_json,
        coordinator_map_json,
        study_commitment_json,
        review_bundle_json,
    )
}

/// Evaluates packet-bound review material for a caller-supplied corpus.
pub fn evaluate_temporal_blind_review(
    corpus_json: &str,
    preregistration_json: &str,
    packet_json: &str,
    coordinator_map_json: &str,
    study_commitment_json: &str,
    review_bundle_json: &str,
) -> Result<TemporalReviewReport, TemporalBlindReviewError> {
    let target = temporal_review_target(corpus_json)?;
    let preregistration = validate_preregistration_against_target(
        preregistration_json,
        &target,
        Some(TemporalStudyCorpusClass::EmbargoedExternal),
    )?;
    evaluate_temporal_blind_review_for_target(
        &target,
        &preregistration,
        packet_json,
        coordinator_map_json,
        study_commitment_json,
        review_bundle_json,
    )
}

fn evaluate_temporal_blind_review_for_target(
    target: &TemporalReviewTarget,
    preregistration: &TemporalPreregistrationBinding,
    packet_json: &str,
    coordinator_map_json: &str,
    study_commitment_json: &str,
    review_bundle_json: &str,
) -> Result<TemporalReviewReport, TemporalBlindReviewError> {
    let (packet, coordinator_map) = validate_temporal_blind_review_binding_for_target(
        target,
        preregistration,
        packet_json,
        coordinator_map_json,
    )?;
    let study_commitment = validate_study_commitment(
        target,
        preregistration,
        &packet,
        &coordinator_map,
        study_commitment_json,
    )?;
    let bundle: TemporalBlindReviewBundle = serde_json::from_str(review_bundle_json)?;
    validate_blind_review_bundle(&bundle, &packet, &coordinator_map, preregistration)?;

    let internal_case_ids = coordinator_map
        .cases
        .iter()
        .map(|case| {
            (
                case.blind_case_token.as_str(),
                case.internal_case_id.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let cases = bundle
        .cases
        .iter()
        .map(|case| {
            let internal_case_id = internal_case_ids
                .get(case.blind_case_token.as_str())
                .ok_or_else(|| {
                    TemporalBlindReviewError::InvalidMaterial(
                        "review bundle references an unknown blind case token".to_string(),
                    )
                })?;
            Ok(serde_json::json!({
                "case_id": internal_case_id,
                "annotations": case.annotations,
                "adjudication": case.adjudication,
            }))
        })
        .collect::<Result<Vec<_>, TemporalBlindReviewError>>()?;
    let legacy_bundle = serde_json::json!({
        "schema_version": "aura.military.temporal_independent_review.v1",
        "review_bundle_id": bundle.review_bundle_id,
        "dataset_id": coordinator_map.dataset_id,
        "corpus_sha256": coordinator_map.corpus_sha256,
        "protocol": bundle.protocol,
        "reviewers": bundle.reviewers,
        "cases": cases,
    });
    let mut report = evaluate_temporal_review_against_target(&legacy_bundle.to_string(), target)?;
    report.blinding_assurance = BLINDING_ASSURANCE;
    report.blind_packet_id = Some(packet.packet_id);
    report.blind_packet_canonical_sha256 = Some(coordinator_map.packet_canonical_sha256);
    report.preregistration_assurance = "packet_bound";
    report.study_id = Some(preregistration.study_id.clone());
    report.study_corpus_class = Some(preregistration.corpus_class);
    report.preregistration_canonical_sha256 = Some(preregistration.canonical_sha256.clone());
    report.study_commitment_canonical_sha256 = Some(canonical_sha256(&study_commitment)?);
    report.chronology.declared_preregistration_at_ms = Some(preregistration.registered_at_ms);
    report.checks.extend([
        minimum_metric_check(
            "exact_set_pair_agreement_threshold",
            report.metrics.exact_set_pair_agreement_rate,
            preregistration.minimum_acceptable_exact_set_pair_agreement_rate,
        ),
        minimum_metric_check(
            "krippendorff_alpha_nominal_threshold",
            report.metrics.krippendorff_alpha_nominal,
            preregistration.minimum_acceptable_krippendorff_alpha,
        ),
    ]);
    if report.overall_status == "pass" && report.checks.iter().any(|check| !check.passed) {
        report.overall_status = "fail";
    }
    Ok(report)
}

fn validate_study_commitment(
    target: &TemporalReviewTarget,
    preregistration: &TemporalPreregistrationBinding,
    packet: &TemporalBlindReviewPacket,
    coordinator_map: &TemporalBlindCoordinatorMap,
    study_commitment_json: &str,
) -> Result<TemporalStudyCommitment, TemporalBlindReviewError> {
    let commitment: TemporalStudyCommitment = serde_json::from_str(study_commitment_json)?;
    if commitment != build_study_commitment(target, preregistration, packet, coordinator_map) {
        return invalid_material("study commitment does not match preregistration and packet");
    }
    Ok(commitment)
}

fn minimum_metric_check(name: &str, actual: Option<f64>, minimum: f64) -> TemporalReviewCheck {
    TemporalReviewCheck {
        name: name.to_string(),
        requirement: format!(">={minimum:.6}"),
        actual: actual.map_or_else(|| "null".to_string(), |value| format!("{value:.6}")),
        passed: actual.is_some_and(|value| value >= minimum),
    }
}

fn validate_packet_and_map(
    target: &TemporalReviewTarget,
    preregistration: &TemporalPreregistrationBinding,
    packet: &TemporalBlindReviewPacket,
    coordinator_map: &TemporalBlindCoordinatorMap,
) -> Result<(), TemporalBlindReviewError> {
    if packet.schema_version != PACKET_SCHEMA_VERSION
        || coordinator_map.schema_version != COORDINATOR_MAP_SCHEMA_VERSION
    {
        return invalid_material("blind packet or coordinator map schema is unsupported");
    }
    if packet.blinding_assurance != BLINDING_ASSURANCE
        || !safe_token(&packet.packet_id)
        || packet.packet_id != coordinator_map.packet_id
        || packet.study_id != preregistration.study_id
        || coordinator_map.study_id != preregistration.study_id
        || packet.preregistration_canonical_sha256 != preregistration.canonical_sha256
        || coordinator_map.preregistration_canonical_sha256 != preregistration.canonical_sha256
    {
        return invalid_material("blind packet identity, preregistration, or assurance is invalid");
    }
    if coordinator_map.dataset_id != target.dataset_id
        || coordinator_map.corpus_sha256 != target.corpus_sha256
    {
        return invalid_material("coordinator map is not bound to the supplied corpus");
    }
    let expected_reason_codes = target
        .expected_labels
        .values()
        .flat_map(|labels| labels.iter().cloned())
        .collect::<BTreeSet<_>>();
    if packet
        .reason_code_catalog
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_reason_codes
        || packet.reason_code_catalog.len() != expected_reason_codes.len()
    {
        return invalid_material("blind packet reason-code catalog is invalid");
    }
    if packet.cases.len() != target.cases.len() || coordinator_map.cases.len() != target.cases.len()
    {
        return invalid_material("blind packet case count does not match the corpus");
    }
    let packet_digest = canonical_sha256(packet)?;
    if packet_digest != coordinator_map.packet_canonical_sha256 {
        return invalid_material("blind packet canonical digest does not match coordinator map");
    }

    let packet_cases = packet
        .cases
        .iter()
        .map(|case| (case.blind_case_token.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    if packet_cases.len() != packet.cases.len() {
        return invalid_material("blind packet case tokens must be unique");
    }
    let mut mapped_tokens = HashSet::with_capacity(coordinator_map.cases.len());
    let mut mapped_case_ids = HashSet::with_capacity(coordinator_map.cases.len());
    let mut case_shape_labels = HashMap::with_capacity(coordinator_map.cases.len());
    for mapping in &coordinator_map.cases {
        if !blind_case_token_is_valid(&mapping.blind_case_token)
            || !mapped_tokens.insert(mapping.blind_case_token.as_str())
            || !mapped_case_ids.insert(mapping.internal_case_id.as_str())
        {
            return invalid_material("coordinator map tokens and case identifiers must be unique");
        }
        let input = target.cases.get(&mapping.internal_case_id).ok_or_else(|| {
            TemporalBlindReviewError::InvalidMaterial(
                "coordinator map references an unknown internal case".to_string(),
            )
        })?;
        let actual_case = packet_cases
            .get(mapping.blind_case_token.as_str())
            .ok_or_else(|| {
                TemporalBlindReviewError::InvalidMaterial(
                    "coordinator map token is absent from blind packet".to_string(),
                )
            })?;
        let expected_case = blind_case(&mapping.blind_case_token, input)?;
        if **actual_case != expected_case {
            return invalid_material("blind packet case does not match its coordinator mapping");
        }
        let labels = target
            .expected_labels
            .get(&mapping.internal_case_id)
            .ok_or_else(|| {
                TemporalBlindReviewError::InvalidMaterial(
                    "mapped corpus case is missing its expected labels".to_string(),
                )
            })?;
        if case_shape_labels
            .insert(blind_case_shape_sha256(actual_case)?, labels)
            .is_some_and(|existing| existing != labels)
        {
            return invalid_material("structurally identical blind cases have different labels");
        }
    }
    if mapped_case_ids
        != target
            .cases
            .keys()
            .map(String::as_str)
            .collect::<HashSet<_>>()
    {
        return invalid_material("coordinator map does not cover the exact corpus");
    }
    Ok(())
}

fn validate_blind_review_bundle(
    bundle: &TemporalBlindReviewBundle,
    packet: &TemporalBlindReviewPacket,
    coordinator_map: &TemporalBlindCoordinatorMap,
    preregistration: &TemporalPreregistrationBinding,
) -> Result<(), TemporalBlindReviewError> {
    if bundle.schema_version != REVIEW_SCHEMA_VERSION
        || bundle.study_id != packet.study_id
        || bundle.preregistration_canonical_sha256 != packet.preregistration_canonical_sha256
        || bundle.packet_id != packet.packet_id
        || bundle.packet_canonical_sha256 != coordinator_map.packet_canonical_sha256
        || !bundle.protocol.label_blinding
        || bundle.protocol.minimum_reviewers_per_case != preregistration.minimum_reviewers_per_case
        || !bundle.protocol.distinct_reviewer_affiliations
        || !bundle.protocol.independent_adjudicator
    {
        return invalid_material("review bundle is not bound to the blind packet");
    }
    let packet_tokens = packet
        .cases
        .iter()
        .map(|case| case.blind_case_token.as_str())
        .collect::<HashSet<_>>();
    let mut review_tokens = HashSet::with_capacity(bundle.cases.len());
    for case in &bundle.cases {
        if !packet_tokens.contains(case.blind_case_token.as_str())
            || !review_tokens.insert(case.blind_case_token.as_str())
        {
            return invalid_material("review bundle has an unknown or duplicate blind case token");
        }
        if case
            .annotations
            .iter()
            .any(|annotation| annotation.completed_at_ms <= preregistration.registered_at_ms)
            || case.adjudication.as_ref().is_some_and(|adjudication| {
                adjudication.completed_at_ms <= preregistration.registered_at_ms
            })
        {
            return invalid_material(
                "review decisions must be completed after the preregistration time",
            );
        }
    }
    Ok(())
}

fn blind_case(
    blind_case_token: &str,
    input: &DomainTemporalInput,
) -> Result<TemporalBlindReviewCase, TemporalBlindReviewError> {
    let mut actor_tokens = BTreeMap::new();
    let mut content_tokens = BTreeMap::new();
    let current_actor_token = local_actor_token(&mut actor_tokens, input.current_actor_id)?;
    let current_content_token = input
        .current_content_hash
        .map(|hash| local_content_token(&mut content_tokens, hash))
        .transpose()?;
    let mut ordered_events = input.events.iter().collect::<Vec<_>>();
    ordered_events.sort_by_key(|event| (event.timestamp_ms, event.event_id));
    let events = ordered_events
        .into_iter()
        .map(|event| {
            Ok(TemporalBlindReviewEvent {
                relative_to_current_ms: relative_time(event.timestamp_ms, input.as_of_ms)?,
                actor_token: local_actor_token(&mut actor_tokens, event.actor_id)?,
                actor_role: event.actor_role,
                kind: event.kind,
                event_evidence_threshold_met: temporal_event_evidence_threshold_met(
                    event.confidence,
                )
                .map_err(TemporalBlindReviewError::InvalidMaterial)?,
                content_token: event
                    .content_hash
                    .map(|hash| local_content_token(&mut content_tokens, hash))
                    .transpose()?,
                context: TemporalBlindReviewContext {
                    speech_act: event.context.speech_act,
                    stance: event.context.stance,
                    directionality: event.context.directionality,
                    trusted_contact: event.context.trusted_contact,
                    interpretation_evidence_present: event.context.confidence > 0.0,
                },
            })
        })
        .collect::<Result<Vec<_>, TemporalBlindReviewError>>()?;
    Ok(TemporalBlindReviewCase {
        blind_case_token: blind_case_token.to_string(),
        current_actor_token,
        current_content_token,
        conversation_type: input.conversation_type,
        events,
    })
}

fn local_actor_token(
    tokens: &mut BTreeMap<u32, u32>,
    actor_id: u32,
) -> Result<u32, TemporalBlindReviewError> {
    if let Some(token) = tokens.get(&actor_id) {
        return Ok(*token);
    }
    let token = u32::try_from(tokens.len() + 1)
        .map_err(|_| TemporalBlindReviewError::InvalidMaterial("too many actors".to_string()))?;
    tokens.insert(actor_id, token);
    Ok(token)
}

fn local_content_token(
    tokens: &mut BTreeMap<u64, u64>,
    content_hash: u64,
) -> Result<u64, TemporalBlindReviewError> {
    if let Some(token) = tokens.get(&content_hash) {
        return Ok(*token);
    }
    let token = u64::try_from(tokens.len() + 1).map_err(|_| {
        TemporalBlindReviewError::InvalidMaterial("too many content references".to_string())
    })?;
    tokens.insert(content_hash, token);
    Ok(token)
}

fn relative_time(timestamp_ms: u64, as_of_ms: u64) -> Result<i64, TemporalBlindReviewError> {
    if timestamp_ms >= as_of_ms {
        i64::try_from(timestamp_ms - as_of_ms).map_err(|_| {
            TemporalBlindReviewError::InvalidMaterial(
                "temporal offset exceeds the blind packet range".to_string(),
            )
        })
    } else {
        let magnitude = i64::try_from(as_of_ms - timestamp_ms).map_err(|_| {
            TemporalBlindReviewError::InvalidMaterial(
                "temporal offset exceeds the blind packet range".to_string(),
            )
        })?;
        Ok(-magnitude)
    }
}

fn derive_case_digest(
    key: &[u8; 32],
    domain: &[u8],
    packet_id: &str,
    preregistration_sha256: &str,
    corpus_sha256: &str,
    case_id: &str,
) -> Result<[u8; 32], TemporalBlindReviewError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        TemporalBlindReviewError::InvalidMaterial("invalid HMAC blinding key".to_string())
    })?;
    mac.update(domain);
    for component in [
        packet_id.as_bytes(),
        preregistration_sha256.as_bytes(),
        corpus_sha256.as_bytes(),
        case_id.as_bytes(),
    ] {
        let length = u64::try_from(component.len()).map_err(|_| {
            TemporalBlindReviewError::InvalidMaterial("HMAC component is too large".to_string())
        })?;
        mac.update(&length.to_be_bytes());
        mac.update(component);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, TemporalBlindReviewError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn blind_case_shape_sha256(
    case: &TemporalBlindReviewCase,
) -> Result<String, TemporalBlindReviewError> {
    let mut shape = case.clone();
    shape.blind_case_token.clear();
    canonical_sha256(&shape)
}

fn safe_token(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn blind_case_token_is_valid(value: &str) -> bool {
    value.len() == 38
        && value.starts_with("blind_")
        && value[6..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn invalid_material<T>(message: impl Into<String>) -> Result<T, TemporalBlindReviewError> {
    Err(TemporalBlindReviewError::InvalidMaterial(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5a; 32];

    fn public_seed_preregistration() -> String {
        let target = embedded_temporal_review_target().expect("embedded review target");
        serde_json::json!({
            "schema_version": "aura.military.temporal_review_preregistration.v1",
            "study_id": "temporal_seed_study_2026",
            "registered_at_ms": 1,
            "corpus_class": "public_seed",
            "research_question": "Do independent reviewers reproduce the frozen temporal labels from content-free event chains?",
            "confirmatory_hypotheses": [{
                "hypothesis_id": "temporal_exact_match",
                "statement": "Adjudicated labels will exactly match the frozen temporal corpus labels for every submitted case."
            }],
            "primary_outcomes": [
                "adjudicated_exact_match_rate",
                "exact_set_pair_agreement_rate",
                "krippendorff_alpha_nominal"
            ],
            "planned_subgroups": ["time_window"],
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
        .to_string()
    }

    fn generated_materials(packet_id: &str) -> TemporalBlindReviewMaterials {
        generate_embedded_temporal_blind_review_materials(
            &public_seed_preregistration(),
            packet_id,
            &KEY,
        )
        .expect("blind review materials")
    }

    fn external_test_corpus_and_preregistration() -> (String, String) {
        let mut corpus: serde_json::Value =
            serde_json::from_str(include_str!("../data/temporal_shadow_corpus.json"))
                .expect("embedded corpus JSON");
        corpus["dataset_id"] =
            serde_json::Value::String("external_temporal_holdout_test".to_string());
        corpus["dataset_label"] =
            serde_json::Value::String("External temporal holdout test".to_string());
        let corpus = corpus.to_string();
        let target = temporal_review_target(&corpus).expect("external review target");
        let mut preregistration: serde_json::Value =
            serde_json::from_str(&public_seed_preregistration()).expect("preregistration JSON");
        preregistration["study_id"] =
            serde_json::Value::String("external_temporal_study_test".to_string());
        preregistration["corpus_class"] =
            serde_json::Value::String("embargoed_external".to_string());
        preregistration["sampling"]["fixed_case_count"] = serde_json::json!(target.cases.len());
        (corpus, preregistration.to_string())
    }

    fn completed_review_bundle(materials: &TemporalBlindReviewMaterials) -> serde_json::Value {
        let target = embedded_temporal_review_target().expect("embedded review target");
        let cases = materials
            .coordinator_map
            .cases
            .iter()
            .map(|mapping| {
                let labels = target
                    .expected_labels
                    .get(&mapping.internal_case_id)
                    .expect("mapped corpus labels");
                serde_json::json!({
                    "blind_case_token": mapping.blind_case_token,
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
                        "completed_at_ms": 30
                    }
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema_version": REVIEW_SCHEMA_VERSION,
            "study_id": materials.packet.study_id,
            "preregistration_canonical_sha256": materials.packet.preregistration_canonical_sha256,
            "review_bundle_id": "blind_round_alpha",
            "packet_id": materials.packet.packet_id,
            "packet_canonical_sha256": materials.coordinator_map.packet_canonical_sha256,
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
            "cases": cases
        })
    }

    #[test]
    fn generated_packet_omits_seed_labels_and_source_identifiers() {
        let materials = generated_materials("blind_round_alpha");
        let json = serde_json::to_string(&materials.packet).expect("packet JSON");

        assert!(![
            "case_id",
            "internal_case_id",
            "expected_reason_codes",
            "positive",
            "negative_control",
            "corpus_sha256",
            "actor_id",
            "content_hash",
            "timestamp_ms",
            "event_id",
            "confidence",
        ]
        .iter()
        .any(|forbidden| json.contains(forbidden)));
    }

    #[test]
    fn packet_generation_is_deterministic_for_one_round() {
        let first = generated_materials("blind_round_alpha");
        let second = generated_materials("blind_round_alpha");

        assert_eq!(first, second);
    }

    #[test]
    fn packet_tokens_change_between_rounds() {
        let first = generated_materials("blind_round_alpha");
        let second = generated_materials("blind_round_bravo");

        assert_ne!(
            first.packet.cases[0].blind_case_token,
            second.packet.cases[0].blind_case_token
        );
    }

    #[test]
    fn tampered_packet_is_rejected_by_coordinator_binding() {
        let materials = generated_materials("blind_round_alpha");
        let mut packet = materials.packet;
        packet.cases[0].events[0].relative_to_current_ms += 1;

        let error = validate_embedded_temporal_blind_review_binding(
            &public_seed_preregistration(),
            &serde_json::to_string(&packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
        )
        .expect_err("tampered packet");

        assert!(error.to_string().contains("canonical digest"));
    }

    #[test]
    fn structurally_identical_packet_cases_share_labels() {
        let materials = generated_materials("blind_round_alpha");
        let target = embedded_temporal_review_target().expect("embedded review target");
        let mut labels_by_shape = HashMap::new();
        for (case, mapping) in materials
            .packet
            .cases
            .iter()
            .zip(&materials.coordinator_map.cases)
        {
            let labels = &target.expected_labels[&mapping.internal_case_id];
            if let Some(existing) =
                labels_by_shape.insert(blind_case_shape_sha256(case).expect("case shape"), labels)
            {
                assert_eq!(existing, labels);
            }
        }
    }

    #[test]
    fn empty_packet_bound_review_remains_pending() {
        let materials = generated_materials("blind_round_alpha");

        let report = evaluate_embedded_temporal_blind_review(
            &public_seed_preregistration(),
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &serde_json::to_string(&materials.review_template).expect("review template JSON"),
        )
        .expect("pending review report");

        assert_eq!(report.overall_status, "pending");
    }

    #[test]
    fn completed_packet_bound_review_passes() {
        let materials = generated_materials("blind_round_alpha");
        let bundle = completed_review_bundle(&materials);

        let report = evaluate_embedded_temporal_blind_review(
            &public_seed_preregistration(),
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &bundle.to_string(),
        )
        .expect("complete review report");

        assert_eq!(report.overall_status, "pass");
        assert!(report.study_commitment_canonical_sha256.is_some());
        assert_eq!(report.chronology.decision_time_assurance, "bundle_declared");
        assert_eq!(report.chronology.declared_preregistration_at_ms, Some(1));
        assert_eq!(
            report.chronology.earliest_annotation_completed_at_ms,
            Some(10)
        );
        assert_eq!(
            report.chronology.latest_annotation_completed_at_ms,
            Some(20)
        );
        assert_eq!(
            report.chronology.earliest_adjudication_completed_at_ms,
            Some(30)
        );
        assert_eq!(
            report.chronology.latest_adjudication_completed_at_ms,
            Some(30)
        );
    }

    #[test]
    fn completed_packet_bound_review_reports_perfect_nominal_alpha() {
        let materials = generated_materials("blind_round_alpha");
        let bundle = completed_review_bundle(&materials);

        let report = evaluate_embedded_temporal_blind_review(
            &public_seed_preregistration(),
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &bundle.to_string(),
        )
        .expect("complete review report");

        assert_eq!(report.metrics.krippendorff_alpha_nominal, Some(1.0));
    }

    #[test]
    fn packet_bound_report_omits_blind_mapping_and_internal_case_ids() {
        let materials = generated_materials("blind_round_alpha");
        let bundle = completed_review_bundle(&materials);
        let report = evaluate_embedded_temporal_blind_review(
            &public_seed_preregistration(),
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &bundle.to_string(),
        )
        .expect("complete review report");
        let json = serde_json::to_string(&report).expect("report JSON");

        assert!(!materials.coordinator_map.cases.iter().any(|mapping| {
            json.contains(&mapping.blind_case_token) || json.contains(&mapping.internal_case_id)
        }));
    }

    #[test]
    fn review_bundle_with_unknown_blind_token_is_rejected() {
        let materials = generated_materials("blind_round_alpha");
        let mut bundle = serde_json::to_value(&materials.review_template).expect("review template");
        bundle["cases"][0]["blind_case_token"] =
            serde_json::Value::String("blind_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());

        let error = evaluate_embedded_temporal_blind_review(
            &public_seed_preregistration(),
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &bundle.to_string(),
        )
        .expect_err("unknown blind token");

        assert!(error.to_string().contains("unknown or duplicate"));
    }

    #[test]
    fn changed_study_commitment_is_rejected() {
        let materials = generated_materials("blind_round_alpha");
        let mut commitment = materials.study_commitment.clone();
        commitment.case_count += 1;

        let error = evaluate_embedded_temporal_blind_review(
            &public_seed_preregistration(),
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&commitment).expect("commitment JSON"),
            &serde_json::to_string(&materials.review_template).expect("review template JSON"),
        )
        .expect_err("changed study commitment");

        assert!(error.to_string().contains("study commitment"));
    }

    #[test]
    fn review_decisions_cannot_predate_preregistration() {
        let mut preregistration: serde_json::Value =
            serde_json::from_str(&public_seed_preregistration()).expect("preregistration JSON");
        preregistration["registered_at_ms"] = serde_json::json!(15);
        let preregistration = preregistration.to_string();
        let materials = generate_embedded_temporal_blind_review_materials(
            &preregistration,
            "blind_round_alpha",
            &KEY,
        )
        .expect("blind review materials");
        let bundle = completed_review_bundle(&materials);

        let error = evaluate_embedded_temporal_blind_review(
            &preregistration,
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &bundle.to_string(),
        )
        .expect_err("review before preregistration");

        assert!(error.to_string().contains("after the preregistration time"));
    }

    #[test]
    fn preregistered_agreement_threshold_can_fail_an_exact_adjudication() {
        let mut preregistration: serde_json::Value =
            serde_json::from_str(&public_seed_preregistration()).expect("preregistration JSON");
        preregistration["analysis"]["minimum_acceptable_exact_set_pair_agreement_rate"] =
            serde_json::json!(1.0);
        preregistration["analysis"]["minimum_acceptable_krippendorff_alpha"] =
            serde_json::json!(1.0);
        let preregistration = preregistration.to_string();
        let materials = generate_embedded_temporal_blind_review_materials(
            &preregistration,
            "blind_round_alpha",
            &KEY,
        )
        .expect("blind review materials");
        let mut bundle = completed_review_bundle(&materials);
        let original_labels = bundle["cases"][0]["annotations"][0]["expected_reason_codes"]
            .as_array()
            .expect("reviewer label array");
        bundle["cases"][0]["annotations"][1]["expected_reason_codes"] =
            if original_labels.is_empty() {
                serde_json::json!([materials.packet.reason_code_catalog[0]])
            } else {
                serde_json::json!([])
            };

        let report = evaluate_embedded_temporal_blind_review(
            &preregistration,
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &bundle.to_string(),
        )
        .expect("review report");

        assert_eq!(report.overall_status, "fail");
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "exact_set_pair_agreement_threshold" && !check.passed));
    }

    #[test]
    fn preregistration_change_after_packet_generation_is_rejected() {
        let materials = generated_materials("blind_round_alpha");
        let mut preregistration: serde_json::Value =
            serde_json::from_str(&public_seed_preregistration()).expect("preregistration JSON");
        preregistration["registered_at_ms"] = serde_json::json!(2);

        let error = validate_embedded_temporal_blind_review_binding(
            &preregistration.to_string(),
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
        )
        .expect_err("changed preregistration");

        assert!(error.to_string().contains("preregistration"));
    }

    #[test]
    fn caller_supplied_external_corpus_round_trip_remains_pending_before_review() {
        let (corpus, preregistration) = external_test_corpus_and_preregistration();
        let materials = generate_temporal_blind_review_materials(
            &corpus,
            &preregistration,
            "external_round_alpha",
            &KEY,
        )
        .expect("external blind material");

        let report = evaluate_temporal_blind_review(
            &corpus,
            &preregistration,
            &serde_json::to_string(&materials.packet).expect("packet JSON"),
            &serde_json::to_string(&materials.coordinator_map).expect("map JSON"),
            &serde_json::to_string(&materials.study_commitment).expect("commitment JSON"),
            &serde_json::to_string(&materials.review_template).expect("review template JSON"),
        )
        .expect("external pending report");

        assert_eq!(report.overall_status, "pending");
    }
}
