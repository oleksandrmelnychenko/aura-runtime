//! Fail-closed result evidence for independent domain evaluation.
//!
//! The private input bundle carries signed reviewer material and trusted-time
//! receipts. The returned report is content-free and never authorizes runtime
//! policy or product actions.

use std::collections::{BTreeSet, HashSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    is_canonical_sha256, validate_domain_study_preregistration, DomainModuleEvidence,
    DomainModuleId, DomainStudyAgreementUncertaintyMethod, DomainStudyBuildProvenance,
    DomainStudyCorpusClass, DomainStudyError, DomainStudyInterRaterAgreementStatistic,
    DomainStudyPreregistration, DomainStudyTemporalMode,
};

/// Supported schema for a private independent-domain result evidence bundle.
pub const DOMAIN_STUDY_RESULT_EVIDENCE_SCHEMA_VERSION: &str =
    "aura.domain.independent_evaluation_evidence.v2";
/// Supported schema for content-free aggregate results.
pub const DOMAIN_STUDY_RESULT_SCHEMA_VERSION: &str = "aura.domain.independent_evaluation_result.v1";
/// Supported schema for governed reviewer-agreement analysis claims.
pub const DOMAIN_STUDY_AGREEMENT_ANALYSIS_SCHEMA_VERSION: &str =
    "aura.domain.reviewer_agreement_analysis.v1";
/// Supported schema for signed adjudication-start authorizations.
pub const DOMAIN_STUDY_ADJUDICATION_START_SCHEMA_VERSION: &str =
    "aura.domain.adjudication_start_authorization.v1";
/// Supported schema for institutional preregistration attestations.
pub const DOMAIN_STUDY_PREREGISTRATION_ATTESTATION_SCHEMA_VERSION: &str =
    "aura.domain.preregistration_attestation.v1";
/// Supported schema for trusted timestamp-verification receipts.
pub const DOMAIN_STUDY_TRUSTED_TIMESTAMP_SCHEMA_VERSION: &str =
    "aura.domain.trusted_timestamp_verification.v2";
/// Supported schema for independently signed reviewer receipts.
pub const DOMAIN_STUDY_REVIEWER_RECEIPT_SCHEMA_VERSION: &str = "aura.domain.reviewer_receipt.v1";
/// Supported schema for private reviewer assignment manifests.
pub const DOMAIN_STUDY_REVIEWER_ASSIGNMENT_SCHEMA_VERSION: &str =
    "aura.domain.reviewer_assignment.v1";
/// Supported schema for the private adjudication manifest.
pub const DOMAIN_STUDY_ADJUDICATION_MANIFEST_SCHEMA_VERSION: &str =
    "aura.domain.adjudication_manifest.v1";
/// Supported schema for the independent adjudicator receipt.
pub const DOMAIN_STUDY_ADJUDICATION_RECEIPT_SCHEMA_VERSION: &str =
    "aura.domain.adjudication_receipt.v1";
/// Supported schema for the signed final evidence manifest.
pub const DOMAIN_STUDY_FINAL_MANIFEST_SCHEMA_VERSION: &str =
    "aura.domain.final_evidence_manifest.v1";

const MAX_EVIDENCE_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_PREREGISTRATION_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_TIMESTAMP_ACCURACY_MICROS: u64 = 5 * 60 * 1_000_000;
const WILSON_95_Z: f64 = 1.959_963_984_540_054;
const PREREGISTRATION_ATTESTATION_DOMAIN: &[u8] = b"aura.domain.preregistration-attestation.v1\0";
const TRUSTED_TIMESTAMP_DOMAIN: &[u8] = b"aura.domain.trusted-timestamp.v1\0";
const REVIEWER_RECEIPT_DOMAIN: &[u8] = b"aura.domain.reviewer-receipt.v1\0";
const ADJUDICATION_START_DOMAIN: &[u8] = b"aura.domain.adjudication-start.v1\0";
const ADJUDICATION_RECEIPT_DOMAIN: &[u8] = b"aura.domain.adjudication-receipt.v1\0";
const FINAL_MANIFEST_DOMAIN: &[u8] = b"aura.domain.final-evidence-manifest.v1\0";

/// Error returned when a result evidence bundle is malformed or untrusted.
#[derive(Debug, Error)]
pub enum DomainStudyResultError {
    /// The supplied evidence is not valid JSON for the strict schema.
    #[error("invalid domain-study result evidence JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// The original preregistration is no longer admissible for this build.
    #[error("invalid bound domain-study preregistration: {0}")]
    InvalidPreregistration(#[from] DomainStudyError),
    /// An evidence, trust, chronology, metric, or privacy invariant failed.
    #[error("invalid domain-study result evidence: {0}")]
    InvalidEvidence(String),
}

/// One Ed25519 public key accepted for a specific evidence role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyTrustedKey {
    /// Stable non-personal key identifier.
    pub key_id: String,
    /// Raw 32-byte Ed25519 public key encoded as lowercase hexadecimal.
    pub public_key_hex: String,
}

/// One trusted reviewer key and its non-reversible affiliation commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyTrustedReviewer {
    /// Trusted reviewer signing key.
    pub key: DomainStudyTrustedKey,
    /// SHA-256 of a governed randomly salted affiliation-commitment artifact.
    pub affiliation_commitment_sha256: String,
}

/// Trust roots supplied by the controlled research environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyTrustPolicy {
    /// Institution key that attests the frozen preregistration.
    pub preregistration_signer: DomainStudyTrustedKey,
    /// Key used only by the verified RFC 3161 adapter.
    pub timestamp_verifier: DomainStudyTrustedKey,
    /// Allowed TSA subject-public-key-info digest.
    pub trusted_tsa_spki_sha256: String,
    /// Allowed RFC 3161 policy object identifier.
    pub trusted_tsa_policy_oid: String,
    /// Reviewer keys, sorted by key identifier.
    pub reviewers: Vec<DomainStudyTrustedReviewer>,
    /// Independent adjudicator key.
    pub adjudicator: DomainStudyTrustedKey,
    /// Institution key that signs the final evidence manifest.
    pub final_manifest_signer: DomainStudyTrustedKey,
}

/// Detached Ed25519 signature over domain-separated canonical claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyDetachedSignature {
    /// Trusted key identifier.
    pub key_id: String,
    /// Raw 64-byte Ed25519 signature encoded as lowercase hexadecimal.
    pub signature_hex: String,
}

/// Institutional claims binding the frozen preregistration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyPreregistrationAttestationClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Canonical digest returned by preregistration validation.
    pub preregistration_canonical_sha256: String,
    /// Declared signing time; trusted chronology comes from the timestamp.
    pub attested_at_ms: u64,
}

/// Signed institutional preregistration attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyPreregistrationAttestation {
    /// Signed claims.
    pub claims: DomainStudyPreregistrationAttestationClaims,
    /// Detached Ed25519 signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Kind of signed artifact covered by a trusted timestamp receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyTimestampSubjectKind {
    /// Signed institutional preregistration attestation.
    PreregistrationAttestation,
    /// Signed reviewer receipt.
    ReviewerReceipt,
    /// Governed reviewer-agreement analysis claims.
    ReviewerAgreementAnalysis,
    /// Signed authorization fixing the earliest admissible adjudication start.
    AdjudicationStartAuthorization,
    /// Signed independent adjudication receipt.
    AdjudicationReceipt,
    /// Signed final evidence manifest.
    FinalEvidenceManifest,
}

/// Accepted trusted-time protocol represented by the signed receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyTimestampProtocol {
    /// RFC 3161 response verified through a trusted chain and complete CRLs.
    Rfc3161TrustedChain,
}

/// Claims emitted by the trusted RFC 3161 verification adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyTrustedTimestampClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Covered artifact kind.
    pub subject_kind: DomainStudyTimestampSubjectKind,
    /// Canonical SHA-256 of the complete signed artifact.
    pub subject_canonical_sha256: String,
    /// Verified timestamp protocol.
    pub protocol: DomainStudyTimestampProtocol,
    /// Floor of the trusted generation time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Microseconds discarded when exact `genTime` is floored to milliseconds.
    pub gen_time_submillisecond_micros: u16,
    /// RFC 3161 declared accuracy bound in microseconds.
    pub accuracy_micros: u64,
    /// Digest of the nonce-bearing DER timestamp request.
    pub request_sha256: String,
    /// Digest of the original DER timestamp response.
    pub response_sha256: String,
    /// Digest of the complete ordered TSA certificate-chain artifact.
    pub certificate_chain_sha256: String,
    /// Digest of the complete revocation-evidence bundle.
    pub revocation_evidence_sha256: String,
    /// TSA subject-public-key-info digest verified through the trusted chain.
    pub tsa_spki_sha256: String,
    /// Verified RFC 3161 policy object identifier.
    pub tsa_policy_oid: String,
}

/// Signed trusted timestamp-verification receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyTrustedTimestampReceipt {
    /// Signed timestamp claims.
    pub claims: DomainStudyTrustedTimestampClaims,
    /// Signature from the configured timestamp-verifier key.
    pub signature: DomainStudyDetachedSignature,
}

/// Private claims signed independently by one reviewer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReviewerReceiptClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Exact preregistration digest reviewed under.
    pub preregistration_canonical_sha256: String,
    /// Exact blinded review-packet digest.
    pub review_packet_sha256: String,
    /// Digest of this reviewer's frozen case assignment.
    pub assignment_manifest_sha256: String,
    /// Digest of this reviewer's frozen decision bundle.
    pub decision_bundle_sha256: String,
    /// Governed salted affiliation commitment bound to the trusted reviewer key.
    pub affiliation_commitment_sha256: String,
    /// Number of cases with a completed decision in this receipt.
    pub completed_case_count: usize,
    /// Declared completion time; trusted chronology comes from the timestamp.
    pub completed_at_ms: u64,
}

/// One independently signed reviewer receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReviewerReceipt {
    /// Signed reviewer claims.
    pub claims: DomainStudyReviewerReceiptClaims,
    /// Reviewer signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Reviewer receipt paired with its trusted timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyTimestampedReviewerReceipt {
    /// Signed private reviewer receipt.
    pub receipt: DomainStudyReviewerReceipt,
    /// Trusted timestamp covering the signed receipt.
    pub trusted_timestamp: DomainStudyTrustedTimestampReceipt,
}

/// Private frozen assignment for one reviewer receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReviewerAssignmentManifest {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Index into the sorted reviewer-receipt array.
    pub reviewer_index: u8,
    /// Sorted blind case-token digests assigned to this reviewer.
    pub blind_case_token_sha256: Vec<String>,
}

/// Private per-case coverage row used to recompute reviewer completeness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyCaseReviewCoverage {
    /// SHA-256 token of the blind case identity; rows are sorted by this value.
    pub blind_case_token_sha256: String,
    /// Sorted indices into the bundle's trusted reviewer-receipt array.
    pub reviewer_indices: Vec<u8>,
    /// Whether the independent adjudicator completed this case.
    pub adjudicated: bool,
}

/// Private frozen mapping from adjudicated cases to the decision artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAdjudicationManifest {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Sorted blind case-token digests completed by the adjudicator.
    pub blind_case_token_sha256: Vec<String>,
    /// Digest of the complete private adjudication decisions.
    pub decision_bundle_sha256: String,
}

/// Claims authorizing adjudication only after agreement analysis is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAdjudicationStartClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Exact preregistration digest.
    pub preregistration_canonical_sha256: String,
    /// Digest of the sorted signed reviewer-receipt set.
    pub reviewer_receipt_set_sha256: String,
    /// Digest of the governed agreement-analysis claims.
    pub agreement_analysis_sha256: String,
    /// Declared authorization time; trusted chronology comes from the timestamp.
    pub authorized_at_ms: u64,
}

/// Adjudicator-signed start authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAdjudicationStartAuthorization {
    /// Signed start claims.
    pub claims: DomainStudyAdjudicationStartClaims,
    /// Independent adjudicator signature under a start-specific domain.
    pub signature: DomainStudyDetachedSignature,
}

/// Claims signed by an adjudicator who is not a reviewer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAdjudicationReceiptClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Exact preregistration digest.
    pub preregistration_canonical_sha256: String,
    /// Digest of the sorted complete reviewer-receipt set.
    pub reviewer_receipt_set_sha256: String,
    /// Digest of the frozen adjudication decision bundle.
    pub adjudication_bundle_sha256: String,
    /// Digest of the label ontology used for adjudication.
    pub label_ontology_sha256: String,
    /// Number of cases adjudicated.
    pub adjudicated_case_count: usize,
    /// Declared completion time; trusted chronology comes from the timestamp.
    pub completed_at_ms: u64,
}

/// Signed independent adjudication receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAdjudicationReceipt {
    /// Signed adjudication claims.
    pub claims: DomainStudyAdjudicationReceiptClaims,
    /// Independent adjudicator signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Integer confusion counts for one preregistered threat family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyThreatCounts {
    /// Preregistered threat-family token.
    pub threat_family: String,
    /// Correct positive decisions.
    pub true_positive: usize,
    /// Incorrect positive decisions.
    pub false_positive: usize,
    /// Missed positive decisions.
    pub false_negative: usize,
}

/// Aggregate counts for one preregistered attack family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAttackFamilyCounts {
    /// Preregistered attack-family token.
    pub attack_family: String,
    /// Evaluated variants in this family.
    pub evaluated_variant_count: usize,
    /// Variants preserving the expected source-case decision.
    pub consistent_variant_count: usize,
}

/// Reported support for one preregistered corpus stratum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyStratumCount {
    /// Preregistered stratum token.
    pub stratum: String,
    /// Analyzed cases represented in this stratum.
    pub case_count: usize,
}

/// Aggregate review-coverage counts without reviewer identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReviewCoverage {
    /// Number of distinct signed reviewer receipts.
    pub reviewer_receipt_count: usize,
    /// Lowest number of completed reviews for any fixed case.
    pub minimum_completed_reviews_per_case: usize,
    /// Highest number of completed reviews for any fixed case.
    pub maximum_completed_reviews_per_case: usize,
    /// Fixed cases meeting the preregistered review minimum.
    pub fully_reviewed_case_count: usize,
    /// Fixed cases completed by the independent adjudicator.
    pub adjudicated_case_count: usize,
}

/// Governed claims for the preregistered reviewer-agreement analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyAgreementAnalysisClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Exact preregistration digest.
    pub preregistration_canonical_sha256: String,
    /// Digest of the sorted signed reviewer-receipt set used as input.
    pub reviewer_receipt_set_sha256: String,
    /// Digest of the exact private coverage matrix used as input.
    pub review_coverage_manifest_sha256: String,
    /// Agreement statistic fixed by the preregistration.
    pub statistic: DomainStudyInterRaterAgreementStatistic,
    /// Uncertainty method fixed by the preregistration.
    pub uncertainty_method: DomainStudyAgreementUncertaintyMethod,
    /// Fixed bootstrap repetition count.
    pub bootstrap_resamples: usize,
    /// Digest of the fixed bootstrap seed material.
    pub bootstrap_seed_sha256: String,
    /// Nominal Krippendorff alpha calculated before adjudication.
    pub agreement: Option<f64>,
    /// BCa bootstrap lower bound of the two-sided 95% interval.
    pub agreement_95_lower: Option<f64>,
    /// Digest of the complete governed analysis output artifact.
    pub analysis_artifact_sha256: String,
    /// Declared completion time; trusted chronology comes from the timestamp.
    pub completed_at_ms: u64,
}

/// Content-free integer metrics supplied for deterministic recomputation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyResultMetrics {
    /// Exact fixed corpus size.
    pub total_case_count: usize,
    /// Cases included in the primary analysis.
    pub analyzed_case_count: usize,
    /// Cases excluded after the corpus was frozen.
    pub excluded_case_count: usize,
    /// Cases lacking a complete primary outcome.
    pub incomplete_case_count: usize,
    /// Sorted confusion counts for every required threat family.
    pub per_threat: Vec<DomainStudyThreatCounts>,
    /// Reported support for every required stratum, sorted by stratum.
    pub per_stratum: Vec<DomainStudyStratumCount>,
    /// Evaluated safe-boundary controls.
    pub evaluated_safe_boundary_case_count: usize,
    /// Safe-boundary controls receiving any false positive decision.
    pub false_positive_safe_boundary_case_count: usize,
    /// Evaluated fixed attack variants.
    pub evaluated_attack_variant_count: usize,
    /// Variants preserving the expected source-case decision.
    pub consistent_attack_variant_count: usize,
    /// Sorted counts for every preregistered attack family.
    pub per_attack_family: Vec<DomainStudyAttackFamilyCounts>,
    /// Fixed review-coverage summary.
    pub review_coverage: DomainStudyReviewCoverage,
    /// Number of fully reported protocol deviations.
    pub protocol_deviation_count: usize,
    /// Deviations that changed the frozen confirmatory analysis.
    pub confirmatory_analysis_deviation_count: usize,
}

/// Strict content-free aggregate result bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyResultBundle {
    /// Schema identity.
    pub schema_version: String,
    /// Stable result identity.
    pub result_id: String,
    /// Stable study identity.
    pub study_id: String,
    /// Domain evaluated.
    pub domain: DomainModuleId,
    /// Exact preregistration digest.
    pub preregistration_canonical_sha256: String,
    /// Exact corpus digest.
    pub corpus_sha256: String,
    /// Exact immutable split-assignment digest.
    pub split_manifest_sha256: String,
    /// Exact policy-evidence digest.
    pub policy_evidence_canonical_sha256: String,
    /// Exact build-provenance digest.
    pub build_provenance_canonical_sha256: String,
    /// Exact blind review-packet digest.
    pub review_packet_sha256: String,
    /// Digest of the sorted signed reviewer-receipt set.
    pub reviewer_receipt_set_sha256: String,
    /// Digest of the complete signed adjudication receipt.
    pub adjudication_receipt_sha256: String,
    /// Digest of the frozen prediction output bundle.
    pub prediction_bundle_sha256: String,
    /// Digest of the exact analysis implementation and environment lock.
    pub analysis_environment_sha256: String,
    /// Governed agreement-analysis claims bound to the preregistration.
    pub review_agreement_analysis: DomainStudyAgreementAnalysisClaims,
    /// Digest of the private case-to-reviewer coverage and completion matrix.
    pub review_coverage_manifest_sha256: String,
    /// Digest of the complete exclusions manifest, including an empty manifest.
    pub exclusion_manifest_sha256: String,
    /// Digest of the complete protocol-deviation manifest.
    pub protocol_deviation_manifest_sha256: String,
    /// Optional exploratory result digest, never used by the primary decision.
    pub exploratory_results_sha256: Option<String>,
    /// Aggregate counts used for deterministic recomputation.
    pub metrics: DomainStudyResultMetrics,
    /// Declared result generation time.
    pub generated_at_ms: u64,
    /// Must remain false for the content-free evidence bundle.
    pub raw_content_exported: bool,
    /// Must remain false outside the controlled private verifier.
    pub reviewer_identifiers_exported: bool,
}

/// Maximum machine-readable claim supported by the verified bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyEvidenceStatus {
    /// Repository or internal corpora remain engineering evidence.
    EngineeringOnly,
    /// The chain is valid but fixed cases, variants, or review are incomplete.
    Incomplete,
    /// The complete independent study did not meet its frozen thresholds.
    ThresholdsNotMet,
    /// The complete chain meets thresholds but still requires scientific review.
    IndependentEvidenceCandidate,
}

/// Outcome of the frozen analysis, independent of corpus evidence maturity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyOutcomeStatus {
    /// Fixed cases, attacks, review, adjudication, or agreement are incomplete.
    Incomplete,
    /// The complete analysis did not meet every frozen conservative threshold.
    ThresholdsNotMet,
    /// The complete analysis met every frozen conservative threshold.
    ThresholdsMet,
}

/// Content-free claims signed as the final evidence manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyFinalManifestClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Domain evaluated.
    pub domain: DomainModuleId,
    /// Exact preregistration digest.
    pub preregistration_canonical_sha256: String,
    /// Exact policy-evidence digest.
    pub policy_evidence_canonical_sha256: String,
    /// Exact build-provenance digest.
    pub build_provenance_canonical_sha256: String,
    /// Exact corpus digest.
    pub corpus_sha256: String,
    /// Canonical digest of every trust root used by the verifier.
    pub trust_policy_canonical_sha256: String,
    /// Digest of the signed preregistration attestation.
    pub preregistration_attestation_sha256: String,
    /// Digest of its trusted timestamp receipt.
    pub preregistration_timestamp_sha256: String,
    /// Digest of the sorted signed reviewer-receipt set.
    pub reviewer_receipt_set_sha256: String,
    /// Digest of the sorted reviewer timestamp-receipt set.
    pub reviewer_timestamp_set_sha256: String,
    /// Digest of the trusted reviewer-agreement analysis timestamp.
    pub agreement_analysis_timestamp_sha256: String,
    /// Digest of the signed adjudication-start authorization.
    pub adjudication_start_authorization_sha256: String,
    /// Digest of the trusted adjudication-start timestamp.
    pub adjudication_start_timestamp_sha256: String,
    /// Digest of the signed adjudication receipt.
    pub adjudication_receipt_sha256: String,
    /// Digest of the adjudication timestamp receipt.
    pub adjudication_timestamp_sha256: String,
    /// Digest of the exact aggregate result bundle.
    pub result_bundle_sha256: String,
    /// Recomputed evidence status.
    pub evidence_status: DomainStudyEvidenceStatus,
    /// Recomputed outcome, retained even when evidence maturity is engineering-only.
    pub outcome_status: DomainStudyOutcomeStatus,
    /// Exact temporal execution boundary.
    pub temporal_mode: DomainStudyTemporalMode,
    /// Must remain false; result evidence cannot enable runtime policy.
    pub temporal_runtime_enabled: bool,
    /// Must remain false; result evidence cannot configure actions.
    pub action_execution_configured: bool,
    /// Must remain false in the final manifest.
    pub raw_content_exported: bool,
    /// Must remain false in the final manifest.
    pub reviewer_identifiers_exported: bool,
    /// Declared manifest completion time.
    pub completed_at_ms: u64,
}

/// Signed final content-free evidence manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyFinalManifest {
    /// Signed final claims.
    pub claims: DomainStudyFinalManifestClaims,
    /// Institutional manifest signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Complete private verification input for one result chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyResultEvidenceBundle {
    /// Schema identity.
    pub schema_version: String,
    /// Signed preregistration attestation.
    pub preregistration_attestation: DomainStudyPreregistrationAttestation,
    /// Trusted timestamp of the preregistration attestation.
    pub preregistration_timestamp: DomainStudyTrustedTimestampReceipt,
    /// Private reviewer receipts and timestamps, sorted by key identifier.
    pub reviewer_receipts: Vec<DomainStudyTimestampedReviewerReceipt>,
    /// Private frozen assignments, sorted by reviewer index.
    pub reviewer_assignments: Vec<DomainStudyReviewerAssignmentManifest>,
    /// Private case-level matrix used to recompute review coverage.
    pub review_coverage: Vec<DomainStudyCaseReviewCoverage>,
    /// Private adjudication manifest bound by the adjudicator receipt.
    pub adjudication_manifest: DomainStudyAdjudicationManifest,
    /// Signed independent adjudication receipt.
    pub adjudication_receipt: DomainStudyAdjudicationReceipt,
    /// Trusted timestamp of adjudication.
    pub adjudication_timestamp: DomainStudyTrustedTimestampReceipt,
    /// Content-free aggregate result bundle.
    pub result: DomainStudyResultBundle,
    /// Trusted timestamp covering the governed agreement-analysis claims.
    pub review_agreement_analysis_timestamp: DomainStudyTrustedTimestampReceipt,
    /// Signed authorization that must precede all adjudication work.
    pub adjudication_start_authorization: DomainStudyAdjudicationStartAuthorization,
    /// Trusted timestamp covering the adjudication-start authorization.
    pub adjudication_start_timestamp: DomainStudyTrustedTimestampReceipt,
    /// Signed final evidence manifest.
    pub final_manifest: DomainStudyFinalManifest,
    /// Trusted timestamp of the signed final manifest.
    pub final_manifest_timestamp: DomainStudyTrustedTimestampReceipt,
}

/// Recomputed report for one threat family.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DomainStudyThreatMetricReport {
    /// Threat-family token.
    pub threat_family: String,
    /// Positive support used for recall.
    pub positive_support: usize,
    /// Recomputed precision.
    pub precision: Option<f64>,
    /// Two-sided 95% Wilson lower bound for precision.
    pub precision_wilson_95_lower: Option<f64>,
    /// Recomputed recall.
    pub recall: Option<f64>,
    /// Two-sided 95% Wilson lower bound for recall.
    pub recall_wilson_95_lower: Option<f64>,
    /// Recomputed F1.
    pub f1: Option<f64>,
    /// Conservative F1 derived from precision and recall Wilson lower bounds.
    pub f1_conservative_95_lower: Option<f64>,
}

/// Recomputed report for one preregistered attack family.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DomainStudyAttackFamilyMetricReport {
    /// Attack-family token.
    pub attack_family: String,
    /// Evaluated variants in this family.
    pub evaluated_variant_count: usize,
    /// Variants preserving the expected decision.
    pub consistent_variant_count: usize,
    /// Recomputed consistency rate.
    pub consistency_rate: Option<f64>,
    /// Two-sided 95% Wilson lower bound for consistency.
    pub consistency_wilson_95_lower: Option<f64>,
}

/// Public content-free validation report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DomainStudyResultReport {
    /// Stable study identity.
    pub study_id: String,
    /// Stable result identity.
    pub result_id: String,
    /// Domain evaluated.
    pub domain: DomainModuleId,
    /// Recomputed evidence status.
    pub evidence_status: DomainStudyEvidenceStatus,
    /// Recomputed outcome independent of evidence maturity.
    pub outcome_status: DomainStudyOutcomeStatus,
    /// Canonical preregistration digest.
    pub preregistration_canonical_sha256: String,
    /// Canonical result-bundle digest.
    pub result_bundle_sha256: String,
    /// Canonical signed final-manifest digest.
    pub final_manifest_sha256: String,
    /// Canonical digest of every trust root used for validation.
    pub trust_policy_canonical_sha256: String,
    /// Trusted upper bound on preregistration time.
    pub preregistration_latest_ms: u64,
    /// Trusted lower bound on the earliest reviewer receipt.
    pub first_review_earliest_ms: u64,
    /// Trusted upper bound on the latest reviewer receipt.
    pub last_review_latest_ms: u64,
    /// Trusted lower bound on adjudication time.
    pub adjudication_earliest_ms: u64,
    /// Trusted upper bound on reviewer-agreement analysis completion.
    pub agreement_analysis_latest_ms: u64,
    /// Trusted lower bound on authorized adjudication start.
    pub adjudication_start_earliest_ms: u64,
    /// Trusted lower bound on final-manifest time.
    pub final_manifest_earliest_ms: u64,
    /// Number of independently signed reviewer receipts.
    pub reviewer_receipt_count: usize,
    /// Exact fixed corpus size.
    pub total_case_count: usize,
    /// Cases included in the primary analysis.
    pub analyzed_case_count: usize,
    /// Fixed cases excluded after freeze.
    pub excluded_case_count: usize,
    /// Fixed cases lacking complete primary outcomes.
    pub incomplete_case_count: usize,
    /// Recomputed content-free review coverage.
    pub review_coverage: DomainStudyReviewCoverage,
    /// Per-stratum analyzed support.
    pub per_stratum: Vec<DomainStudyStratumCount>,
    /// Recomputed per-family attack coverage and consistency.
    pub per_attack_family: Vec<DomainStudyAttackFamilyMetricReport>,
    /// Fully reported protocol-deviation count.
    pub protocol_deviation_count: usize,
    /// Deviations affecting the confirmatory analysis.
    pub confirmatory_analysis_deviation_count: usize,
    /// Recomputed macro F1.
    pub macro_f1: Option<f64>,
    /// Mean of the per-threat conservative F1 lower bounds.
    pub macro_f1_conservative_95_lower: Option<f64>,
    /// Per-threat recomputed metrics.
    pub per_threat: Vec<DomainStudyThreatMetricReport>,
    /// Recomputed safe-boundary false-positive rate.
    pub safe_boundary_false_positive_rate: Option<f64>,
    /// Two-sided 95% Wilson upper bound for the safe-boundary rate.
    pub safe_boundary_false_positive_wilson_95_upper: Option<f64>,
    /// Recomputed attack-variant consistency rate.
    pub attack_variant_consistency_rate: Option<f64>,
    /// Two-sided 95% Wilson lower bound for attack consistency.
    pub attack_variant_consistency_wilson_95_lower: Option<f64>,
    /// Reported and signed nominal Krippendorff alpha.
    pub inter_rater_agreement: Option<f64>,
    /// Reported and signed BCa bootstrap lower 95% agreement bound.
    pub inter_rater_agreement_95_lower: Option<f64>,
    /// Agreement statistic fixed by the canonical preregistration.
    pub inter_rater_agreement_statistic: DomainStudyInterRaterAgreementStatistic,
    /// Agreement uncertainty method fixed by the canonical preregistration.
    pub inter_rater_agreement_uncertainty_method: DomainStudyAgreementUncertaintyMethod,
    /// Fixed temporal boundary.
    pub temporal_mode: DomainStudyTemporalMode,
    /// Always false for this result contract.
    pub temporal_runtime_enabled: bool,
    /// Always false for this result contract.
    pub action_execution_configured: bool,
}

#[derive(Serialize)]
struct SignedClaims<'a, T> {
    key_id: &'a str,
    claims: &'a T,
}

#[derive(Debug, Clone, Copy)]
struct TrustedTimeInterval {
    earliest_ms: u64,
    latest_ms: u64,
}

#[derive(Debug)]
struct MetricDecision {
    macro_f1: Option<f64>,
    macro_f1_conservative_95_lower: Option<f64>,
    per_threat: Vec<DomainStudyThreatMetricReport>,
    safe_boundary_false_positive_rate: Option<f64>,
    safe_boundary_false_positive_wilson_95_upper: Option<f64>,
    attack_variant_consistency_rate: Option<f64>,
    attack_variant_consistency_wilson_95_lower: Option<f64>,
    per_attack_family: Vec<DomainStudyAttackFamilyMetricReport>,
    complete: bool,
    thresholds_met: bool,
}

/// Produces the domain-separated payload for a preregistration attestation.
pub fn domain_study_preregistration_attestation_signing_payload(
    claims: &DomainStudyPreregistrationAttestationClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyResultError> {
    signing_payload(PREREGISTRATION_ATTESTATION_DOMAIN, claims, key_id)
}

/// Produces the domain-separated payload for a trusted timestamp receipt.
pub fn domain_study_trusted_timestamp_signing_payload(
    claims: &DomainStudyTrustedTimestampClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyResultError> {
    signing_payload(TRUSTED_TIMESTAMP_DOMAIN, claims, key_id)
}

/// Produces the domain-separated payload for an independent reviewer receipt.
pub fn domain_study_reviewer_receipt_signing_payload(
    claims: &DomainStudyReviewerReceiptClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyResultError> {
    signing_payload(REVIEWER_RECEIPT_DOMAIN, claims, key_id)
}

/// Produces the domain-separated payload for an adjudication-start authorization.
pub fn domain_study_adjudication_start_signing_payload(
    claims: &DomainStudyAdjudicationStartClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyResultError> {
    signing_payload(ADJUDICATION_START_DOMAIN, claims, key_id)
}

/// Produces the domain-separated payload for an adjudication receipt.
pub fn domain_study_adjudication_receipt_signing_payload(
    claims: &DomainStudyAdjudicationReceiptClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyResultError> {
    signing_payload(ADJUDICATION_RECEIPT_DOMAIN, claims, key_id)
}

/// Produces the domain-separated payload for the final evidence manifest.
pub fn domain_study_final_manifest_signing_payload(
    claims: &DomainStudyFinalManifestClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyResultError> {
    signing_payload(FINAL_MANIFEST_DOMAIN, claims, key_id)
}

/// Returns the canonical SHA-256 used by every result-chain binding.
pub fn domain_study_result_canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, DomainStudyResultError> {
    canonical_sha256(value)
}

/// Returns the exact compact JSON bytes used by result-chain bindings.
///
/// Interoperable timestamp subjects must be produced from the typed AURA
/// evidence structures, not from unordered custom map types. The returned
/// bytes contain no trailing newline and can be passed directly to the trusted
/// RFC 3161 adapter.
pub fn domain_study_result_canonical_json<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, DomainStudyResultError> {
    Ok(serde_json::to_vec(value)?)
}

/// Validates a complete signed and timestamped result chain.
///
/// The original preregistration is revalidated against the current policy and
/// build before any result evidence is considered. `additional_known_seed_sha256`
/// must be the same complete private seed registry used at preregistration.
pub fn validate_domain_study_result_evidence(
    preregistration_json: &str,
    evidence_json: &str,
    expected_policy_evidence: &DomainModuleEvidence,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    trust_policy: &DomainStudyTrustPolicy,
) -> Result<DomainStudyResultReport, DomainStudyResultError> {
    if preregistration_json.is_empty()
        || preregistration_json.len() > MAX_PREREGISTRATION_JSON_BYTES
    {
        return invalid("preregistration JSON is empty or exceeds the 2 MiB bound");
    }
    if evidence_json.is_empty() || evidence_json.len() > MAX_EVIDENCE_JSON_BYTES {
        return invalid("result evidence JSON is empty or exceeds the 8 MiB bound");
    }
    validate_trust_policy(trust_policy)?;
    let trust_policy_canonical_sha256 = canonical_sha256(trust_policy)?;
    let binding = validate_domain_study_preregistration(
        preregistration_json,
        expected_policy_evidence,
        expected_build_provenance,
        additional_known_seed_sha256,
    )?;
    let preregistration: DomainStudyPreregistration = serde_json::from_str(preregistration_json)?;
    let evidence: DomainStudyResultEvidenceBundle = serde_json::from_str(evidence_json)?;
    if evidence.schema_version != DOMAIN_STUDY_RESULT_EVIDENCE_SCHEMA_VERSION {
        return invalid("result evidence bundle schema is unsupported");
    }

    let preregistration_attestation_sha256 = validate_preregistration_attestation(
        &evidence.preregistration_attestation,
        &binding.study_id,
        binding.registered_at_ms,
        &binding.preregistration_canonical_sha256,
        &trust_policy.preregistration_signer,
    )?;
    let preregistration_time = validate_timestamp_receipt(
        &evidence.preregistration_timestamp,
        DomainStudyTimestampSubjectKind::PreregistrationAttestation,
        &preregistration_attestation_sha256,
        trust_policy,
    )?;
    if evidence.preregistration_attestation.claims.attested_at_ms > preregistration_time.latest_ms {
        return invalid("preregistration attestation claims a time after its trusted timestamp");
    }

    let reviewer_chain = validate_reviewer_receipts(
        &evidence.reviewer_receipts,
        &preregistration,
        &binding.preregistration_canonical_sha256,
        preregistration_time,
        trust_policy,
    )?;
    let review_coverage = validate_review_coverage_matrix(
        &evidence.review_coverage,
        &evidence.reviewer_assignments,
        &preregistration,
        &evidence.reviewer_receipts,
    )?;
    let agreement_analysis_sha256 = canonical_sha256(&evidence.result.review_agreement_analysis)?;
    let agreement_analysis_time = validate_timestamp_receipt(
        &evidence.review_agreement_analysis_timestamp,
        DomainStudyTimestampSubjectKind::ReviewerAgreementAnalysis,
        &agreement_analysis_sha256,
        trust_policy,
    )?;
    if reviewer_chain.latest_time.latest_ms >= agreement_analysis_time.earliest_ms
        || evidence.result.review_agreement_analysis.completed_at_ms
            <= reviewer_chain.latest_time.latest_ms
        || evidence.result.review_agreement_analysis.completed_at_ms
            > agreement_analysis_time.latest_ms
    {
        return invalid("agreement analysis does not provably follow frozen reviewer decisions");
    }
    let adjudication_start_sha256 = validate_adjudication_start_authorization(
        &evidence.adjudication_start_authorization,
        &binding.study_id,
        &binding.preregistration_canonical_sha256,
        &reviewer_chain.receipt_set_sha256,
        &agreement_analysis_sha256,
        &trust_policy.adjudicator,
    )?;
    let adjudication_start_time = validate_timestamp_receipt(
        &evidence.adjudication_start_timestamp,
        DomainStudyTimestampSubjectKind::AdjudicationStartAuthorization,
        &adjudication_start_sha256,
        trust_policy,
    )?;
    if agreement_analysis_time.latest_ms >= adjudication_start_time.earliest_ms
        || evidence
            .adjudication_start_authorization
            .claims
            .authorized_at_ms
            <= agreement_analysis_time.latest_ms
        || evidence
            .adjudication_start_authorization
            .claims
            .authorized_at_ms
            > adjudication_start_time.latest_ms
    {
        return invalid("adjudication start is not provably after frozen agreement analysis");
    }
    validate_adjudication_manifest(
        &evidence.adjudication_manifest,
        &evidence.adjudication_receipt,
        &evidence.review_coverage,
        &preregistration,
        review_coverage.aggregate.adjudicated_case_count,
    )?;
    let adjudication_receipt_sha256 = validate_adjudication_receipt(
        &evidence.adjudication_receipt,
        &preregistration,
        &binding.preregistration_canonical_sha256,
        &reviewer_chain.receipt_set_sha256,
        review_coverage.aggregate.adjudicated_case_count,
        &trust_policy.adjudicator,
    )?;
    let adjudication_time = validate_timestamp_receipt(
        &evidence.adjudication_timestamp,
        DomainStudyTimestampSubjectKind::AdjudicationReceipt,
        &adjudication_receipt_sha256,
        trust_policy,
    )?;
    if adjudication_start_time.latest_ms >= adjudication_time.earliest_ms {
        return invalid(
            "adjudication-start timestamp overlaps completion; ordered adjudication is not proven",
        );
    }
    if evidence.adjudication_receipt.claims.completed_at_ms <= adjudication_start_time.latest_ms
        || evidence.adjudication_receipt.claims.completed_at_ms > adjudication_time.latest_ms
    {
        return invalid(
            "adjudication declared time is outside the trusted post-agreement interval",
        );
    }

    let metric_decision = validate_result_bundle(
        &evidence.result,
        &preregistration,
        &binding,
        &reviewer_chain.receipt_set_sha256,
        &reviewer_chain.review_packet_sha256,
        &adjudication_receipt_sha256,
        &review_coverage,
    )?;
    if evidence.result.generated_at_ms < adjudication_time.latest_ms {
        return invalid("aggregate result predates completed adjudication");
    }
    let outcome_status = outcome_status(metric_decision.complete, metric_decision.thresholds_met);
    let evidence_status = evidence_status(binding.corpus_class, outcome_status);
    let result_bundle_sha256 = canonical_sha256(&evidence.result)?;
    let preregistration_timestamp_sha256 = canonical_sha256(&evidence.preregistration_timestamp)?;
    let agreement_analysis_timestamp_sha256 =
        canonical_sha256(&evidence.review_agreement_analysis_timestamp)?;
    let adjudication_start_timestamp_sha256 =
        canonical_sha256(&evidence.adjudication_start_timestamp)?;
    let adjudication_timestamp_sha256 = canonical_sha256(&evidence.adjudication_timestamp)?;
    let expected_manifest_claims = DomainStudyFinalManifestClaims {
        schema_version: DOMAIN_STUDY_FINAL_MANIFEST_SCHEMA_VERSION.to_string(),
        study_id: binding.study_id.clone(),
        domain: binding.domain,
        preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
        policy_evidence_canonical_sha256: binding.policy_evidence_canonical_sha256.clone(),
        build_provenance_canonical_sha256: binding.build_provenance_canonical_sha256.clone(),
        corpus_sha256: binding.corpus_sha256.clone(),
        trust_policy_canonical_sha256: trust_policy_canonical_sha256.clone(),
        preregistration_attestation_sha256,
        preregistration_timestamp_sha256,
        reviewer_receipt_set_sha256: reviewer_chain.receipt_set_sha256.clone(),
        reviewer_timestamp_set_sha256: reviewer_chain.timestamp_set_sha256,
        agreement_analysis_timestamp_sha256,
        adjudication_start_authorization_sha256: adjudication_start_sha256,
        adjudication_start_timestamp_sha256,
        adjudication_receipt_sha256,
        adjudication_timestamp_sha256,
        result_bundle_sha256: result_bundle_sha256.clone(),
        evidence_status,
        outcome_status,
        temporal_mode: binding.temporal_mode,
        temporal_runtime_enabled: false,
        action_execution_configured: false,
        raw_content_exported: false,
        reviewer_identifiers_exported: false,
        completed_at_ms: evidence.final_manifest.claims.completed_at_ms,
    };
    if evidence.final_manifest.claims != expected_manifest_claims
        || evidence.final_manifest.claims.completed_at_ms < evidence.result.generated_at_ms
    {
        return invalid("final manifest does not exactly bind the recomputed evidence chain");
    }
    verify_signed_claims(
        FINAL_MANIFEST_DOMAIN,
        &evidence.final_manifest.claims,
        &evidence.final_manifest.signature,
        &trust_policy.final_manifest_signer,
        "final evidence manifest",
    )?;
    let final_manifest_sha256 = canonical_sha256(&evidence.final_manifest)?;
    let final_manifest_time = validate_timestamp_receipt(
        &evidence.final_manifest_timestamp,
        DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
        &final_manifest_sha256,
        trust_policy,
    )?;
    if adjudication_time.latest_ms >= final_manifest_time.earliest_ms
        || evidence.final_manifest.claims.completed_at_ms > final_manifest_time.latest_ms
    {
        return invalid("final manifest does not provably follow adjudication");
    }

    Ok(DomainStudyResultReport {
        study_id: binding.study_id,
        result_id: evidence.result.result_id,
        domain: binding.domain,
        evidence_status,
        outcome_status,
        preregistration_canonical_sha256: binding.preregistration_canonical_sha256,
        result_bundle_sha256,
        final_manifest_sha256,
        trust_policy_canonical_sha256,
        preregistration_latest_ms: preregistration_time.latest_ms,
        first_review_earliest_ms: reviewer_chain.earliest_time.earliest_ms,
        last_review_latest_ms: reviewer_chain.latest_time.latest_ms,
        adjudication_earliest_ms: adjudication_time.earliest_ms,
        agreement_analysis_latest_ms: agreement_analysis_time.latest_ms,
        adjudication_start_earliest_ms: adjudication_start_time.earliest_ms,
        final_manifest_earliest_ms: final_manifest_time.earliest_ms,
        reviewer_receipt_count: evidence.reviewer_receipts.len(),
        total_case_count: evidence.result.metrics.total_case_count,
        analyzed_case_count: evidence.result.metrics.analyzed_case_count,
        excluded_case_count: evidence.result.metrics.excluded_case_count,
        incomplete_case_count: evidence.result.metrics.incomplete_case_count,
        review_coverage: evidence.result.metrics.review_coverage,
        per_stratum: evidence.result.metrics.per_stratum,
        per_attack_family: metric_decision.per_attack_family,
        protocol_deviation_count: evidence.result.metrics.protocol_deviation_count,
        confirmatory_analysis_deviation_count: evidence
            .result
            .metrics
            .confirmatory_analysis_deviation_count,
        macro_f1: metric_decision.macro_f1,
        macro_f1_conservative_95_lower: metric_decision.macro_f1_conservative_95_lower,
        per_threat: metric_decision.per_threat,
        safe_boundary_false_positive_rate: metric_decision.safe_boundary_false_positive_rate,
        safe_boundary_false_positive_wilson_95_upper: metric_decision
            .safe_boundary_false_positive_wilson_95_upper,
        attack_variant_consistency_rate: metric_decision.attack_variant_consistency_rate,
        attack_variant_consistency_wilson_95_lower: metric_decision
            .attack_variant_consistency_wilson_95_lower,
        inter_rater_agreement: evidence.result.review_agreement_analysis.agreement,
        inter_rater_agreement_95_lower: evidence
            .result
            .review_agreement_analysis
            .agreement_95_lower,
        inter_rater_agreement_statistic: preregistration.analysis.inter_rater_agreement_statistic,
        inter_rater_agreement_uncertainty_method: preregistration
            .analysis
            .inter_rater_agreement_uncertainty_method,
        temporal_mode: binding.temporal_mode,
        temporal_runtime_enabled: false,
        action_execution_configured: false,
    })
}

struct ReviewerChain {
    receipt_set_sha256: String,
    timestamp_set_sha256: String,
    review_packet_sha256: String,
    earliest_time: TrustedTimeInterval,
    latest_time: TrustedTimeInterval,
}

struct ReviewCoverageBinding {
    canonical_sha256: String,
    aggregate: DomainStudyReviewCoverage,
}

struct AttackFamilyDecision {
    coverage_complete: bool,
    thresholds_met: bool,
    reports: Vec<DomainStudyAttackFamilyMetricReport>,
}

fn validate_preregistration_attestation(
    attestation: &DomainStudyPreregistrationAttestation,
    study_id: &str,
    registered_at_ms: u64,
    preregistration_sha256: &str,
    trusted_key: &DomainStudyTrustedKey,
) -> Result<String, DomainStudyResultError> {
    let expected = DomainStudyPreregistrationAttestationClaims {
        schema_version: DOMAIN_STUDY_PREREGISTRATION_ATTESTATION_SCHEMA_VERSION.to_string(),
        study_id: study_id.to_string(),
        preregistration_canonical_sha256: preregistration_sha256.to_string(),
        attested_at_ms: registered_at_ms,
    };
    if attestation.claims != expected {
        return invalid("preregistration attestation does not bind the canonical preregistration");
    }
    verify_signed_claims(
        PREREGISTRATION_ATTESTATION_DOMAIN,
        &attestation.claims,
        &attestation.signature,
        trusted_key,
        "preregistration attestation",
    )?;
    canonical_sha256(attestation)
}

fn validate_reviewer_receipts(
    evidence: &[DomainStudyTimestampedReviewerReceipt],
    preregistration: &DomainStudyPreregistration,
    preregistration_sha256: &str,
    preregistration_time: TrustedTimeInterval,
    trust_policy: &DomainStudyTrustPolicy,
) -> Result<ReviewerChain, DomainStudyResultError> {
    if !(2..=5).contains(&evidence.len()) {
        return invalid("result evidence must contain two to five reviewer receipts");
    }
    let mut receipt_digests = Vec::with_capacity(evidence.len());
    let mut timestamp_digests = Vec::with_capacity(evidence.len());
    let mut previous_key_id: Option<&str> = None;
    let mut review_packet_sha256: Option<&str> = None;
    let mut earliest_time: Option<TrustedTimeInterval> = None;
    let mut latest_time: Option<TrustedTimeInterval> = None;

    for item in evidence {
        let key_id = item.receipt.signature.key_id.as_str();
        if previous_key_id.is_some_and(|previous| previous >= key_id) {
            return invalid("reviewer receipts must be unique and sorted by trusted key id");
        }
        previous_key_id = Some(key_id);
        let trusted = trust_policy
            .reviewers
            .binary_search_by(|reviewer| reviewer.key.key_id.as_str().cmp(key_id))
            .ok()
            .and_then(|index| trust_policy.reviewers.get(index))
            .ok_or_else(|| {
                DomainStudyResultError::InvalidEvidence(
                    "reviewer receipt is signed by an untrusted key".to_string(),
                )
            })?;
        let claims = &item.receipt.claims;
        if claims.schema_version != DOMAIN_STUDY_REVIEWER_RECEIPT_SCHEMA_VERSION
            || claims.study_id != preregistration.study_id
            || claims.preregistration_canonical_sha256 != preregistration_sha256
            || !is_canonical_sha256(&claims.review_packet_sha256)
            || !is_canonical_sha256(&claims.assignment_manifest_sha256)
            || !is_canonical_sha256(&claims.decision_bundle_sha256)
            || claims.affiliation_commitment_sha256 != trusted.affiliation_commitment_sha256
            || claims.completed_case_count == 0
            || claims.completed_case_count > preregistration.dataset.fixed_case_count
            || claims.completed_at_ms == 0
        {
            return invalid("reviewer receipt identity, coverage, or private binding is invalid");
        }
        if let Some(expected_packet) = review_packet_sha256 {
            if claims.review_packet_sha256 != expected_packet {
                return invalid("reviewer receipts do not bind one exact blind packet");
            }
        } else {
            review_packet_sha256 = Some(&claims.review_packet_sha256);
        }
        verify_signed_claims(
            REVIEWER_RECEIPT_DOMAIN,
            claims,
            &item.receipt.signature,
            &trusted.key,
            "reviewer receipt",
        )?;
        let receipt_digest = canonical_sha256(&item.receipt)?;
        let timestamp = validate_timestamp_receipt(
            &item.trusted_timestamp,
            DomainStudyTimestampSubjectKind::ReviewerReceipt,
            &receipt_digest,
            trust_policy,
        )?;
        if claims.completed_at_ms <= preregistration_time.latest_ms
            || claims.completed_at_ms > timestamp.latest_ms
            || preregistration_time.latest_ms >= timestamp.earliest_ms
        {
            return invalid("review receipt does not provably follow preregistration");
        }
        receipt_digests.push(receipt_digest);
        timestamp_digests.push(canonical_sha256(&item.trusted_timestamp)?);
        earliest_time = Some(match earliest_time {
            Some(current) if current.earliest_ms <= timestamp.earliest_ms => current,
            _ => timestamp,
        });
        latest_time = Some(match latest_time {
            Some(current) if current.latest_ms >= timestamp.latest_ms => current,
            _ => timestamp,
        });
    }

    Ok(ReviewerChain {
        receipt_set_sha256: canonical_sha256(&receipt_digests)?,
        timestamp_set_sha256: canonical_sha256(&timestamp_digests)?,
        review_packet_sha256: review_packet_sha256
            .ok_or_else(|| {
                DomainStudyResultError::InvalidEvidence(
                    "review packet digest is absent".to_string(),
                )
            })?
            .to_string(),
        earliest_time: earliest_time.ok_or_else(|| {
            DomainStudyResultError::InvalidEvidence("review timestamps are absent".to_string())
        })?,
        latest_time: latest_time.ok_or_else(|| {
            DomainStudyResultError::InvalidEvidence("review timestamps are absent".to_string())
        })?,
    })
}

fn validate_adjudication_receipt(
    receipt: &DomainStudyAdjudicationReceipt,
    preregistration: &DomainStudyPreregistration,
    preregistration_sha256: &str,
    reviewer_receipt_set_sha256: &str,
    expected_adjudicated_case_count: usize,
    trusted_key: &DomainStudyTrustedKey,
) -> Result<String, DomainStudyResultError> {
    let claims = &receipt.claims;
    if claims.schema_version != DOMAIN_STUDY_ADJUDICATION_RECEIPT_SCHEMA_VERSION
        || claims.study_id != preregistration.study_id
        || claims.preregistration_canonical_sha256 != preregistration_sha256
        || claims.reviewer_receipt_set_sha256 != reviewer_receipt_set_sha256
        || !is_canonical_sha256(&claims.adjudication_bundle_sha256)
        || claims.label_ontology_sha256 != preregistration.dataset.label_ontology_sha256
        || claims.adjudicated_case_count != expected_adjudicated_case_count
        || claims.completed_at_ms == 0
    {
        return invalid("adjudication receipt does not bind the frozen study and reviews");
    }
    verify_signed_claims(
        ADJUDICATION_RECEIPT_DOMAIN,
        claims,
        &receipt.signature,
        trusted_key,
        "adjudication receipt",
    )?;
    canonical_sha256(receipt)
}

fn validate_adjudication_start_authorization(
    authorization: &DomainStudyAdjudicationStartAuthorization,
    study_id: &str,
    preregistration_sha256: &str,
    reviewer_receipt_set_sha256: &str,
    agreement_analysis_sha256: &str,
    trusted_key: &DomainStudyTrustedKey,
) -> Result<String, DomainStudyResultError> {
    let claims = &authorization.claims;
    if claims.schema_version != DOMAIN_STUDY_ADJUDICATION_START_SCHEMA_VERSION
        || claims.study_id != study_id
        || claims.preregistration_canonical_sha256 != preregistration_sha256
        || claims.reviewer_receipt_set_sha256 != reviewer_receipt_set_sha256
        || claims.agreement_analysis_sha256 != agreement_analysis_sha256
        || claims.authorized_at_ms == 0
    {
        return invalid("adjudication-start authorization does not bind the frozen study");
    }
    verify_signed_claims(
        ADJUDICATION_START_DOMAIN,
        claims,
        &authorization.signature,
        trusted_key,
        "adjudication-start authorization",
    )?;
    canonical_sha256(authorization)
}

fn validate_adjudication_manifest(
    manifest: &DomainStudyAdjudicationManifest,
    receipt: &DomainStudyAdjudicationReceipt,
    coverage_rows: &[DomainStudyCaseReviewCoverage],
    preregistration: &DomainStudyPreregistration,
    expected_adjudicated_case_count: usize,
) -> Result<(), DomainStudyResultError> {
    if manifest.schema_version != DOMAIN_STUDY_ADJUDICATION_MANIFEST_SCHEMA_VERSION
        || manifest.study_id != preregistration.study_id
        || manifest.blind_case_token_sha256.len() != expected_adjudicated_case_count
        || !is_canonical_sha256(&manifest.decision_bundle_sha256)
        || manifest
            .blind_case_token_sha256
            .iter()
            .any(|case| !is_canonical_sha256(case))
        || manifest
            .blind_case_token_sha256
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || canonical_sha256(manifest)? != receipt.claims.adjudication_bundle_sha256
    {
        return invalid("private adjudication manifest does not match its signed receipt");
    }
    let adjudicated_cases = manifest
        .blind_case_token_sha256
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if coverage_rows.iter().any(|row| {
        row.adjudicated != adjudicated_cases.contains(row.blind_case_token_sha256.as_str())
    }) {
        return invalid("private adjudication manifest does not match case-level coverage");
    }
    Ok(())
}

fn validate_review_coverage_matrix(
    rows: &[DomainStudyCaseReviewCoverage],
    assignments: &[DomainStudyReviewerAssignmentManifest],
    preregistration: &DomainStudyPreregistration,
    reviewer_receipts: &[DomainStudyTimestampedReviewerReceipt],
) -> Result<ReviewCoverageBinding, DomainStudyResultError> {
    if rows.len() != preregistration.dataset.fixed_case_count {
        return invalid("private review-coverage matrix does not cover the fixed corpus");
    }
    if assignments.len() != reviewer_receipts.len() {
        return invalid("private reviewer assignments do not cover every signed receipt");
    }
    let mut assigned_cases_by_reviewer = Vec::with_capacity(assignments.len());
    for (reviewer_index, (assignment, receipt)) in
        assignments.iter().zip(reviewer_receipts).enumerate()
    {
        if assignment.schema_version != DOMAIN_STUDY_REVIEWER_ASSIGNMENT_SCHEMA_VERSION
            || assignment.study_id != preregistration.study_id
            || usize::from(assignment.reviewer_index) != reviewer_index
            || assignment.blind_case_token_sha256.is_empty()
            || assignment.blind_case_token_sha256.len()
                != receipt.receipt.claims.completed_case_count
            || assignment
                .blind_case_token_sha256
                .iter()
                .any(|case| !is_canonical_sha256(case))
            || assignment
                .blind_case_token_sha256
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || canonical_sha256(assignment)? != receipt.receipt.claims.assignment_manifest_sha256
        {
            return invalid("private reviewer assignment does not match its signed receipt");
        }
        assigned_cases_by_reviewer.push(
            assignment
                .blind_case_token_sha256
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
        );
    }
    let mut completed_by_reviewer = vec![0_usize; reviewer_receipts.len()];
    let mut previous_case: Option<&str> = None;
    let mut minimum = usize::MAX;
    let mut maximum = 0_usize;
    let mut fully_reviewed = 0_usize;
    let mut adjudicated = 0_usize;
    for row in rows {
        if !is_canonical_sha256(&row.blind_case_token_sha256)
            || previous_case
                .is_some_and(|previous| previous >= row.blind_case_token_sha256.as_str())
            || row
                .reviewer_indices
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || row
                .reviewer_indices
                .iter()
                .any(|index| usize::from(*index) >= reviewer_receipts.len())
            || row.reviewer_indices.len() > preregistration.review.maximum_reviewers_per_case
            || assigned_cases_by_reviewer.iter().enumerate().any(
                |(reviewer_index, assigned_cases)| {
                    assigned_cases.contains(row.blind_case_token_sha256.as_str())
                        != row.reviewer_indices.contains(&(reviewer_index as u8))
                },
            )
        {
            return invalid("private review-coverage rows or reviewer assignments are invalid");
        }
        previous_case = Some(&row.blind_case_token_sha256);
        let review_count = row.reviewer_indices.len();
        minimum = minimum.min(review_count);
        maximum = maximum.max(review_count);
        if review_count >= preregistration.review.minimum_reviewers_per_case {
            fully_reviewed += 1;
        }
        if row.adjudicated {
            adjudicated += 1;
        }
        for reviewer_index in &row.reviewer_indices {
            *completed_by_reviewer
                .get_mut(usize::from(*reviewer_index))
                .ok_or_else(|| {
                    DomainStudyResultError::InvalidEvidence(
                        "coverage matrix references an absent reviewer".to_string(),
                    )
                })? += 1;
        }
    }
    for (reviewer_index, item) in reviewer_receipts.iter().enumerate() {
        if completed_by_reviewer.get(reviewer_index).copied()
            != Some(item.receipt.claims.completed_case_count)
        {
            return invalid("reviewer receipt count does not match the private coverage matrix");
        }
    }
    Ok(ReviewCoverageBinding {
        canonical_sha256: canonical_sha256(&rows)?,
        aggregate: DomainStudyReviewCoverage {
            reviewer_receipt_count: reviewer_receipts.len(),
            minimum_completed_reviews_per_case: minimum,
            maximum_completed_reviews_per_case: maximum,
            fully_reviewed_case_count: fully_reviewed,
            adjudicated_case_count: adjudicated,
        },
    })
}

fn validate_result_bundle(
    result: &DomainStudyResultBundle,
    preregistration: &DomainStudyPreregistration,
    binding: &crate::DomainStudyBinding,
    reviewer_receipt_set_sha256: &str,
    review_packet_sha256: &str,
    adjudication_receipt_sha256: &str,
    review_coverage: &ReviewCoverageBinding,
) -> Result<MetricDecision, DomainStudyResultError> {
    if result.schema_version != DOMAIN_STUDY_RESULT_SCHEMA_VERSION
        || !safe_token(&result.result_id)
        || result.study_id != binding.study_id
        || result.domain != binding.domain
        || result.preregistration_canonical_sha256 != binding.preregistration_canonical_sha256
        || result.corpus_sha256 != binding.corpus_sha256
        || result.split_manifest_sha256 != preregistration.dataset.split_manifest_sha256
        || result.policy_evidence_canonical_sha256 != binding.policy_evidence_canonical_sha256
        || result.build_provenance_canonical_sha256 != binding.build_provenance_canonical_sha256
        || result.review_packet_sha256 != review_packet_sha256
        || result.reviewer_receipt_set_sha256 != reviewer_receipt_set_sha256
        || result.adjudication_receipt_sha256 != adjudication_receipt_sha256
        || !is_canonical_sha256(&result.prediction_bundle_sha256)
        || !is_canonical_sha256(&result.analysis_environment_sha256)
        || result.review_coverage_manifest_sha256 != review_coverage.canonical_sha256
        || !is_canonical_sha256(&result.exclusion_manifest_sha256)
        || !is_canonical_sha256(&result.protocol_deviation_manifest_sha256)
        || result
            .exploratory_results_sha256
            .as_deref()
            .is_some_and(|value| !is_canonical_sha256(value))
        || result.generated_at_ms == 0
        || result.raw_content_exported
        || result.reviewer_identifiers_exported
    {
        return invalid("aggregate result identity, provenance, or privacy binding is invalid");
    }
    let agreement = &result.review_agreement_analysis;
    if agreement.schema_version != DOMAIN_STUDY_AGREEMENT_ANALYSIS_SCHEMA_VERSION
        || agreement.study_id != binding.study_id
        || agreement.preregistration_canonical_sha256 != binding.preregistration_canonical_sha256
        || agreement.reviewer_receipt_set_sha256 != reviewer_receipt_set_sha256
        || agreement.review_coverage_manifest_sha256 != review_coverage.canonical_sha256
        || agreement.statistic != preregistration.analysis.inter_rater_agreement_statistic
        || agreement.uncertainty_method
            != preregistration
                .analysis
                .inter_rater_agreement_uncertainty_method
        || agreement.bootstrap_resamples
            != preregistration
                .analysis
                .inter_rater_agreement_bootstrap_resamples
        || agreement.bootstrap_seed_sha256
            != preregistration
                .analysis
                .inter_rater_agreement_bootstrap_seed_sha256
        || !is_canonical_sha256(&agreement.analysis_artifact_sha256)
        || agreement.completed_at_ms == 0
        || agreement
            .agreement
            .is_some_and(|value| !signed_unit_interval(value))
        || agreement
            .agreement_95_lower
            .is_some_and(|value| !signed_unit_interval(value))
        || match (agreement.agreement, agreement.agreement_95_lower) {
            (Some(point), Some(lower)) => lower > point,
            (None, Some(_)) => true,
            _ => false,
        }
    {
        return invalid("reviewer-agreement analysis does not match the frozen procedure");
    }
    let metrics = &result.metrics;
    let accounted_case_count = checked_sum_counts(&[
        metrics.analyzed_case_count,
        metrics.excluded_case_count,
        metrics.incomplete_case_count,
    ])?;
    if metrics.total_case_count != preregistration.dataset.fixed_case_count
        || accounted_case_count != metrics.total_case_count
        || metrics.false_positive_safe_boundary_case_count
            > metrics.evaluated_safe_boundary_case_count
        || metrics.evaluated_safe_boundary_case_count > metrics.analyzed_case_count
        || metrics.consistent_attack_variant_count > metrics.evaluated_attack_variant_count
        || metrics.evaluated_attack_variant_count > preregistration.attacks.fixed_variant_count
    {
        return invalid("aggregate result counts or agreement value are inconsistent");
    }
    if metrics.review_coverage != review_coverage.aggregate
        || metrics.confirmatory_analysis_deviation_count > metrics.protocol_deviation_count
    {
        return invalid("reported review coverage or protocol deviations are inconsistent");
    }
    let stratum_coverage_complete = validate_strata(
        &metrics.per_stratum,
        preregistration,
        metrics.analyzed_case_count,
    )?;
    let attack_family_decision = validate_attack_families(
        &metrics.per_attack_family,
        preregistration,
        metrics.evaluated_attack_variant_count,
        metrics.consistent_attack_variant_count,
    )?;
    if metrics.per_threat.len() != preregistration.dataset.required_threat_families.len() {
        return invalid("result omits or adds a preregistered threat family");
    }

    let mut per_threat = Vec::with_capacity(metrics.per_threat.len());
    let mut macro_f1_sum = 0.0;
    let mut macro_f1_lower_sum = 0.0;
    let mut all_f1_defined = true;
    let mut all_family_support_complete = true;
    let mut all_recall_bounds_pass = true;
    for (counts, expected_family) in metrics
        .per_threat
        .iter()
        .zip(&preregistration.dataset.required_threat_families)
    {
        let positive_support = checked_sum_counts(&[counts.true_positive, counts.false_negative])?;
        let observed_count = checked_sum_counts(&[
            counts.true_positive,
            counts.false_positive,
            counts.false_negative,
        ])?;
        if counts.threat_family != *expected_family || observed_count > metrics.analyzed_case_count
        {
            return invalid("per-threat counts do not satisfy the frozen family denominators");
        }
        all_family_support_complete &=
            positive_support >= preregistration.dataset.minimum_cases_per_threat_family;
        let recall = optional_ratio(counts.true_positive, positive_support)?;
        let predicted_positive =
            checked_sum_counts(&[counts.true_positive, counts.false_positive])?;
        let precision = optional_ratio(counts.true_positive, predicted_positive)?;
        let doubled_true_positive = counts.true_positive.checked_mul(2).ok_or_else(|| {
            DomainStudyResultError::InvalidEvidence(
                "per-threat F1 numerator overflows the supported count range".to_string(),
            )
        })?;
        let f1_denominator = checked_sum_counts(&[
            doubled_true_positive,
            counts.false_positive,
            counts.false_negative,
        ])?;
        let f1 = optional_ratio(doubled_true_positive, f1_denominator)?;
        let recall_lower =
            optional_wilson_interval(counts.true_positive, positive_support)?.map(|value| value.0);
        let precision_lower = optional_wilson_interval(counts.true_positive, predicted_positive)?
            .map(|value| value.0);
        let f1_lower = precision_lower
            .zip(recall_lower)
            .map(|(precision, recall)| harmonic_mean(precision, recall));
        if let (Some(f1_value), Some(f1_lower_value)) = (f1, f1_lower) {
            macro_f1_sum += f1_value;
            macro_f1_lower_sum += f1_lower_value;
        } else {
            all_f1_defined = false;
        }
        all_recall_bounds_pass &= recall
            .is_some_and(|value| value >= preregistration.analysis.minimum_per_threat_recall)
            && recall_lower
                .is_some_and(|value| value >= preregistration.analysis.minimum_per_threat_recall);
        per_threat.push(DomainStudyThreatMetricReport {
            threat_family: counts.threat_family.clone(),
            positive_support,
            precision,
            precision_wilson_95_lower: precision_lower,
            recall,
            recall_wilson_95_lower: recall_lower,
            f1,
            f1_conservative_95_lower: f1_lower,
        });
    }
    let macro_f1 = all_f1_defined.then(|| macro_f1_sum / per_threat.len() as f64);
    let macro_f1_lower = all_f1_defined.then(|| macro_f1_lower_sum / per_threat.len() as f64);
    let safe_rate = optional_ratio(
        metrics.false_positive_safe_boundary_case_count,
        metrics.evaluated_safe_boundary_case_count,
    )?;
    let safe_upper = optional_wilson_interval(
        metrics.false_positive_safe_boundary_case_count,
        metrics.evaluated_safe_boundary_case_count,
    )?
    .map(|value| value.1);
    let attack_rate = optional_ratio(
        metrics.consistent_attack_variant_count,
        metrics.evaluated_attack_variant_count,
    )?;
    let attack_lower = optional_wilson_interval(
        metrics.consistent_attack_variant_count,
        metrics.evaluated_attack_variant_count,
    )?
    .map(|value| value.0);
    let complete = metrics.excluded_case_count == 0
        && metrics.incomplete_case_count == 0
        && metrics.analyzed_case_count == metrics.total_case_count
        && metrics.evaluated_safe_boundary_case_count
            >= preregistration.dataset.minimum_safe_boundary_cases
        && metrics.evaluated_attack_variant_count == preregistration.attacks.fixed_variant_count
        && metrics.review_coverage.fully_reviewed_case_count == metrics.total_case_count
        && metrics.review_coverage.adjudicated_case_count == metrics.total_case_count
        && metrics.confirmatory_analysis_deviation_count == 0
        && all_family_support_complete
        && stratum_coverage_complete
        && attack_family_decision.coverage_complete
        && agreement.agreement.is_some()
        && agreement.agreement_95_lower.is_some();
    let thresholds_met = complete
        && macro_f1.is_some_and(|value| value >= preregistration.analysis.minimum_macro_f1)
        && macro_f1_lower.is_some_and(|value| value >= preregistration.analysis.minimum_macro_f1)
        && all_recall_bounds_pass
        && safe_rate.is_some_and(|value| {
            value
                <= preregistration
                    .analysis
                    .maximum_safe_boundary_false_positive_rate
        })
        && safe_upper.is_some_and(|value| {
            value
                <= preregistration
                    .analysis
                    .maximum_safe_boundary_false_positive_rate
        })
        && attack_rate.is_some_and(|value| {
            value
                >= preregistration
                    .analysis
                    .minimum_attack_variant_consistency_rate
        })
        && attack_lower.is_some_and(|value| {
            value
                >= preregistration
                    .analysis
                    .minimum_attack_variant_consistency_rate
        })
        && attack_family_decision.thresholds_met
        && agreement
            .agreement
            .is_some_and(|value| value >= preregistration.analysis.minimum_inter_rater_agreement)
        && agreement
            .agreement_95_lower
            .is_some_and(|value| value >= preregistration.analysis.minimum_inter_rater_agreement);

    Ok(MetricDecision {
        macro_f1,
        macro_f1_conservative_95_lower: macro_f1_lower,
        per_threat,
        safe_boundary_false_positive_rate: safe_rate,
        safe_boundary_false_positive_wilson_95_upper: safe_upper,
        attack_variant_consistency_rate: attack_rate,
        attack_variant_consistency_wilson_95_lower: attack_lower,
        per_attack_family: attack_family_decision.reports,
        complete,
        thresholds_met,
    })
}

fn validate_strata(
    strata: &[DomainStudyStratumCount],
    preregistration: &DomainStudyPreregistration,
    analyzed_case_count: usize,
) -> Result<bool, DomainStudyResultError> {
    if strata.len() != preregistration.dataset.required_strata.len()
        || strata
            .iter()
            .zip(&preregistration.dataset.required_strata)
            .any(|(actual, expected)| {
                actual.stratum != *expected || actual.case_count > analyzed_case_count
            })
    {
        return invalid("result does not report support for every preregistered stratum");
    }
    Ok(strata.iter().all(|stratum| stratum.case_count > 0))
}

fn validate_attack_families(
    families: &[DomainStudyAttackFamilyCounts],
    preregistration: &DomainStudyPreregistration,
    evaluated_total: usize,
    consistent_total: usize,
) -> Result<AttackFamilyDecision, DomainStudyResultError> {
    if families.len() != preregistration.attacks.attack_families.len()
        || families
            .iter()
            .zip(&preregistration.attacks.attack_families)
            .any(|(actual, expected)| {
                actual.attack_family != *expected
                    || actual.consistent_variant_count > actual.evaluated_variant_count
            })
    {
        return invalid("attack-family counts do not satisfy the frozen coverage plan");
    }
    let evaluated_sum = checked_sum_counts(
        &families
            .iter()
            .map(|family| family.evaluated_variant_count)
            .collect::<Vec<_>>(),
    )?;
    let consistent_sum = checked_sum_counts(
        &families
            .iter()
            .map(|family| family.consistent_variant_count)
            .collect::<Vec<_>>(),
    )?;
    if evaluated_sum != evaluated_total || consistent_sum != consistent_total {
        return invalid("attack-family counts do not satisfy the frozen coverage plan");
    }
    let coverage_complete = families.iter().all(|family| {
        family.evaluated_variant_count >= preregistration.attacks.minimum_variants_per_family
    });
    let mut thresholds_met = true;
    let mut reports = Vec::with_capacity(families.len());
    for family in families {
        let rate = optional_ratio(
            family.consistent_variant_count,
            family.evaluated_variant_count,
        )?;
        let lower = optional_wilson_interval(
            family.consistent_variant_count,
            family.evaluated_variant_count,
        )?
        .map(|interval| interval.0);
        thresholds_met &= rate.is_some_and(|value| {
            value
                >= preregistration
                    .analysis
                    .minimum_attack_variant_consistency_rate
        }) && lower.is_some_and(|value| {
            value
                >= preregistration
                    .analysis
                    .minimum_attack_variant_consistency_rate
        });
        reports.push(DomainStudyAttackFamilyMetricReport {
            attack_family: family.attack_family.clone(),
            evaluated_variant_count: family.evaluated_variant_count,
            consistent_variant_count: family.consistent_variant_count,
            consistency_rate: rate,
            consistency_wilson_95_lower: lower,
        });
    }
    Ok(AttackFamilyDecision {
        coverage_complete,
        thresholds_met,
        reports,
    })
}

fn validate_timestamp_receipt(
    receipt: &DomainStudyTrustedTimestampReceipt,
    expected_subject_kind: DomainStudyTimestampSubjectKind,
    expected_subject_sha256: &str,
    trust_policy: &DomainStudyTrustPolicy,
) -> Result<TrustedTimeInterval, DomainStudyResultError> {
    let claims = &receipt.claims;
    if claims.schema_version != DOMAIN_STUDY_TRUSTED_TIMESTAMP_SCHEMA_VERSION
        || claims.subject_kind != expected_subject_kind
        || claims.subject_canonical_sha256 != expected_subject_sha256
        || claims.protocol != DomainStudyTimestampProtocol::Rfc3161TrustedChain
        || claims.issued_at_ms == 0
        || claims.gen_time_submillisecond_micros > 999
        || claims.accuracy_micros == 0
        || claims.accuracy_micros > MAX_TIMESTAMP_ACCURACY_MICROS
        || !is_canonical_sha256(&claims.request_sha256)
        || !is_canonical_sha256(&claims.response_sha256)
        || !is_canonical_sha256(&claims.certificate_chain_sha256)
        || !is_canonical_sha256(&claims.revocation_evidence_sha256)
        || claims.tsa_spki_sha256 != trust_policy.trusted_tsa_spki_sha256
        || claims.tsa_policy_oid != trust_policy.trusted_tsa_policy_oid
    {
        return invalid("trusted timestamp receipt is malformed or outside the trust policy");
    }
    verify_signed_claims(
        TRUSTED_TIMESTAMP_DOMAIN,
        claims,
        &receipt.signature,
        &trust_policy.timestamp_verifier,
        "trusted timestamp receipt",
    )?;
    let exact_time_micros = claims
        .issued_at_ms
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(u64::from(claims.gen_time_submillisecond_micros)))
        .ok_or_else(|| {
            DomainStudyResultError::InvalidEvidence(
                "trusted timestamp generation time overflows Unix microseconds".to_string(),
            )
        })?;
    let earliest_micros = exact_time_micros
        .checked_sub(claims.accuracy_micros)
        .ok_or_else(|| {
            DomainStudyResultError::InvalidEvidence(
                "trusted timestamp uncertainty interval underflows Unix microseconds".to_string(),
            )
        })?;
    let latest_micros = exact_time_micros
        .checked_add(claims.accuracy_micros)
        .ok_or_else(|| {
            DomainStudyResultError::InvalidEvidence(
                "trusted timestamp uncertainty interval overflows Unix microseconds".to_string(),
            )
        })?;
    let earliest_ms = earliest_micros / 1_000;
    let latest_ms = latest_micros.div_ceil(1_000);
    Ok(TrustedTimeInterval {
        earliest_ms,
        latest_ms,
    })
}

fn validate_trust_policy(policy: &DomainStudyTrustPolicy) -> Result<(), DomainStudyResultError> {
    validate_trusted_key(&policy.preregistration_signer)?;
    validate_trusted_key(&policy.timestamp_verifier)?;
    validate_trusted_key(&policy.adjudicator)?;
    validate_trusted_key(&policy.final_manifest_signer)?;
    if !is_canonical_sha256(&policy.trusted_tsa_spki_sha256)
        || !safe_oid(&policy.trusted_tsa_policy_oid)
        || !(2..=5).contains(&policy.reviewers.len())
    {
        return invalid("result trust policy has invalid TSA or reviewer bounds");
    }
    let privileged = [
        policy.preregistration_signer.key_id.as_str(),
        policy.timestamp_verifier.key_id.as_str(),
        policy.adjudicator.key_id.as_str(),
        policy.final_manifest_signer.key_id.as_str(),
    ];
    if privileged.iter().copied().collect::<HashSet<_>>().len() != privileged.len() {
        return invalid("institution, timestamp, adjudicator, and manifest keys must be distinct");
    }
    let mut public_keys = [
        policy.preregistration_signer.public_key_hex.as_str(),
        policy.timestamp_verifier.public_key_hex.as_str(),
        policy.adjudicator.public_key_hex.as_str(),
        policy.final_manifest_signer.public_key_hex.as_str(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    if public_keys.len() != 4 {
        return invalid("privileged evidence roles must use distinct Ed25519 keys");
    }
    let mut affiliations = BTreeSet::new();
    let mut previous_key_id: Option<&str> = None;
    for reviewer in &policy.reviewers {
        validate_trusted_key(&reviewer.key)?;
        if previous_key_id.is_some_and(|previous| previous >= reviewer.key.key_id.as_str())
            || privileged.contains(&reviewer.key.key_id.as_str())
            || !is_canonical_sha256(&reviewer.affiliation_commitment_sha256)
            || !affiliations.insert(reviewer.affiliation_commitment_sha256.as_str())
            || !public_keys.insert(reviewer.key.public_key_hex.as_str())
        {
            return invalid("reviewer trust entries must be sorted, distinct, and independent");
        }
        previous_key_id = Some(&reviewer.key.key_id);
    }
    Ok(())
}

fn validate_trusted_key(key: &DomainStudyTrustedKey) -> Result<(), DomainStudyResultError> {
    if !safe_token(&key.key_id) {
        return invalid("trusted Ed25519 key identifier is invalid");
    }
    let public_key = decode_hex_array::<32>(&key.public_key_hex).ok_or_else(|| {
        DomainStudyResultError::InvalidEvidence(
            "trusted Ed25519 public key is malformed".to_string(),
        )
    })?;
    VerifyingKey::from_bytes(&public_key).map_err(|_| {
        DomainStudyResultError::InvalidEvidence("trusted Ed25519 public key is invalid".to_string())
    })?;
    Ok(())
}

fn verify_signed_claims<T: Serialize>(
    domain: &[u8],
    claims: &T,
    signature: &DomainStudyDetachedSignature,
    trusted_key: &DomainStudyTrustedKey,
    label: &str,
) -> Result<(), DomainStudyResultError> {
    if signature.key_id != trusted_key.key_id {
        return invalid(format!("{label} key identifier is not trusted"));
    }
    let public_key = decode_hex_array::<32>(&trusted_key.public_key_hex).ok_or_else(|| {
        DomainStudyResultError::InvalidEvidence(format!("{label} public key is malformed"))
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        DomainStudyResultError::InvalidEvidence(format!("{label} public key is invalid"))
    })?;
    let signature_bytes = decode_hex_array::<64>(&signature.signature_hex).ok_or_else(|| {
        DomainStudyResultError::InvalidEvidence(format!("{label} signature is malformed"))
    })?;
    let signature_value = Signature::from_bytes(&signature_bytes);
    let payload = signing_payload(domain, claims, &signature.key_id)?;
    verifying_key
        .verify_strict(&payload, &signature_value)
        .map_err(|_| {
            DomainStudyResultError::InvalidEvidence(format!(
                "{label} signature verification failed"
            ))
        })
}

fn signing_payload<T: Serialize>(
    domain: &[u8],
    claims: &T,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyResultError> {
    if !safe_token(key_id) {
        return invalid("signing key identifier is invalid");
    }
    let mut payload = domain.to_vec();
    payload.extend(serde_json::to_vec(&SignedClaims { key_id, claims })?);
    Ok(payload)
}

fn outcome_status(complete: bool, thresholds_met: bool) -> DomainStudyOutcomeStatus {
    if !complete {
        DomainStudyOutcomeStatus::Incomplete
    } else if thresholds_met {
        DomainStudyOutcomeStatus::ThresholdsMet
    } else {
        DomainStudyOutcomeStatus::ThresholdsNotMet
    }
}

fn evidence_status(
    corpus_class: DomainStudyCorpusClass,
    outcome_status: DomainStudyOutcomeStatus,
) -> DomainStudyEvidenceStatus {
    match corpus_class {
        DomainStudyCorpusClass::RepositorySeed | DomainStudyCorpusClass::CuratedInternal => {
            DomainStudyEvidenceStatus::EngineeringOnly
        }
        DomainStudyCorpusClass::IndependentExternal
            if outcome_status == DomainStudyOutcomeStatus::Incomplete =>
        {
            DomainStudyEvidenceStatus::Incomplete
        }
        DomainStudyCorpusClass::IndependentExternal
            if outcome_status == DomainStudyOutcomeStatus::ThresholdsNotMet =>
        {
            DomainStudyEvidenceStatus::ThresholdsNotMet
        }
        DomainStudyCorpusClass::IndependentExternal => {
            DomainStudyEvidenceStatus::IndependentEvidenceCandidate
        }
    }
}

fn checked_sum_counts(values: &[usize]) -> Result<usize, DomainStudyResultError> {
    values.iter().try_fold(0_usize, |sum, value| {
        sum.checked_add(*value).ok_or_else(|| {
            DomainStudyResultError::InvalidEvidence(
                "aggregate evidence count overflows the supported range".to_string(),
            )
        })
    })
}

fn ratio(numerator: usize, denominator: usize) -> Result<f64, DomainStudyResultError> {
    if denominator == 0 || numerator > denominator {
        return invalid("metric denominator is zero or smaller than its numerator");
    }
    Ok(numerator as f64 / denominator as f64)
}

fn optional_ratio(
    numerator: usize,
    denominator: usize,
) -> Result<Option<f64>, DomainStudyResultError> {
    if denominator == 0 {
        return if numerator == 0 {
            Ok(None)
        } else {
            invalid("zero metric denominator has a nonzero numerator")
        };
    }
    ratio(numerator, denominator).map(Some)
}

fn harmonic_mean(left: f64, right: f64) -> f64 {
    if left == 0.0 || right == 0.0 {
        0.0
    } else {
        2.0 * left * right / (left + right)
    }
}

fn wilson_interval(successes: usize, trials: usize) -> Result<(f64, f64), DomainStudyResultError> {
    if trials == 0 || successes > trials {
        return invalid("Wilson interval requires nonzero consistent binomial counts");
    }
    let n = trials as f64;
    let p = successes as f64 / n;
    let z2 = WILSON_95_Z * WILSON_95_Z;
    let denominator = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denominator;
    let half_width = WILSON_95_Z * ((p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt()) / denominator;
    Ok((
        (center - half_width).max(0.0),
        (center + half_width).min(1.0),
    ))
}

fn optional_wilson_interval(
    successes: usize,
    trials: usize,
) -> Result<Option<(f64, f64)>, DomainStudyResultError> {
    if trials == 0 {
        return if successes == 0 {
            Ok(None)
        } else {
            invalid("zero Wilson denominator has nonzero successes")
        };
    }
    wilson_interval(successes, trials).map(Some)
}

fn signed_unit_interval(value: f64) -> bool {
    value.is_finite()
        && (-1.0..=1.0).contains(&value)
        && !(value == 0.0 && value.is_sign_negative())
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, DomainStudyResultError> {
    let digest = Sha256::digest(domain_study_result_canonical_json(value)?);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn decode_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

fn safe_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn safe_oid(value: &str) -> bool {
    if !(3..=128).contains(&value.len()) {
        return false;
    }
    let components = value.split('.').collect::<Vec<_>>();
    if components.len() < 3
        || components.iter().any(|component| {
            component.is_empty()
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
        })
    {
        return false;
    }
    let Ok(first) = components[0].parse::<u8>() else {
        return false;
    };
    if !matches!(first, 0..=2) {
        return false;
    }
    first == 2 || components[1].parse::<u8>().is_ok_and(|second| second <= 39)
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DomainStudyResultError> {
    Err(DomainStudyResultError::InvalidEvidence(message.into()))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::{
        domain_study_seed_registry_sha256, validate_domain_study_reproduction_manifest,
        DomainPolicyPackEvidence, DomainStudyAnalysisPlan, DomainStudyAttackPlan,
        DomainStudyDatasetPlan, DomainStudyHypothesis, DomainStudyMissingDataRule,
        DomainStudyPrimaryOutcome, DomainStudyReproductionArtifact,
        DomainStudyReproductionArtifactRole, DomainStudyReproductionDigestKind,
        DomainStudyReproductionFileIdentity, DomainStudyReproductionManifest,
        DomainStudyReproductionStatus, DomainStudyReproductionTimestampMaterial,
        DomainStudyReviewPlan, DomainTemporalPolicyEvidence, DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
        DOMAIN_STUDY_PREREGISTRATION_SCHEMA_VERSION,
        DOMAIN_STUDY_REPRODUCTION_MANIFEST_SCHEMA_VERSION,
    };

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SHA_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const REGISTERED_AT_MS: u64 = 1_780_000_000_000;

    struct TestKeys {
        preregistration: SigningKey,
        timestamp: SigningKey,
        reviewer_a: SigningKey,
        reviewer_b: SigningKey,
        adjudicator: SigningKey,
        manifest: SigningKey,
    }

    impl TestKeys {
        fn new() -> Self {
            Self {
                preregistration: SigningKey::from_bytes(&[1; 32]),
                timestamp: SigningKey::from_bytes(&[2; 32]),
                reviewer_a: SigningKey::from_bytes(&[3; 32]),
                reviewer_b: SigningKey::from_bytes(&[4; 32]),
                adjudicator: SigningKey::from_bytes(&[5; 32]),
                manifest: SigningKey::from_bytes(&[6; 32]),
            }
        }

        fn trust_policy(&self) -> DomainStudyTrustPolicy {
            DomainStudyTrustPolicy {
                preregistration_signer: trusted_key("institution_prereg", &self.preregistration),
                timestamp_verifier: trusted_key("timestamp_verifier", &self.timestamp),
                trusted_tsa_spki_sha256: SHA_A.to_string(),
                trusted_tsa_policy_oid: "1.3.6.1.4.1.57264.1".to_string(),
                reviewers: vec![
                    DomainStudyTrustedReviewer {
                        key: trusted_key("reviewer_alpha", &self.reviewer_a),
                        affiliation_commitment_sha256: SHA_B.to_string(),
                    },
                    DomainStudyTrustedReviewer {
                        key: trusted_key("reviewer_beta", &self.reviewer_b),
                        affiliation_commitment_sha256: SHA_C.to_string(),
                    },
                ],
                adjudicator: trusted_key("independent_adjudicator", &self.adjudicator),
                final_manifest_signer: trusted_key("institution_manifest", &self.manifest),
            }
        }
    }

    struct TestFixture {
        preregistration_json: String,
        policy: DomainModuleEvidence,
        build: DomainStudyBuildProvenance,
        trust: DomainStudyTrustPolicy,
        evidence: DomainStudyResultEvidenceBundle,
        keys: TestKeys,
    }

    fn trusted_key(key_id: &str, signing_key: &SigningKey) -> DomainStudyTrustedKey {
        DomainStudyTrustedKey {
            key_id: key_id.to_string(),
            public_key_hex: hex(&signing_key.verifying_key().to_bytes()),
        }
    }

    fn signature<T: Serialize>(
        domain: &[u8],
        claims: &T,
        key_id: &str,
        signing_key: &SigningKey,
    ) -> DomainStudyDetachedSignature {
        let payload = signing_payload(domain, claims, key_id).expect("signing payload");
        DomainStudyDetachedSignature {
            key_id: key_id.to_string(),
            signature_hex: hex(&signing_key.sign(&payload).to_bytes()),
        }
    }

    fn timestamp(
        subject_kind: DomainStudyTimestampSubjectKind,
        subject_sha256: String,
        issued_at_ms: u64,
        keys: &TestKeys,
    ) -> DomainStudyTrustedTimestampReceipt {
        let claims = DomainStudyTrustedTimestampClaims {
            schema_version: DOMAIN_STUDY_TRUSTED_TIMESTAMP_SCHEMA_VERSION.to_string(),
            subject_kind,
            subject_canonical_sha256: subject_sha256,
            protocol: DomainStudyTimestampProtocol::Rfc3161TrustedChain,
            issued_at_ms,
            gen_time_submillisecond_micros: 0,
            accuracy_micros: 1_000,
            request_sha256: SHA_B.to_string(),
            response_sha256: SHA_C.to_string(),
            certificate_chain_sha256: aggregate_sha256(
                b"aura.domain.rfc3161-certificate-chain.v1\0",
                &[SHA_A, SHA_B],
            ),
            revocation_evidence_sha256: aggregate_sha256(
                b"aura.domain.rfc3161-revocation-evidence.v1\0",
                &[SHA_C],
            ),
            tsa_spki_sha256: SHA_A.to_string(),
            tsa_policy_oid: "1.3.6.1.4.1.57264.1".to_string(),
        };
        let key_id = "timestamp_verifier";
        let signature = signature(TRUSTED_TIMESTAMP_DOMAIN, &claims, key_id, &keys.timestamp);
        DomainStudyTrustedTimestampReceipt { claims, signature }
    }

    fn policy() -> DomainModuleEvidence {
        DomainModuleEvidence {
            schema_version: DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
            module_id: DomainModuleId::Military,
            module_version: "0.2.0".to_string(),
            stateful: false,
            state_schema_version: None,
            lexical_policy: DomainPolicyPackEvidence {
                pack_id: "military.lexical.v1".to_string(),
                schema_version: 1,
                sha256: SHA_A.to_string(),
                rule_count: 12,
            },
            temporal_policy: Some(DomainTemporalPolicyEvidence {
                pack: DomainPolicyPackEvidence {
                    pack_id: "military.temporal.v1".to_string(),
                    schema_version: 1,
                    sha256: SHA_B.to_string(),
                    rule_count: 3,
                },
                runtime_enabled: false,
                action_execution_configured: false,
            }),
        }
    }

    fn build() -> DomainStudyBuildProvenance {
        DomainStudyBuildProvenance {
            git_revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
            source_tree_sha256: SHA_A.to_string(),
            cargo_lock_sha256: SHA_B.to_string(),
            rust_toolchain_sha256: SHA_C.to_string(),
            target_triple: "aarch64-apple-ios".to_string(),
            cargo_profile: "release".to_string(),
            feature_set: Vec::new(),
            binary_sha256: SHA_D.to_string(),
            source_tree_clean: true,
        }
    }

    fn preregistration(
        policy: DomainModuleEvidence,
        build: DomainStudyBuildProvenance,
    ) -> DomainStudyPreregistration {
        DomainStudyPreregistration {
            schema_version: DOMAIN_STUDY_PREREGISTRATION_SCHEMA_VERSION.to_string(),
            study_id: "external_military_study_2026".to_string(),
            registered_at_ms: REGISTERED_AT_MS,
            domain: DomainModuleId::Military,
            policy_evidence: policy,
            build_provenance: build,
            temporal_mode: DomainStudyTemporalMode::ShadowOnly,
            confirmatory_hypotheses: vec![DomainStudyHypothesis {
                hypothesis_id: "h1_primary".to_string(),
                statement: "The frozen policy meets every conservative primary outcome threshold."
                    .to_string(),
            }],
            dataset: DomainStudyDatasetPlan {
                dataset_id: "external_military_corpus_2026".to_string(),
                corpus_class: DomainStudyCorpusClass::IndependentExternal,
                corpus_sha256: SHA_D.to_string(),
                fixed_case_count: 120,
                inclusion_criteria_sha256: SHA_A.to_string(),
                exclusion_criteria_sha256: SHA_B.to_string(),
                label_ontology_sha256: SHA_C.to_string(),
                safe_boundary_definition_sha256: SHA_D.to_string(),
                split_manifest_sha256: SHA_A.to_string(),
                required_threat_families: vec!["opsec".to_string(), "psyops".to_string()],
                minimum_cases_per_threat_family: 20,
                minimum_safe_boundary_cases: 20,
                required_strata: vec!["high_risk".to_string(), "safe_boundary".to_string()],
                a_priori_sample_size_rationale:
                    "Fixed precision and conservative confidence-bound targets set in advance."
                        .to_string(),
                independent_sampling_frame: true,
                identity_disjoint_splits: true,
                labels_hidden_from_implementers_until_policy_freeze: true,
                raw_content_exported_in_public_evidence: false,
                known_seed_registry_sha256: domain_study_seed_registry_sha256(&[])
                    .expect("seed registry"),
            },
            attacks: DomainStudyAttackPlan {
                attack_families: vec![
                    "code_switching".to_string(),
                    "orthographic_noise".to_string(),
                    "paraphrase".to_string(),
                ],
                fixed_variant_count: 60,
                minimum_variants_per_family: 20,
                construction_manifest_sha256: SHA_B.to_string(),
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
                inter_rater_agreement_statistic:
                    DomainStudyInterRaterAgreementStatistic::KrippendorffAlphaNominal,
                inter_rater_agreement_uncertainty_method:
                    DomainStudyAgreementUncertaintyMethod::CaseBootstrapBca95,
                inter_rater_agreement_bootstrap_resamples: 20_000,
                inter_rater_agreement_bootstrap_seed_sha256: SHA_D.to_string(),
                missing_data_rule: DomainStudyMissingDataRule::NoImputationReportIncomplete,
                exploratory_analyses_reported_separately: true,
                all_exclusions_and_deviations_reported: true,
                fixed_corpus_no_optional_stopping: true,
            },
        }
    }

    fn fixture() -> TestFixture {
        let keys = TestKeys::new();
        let trust = keys.trust_policy();
        let policy = policy();
        let build = build();
        let preregistration = preregistration(policy.clone(), build.clone());
        let preregistration_json = serde_json::to_string(&preregistration).expect("prereg JSON");
        let binding =
            validate_domain_study_preregistration(&preregistration_json, &policy, &build, &[])
                .expect("preregistration binding");

        let preregistration_claims = DomainStudyPreregistrationAttestationClaims {
            schema_version: DOMAIN_STUDY_PREREGISTRATION_ATTESTATION_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            attested_at_ms: REGISTERED_AT_MS,
        };
        let preregistration_attestation = DomainStudyPreregistrationAttestation {
            signature: signature(
                PREREGISTRATION_ATTESTATION_DOMAIN,
                &preregistration_claims,
                "institution_prereg",
                &keys.preregistration,
            ),
            claims: preregistration_claims,
        };
        let preregistration_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::PreregistrationAttestation,
            canonical_sha256(&preregistration_attestation).expect("prereg attestation digest"),
            REGISTERED_AT_MS + 10_000,
            &keys,
        );

        let mut review_coverage = (0..120)
            .map(|index| DomainStudyCaseReviewCoverage {
                blind_case_token_sha256: hex(&Sha256::digest(format!("blind-case-{index}"))),
                reviewer_indices: vec![0, 1],
                adjudicated: true,
            })
            .collect::<Vec<_>>();
        review_coverage.sort_by(|left, right| {
            left.blind_case_token_sha256
                .cmp(&right.blind_case_token_sha256)
        });
        let assigned_cases = review_coverage
            .iter()
            .map(|row| row.blind_case_token_sha256.clone())
            .collect::<Vec<_>>();
        let reviewer_assignments = vec![
            DomainStudyReviewerAssignmentManifest {
                schema_version: DOMAIN_STUDY_REVIEWER_ASSIGNMENT_SCHEMA_VERSION.to_string(),
                study_id: binding.study_id.clone(),
                reviewer_index: 0,
                blind_case_token_sha256: assigned_cases.clone(),
            },
            DomainStudyReviewerAssignmentManifest {
                schema_version: DOMAIN_STUDY_REVIEWER_ASSIGNMENT_SCHEMA_VERSION.to_string(),
                study_id: binding.study_id.clone(),
                reviewer_index: 1,
                blind_case_token_sha256: assigned_cases,
            },
        ];
        let reviewer_a = reviewer_receipt(
            "reviewer_alpha",
            SHA_B,
            &canonical_sha256(&reviewer_assignments[0]).expect("reviewer assignment digest"),
            SHA_A,
            &binding,
            REGISTERED_AT_MS + 20_000,
            &keys.reviewer_a,
        );
        let reviewer_b = reviewer_receipt(
            "reviewer_beta",
            SHA_C,
            &canonical_sha256(&reviewer_assignments[1]).expect("reviewer assignment digest"),
            SHA_B,
            &binding,
            REGISTERED_AT_MS + 21_000,
            &keys.reviewer_b,
        );
        let reviewer_receipts = vec![
            DomainStudyTimestampedReviewerReceipt {
                trusted_timestamp: timestamp(
                    DomainStudyTimestampSubjectKind::ReviewerReceipt,
                    canonical_sha256(&reviewer_a).expect("reviewer receipt digest"),
                    REGISTERED_AT_MS + 20_500,
                    &keys,
                ),
                receipt: reviewer_a,
            },
            DomainStudyTimestampedReviewerReceipt {
                trusted_timestamp: timestamp(
                    DomainStudyTimestampSubjectKind::ReviewerReceipt,
                    canonical_sha256(&reviewer_b).expect("reviewer receipt digest"),
                    REGISTERED_AT_MS + 21_500,
                    &keys,
                ),
                receipt: reviewer_b,
            },
        ];
        let reviewer_receipt_set_sha256 = canonical_sha256(
            &reviewer_receipts
                .iter()
                .map(|item| canonical_sha256(&item.receipt).expect("reviewer digest"))
                .collect::<Vec<_>>(),
        )
        .expect("reviewer set digest");
        let review_coverage_manifest_sha256 =
            canonical_sha256(&review_coverage).expect("review coverage digest");
        let adjudication_manifest = DomainStudyAdjudicationManifest {
            schema_version: DOMAIN_STUDY_ADJUDICATION_MANIFEST_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            blind_case_token_sha256: review_coverage
                .iter()
                .map(|row| row.blind_case_token_sha256.clone())
                .collect(),
            decision_bundle_sha256: SHA_D.to_string(),
        };
        let adjudication_claims = DomainStudyAdjudicationReceiptClaims {
            schema_version: DOMAIN_STUDY_ADJUDICATION_RECEIPT_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            reviewer_receipt_set_sha256: reviewer_receipt_set_sha256.clone(),
            adjudication_bundle_sha256: canonical_sha256(&adjudication_manifest)
                .expect("adjudication manifest digest"),
            label_ontology_sha256: preregistration.dataset.label_ontology_sha256.clone(),
            adjudicated_case_count: 120,
            completed_at_ms: REGISTERED_AT_MS + 30_000,
        };
        let adjudication_receipt = DomainStudyAdjudicationReceipt {
            signature: signature(
                ADJUDICATION_RECEIPT_DOMAIN,
                &adjudication_claims,
                "independent_adjudicator",
                &keys.adjudicator,
            ),
            claims: adjudication_claims,
        };
        let adjudication_receipt_sha256 =
            canonical_sha256(&adjudication_receipt).expect("adjudication digest");
        let adjudication_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::AdjudicationReceipt,
            adjudication_receipt_sha256.clone(),
            REGISTERED_AT_MS + 30_500,
            &keys,
        );
        let result = DomainStudyResultBundle {
            schema_version: DOMAIN_STUDY_RESULT_SCHEMA_VERSION.to_string(),
            result_id: "result_round_2026_01".to_string(),
            study_id: binding.study_id.clone(),
            domain: binding.domain,
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            corpus_sha256: binding.corpus_sha256.clone(),
            split_manifest_sha256: preregistration.dataset.split_manifest_sha256.clone(),
            policy_evidence_canonical_sha256: binding.policy_evidence_canonical_sha256.clone(),
            build_provenance_canonical_sha256: binding.build_provenance_canonical_sha256.clone(),
            review_packet_sha256: SHA_C.to_string(),
            reviewer_receipt_set_sha256: reviewer_receipt_set_sha256.clone(),
            adjudication_receipt_sha256,
            prediction_bundle_sha256: SHA_A.to_string(),
            analysis_environment_sha256: SHA_B.to_string(),
            review_agreement_analysis: DomainStudyAgreementAnalysisClaims {
                schema_version: DOMAIN_STUDY_AGREEMENT_ANALYSIS_SCHEMA_VERSION.to_string(),
                study_id: binding.study_id.clone(),
                preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
                reviewer_receipt_set_sha256: reviewer_receipt_set_sha256.clone(),
                review_coverage_manifest_sha256: review_coverage_manifest_sha256.clone(),
                statistic: preregistration.analysis.inter_rater_agreement_statistic,
                uncertainty_method: preregistration
                    .analysis
                    .inter_rater_agreement_uncertainty_method,
                bootstrap_resamples: preregistration
                    .analysis
                    .inter_rater_agreement_bootstrap_resamples,
                bootstrap_seed_sha256: preregistration
                    .analysis
                    .inter_rater_agreement_bootstrap_seed_sha256
                    .clone(),
                agreement: Some(0.9),
                agreement_95_lower: Some(0.85),
                analysis_artifact_sha256: SHA_C.to_string(),
                completed_at_ms: REGISTERED_AT_MS + 25_000,
            },
            review_coverage_manifest_sha256,
            exclusion_manifest_sha256: SHA_A.to_string(),
            protocol_deviation_manifest_sha256: SHA_B.to_string(),
            exploratory_results_sha256: None,
            metrics: DomainStudyResultMetrics {
                total_case_count: 120,
                analyzed_case_count: 120,
                excluded_case_count: 0,
                incomplete_case_count: 0,
                per_threat: vec![
                    DomainStudyThreatCounts {
                        threat_family: "opsec".to_string(),
                        true_positive: 50,
                        false_positive: 0,
                        false_negative: 0,
                    },
                    DomainStudyThreatCounts {
                        threat_family: "psyops".to_string(),
                        true_positive: 50,
                        false_positive: 0,
                        false_negative: 0,
                    },
                ],
                per_stratum: vec![
                    DomainStudyStratumCount {
                        stratum: "high_risk".to_string(),
                        case_count: 60,
                    },
                    DomainStudyStratumCount {
                        stratum: "safe_boundary".to_string(),
                        case_count: 60,
                    },
                ],
                evaluated_safe_boundary_case_count: 100,
                false_positive_safe_boundary_case_count: 0,
                evaluated_attack_variant_count: 60,
                consistent_attack_variant_count: 60,
                per_attack_family: vec![
                    DomainStudyAttackFamilyCounts {
                        attack_family: "code_switching".to_string(),
                        evaluated_variant_count: 20,
                        consistent_variant_count: 20,
                    },
                    DomainStudyAttackFamilyCounts {
                        attack_family: "orthographic_noise".to_string(),
                        evaluated_variant_count: 20,
                        consistent_variant_count: 20,
                    },
                    DomainStudyAttackFamilyCounts {
                        attack_family: "paraphrase".to_string(),
                        evaluated_variant_count: 20,
                        consistent_variant_count: 20,
                    },
                ],
                review_coverage: DomainStudyReviewCoverage {
                    reviewer_receipt_count: 2,
                    minimum_completed_reviews_per_case: 2,
                    maximum_completed_reviews_per_case: 2,
                    fully_reviewed_case_count: 120,
                    adjudicated_case_count: 120,
                },
                protocol_deviation_count: 0,
                confirmatory_analysis_deviation_count: 0,
            },
            generated_at_ms: REGISTERED_AT_MS + 31_000,
            raw_content_exported: false,
            reviewer_identifiers_exported: false,
        };
        let review_agreement_analysis_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::ReviewerAgreementAnalysis,
            canonical_sha256(&result.review_agreement_analysis).expect("agreement analysis digest"),
            REGISTERED_AT_MS + 25_500,
            &keys,
        );
        let adjudication_start_claims = DomainStudyAdjudicationStartClaims {
            schema_version: DOMAIN_STUDY_ADJUDICATION_START_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            reviewer_receipt_set_sha256: result.reviewer_receipt_set_sha256.clone(),
            agreement_analysis_sha256: canonical_sha256(&result.review_agreement_analysis)
                .expect("agreement analysis digest"),
            authorized_at_ms: REGISTERED_AT_MS + 27_000,
        };
        let adjudication_start_authorization = DomainStudyAdjudicationStartAuthorization {
            signature: signature(
                ADJUDICATION_START_DOMAIN,
                &adjudication_start_claims,
                "independent_adjudicator",
                &keys.adjudicator,
            ),
            claims: adjudication_start_claims,
        };
        let adjudication_start_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::AdjudicationStartAuthorization,
            canonical_sha256(&adjudication_start_authorization).expect("adjudication start digest"),
            REGISTERED_AT_MS + 27_500,
            &keys,
        );
        let mut evidence = DomainStudyResultEvidenceBundle {
            schema_version: DOMAIN_STUDY_RESULT_EVIDENCE_SCHEMA_VERSION.to_string(),
            preregistration_attestation,
            preregistration_timestamp,
            reviewer_receipts,
            reviewer_assignments,
            review_coverage,
            adjudication_manifest,
            adjudication_receipt,
            adjudication_timestamp,
            result,
            review_agreement_analysis_timestamp,
            adjudication_start_authorization,
            adjudication_start_timestamp,
            final_manifest: DomainStudyFinalManifest {
                claims: placeholder_manifest_claims(&binding),
                signature: DomainStudyDetachedSignature {
                    key_id: "institution_manifest".to_string(),
                    signature_hex: "00".repeat(64),
                },
            },
            final_manifest_timestamp: timestamp(
                DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
                SHA_A.to_string(),
                REGISTERED_AT_MS + 33_000,
                &keys,
            ),
        };
        finalize_manifest(
            &mut evidence,
            &binding,
            &keys,
            DomainStudyEvidenceStatus::IndependentEvidenceCandidate,
        );

        TestFixture {
            preregistration_json,
            policy,
            build,
            trust,
            evidence,
            keys,
        }
    }

    fn reviewer_receipt(
        key_id: &str,
        affiliation_sha256: &str,
        assignment_sha256: &str,
        decision_sha256: &str,
        binding: &crate::DomainStudyBinding,
        completed_at_ms: u64,
        signing_key: &SigningKey,
    ) -> DomainStudyReviewerReceipt {
        let claims = DomainStudyReviewerReceiptClaims {
            schema_version: DOMAIN_STUDY_REVIEWER_RECEIPT_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            review_packet_sha256: SHA_C.to_string(),
            assignment_manifest_sha256: assignment_sha256.to_string(),
            decision_bundle_sha256: decision_sha256.to_string(),
            affiliation_commitment_sha256: affiliation_sha256.to_string(),
            completed_case_count: 120,
            completed_at_ms,
        };
        DomainStudyReviewerReceipt {
            signature: signature(REVIEWER_RECEIPT_DOMAIN, &claims, key_id, signing_key),
            claims,
        }
    }

    fn placeholder_manifest_claims(
        binding: &crate::DomainStudyBinding,
    ) -> DomainStudyFinalManifestClaims {
        DomainStudyFinalManifestClaims {
            schema_version: DOMAIN_STUDY_FINAL_MANIFEST_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            domain: binding.domain,
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            policy_evidence_canonical_sha256: binding.policy_evidence_canonical_sha256.clone(),
            build_provenance_canonical_sha256: binding.build_provenance_canonical_sha256.clone(),
            corpus_sha256: binding.corpus_sha256.clone(),
            trust_policy_canonical_sha256: SHA_A.to_string(),
            preregistration_attestation_sha256: SHA_A.to_string(),
            preregistration_timestamp_sha256: SHA_A.to_string(),
            reviewer_receipt_set_sha256: SHA_A.to_string(),
            reviewer_timestamp_set_sha256: SHA_A.to_string(),
            agreement_analysis_timestamp_sha256: SHA_A.to_string(),
            adjudication_start_authorization_sha256: SHA_A.to_string(),
            adjudication_start_timestamp_sha256: SHA_A.to_string(),
            adjudication_receipt_sha256: SHA_A.to_string(),
            adjudication_timestamp_sha256: SHA_A.to_string(),
            result_bundle_sha256: SHA_A.to_string(),
            evidence_status: DomainStudyEvidenceStatus::Incomplete,
            outcome_status: DomainStudyOutcomeStatus::Incomplete,
            temporal_mode: binding.temporal_mode,
            temporal_runtime_enabled: false,
            action_execution_configured: false,
            raw_content_exported: false,
            reviewer_identifiers_exported: false,
            completed_at_ms: REGISTERED_AT_MS + 32_000,
        }
    }

    fn finalize_manifest(
        evidence: &mut DomainStudyResultEvidenceBundle,
        binding: &crate::DomainStudyBinding,
        keys: &TestKeys,
        evidence_status: DomainStudyEvidenceStatus,
    ) {
        evidence.review_agreement_analysis_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::ReviewerAgreementAnalysis,
            canonical_sha256(&evidence.result.review_agreement_analysis)
                .expect("agreement analysis digest"),
            REGISTERED_AT_MS + 25_500,
            keys,
        );
        let start_claims = DomainStudyAdjudicationStartClaims {
            schema_version: DOMAIN_STUDY_ADJUDICATION_START_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            reviewer_receipt_set_sha256: evidence.result.reviewer_receipt_set_sha256.clone(),
            agreement_analysis_sha256: canonical_sha256(&evidence.result.review_agreement_analysis)
                .expect("agreement analysis digest"),
            authorized_at_ms: REGISTERED_AT_MS + 27_000,
        };
        evidence.adjudication_start_authorization = DomainStudyAdjudicationStartAuthorization {
            signature: signature(
                ADJUDICATION_START_DOMAIN,
                &start_claims,
                "independent_adjudicator",
                &keys.adjudicator,
            ),
            claims: start_claims,
        };
        evidence.adjudication_start_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::AdjudicationStartAuthorization,
            canonical_sha256(&evidence.adjudication_start_authorization)
                .expect("adjudication start digest"),
            REGISTERED_AT_MS + 27_500,
            keys,
        );
        let reviewer_receipt_digests = evidence
            .reviewer_receipts
            .iter()
            .map(|item| canonical_sha256(&item.receipt).expect("reviewer receipt digest"))
            .collect::<Vec<_>>();
        let reviewer_timestamp_digests = evidence
            .reviewer_receipts
            .iter()
            .map(|item| canonical_sha256(&item.trusted_timestamp).expect("review timestamp digest"))
            .collect::<Vec<_>>();
        let claims = DomainStudyFinalManifestClaims {
            schema_version: DOMAIN_STUDY_FINAL_MANIFEST_SCHEMA_VERSION.to_string(),
            study_id: binding.study_id.clone(),
            domain: binding.domain,
            preregistration_canonical_sha256: binding.preregistration_canonical_sha256.clone(),
            policy_evidence_canonical_sha256: binding.policy_evidence_canonical_sha256.clone(),
            build_provenance_canonical_sha256: binding.build_provenance_canonical_sha256.clone(),
            corpus_sha256: binding.corpus_sha256.clone(),
            trust_policy_canonical_sha256: canonical_sha256(&keys.trust_policy())
                .expect("trust policy digest"),
            preregistration_attestation_sha256: canonical_sha256(
                &evidence.preregistration_attestation,
            )
            .expect("preregistration attestation digest"),
            preregistration_timestamp_sha256: canonical_sha256(&evidence.preregistration_timestamp)
                .expect("preregistration timestamp digest"),
            reviewer_receipt_set_sha256: canonical_sha256(&reviewer_receipt_digests)
                .expect("reviewer receipt set digest"),
            reviewer_timestamp_set_sha256: canonical_sha256(&reviewer_timestamp_digests)
                .expect("reviewer timestamp set digest"),
            agreement_analysis_timestamp_sha256: canonical_sha256(
                &evidence.review_agreement_analysis_timestamp,
            )
            .expect("agreement timestamp digest"),
            adjudication_start_authorization_sha256: canonical_sha256(
                &evidence.adjudication_start_authorization,
            )
            .expect("adjudication start digest"),
            adjudication_start_timestamp_sha256: canonical_sha256(
                &evidence.adjudication_start_timestamp,
            )
            .expect("adjudication start timestamp digest"),
            adjudication_receipt_sha256: canonical_sha256(&evidence.adjudication_receipt)
                .expect("adjudication receipt digest"),
            adjudication_timestamp_sha256: canonical_sha256(&evidence.adjudication_timestamp)
                .expect("adjudication timestamp digest"),
            result_bundle_sha256: canonical_sha256(&evidence.result).expect("result digest"),
            evidence_status,
            outcome_status: match evidence_status {
                DomainStudyEvidenceStatus::Incomplete => DomainStudyOutcomeStatus::Incomplete,
                DomainStudyEvidenceStatus::ThresholdsNotMet => {
                    DomainStudyOutcomeStatus::ThresholdsNotMet
                }
                DomainStudyEvidenceStatus::EngineeringOnly
                | DomainStudyEvidenceStatus::IndependentEvidenceCandidate => {
                    DomainStudyOutcomeStatus::ThresholdsMet
                }
            },
            temporal_mode: binding.temporal_mode,
            temporal_runtime_enabled: false,
            action_execution_configured: false,
            raw_content_exported: false,
            reviewer_identifiers_exported: false,
            completed_at_ms: REGISTERED_AT_MS + 32_000,
        };
        let final_manifest = DomainStudyFinalManifest {
            signature: signature(
                FINAL_MANIFEST_DOMAIN,
                &claims,
                "institution_manifest",
                &keys.manifest,
            ),
            claims,
        };
        let final_manifest_sha256 = canonical_sha256(&final_manifest).expect("manifest digest");
        evidence.final_manifest = final_manifest;
        evidence.final_manifest_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            final_manifest_sha256,
            REGISTERED_AT_MS + 33_000,
            keys,
        );
    }

    fn binding(fixture: &TestFixture) -> crate::DomainStudyBinding {
        validate_domain_study_preregistration(
            &fixture.preregistration_json,
            &fixture.policy,
            &fixture.build,
            &[],
        )
        .expect("preregistration binding")
    }

    fn validate(fixture: &TestFixture) -> Result<DomainStudyResultReport, DomainStudyResultError> {
        validate_domain_study_result_evidence(
            &fixture.preregistration_json,
            &serde_json::to_string(&fixture.evidence).expect("evidence JSON"),
            &fixture.policy,
            &fixture.build,
            &[],
            &fixture.trust,
        )
    }

    fn file(sha256: &str) -> DomainStudyReproductionFileIdentity {
        DomainStudyReproductionFileIdentity {
            sha256: sha256.to_string(),
            byte_length: 1,
        }
    }

    fn reproduction_manifest(fixture: &TestFixture) -> DomainStudyReproductionManifest {
        use DomainStudyReproductionArtifactRole as Role;

        let preregistration: DomainStudyPreregistration =
            serde_json::from_str(&fixture.preregistration_json).expect("preregistration");
        let report = validate(fixture).expect("result evidence");
        let result = &fixture.evidence.result;
        let mut primary = vec![
            (
                Role::Preregistration,
                0,
                result.preregistration_canonical_sha256.as_str(),
            ),
            (
                Role::PolicyEvidence,
                0,
                result.policy_evidence_canonical_sha256.as_str(),
            ),
            (
                Role::BuildProvenance,
                0,
                result.build_provenance_canonical_sha256.as_str(),
            ),
            (
                Role::TrustPolicy,
                0,
                fixture
                    .evidence
                    .final_manifest
                    .claims
                    .trust_policy_canonical_sha256
                    .as_str(),
            ),
            (
                Role::SourceTree,
                0,
                preregistration.build_provenance.source_tree_sha256.as_str(),
            ),
            (
                Role::CargoLock,
                0,
                preregistration.build_provenance.cargo_lock_sha256.as_str(),
            ),
            (
                Role::RustToolchain,
                0,
                preregistration
                    .build_provenance
                    .rust_toolchain_sha256
                    .as_str(),
            ),
            (
                Role::EvaluatedBinary,
                0,
                preregistration.build_provenance.binary_sha256.as_str(),
            ),
            (Role::Corpus, 0, result.corpus_sha256.as_str()),
            (
                Role::KnownSeedRegistry,
                0,
                preregistration.dataset.known_seed_registry_sha256.as_str(),
            ),
            (
                Role::InclusionCriteria,
                0,
                preregistration.dataset.inclusion_criteria_sha256.as_str(),
            ),
            (
                Role::ExclusionCriteria,
                0,
                preregistration.dataset.exclusion_criteria_sha256.as_str(),
            ),
            (
                Role::LabelOntology,
                0,
                preregistration.dataset.label_ontology_sha256.as_str(),
            ),
            (
                Role::SafeBoundaryDefinition,
                0,
                preregistration
                    .dataset
                    .safe_boundary_definition_sha256
                    .as_str(),
            ),
            (
                Role::SplitManifest,
                0,
                result.split_manifest_sha256.as_str(),
            ),
            (
                Role::AttackConstructionManifest,
                0,
                preregistration
                    .attacks
                    .construction_manifest_sha256
                    .as_str(),
            ),
            (
                Role::AgreementBootstrapSeed,
                0,
                preregistration
                    .analysis
                    .inter_rater_agreement_bootstrap_seed_sha256
                    .as_str(),
            ),
            (Role::ReviewPacket, 0, result.review_packet_sha256.as_str()),
            (
                Role::ReviewCoverageManifest,
                0,
                result.review_coverage_manifest_sha256.as_str(),
            ),
            (
                Role::AgreementAnalysisArtifact,
                0,
                result
                    .review_agreement_analysis
                    .analysis_artifact_sha256
                    .as_str(),
            ),
            (
                Role::AdjudicationManifest,
                0,
                fixture
                    .evidence
                    .adjudication_receipt
                    .claims
                    .adjudication_bundle_sha256
                    .as_str(),
            ),
            (
                Role::AdjudicationDecisionBundle,
                0,
                fixture
                    .evidence
                    .adjudication_manifest
                    .decision_bundle_sha256
                    .as_str(),
            ),
            (
                Role::PredictionBundle,
                0,
                result.prediction_bundle_sha256.as_str(),
            ),
            (
                Role::AnalysisEnvironment,
                0,
                result.analysis_environment_sha256.as_str(),
            ),
            (
                Role::ExclusionManifest,
                0,
                result.exclusion_manifest_sha256.as_str(),
            ),
            (
                Role::ProtocolDeviationManifest,
                0,
                result.protocol_deviation_manifest_sha256.as_str(),
            ),
        ];
        for (index, receipt) in fixture.evidence.reviewer_receipts.iter().enumerate() {
            primary.push((
                Role::ReviewerAssignment,
                u16::try_from(index).expect("reviewer ordinal"),
                receipt.receipt.claims.assignment_manifest_sha256.as_str(),
            ));
            primary.push((
                Role::ReviewerDecisionBundle,
                u16::try_from(index).expect("reviewer ordinal"),
                receipt.receipt.claims.decision_bundle_sha256.as_str(),
            ));
        }
        if let Some(exploratory) = result.exploratory_results_sha256.as_deref() {
            primary.push((Role::ExploratoryResults, 0, exploratory));
        }
        let evidence_sha256 = canonical_sha256(&fixture.evidence).expect("evidence digest");
        primary.push((Role::ResultEvidenceBundle, 0, evidence_sha256.as_str()));
        primary.sort_by_key(|(role, ordinal, _)| (*role, *ordinal));
        let primary_artifacts = primary
            .into_iter()
            .map(|(role, ordinal, sha256)| DomainStudyReproductionArtifact {
                role,
                ordinal,
                digest_kind: match role {
                    Role::Preregistration
                    | Role::PolicyEvidence
                    | Role::BuildProvenance
                    | Role::TrustPolicy
                    | Role::KnownSeedRegistry
                    | Role::ReviewerAssignment
                    | Role::ReviewCoverageManifest
                    | Role::AdjudicationManifest
                    | Role::ResultEvidenceBundle => {
                        DomainStudyReproductionDigestKind::CanonicalJsonSha256
                    }
                    Role::SourceTree => DomainStudyReproductionDigestKind::BuildSourceTreeV2,
                    _ => DomainStudyReproductionDigestKind::RawFileSha256,
                },
                covered_file_count: 1,
                file: file(sha256),
            })
            .collect::<Vec<_>>();

        let mut timestamps = vec![(
            DomainStudyTimestampSubjectKind::PreregistrationAttestation,
            None,
        )];
        timestamps.extend(fixture.evidence.reviewer_receipts.iter().enumerate().map(
            |(index, _)| {
                (
                    DomainStudyTimestampSubjectKind::ReviewerReceipt,
                    Some(u16::try_from(index).expect("reviewer ordinal")),
                )
            },
        ));
        timestamps.extend([
            (
                DomainStudyTimestampSubjectKind::ReviewerAgreementAnalysis,
                None,
            ),
            (
                DomainStudyTimestampSubjectKind::AdjudicationStartAuthorization,
                None,
            ),
            (DomainStudyTimestampSubjectKind::AdjudicationReceipt, None),
            (DomainStudyTimestampSubjectKind::FinalEvidenceManifest, None),
        ]);
        let timestamp_materials = timestamps
            .into_iter()
            .map(
                |(subject_kind, reviewer_index)| DomainStudyReproductionTimestampMaterial {
                    subject_kind,
                    reviewer_index,
                    request: file(SHA_B),
                    response: file(SHA_C),
                    certificate_chain_der: vec![file(SHA_A), file(SHA_B)],
                    revocation_crl_der: vec![file(SHA_C)],
                },
            )
            .collect::<Vec<_>>();
        let file_count = u32::try_from(primary_artifacts.len() + timestamp_materials.len() * 5)
            .expect("file count");

        DomainStudyReproductionManifest {
            schema_version: DOMAIN_STUDY_REPRODUCTION_MANIFEST_SCHEMA_VERSION.to_string(),
            study_id: report.study_id,
            result_id: report.result_id,
            preregistration_canonical_sha256: report.preregistration_canonical_sha256,
            result_bundle_sha256: report.result_bundle_sha256,
            final_manifest_sha256: report.final_manifest_sha256,
            evidence_bundle_canonical_sha256: canonical_sha256(&fixture.evidence)
                .expect("evidence digest"),
            primary_artifacts,
            timestamp_materials,
            file_count,
            total_file_bytes: u64::from(file_count),
            public_distribution_permitted: false,
            independent_recomputation_completed: false,
        }
    }

    fn validate_reproduction(
        fixture: &TestFixture,
        manifest: &DomainStudyReproductionManifest,
    ) -> Result<crate::DomainStudyReproductionReport, crate::DomainStudyReproductionError> {
        validate_domain_study_reproduction_manifest(
            &fixture.preregistration_json,
            &serde_json::to_string(&fixture.evidence).expect("evidence JSON"),
            &serde_json::to_string(manifest).expect("reproduction JSON"),
            &fixture.policy,
            &fixture.build,
            &[],
            &fixture.trust,
        )
    }

    #[test]
    fn complete_reproduction_manifest_is_consistent_but_not_a_completed_rerun() {
        let fixture = fixture();
        let manifest = reproduction_manifest(&fixture);

        let report = validate_reproduction(&fixture, &manifest).expect("reproduction manifest");

        assert_eq!(
            report.status,
            DomainStudyReproductionStatus::ManifestConsistent
        );
        assert_eq!(report.file_count, manifest.file_count);
        assert!(!report.independent_recomputation_completed);
        assert!(!report.public_distribution_permitted);
    }

    #[test]
    fn reproduction_manifest_rejects_missing_primary_artifact() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        manifest.primary_artifacts.pop();
        manifest.file_count -= 1;
        manifest.total_file_bytes -= 1;

        let error = validate_reproduction(&fixture, &manifest)
            .expect_err("incomplete materialization must fail");

        assert!(error.to_string().contains("incomplete or has extra roles"));
    }

    #[test]
    fn reproduction_manifest_rejects_timestamp_chain_substitution() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        manifest.timestamp_materials[0].certificate_chain_der[0].sha256 = SHA_D.to_string();

        let error = validate_reproduction(&fixture, &manifest)
            .expect_err("substituted timestamp chain must fail");

        assert!(error.to_string().contains("does not match receipt"));
    }

    #[test]
    fn materialization_manifest_cannot_claim_independent_recomputation() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        manifest.independent_recomputation_completed = true;

        let error = validate_reproduction(&fixture, &manifest)
            .expect_err("materialization cannot claim a rerun");

        assert!(error.to_string().contains("completed rerun"));
    }

    #[test]
    fn reproduction_manifest_rejects_incorrect_file_totals() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        manifest.total_file_bytes += 1;

        let error =
            validate_reproduction(&fixture, &manifest).expect_err("incorrect totals must fail");

        assert!(error
            .to_string()
            .contains("totals are not exactly recomputed"));
    }

    #[test]
    fn reproduction_manifest_rejects_unsorted_crl_material() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        let timestamp = &mut manifest.timestamp_materials[0];
        timestamp.certificate_chain_der.push(file(SHA_D));
        timestamp.revocation_crl_der = vec![file(SHA_D), file(SHA_C)];
        manifest.file_count += 2;
        manifest.total_file_bytes += 2;

        let error = validate_reproduction(&fixture, &manifest)
            .expect_err("unsorted CRL material must fail before its aggregate is trusted");

        assert!(error.to_string().contains("duplicated or not sorted"));
    }

    #[test]
    fn reproduction_manifest_rejects_old_schema() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        manifest.schema_version = "aura.domain.independent_reproduction_package.v0".to_string();

        let error =
            validate_reproduction(&fixture, &manifest).expect_err("old schema must fail closed");

        assert!(error.to_string().contains("identity does not match"));
    }

    #[test]
    fn reproduction_manifest_rejects_wrong_digest_semantics() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        let source = manifest
            .primary_artifacts
            .iter_mut()
            .find(|item| item.role == DomainStudyReproductionArtifactRole::SourceTree)
            .expect("source tree entry");
        source.digest_kind = DomainStudyReproductionDigestKind::RawFileSha256;

        let error = validate_reproduction(&fixture, &manifest)
            .expect_err("source tree cannot be interpreted as a raw file");

        assert!(error
            .to_string()
            .contains("does not match its bound chain digest"));
    }

    #[test]
    fn reproduction_manifest_rejects_hidden_multifile_canonical_artifact() {
        let fixture = fixture();
        let mut manifest = reproduction_manifest(&fixture);
        manifest.primary_artifacts[0].covered_file_count = 2;
        manifest.file_count += 1;

        let error = validate_reproduction(&fixture, &manifest)
            .expect_err("canonical JSON must identify exactly one file");

        assert!(error
            .to_string()
            .contains("does not match its bound chain digest"));
    }

    #[test]
    fn reproduction_file_identity_hashes_exact_nonempty_bytes() {
        let identity = crate::domain_study_reproduction_file_identity(b"exact bytes")
            .expect("bounded file identity");

        assert_eq!(identity.sha256, hex(&Sha256::digest(b"exact bytes")));
        assert_eq!(identity.byte_length, 11);
        assert!(crate::domain_study_reproduction_file_identity(b"").is_err());
    }

    #[test]
    fn reproduction_artifact_role_wire_values_are_stable() {
        use DomainStudyReproductionArtifactRole as Role;

        let cases = [
            (Role::Preregistration, "preregistration"),
            (Role::PolicyEvidence, "policy_evidence"),
            (Role::BuildProvenance, "build_provenance"),
            (Role::TrustPolicy, "trust_policy"),
            (Role::SourceTree, "source_tree"),
            (Role::CargoLock, "cargo_lock"),
            (Role::RustToolchain, "rust_toolchain"),
            (Role::EvaluatedBinary, "evaluated_binary"),
            (Role::Corpus, "corpus"),
            (Role::KnownSeedRegistry, "known_seed_registry"),
            (Role::InclusionCriteria, "inclusion_criteria"),
            (Role::ExclusionCriteria, "exclusion_criteria"),
            (Role::LabelOntology, "label_ontology"),
            (Role::SafeBoundaryDefinition, "safe_boundary_definition"),
            (Role::SplitManifest, "split_manifest"),
            (
                Role::AttackConstructionManifest,
                "attack_construction_manifest",
            ),
            (Role::AgreementBootstrapSeed, "agreement_bootstrap_seed"),
            (Role::ReviewPacket, "review_packet"),
            (Role::ReviewerAssignment, "reviewer_assignment"),
            (Role::ReviewerDecisionBundle, "reviewer_decision_bundle"),
            (Role::ReviewCoverageManifest, "review_coverage_manifest"),
            (
                Role::AgreementAnalysisArtifact,
                "agreement_analysis_artifact",
            ),
            (Role::AdjudicationManifest, "adjudication_manifest"),
            (
                Role::AdjudicationDecisionBundle,
                "adjudication_decision_bundle",
            ),
            (Role::PredictionBundle, "prediction_bundle"),
            (Role::AnalysisEnvironment, "analysis_environment"),
            (Role::ExclusionManifest, "exclusion_manifest"),
            (
                Role::ProtocolDeviationManifest,
                "protocol_deviation_manifest",
            ),
            (Role::ExploratoryResults, "exploratory_results"),
            (Role::ResultEvidenceBundle, "result_evidence_bundle"),
        ];

        for (role, expected) in cases {
            assert_eq!(
                serde_json::to_string(&role).expect("serialize role"),
                format!("\"{expected}\"")
            );
        }
    }

    #[test]
    fn complete_external_chain_is_only_an_independent_evidence_candidate() {
        let fixture = fixture();
        let report = validate(&fixture).expect("valid result evidence");

        assert_eq!(
            report.evidence_status,
            DomainStudyEvidenceStatus::IndependentEvidenceCandidate
        );
        assert_eq!(
            report.outcome_status,
            DomainStudyOutcomeStatus::ThresholdsMet
        );
        assert_eq!(report.total_case_count, 120);
        assert_eq!(report.review_coverage.fully_reviewed_case_count, 120);
        assert_eq!(report.per_attack_family.len(), 3);
        assert!(!report.temporal_runtime_enabled);
        assert!(!report.action_execution_configured);
        assert!(report
            .macro_f1_conservative_95_lower
            .is_some_and(|value| value >= 0.8));
        assert_eq!(
            report.inter_rater_agreement_uncertainty_method,
            DomainStudyAgreementUncertaintyMethod::CaseBootstrapBca95
        );
        assert_eq!(
            report.trust_policy_canonical_sha256,
            canonical_sha256(&fixture.trust).expect("trust policy digest")
        );
    }

    #[test]
    fn tampered_reviewer_signature_is_rejected() {
        let mut fixture = fixture();
        fixture.evidence.reviewer_receipts[0]
            .receipt
            .signature
            .signature_hex
            .replace_range(0..2, "00");

        let error = validate(&fixture).expect_err("tampered signature must fail");

        assert!(error.to_string().contains("signature verification failed"));
    }

    #[test]
    fn identical_independent_decision_bundles_are_admissible() {
        let mut fixture = fixture();
        let preregistration: DomainStudyPreregistration =
            serde_json::from_str(&fixture.preregistration_json).expect("preregistration");
        let binding = binding(&fixture);
        let shared_decision_sha256 = fixture.evidence.reviewer_receipts[0]
            .receipt
            .claims
            .decision_bundle_sha256
            .clone();
        let reviewer = &mut fixture.evidence.reviewer_receipts[1];
        reviewer.receipt.claims.decision_bundle_sha256 = shared_decision_sha256;
        reviewer.receipt.signature = signature(
            REVIEWER_RECEIPT_DOMAIN,
            &reviewer.receipt.claims,
            "reviewer_beta",
            &fixture.keys.reviewer_b,
        );
        reviewer.trusted_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::ReviewerReceipt,
            canonical_sha256(&reviewer.receipt).expect("reviewer digest"),
            REGISTERED_AT_MS + 21_500,
            &fixture.keys,
        );
        let preregistration_attestation_sha256 =
            canonical_sha256(&fixture.evidence.preregistration_attestation)
                .expect("attestation digest");
        let preregistration_time = validate_timestamp_receipt(
            &fixture.evidence.preregistration_timestamp,
            DomainStudyTimestampSubjectKind::PreregistrationAttestation,
            &preregistration_attestation_sha256,
            &fixture.trust,
        )
        .expect("trusted preregistration time");

        validate_reviewer_receipts(
            &fixture.evidence.reviewer_receipts,
            &preregistration,
            &binding.preregistration_canonical_sha256,
            preregistration_time,
            &fixture.trust,
        )
        .expect("identical decisions from distinct signers are valid");
    }

    #[test]
    fn overlapping_preregistration_and_review_time_is_rejected() {
        let mut fixture = fixture();
        let receipt = &fixture.evidence.reviewer_receipts[0].receipt;
        fixture.evidence.reviewer_receipts[0].trusted_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::ReviewerReceipt,
            canonical_sha256(receipt).expect("reviewer digest"),
            REGISTERED_AT_MS + 9_999,
            &fixture.keys,
        );

        let error = validate(&fixture).expect_err("overlapping trusted intervals must fail");

        assert!(error.to_string().contains("follow preregistration"));
    }

    #[test]
    fn point_estimate_without_conservative_false_positive_bound_does_not_pass() {
        let mut fixture = fixture();
        fixture
            .evidence
            .result
            .metrics
            .evaluated_safe_boundary_case_count = 20;
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::ThresholdsNotMet,
        );

        let report = validate(&fixture).expect("valid negative result evidence");

        assert_eq!(
            report.evidence_status,
            DomainStudyEvidenceStatus::ThresholdsNotMet
        );
        assert_eq!(
            report.outcome_status,
            DomainStudyOutcomeStatus::ThresholdsNotMet
        );
        assert!(report
            .safe_boundary_false_positive_wilson_95_upper
            .is_some_and(|value| value > 0.05));
    }

    #[test]
    fn excluded_fixed_case_keeps_independent_result_incomplete() {
        let mut fixture = fixture();
        fixture.evidence.result.metrics.analyzed_case_count = 119;
        fixture.evidence.result.metrics.excluded_case_count = 1;
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::Incomplete,
        );

        let report = validate(&fixture).expect("valid incomplete result evidence");

        assert_eq!(
            report.evidence_status,
            DomainStudyEvidenceStatus::Incomplete
        );
        assert_eq!(report.outcome_status, DomainStudyOutcomeStatus::Incomplete);
        assert_eq!(report.excluded_case_count, 1);
    }

    #[test]
    fn manifest_cannot_upgrade_a_negative_result() {
        let mut fixture = fixture();
        fixture
            .evidence
            .result
            .metrics
            .evaluated_safe_boundary_case_count = 20;
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::IndependentEvidenceCandidate,
        );

        let error = validate(&fixture).expect_err("manifest status escalation must fail");

        assert!(error.to_string().contains("recomputed evidence chain"));
    }

    #[test]
    fn trust_policy_rejects_repeated_affiliation_commitments() {
        let mut fixture = fixture();
        fixture.trust.reviewers[1].affiliation_commitment_sha256 = SHA_B.to_string();

        let error = validate(&fixture).expect_err("same affiliation must fail");

        assert!(error.to_string().contains("independent"));
    }

    #[test]
    fn private_coverage_matrix_cannot_hide_a_missing_review() {
        let mut fixture = fixture();
        fixture.evidence.review_coverage[0].reviewer_indices.pop();

        let error = validate(&fixture).expect_err("coverage substitution must fail");

        assert!(error.to_string().contains("coverage"));
    }

    #[test]
    fn private_coverage_matrix_rejects_duplicate_reviewer_indices() {
        let mut fixture = fixture();
        fixture.evidence.review_coverage[0].reviewer_indices = vec![0, 0];

        let error = validate(&fixture).expect_err("duplicate reviewer assignment must fail");

        assert!(error.to_string().contains("coverage rows"));
    }

    #[test]
    fn signed_assignment_digest_is_connected_to_private_coverage() {
        let mut fixture = fixture();
        fixture.evidence.reviewer_assignments[0].blind_case_token_sha256[0] = SHA_A.to_string();
        fixture.evidence.reviewer_assignments[0]
            .blind_case_token_sha256
            .sort();

        let error = validate(&fixture).expect_err("assignment substitution must fail");

        assert!(error.to_string().contains("signed receipt"));
    }

    #[test]
    fn signed_adjudication_manifest_is_connected_to_private_coverage() {
        let mut fixture = fixture();
        fixture.evidence.review_coverage[0].adjudicated = false;

        let error = validate(&fixture).expect_err("adjudication substitution must fail");

        assert!(error.to_string().contains("adjudication manifest"));
    }

    #[test]
    fn pooled_attack_total_cannot_hide_an_undercovered_family() {
        let mut fixture = fixture();
        fixture.evidence.result.metrics.per_attack_family[0].evaluated_variant_count = 19;
        fixture.evidence.result.metrics.per_attack_family[0].consistent_variant_count = 19;
        fixture.evidence.result.metrics.per_attack_family[1].evaluated_variant_count = 21;
        fixture.evidence.result.metrics.per_attack_family[1].consistent_variant_count = 21;
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::Incomplete,
        );

        let report = validate(&fixture).expect("undercovered family is valid incomplete evidence");

        assert_eq!(
            report.evidence_status,
            DomainStudyEvidenceStatus::Incomplete
        );
    }

    #[test]
    fn pooled_attack_rate_cannot_hide_a_weak_family() {
        let mut fixture = fixture();
        fixture
            .evidence
            .result
            .metrics
            .consistent_attack_variant_count = 55;
        fixture.evidence.result.metrics.per_attack_family[0].consistent_variant_count = 15;
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::ThresholdsNotMet,
        );

        let report = validate(&fixture).expect("weak family is valid negative evidence");

        assert_eq!(
            report.evidence_status,
            DomainStudyEvidenceStatus::ThresholdsNotMet
        );
        assert!(report.per_attack_family[0]
            .consistency_wilson_95_lower
            .is_some_and(|value| value < 0.8));
        assert!(report
            .attack_variant_consistency_wilson_95_lower
            .is_some_and(|value| value >= 0.8));
    }

    #[test]
    fn undefined_agreement_is_preserved_as_incomplete_not_fabricated() {
        let mut fixture = fixture();
        fixture.evidence.result.review_agreement_analysis.agreement = None;
        fixture
            .evidence
            .result
            .review_agreement_analysis
            .agreement_95_lower = None;
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::Incomplete,
        );

        let report = validate(&fixture).expect("undefined agreement is valid incomplete evidence");

        assert_eq!(
            report.evidence_status,
            DomainStudyEvidenceStatus::Incomplete
        );
        assert_eq!(report.inter_rater_agreement, None);
        assert_eq!(report.inter_rater_agreement_95_lower, None);
    }

    #[test]
    fn agreement_point_estimate_cannot_hide_a_low_uncertainty_bound() {
        let mut fixture = fixture();
        fixture
            .evidence
            .result
            .review_agreement_analysis
            .agreement_95_lower = Some(0.79);
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::ThresholdsNotMet,
        );

        let report = validate(&fixture).expect("low agreement bound is valid negative evidence");

        assert_eq!(
            report.evidence_status,
            DomainStudyEvidenceStatus::ThresholdsNotMet
        );
    }

    #[test]
    fn agreement_procedure_cannot_drift_from_preregistration() {
        let mut fixture = fixture();
        fixture
            .evidence
            .result
            .review_agreement_analysis
            .bootstrap_resamples += 1;
        let binding = binding(&fixture);
        finalize_manifest(
            &mut fixture.evidence,
            &binding,
            &fixture.keys,
            DomainStudyEvidenceStatus::IndependentEvidenceCandidate,
        );

        let error = validate(&fixture).expect_err("post-hoc agreement procedure must fail");

        assert!(error.to_string().contains("frozen procedure"));
    }

    #[test]
    fn adjudication_start_must_provably_follow_agreement_analysis() {
        let mut fixture = fixture();
        fixture
            .evidence
            .adjudication_start_authorization
            .claims
            .authorized_at_ms = REGISTERED_AT_MS + 24_000;
        fixture.evidence.adjudication_start_authorization.signature = signature(
            ADJUDICATION_START_DOMAIN,
            &fixture.evidence.adjudication_start_authorization.claims,
            "independent_adjudicator",
            &fixture.keys.adjudicator,
        );
        fixture.evidence.adjudication_start_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::AdjudicationStartAuthorization,
            canonical_sha256(&fixture.evidence.adjudication_start_authorization)
                .expect("adjudication start digest"),
            REGISTERED_AT_MS + 24_500,
            &fixture.keys,
        );

        let error = validate(&fixture).expect_err("early adjudication start must fail");

        assert!(error.to_string().contains("adjudication start"));
    }

    #[test]
    fn different_key_ids_cannot_reuse_one_ed25519_key() {
        let mut fixture = fixture();
        fixture.trust.reviewers[0].key.public_key_hex =
            fixture.trust.preregistration_signer.public_key_hex.clone();

        let error = validate(&fixture).expect_err("cross-role key reuse must fail");

        assert!(error.to_string().contains("independent"));
    }

    #[test]
    fn unknown_nested_result_field_is_rejected() {
        let fixture = fixture();
        let mut value = serde_json::to_value(&fixture.evidence).expect("evidence value");
        value["result"]["metrics"]["claimed_pass"] = serde_json::Value::Bool(true);

        let error = validate_domain_study_result_evidence(
            &fixture.preregistration_json,
            &value.to_string(),
            &fixture.policy,
            &fixture.build,
            &[],
            &fixture.trust,
        )
        .expect_err("unknown nested field must fail");

        assert!(matches!(error, DomainStudyResultError::InvalidJson(_)));
    }

    #[test]
    fn oversized_preregistration_is_rejected_before_deserialization() {
        let fixture = fixture();
        let oversized = " ".repeat(MAX_PREREGISTRATION_JSON_BYTES + 1);

        let error = validate_domain_study_result_evidence(
            &oversized,
            "{}",
            &fixture.policy,
            &fixture.build,
            &[],
            &fixture.trust,
        )
        .expect_err("oversized preregistration must fail");

        assert!(error.to_string().contains("2 MiB"));
    }

    #[test]
    fn aggregate_count_overflow_is_rejected() {
        let mut fixture = fixture();
        fixture.evidence.result.metrics.analyzed_case_count = usize::MAX;
        fixture.evidence.result.metrics.excluded_case_count = 1;

        let error = validate(&fixture).expect_err("overflowing aggregate counts must fail");

        assert!(error.to_string().contains("overflows"));
    }

    #[test]
    fn trusted_timestamp_interval_overflow_is_rejected() {
        let mut fixture = fixture();
        let subject_sha256 = fixture
            .evidence
            .final_manifest_timestamp
            .claims
            .subject_canonical_sha256
            .clone();
        fixture.evidence.final_manifest_timestamp = timestamp(
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            subject_sha256,
            u64::MAX,
            &fixture.keys,
        );

        let error = validate(&fixture).expect_err("overflowing trusted interval must fail");

        assert!(error.to_string().contains("overflows"));
    }

    #[test]
    fn trusted_timestamp_interval_underflow_is_rejected() {
        let fixture = fixture();
        let mut receipt = timestamp(
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            SHA_A.to_string(),
            1,
            &fixture.keys,
        );
        receipt.claims.accuracy_micros = 2_000;
        receipt.signature = signature(
            TRUSTED_TIMESTAMP_DOMAIN,
            &receipt.claims,
            "timestamp_verifier",
            &fixture.keys.timestamp,
        );

        let error = validate_timestamp_receipt(
            &receipt,
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            SHA_A,
            &fixture.trust,
        )
        .expect_err("underflowing trusted interval must fail");

        assert!(error.to_string().contains("underflows"));
    }

    #[test]
    fn trusted_timestamp_fractional_gen_time_rounds_outward() {
        let fixture = fixture();
        let mut receipt = timestamp(
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            SHA_A.to_string(),
            1_780_000_000_000,
            &fixture.keys,
        );
        receipt.claims.gen_time_submillisecond_micros = 999;
        receipt.signature = signature(
            TRUSTED_TIMESTAMP_DOMAIN,
            &receipt.claims,
            "timestamp_verifier",
            &fixture.keys.timestamp,
        );

        let interval = validate_timestamp_receipt(
            &receipt,
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            SHA_A,
            &fixture.trust,
        )
        .expect("fractional timestamp must remain representable");

        assert_eq!(interval.earliest_ms, 1_779_999_999_999);
        assert_eq!(interval.latest_ms, 1_780_000_000_002);
    }

    #[test]
    fn trusted_timestamp_invalid_fractional_remainder_is_rejected() {
        let fixture = fixture();
        let mut receipt = timestamp(
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            SHA_A.to_string(),
            1_780_000_000_000,
            &fixture.keys,
        );
        receipt.claims.gen_time_submillisecond_micros = 1_000;
        receipt.signature = signature(
            TRUSTED_TIMESTAMP_DOMAIN,
            &receipt.claims,
            "timestamp_verifier",
            &fixture.keys.timestamp,
        );

        let error = validate_timestamp_receipt(
            &receipt,
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            SHA_A,
            &fixture.trust,
        )
        .expect_err("invalid fractional remainder must fail");

        assert!(error.to_string().contains("malformed"));
    }

    #[test]
    fn trusted_timestamp_signing_payload_is_cross_language_stable() {
        let claims = DomainStudyTrustedTimestampClaims {
            schema_version: DOMAIN_STUDY_TRUSTED_TIMESTAMP_SCHEMA_VERSION.to_string(),
            subject_kind: DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            subject_canonical_sha256: SHA_A.to_string(),
            protocol: DomainStudyTimestampProtocol::Rfc3161TrustedChain,
            issued_at_ms: 1_780_000_000_000,
            gen_time_submillisecond_micros: 999,
            accuracy_micros: 1_000,
            request_sha256: SHA_B.to_string(),
            response_sha256: SHA_C.to_string(),
            certificate_chain_sha256: SHA_D.to_string(),
            revocation_evidence_sha256: SHA_A.to_string(),
            tsa_spki_sha256: SHA_B.to_string(),
            tsa_policy_oid: "1.3.6.1.4.1.57264.1".to_string(),
        };

        let payload = domain_study_trusted_timestamp_signing_payload(&claims, "timestamp_verifier")
            .expect("timestamp signing payload");
        let expected = concat!(
            "aura.domain.trusted-timestamp.v1\0",
            r#"{"key_id":"timestamp_verifier","claims":{"schema_version":"aura.domain.trusted_timestamp_verification.v2","subject_kind":"final_evidence_manifest","subject_canonical_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","protocol":"rfc3161_trusted_chain","issued_at_ms":1780000000000,"gen_time_submillisecond_micros":999,"accuracy_micros":1000,"request_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","response_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","certificate_chain_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","revocation_evidence_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tsa_spki_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tsa_policy_oid":"1.3.6.1.4.1.57264.1"}}"#,
        );

        assert_eq!(payload, expected.as_bytes());
    }

    #[test]
    fn every_timestamp_subject_kind_has_stable_snake_case_wire_value() {
        let cases = [
            (
                DomainStudyTimestampSubjectKind::PreregistrationAttestation,
                "\"preregistration_attestation\"",
            ),
            (
                DomainStudyTimestampSubjectKind::ReviewerReceipt,
                "\"reviewer_receipt\"",
            ),
            (
                DomainStudyTimestampSubjectKind::ReviewerAgreementAnalysis,
                "\"reviewer_agreement_analysis\"",
            ),
            (
                DomainStudyTimestampSubjectKind::AdjudicationStartAuthorization,
                "\"adjudication_start_authorization\"",
            ),
            (
                DomainStudyTimestampSubjectKind::AdjudicationReceipt,
                "\"adjudication_receipt\"",
            ),
            (
                DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
                "\"final_evidence_manifest\"",
            ),
        ];

        for (kind, expected) in cases {
            assert_eq!(
                serde_json::to_string(&kind).expect("serialize kind"),
                expected
            );
        }
    }

    #[test]
    fn python_openssl_timestamp_signature_verifies_with_dalek() {
        let claims = DomainStudyTrustedTimestampClaims {
            schema_version: DOMAIN_STUDY_TRUSTED_TIMESTAMP_SCHEMA_VERSION.to_string(),
            subject_kind: DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            subject_canonical_sha256: SHA_A.to_string(),
            protocol: DomainStudyTimestampProtocol::Rfc3161TrustedChain,
            issued_at_ms: 1_780_000_000_000,
            gen_time_submillisecond_micros: 999,
            accuracy_micros: 1_000,
            request_sha256: SHA_B.to_string(),
            response_sha256: SHA_C.to_string(),
            certificate_chain_sha256: SHA_D.to_string(),
            revocation_evidence_sha256: SHA_A.to_string(),
            tsa_spki_sha256: SHA_B.to_string(),
            tsa_policy_oid: "1.3.6.1.4.1.57264.1".to_string(),
        };
        let receipt = DomainStudyTrustedTimestampReceipt {
            claims,
            signature: DomainStudyDetachedSignature {
                key_id: "timestamp_verifier".to_string(),
                signature_hex: concat!(
                    "a09b19f78bceb5a0ab643bf1eeb339ad9efe9fecc2fdda98ecdc25c279a60141",
                    "35868bb7ac18ea249f029613bdcf7ab878e690ab77cbe6170ed53d33fd19800e"
                )
                .to_string(),
            },
        };
        let trust = DomainStudyTrustPolicy {
            timestamp_verifier: DomainStudyTrustedKey {
                key_id: "timestamp_verifier".to_string(),
                public_key_hex: concat!(
                    "d75a980182b10ab7d54bfed3c964073a",
                    "0ee172f3daa62325af021a68f707511a"
                )
                .to_string(),
            },
            trusted_tsa_spki_sha256: SHA_B.to_string(),
            ..fixture().trust
        };

        validate_timestamp_receipt(
            &receipt,
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            SHA_A,
            &trust,
        )
        .expect("Python/OpenSSL Ed25519 receipt must verify in Rust/dalek");
    }

    #[test]
    fn timestamp_subject_bytes_match_the_result_chain_digest() {
        let fixture = fixture();
        let subject = &fixture.evidence.preregistration_attestation;
        let canonical_json =
            domain_study_result_canonical_json(subject).expect("canonical subject JSON");

        assert!(!canonical_json.ends_with(b"\n"));
        assert_eq!(
            hex(&Sha256::digest(&canonical_json)),
            domain_study_result_canonical_sha256(subject).expect("canonical subject digest")
        );
    }

    #[test]
    fn timestamp_receipt_requires_certificate_chain_digest() {
        let mut fixture = fixture();
        fixture
            .evidence
            .preregistration_timestamp
            .claims
            .certificate_chain_sha256 = "missing".to_string();

        let error = validate(&fixture).expect_err("missing chain digest must fail");

        assert!(error.to_string().contains("timestamp receipt"));
    }

    #[test]
    fn engineering_maturity_does_not_erase_negative_outcome() {
        let outcome = outcome_status(true, false);

        assert_eq!(outcome, DomainStudyOutcomeStatus::ThresholdsNotMet);
        assert_eq!(
            evidence_status(DomainStudyCorpusClass::CuratedInternal, outcome),
            DomainStudyEvidenceStatus::EngineeringOnly
        );
    }

    #[test]
    fn oid_with_large_second_arc_under_arc_two_is_valid() {
        assert!(safe_oid("2.999.3"));
        assert!(!safe_oid("1.40.3"));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn aggregate_sha256(domain: &[u8], digests: &[&str]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(
            u32::try_from(digests.len())
                .expect("aggregate count")
                .to_be_bytes(),
        );
        for digest in digests {
            hasher.update(decode_hex_array::<32>(digest).expect("aggregate member digest"));
        }
        hex(&hasher.finalize())
    }
}
