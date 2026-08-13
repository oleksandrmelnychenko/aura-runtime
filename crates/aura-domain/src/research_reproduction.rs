//! Private materialization contract for independent study reproduction.
//!
//! The contract proves that a bounded, content-addressed file inventory is
//! consistent with an already validated result-evidence chain. It deliberately
//! does not claim that an independent party reran the analysis or reproduced
//! its outcome.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    domain_study_result_canonical_sha256, is_canonical_sha256,
    validate_domain_study_result_evidence, DomainModuleEvidence, DomainStudyBuildProvenance,
    DomainStudyEvidenceStatus, DomainStudyOutcomeStatus, DomainStudyPreregistration,
    DomainStudyResultError, DomainStudyResultEvidenceBundle, DomainStudyTimestampSubjectKind,
    DomainStudyTrustPolicy, DomainStudyTrustedTimestampReceipt,
};

/// Supported schema for a private reproduction-package manifest.
pub const DOMAIN_STUDY_REPRODUCTION_MANIFEST_SCHEMA_VERSION: &str =
    "aura.domain.independent_reproduction_package.v1";

const MAX_PREREGISTRATION_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVIDENCE_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_REPRODUCTION_MANIFEST_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_PRIMARY_ARTIFACT_COUNT: usize = 40;
const MAX_TIMESTAMP_MATERIAL_COUNT: usize = 10;
const MIN_TIMESTAMP_CHAIN_CERTIFICATES: usize = 2;
const MAX_TIMESTAMP_CHAIN_CERTIFICATES: usize = 7;
const MAX_TIMESTAMP_REVOCATION_CRLS: usize = 6;
const MAX_REPRODUCTION_FILE_COUNT: u32 = 100_000;
const MAX_REPRODUCTION_FILE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_REPRODUCTION_PACKAGE_BYTES: u64 = 4 * MAX_REPRODUCTION_FILE_BYTES;
const CERTIFICATE_CHAIN_DOMAIN: &[u8] = b"aura.domain.rfc3161-certificate-chain.v1\0";
const REVOCATION_EVIDENCE_DOMAIN: &[u8] = b"aura.domain.rfc3161-revocation-evidence.v1\0";

/// Error returned when a reproduction manifest is malformed or inconsistent.
#[derive(Debug, Error)]
pub enum DomainStudyReproductionError {
    /// The bound result-evidence chain failed validation.
    #[error("invalid bound domain-study result evidence: {0}")]
    InvalidResult(#[from] DomainStudyResultError),
    /// A supplied JSON document does not match its strict schema.
    #[error("invalid domain-study reproduction JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A package identity, ordering, bound, or cross-link failed.
    #[error("invalid domain-study reproduction manifest: {0}")]
    InvalidManifest(String),
}

/// Primary private file role bound by the result and preregistration chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyReproductionArtifactRole {
    /// Exact canonical preregistration document.
    Preregistration,
    /// Exact canonical policy-evidence document.
    PolicyEvidence,
    /// Exact canonical build-provenance document.
    BuildProvenance,
    /// Exact canonical trust-policy document used by the verifier.
    TrustPolicy,
    /// Deterministic evaluated source-tree artifact.
    SourceTree,
    /// Exact Cargo.lock used for the evaluated build.
    CargoLock,
    /// Exact pinned Rust toolchain descriptor.
    RustToolchain,
    /// Exact evaluated executable or linked library.
    EvaluatedBinary,
    /// Exact fixed corpus bytes.
    Corpus,
    /// Complete repository and caller-supplied known-seed registry.
    KnownSeedRegistry,
    /// Frozen inclusion criteria.
    InclusionCriteria,
    /// Frozen exclusion criteria.
    ExclusionCriteria,
    /// Frozen threat-label ontology and decision rules.
    LabelOntology,
    /// Frozen safe-boundary definition.
    SafeBoundaryDefinition,
    /// Immutable case-to-split assignments.
    SplitManifest,
    /// Frozen attack-variation construction manifest.
    AttackConstructionManifest,
    /// Fixed bootstrap seed material for agreement analysis.
    AgreementBootstrapSeed,
    /// Exact blinded packet supplied to reviewers.
    ReviewPacket,
    /// One frozen reviewer assignment; ordinal is the reviewer index.
    ReviewerAssignment,
    /// One frozen reviewer decision bundle; ordinal is the reviewer index.
    ReviewerDecisionBundle,
    /// Private case-to-reviewer completion matrix.
    ReviewCoverageManifest,
    /// Governed reviewer-agreement analysis output.
    AgreementAnalysisArtifact,
    /// Frozen private adjudication manifest.
    AdjudicationManifest,
    /// Complete private adjudication decisions.
    AdjudicationDecisionBundle,
    /// Frozen model prediction output bundle.
    PredictionBundle,
    /// Exact analysis implementation and environment lock.
    AnalysisEnvironment,
    /// Complete exclusions manifest, including an empty manifest.
    ExclusionManifest,
    /// Complete protocol-deviation manifest.
    ProtocolDeviationManifest,
    /// Optional exploratory output, isolated from confirmatory results.
    ExploratoryResults,
    /// Exact canonical private result-evidence bundle validated by the core.
    ResultEvidenceBundle,
}

/// Hash interpretation required for one primary artifact role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyReproductionDigestKind {
    /// SHA-256 over one exact retained file.
    RawFileSha256,
    /// SHA-256 over one exact compact typed JSON document.
    CanonicalJsonSha256,
    /// Domain-separated `aura.build-source-tree.v2` Git-tree digest.
    BuildSourceTreeV2,
}

/// Content identity of one file retained in the private package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReproductionFileIdentity {
    /// Lowercase SHA-256 of the exact file bytes.
    pub sha256: String,
    /// Exact nonzero file size in bytes.
    pub byte_length: u64,
}

/// One primary content-addressed study artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReproductionArtifact {
    /// Governed semantic role.
    pub role: DomainStudyReproductionArtifactRole,
    /// Zero for singleton roles; reviewer index for reviewer-specific roles.
    pub ordinal: u16,
    /// Exact hashing contract for this role.
    pub digest_kind: DomainStudyReproductionDigestKind,
    /// Number of regular/link/missing source entries covered by this identity.
    pub covered_file_count: u32,
    /// Exact retained-file identity.
    #[serde(flatten)]
    pub file: DomainStudyReproductionFileIdentity,
}

/// Original material required to independently recheck one RFC 3161 receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReproductionTimestampMaterial {
    /// Covered signed artifact kind.
    pub subject_kind: DomainStudyTimestampSubjectKind,
    /// Reviewer index only for `reviewer_receipt`; otherwise absent.
    pub reviewer_index: Option<u16>,
    /// Original nonce-bearing DER timestamp request.
    pub request: DomainStudyReproductionFileIdentity,
    /// Original DER timestamp response.
    pub response: DomainStudyReproductionFileIdentity,
    /// Exact selected DER chain, ordered TSA signer to trust anchor.
    pub certificate_chain_der: Vec<DomainStudyReproductionFileIdentity>,
    /// Exact complete CRL DER set, sorted by SHA-256.
    pub revocation_crl_der: Vec<DomainStudyReproductionFileIdentity>,
}

/// Private, path-free materialization manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyReproductionManifest {
    /// Schema identity.
    pub schema_version: String,
    /// Stable study identity.
    pub study_id: String,
    /// Stable result identity.
    pub result_id: String,
    /// Canonical preregistration digest returned by the core validator.
    pub preregistration_canonical_sha256: String,
    /// Canonical aggregate-result digest returned by the core validator.
    pub result_bundle_sha256: String,
    /// Canonical signed final-manifest digest returned by the core validator.
    pub final_manifest_sha256: String,
    /// Canonical digest of the complete private result-evidence bundle.
    pub evidence_bundle_canonical_sha256: String,
    /// Primary artifacts sorted by `(role, ordinal)`.
    pub primary_artifacts: Vec<DomainStudyReproductionArtifact>,
    /// Timestamp materials sorted by `(subject_kind, reviewer_index)`.
    pub timestamp_materials: Vec<DomainStudyReproductionTimestampMaterial>,
    /// Recomputed number of retained files represented by the manifest.
    pub file_count: u32,
    /// Recomputed total exact byte length of retained files.
    pub total_file_bytes: u64,
    /// Must remain false; the private package is not a public export.
    pub public_distribution_permitted: bool,
    /// Must remain false until an external procedure records a real rerun.
    pub independent_recomputation_completed: bool,
}

/// Maximum claim supported by this structural manifest validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyReproductionStatus {
    /// File identities are complete and consistent with the validated chain.
    ManifestConsistent,
}

/// Content-free result of validating a private reproduction manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyReproductionReport {
    /// Stable study identity.
    pub study_id: String,
    /// Stable result identity.
    pub result_id: String,
    /// Canonical reproduction-manifest digest.
    pub reproduction_manifest_canonical_sha256: String,
    /// Status bounded to structural consistency, not outcome reproduction.
    pub status: DomainStudyReproductionStatus,
    /// Evidence maturity recomputed by the underlying result validator.
    pub evidence_status: DomainStudyEvidenceStatus,
    /// Frozen-analysis outcome recomputed by the underlying result validator.
    pub outcome_status: DomainStudyOutcomeStatus,
    /// Number of exact retained files represented by the manifest.
    pub file_count: u32,
    /// Total exact byte length represented by the manifest.
    pub total_file_bytes: u64,
    /// Always false for this validator; a rerun requires a separate record.
    pub independent_recomputation_completed: bool,
    /// Always false; the validator does not authorize disclosure.
    pub public_distribution_permitted: bool,
}

/// Calculates the exact identity used for one already-bounded byte slice.
pub fn domain_study_reproduction_file_identity(
    bytes: &[u8],
) -> Result<DomainStudyReproductionFileIdentity, DomainStudyReproductionError> {
    let byte_length = u64::try_from(bytes.len())
        .map_err(|_| invalid_manifest_error("file length does not fit in u64"))?;
    if byte_length == 0 || byte_length > MAX_REPRODUCTION_FILE_BYTES {
        return invalid_manifest("file byte length is outside the supported bound");
    }
    Ok(DomainStudyReproductionFileIdentity {
        sha256: hex_digest(bytes),
        byte_length,
    })
}

/// Validates a path-free reproduction inventory against a trusted result chain.
///
/// The caller must calculate every file identity from the same immutable bytes
/// retained for independent access. Passing a self-declared digest inventory is
/// insufficient evidence that the files exist. A successful report proves only
/// manifest consistency; it never proves that an independent rerun occurred.
pub fn validate_domain_study_reproduction_manifest(
    preregistration_json: &str,
    evidence_json: &str,
    reproduction_manifest_json: &str,
    expected_policy_evidence: &DomainModuleEvidence,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    trust_policy: &DomainStudyTrustPolicy,
) -> Result<DomainStudyReproductionReport, DomainStudyReproductionError> {
    validate_json_bound(
        preregistration_json,
        MAX_PREREGISTRATION_JSON_BYTES,
        "preregistration",
    )?;
    validate_json_bound(evidence_json, MAX_EVIDENCE_JSON_BYTES, "result evidence")?;
    validate_json_bound(
        reproduction_manifest_json,
        MAX_REPRODUCTION_MANIFEST_JSON_BYTES,
        "reproduction manifest",
    )?;

    let result_report = validate_domain_study_result_evidence(
        preregistration_json,
        evidence_json,
        expected_policy_evidence,
        expected_build_provenance,
        additional_known_seed_sha256,
        trust_policy,
    )?;
    let preregistration: DomainStudyPreregistration = serde_json::from_str(preregistration_json)?;
    let evidence: DomainStudyResultEvidenceBundle = serde_json::from_str(evidence_json)?;
    let manifest: DomainStudyReproductionManifest =
        serde_json::from_str(reproduction_manifest_json)?;

    let evidence_bundle_canonical_sha256 = domain_study_result_canonical_sha256(&evidence)?;
    if manifest.schema_version != DOMAIN_STUDY_REPRODUCTION_MANIFEST_SCHEMA_VERSION
        || manifest.study_id != result_report.study_id
        || manifest.result_id != result_report.result_id
        || manifest.preregistration_canonical_sha256
            != result_report.preregistration_canonical_sha256
        || manifest.result_bundle_sha256 != result_report.result_bundle_sha256
        || manifest.final_manifest_sha256 != result_report.final_manifest_sha256
        || manifest.evidence_bundle_canonical_sha256 != evidence_bundle_canonical_sha256
    {
        return invalid_manifest("manifest identity does not match the validated evidence chain");
    }
    if manifest.public_distribution_permitted || manifest.independent_recomputation_completed {
        return invalid_manifest(
            "materialization manifest cannot authorize disclosure or claim a completed rerun",
        );
    }

    validate_primary_artifacts(&manifest.primary_artifacts, &preregistration, &evidence)?;
    validate_timestamp_materials(&manifest.timestamp_materials, &evidence)?;
    let (file_count, total_file_bytes) = manifest_totals(&manifest)?;
    if manifest.file_count != file_count || manifest.total_file_bytes != total_file_bytes {
        return invalid_manifest("manifest file totals are not exactly recomputed");
    }

    Ok(DomainStudyReproductionReport {
        study_id: result_report.study_id,
        result_id: result_report.result_id,
        reproduction_manifest_canonical_sha256: domain_study_result_canonical_sha256(&manifest)?,
        status: DomainStudyReproductionStatus::ManifestConsistent,
        evidence_status: result_report.evidence_status,
        outcome_status: result_report.outcome_status,
        file_count,
        total_file_bytes,
        independent_recomputation_completed: false,
        public_distribution_permitted: false,
    })
}

fn validate_primary_artifacts(
    artifacts: &[DomainStudyReproductionArtifact],
    preregistration: &DomainStudyPreregistration,
    evidence: &DomainStudyResultEvidenceBundle,
) -> Result<(), DomainStudyReproductionError> {
    if artifacts.is_empty() || artifacts.len() > MAX_PRIMARY_ARTIFACT_COUNT {
        return invalid_manifest("primary artifact count is outside the supported bound");
    }
    let expected = expected_primary_artifacts(preregistration, evidence)?;
    if artifacts.len() != expected.len() {
        return invalid_manifest("primary artifact inventory is incomplete or has extra roles");
    }
    let mut previous = None;
    for (artifact, (expected_role, expected_ordinal, expected_sha256)) in
        artifacts.iter().zip(expected.iter())
    {
        validate_file_identity(&artifact.file)?;
        let key = (artifact.role, artifact.ordinal);
        if previous.is_some_and(|value| value >= key) {
            return invalid_manifest("primary artifacts are not unique and strictly sorted");
        }
        previous = Some(key);
        let expected_digest_kind = primary_digest_kind(artifact.role);
        if key != (*expected_role, *expected_ordinal)
            || artifact.digest_kind != expected_digest_kind
            || artifact.file.sha256 != *expected_sha256
            || artifact.covered_file_count == 0
            || (artifact.digest_kind != DomainStudyReproductionDigestKind::BuildSourceTreeV2
                && artifact.covered_file_count != 1)
        {
            return invalid_manifest("primary artifact does not match its bound chain digest");
        }
    }
    Ok(())
}

fn expected_primary_artifacts(
    preregistration: &DomainStudyPreregistration,
    evidence: &DomainStudyResultEvidenceBundle,
) -> Result<Vec<(DomainStudyReproductionArtifactRole, u16, String)>, DomainStudyReproductionError> {
    use DomainStudyReproductionArtifactRole as Role;

    let result = &evidence.result;
    let mut expected = vec![
        (
            Role::Preregistration,
            0,
            result.preregistration_canonical_sha256.clone(),
        ),
        (
            Role::PolicyEvidence,
            0,
            result.policy_evidence_canonical_sha256.clone(),
        ),
        (
            Role::BuildProvenance,
            0,
            result.build_provenance_canonical_sha256.clone(),
        ),
        (
            Role::TrustPolicy,
            0,
            evidence
                .final_manifest
                .claims
                .trust_policy_canonical_sha256
                .clone(),
        ),
        (
            Role::SourceTree,
            0,
            preregistration.build_provenance.source_tree_sha256.clone(),
        ),
        (
            Role::CargoLock,
            0,
            preregistration.build_provenance.cargo_lock_sha256.clone(),
        ),
        (
            Role::RustToolchain,
            0,
            preregistration
                .build_provenance
                .rust_toolchain_sha256
                .clone(),
        ),
        (
            Role::EvaluatedBinary,
            0,
            preregistration.build_provenance.binary_sha256.clone(),
        ),
        (Role::Corpus, 0, result.corpus_sha256.clone()),
        (
            Role::KnownSeedRegistry,
            0,
            preregistration.dataset.known_seed_registry_sha256.clone(),
        ),
        (
            Role::InclusionCriteria,
            0,
            preregistration.dataset.inclusion_criteria_sha256.clone(),
        ),
        (
            Role::ExclusionCriteria,
            0,
            preregistration.dataset.exclusion_criteria_sha256.clone(),
        ),
        (
            Role::LabelOntology,
            0,
            preregistration.dataset.label_ontology_sha256.clone(),
        ),
        (
            Role::SafeBoundaryDefinition,
            0,
            preregistration
                .dataset
                .safe_boundary_definition_sha256
                .clone(),
        ),
        (Role::SplitManifest, 0, result.split_manifest_sha256.clone()),
        (
            Role::AttackConstructionManifest,
            0,
            preregistration.attacks.construction_manifest_sha256.clone(),
        ),
        (
            Role::AgreementBootstrapSeed,
            0,
            preregistration
                .analysis
                .inter_rater_agreement_bootstrap_seed_sha256
                .clone(),
        ),
        (Role::ReviewPacket, 0, result.review_packet_sha256.clone()),
        (
            Role::ReviewCoverageManifest,
            0,
            result.review_coverage_manifest_sha256.clone(),
        ),
        (
            Role::AgreementAnalysisArtifact,
            0,
            result
                .review_agreement_analysis
                .analysis_artifact_sha256
                .clone(),
        ),
        (
            Role::AdjudicationManifest,
            0,
            evidence
                .adjudication_receipt
                .claims
                .adjudication_bundle_sha256
                .clone(),
        ),
        (
            Role::AdjudicationDecisionBundle,
            0,
            evidence
                .adjudication_manifest
                .decision_bundle_sha256
                .clone(),
        ),
        (
            Role::PredictionBundle,
            0,
            result.prediction_bundle_sha256.clone(),
        ),
        (
            Role::AnalysisEnvironment,
            0,
            result.analysis_environment_sha256.clone(),
        ),
        (
            Role::ExclusionManifest,
            0,
            result.exclusion_manifest_sha256.clone(),
        ),
        (
            Role::ProtocolDeviationManifest,
            0,
            result.protocol_deviation_manifest_sha256.clone(),
        ),
    ];
    for (index, item) in evidence.reviewer_receipts.iter().enumerate() {
        let ordinal = u16::try_from(index)
            .map_err(|_| invalid_manifest_error("reviewer index exceeds u16"))?;
        expected.push((
            Role::ReviewerAssignment,
            ordinal,
            item.receipt.claims.assignment_manifest_sha256.clone(),
        ));
        expected.push((
            Role::ReviewerDecisionBundle,
            ordinal,
            item.receipt.claims.decision_bundle_sha256.clone(),
        ));
    }
    if let Some(exploratory) = &result.exploratory_results_sha256 {
        expected.push((Role::ExploratoryResults, 0, exploratory.clone()));
    }
    expected.push((
        Role::ResultEvidenceBundle,
        0,
        domain_study_result_canonical_sha256(evidence)?,
    ));
    expected.sort_by_key(|(role, ordinal, _)| (*role, *ordinal));
    Ok(expected)
}

fn validate_timestamp_materials(
    materials: &[DomainStudyReproductionTimestampMaterial],
    evidence: &DomainStudyResultEvidenceBundle,
) -> Result<(), DomainStudyReproductionError> {
    if materials.is_empty() || materials.len() > MAX_TIMESTAMP_MATERIAL_COUNT {
        return invalid_manifest("timestamp material count is outside the supported bound");
    }
    let expected = expected_timestamps(evidence)?;
    if materials.len() != expected.len() {
        return invalid_manifest("timestamp material inventory is incomplete or has extra groups");
    }
    let mut previous = None;
    for (material, (expected_kind, expected_index, receipt)) in materials.iter().zip(expected) {
        let key = (material.subject_kind, material.reviewer_index);
        if previous.is_some_and(|value| value >= key) {
            return invalid_manifest("timestamp materials are not unique and strictly sorted");
        }
        previous = Some(key);
        if key != (expected_kind, expected_index) {
            return invalid_manifest(
                "timestamp material subject does not match the evidence chain",
            );
        }
        validate_file_identity(&material.request)?;
        validate_file_identity(&material.response)?;
        if material.request.sha256 != receipt.claims.request_sha256
            || material.response.sha256 != receipt.claims.response_sha256
        {
            return invalid_manifest("timestamp request or response digest does not match receipt");
        }
        validate_timestamp_members(
            &material.certificate_chain_der,
            MIN_TIMESTAMP_CHAIN_CERTIFICATES,
            MAX_TIMESTAMP_CHAIN_CERTIFICATES,
            false,
            "certificate chain",
        )?;
        validate_timestamp_members(
            &material.revocation_crl_der,
            1,
            MAX_TIMESTAMP_REVOCATION_CRLS,
            true,
            "revocation evidence",
        )?;
        if material.revocation_crl_der.len() + 1 != material.certificate_chain_der.len() {
            return invalid_manifest(
                "timestamp CRL count does not cover every non-anchor chain certificate",
            );
        }
        let chain_sha256 = aggregate_digest(
            CERTIFICATE_CHAIN_DOMAIN,
            material
                .certificate_chain_der
                .iter()
                .map(|item| item.sha256.as_str()),
        )?;
        let revocation_sha256 = aggregate_digest(
            REVOCATION_EVIDENCE_DOMAIN,
            material
                .revocation_crl_der
                .iter()
                .map(|item| item.sha256.as_str()),
        )?;
        if chain_sha256 != receipt.claims.certificate_chain_sha256
            || revocation_sha256 != receipt.claims.revocation_evidence_sha256
        {
            return invalid_manifest(
                "timestamp certificate or revocation material does not match receipt",
            );
        }
    }
    Ok(())
}

fn primary_digest_kind(
    role: DomainStudyReproductionArtifactRole,
) -> DomainStudyReproductionDigestKind {
    use DomainStudyReproductionArtifactRole as Role;

    match role {
        Role::Preregistration
        | Role::PolicyEvidence
        | Role::BuildProvenance
        | Role::TrustPolicy
        | Role::KnownSeedRegistry
        | Role::ReviewerAssignment
        | Role::ReviewCoverageManifest
        | Role::AdjudicationManifest
        | Role::ResultEvidenceBundle => DomainStudyReproductionDigestKind::CanonicalJsonSha256,
        Role::SourceTree => DomainStudyReproductionDigestKind::BuildSourceTreeV2,
        Role::CargoLock
        | Role::RustToolchain
        | Role::EvaluatedBinary
        | Role::Corpus
        | Role::InclusionCriteria
        | Role::ExclusionCriteria
        | Role::LabelOntology
        | Role::SafeBoundaryDefinition
        | Role::SplitManifest
        | Role::AttackConstructionManifest
        | Role::AgreementBootstrapSeed
        | Role::ReviewPacket
        | Role::ReviewerDecisionBundle
        | Role::AgreementAnalysisArtifact
        | Role::AdjudicationDecisionBundle
        | Role::PredictionBundle
        | Role::AnalysisEnvironment
        | Role::ExclusionManifest
        | Role::ProtocolDeviationManifest
        | Role::ExploratoryResults => DomainStudyReproductionDigestKind::RawFileSha256,
    }
}

type ExpectedTimestamp<'a> = (
    DomainStudyTimestampSubjectKind,
    Option<u16>,
    &'a DomainStudyTrustedTimestampReceipt,
);

fn expected_timestamps(
    evidence: &DomainStudyResultEvidenceBundle,
) -> Result<Vec<ExpectedTimestamp<'_>>, DomainStudyReproductionError> {
    let mut expected = vec![(
        DomainStudyTimestampSubjectKind::PreregistrationAttestation,
        None,
        &evidence.preregistration_timestamp,
    )];
    for (index, item) in evidence.reviewer_receipts.iter().enumerate() {
        expected.push((
            DomainStudyTimestampSubjectKind::ReviewerReceipt,
            Some(
                u16::try_from(index)
                    .map_err(|_| invalid_manifest_error("reviewer index exceeds u16"))?,
            ),
            &item.trusted_timestamp,
        ));
    }
    expected.extend([
        (
            DomainStudyTimestampSubjectKind::ReviewerAgreementAnalysis,
            None,
            &evidence.review_agreement_analysis_timestamp,
        ),
        (
            DomainStudyTimestampSubjectKind::AdjudicationStartAuthorization,
            None,
            &evidence.adjudication_start_timestamp,
        ),
        (
            DomainStudyTimestampSubjectKind::AdjudicationReceipt,
            None,
            &evidence.adjudication_timestamp,
        ),
        (
            DomainStudyTimestampSubjectKind::FinalEvidenceManifest,
            None,
            &evidence.final_manifest_timestamp,
        ),
    ]);
    Ok(expected)
}

fn validate_timestamp_members(
    members: &[DomainStudyReproductionFileIdentity],
    minimum: usize,
    maximum: usize,
    require_sorted: bool,
    label: &str,
) -> Result<(), DomainStudyReproductionError> {
    if !(minimum..=maximum).contains(&members.len()) {
        return invalid_manifest(format!(
            "timestamp {label} count is outside the supported bound"
        ));
    }
    let mut seen = HashSet::with_capacity(members.len());
    let mut previous = None;
    for member in members {
        validate_file_identity(member)?;
        if !seen.insert(member.sha256.as_str())
            || (require_sorted
                && previous.is_some_and(|value: &str| value >= member.sha256.as_str()))
        {
            return invalid_manifest(format!("timestamp {label} is duplicated or not sorted"));
        }
        previous = Some(member.sha256.as_str());
    }
    Ok(())
}

fn manifest_totals(
    manifest: &DomainStudyReproductionManifest,
) -> Result<(u32, u64), DomainStudyReproductionError> {
    let mut count = 0_u32;
    let mut total = 0_u64;
    for artifact in &manifest.primary_artifacts {
        validate_file_identity(&artifact.file)?;
        count = count
            .checked_add(artifact.covered_file_count)
            .ok_or_else(|| invalid_manifest_error("manifest file count overflow"))?;
        total = total
            .checked_add(artifact.file.byte_length)
            .ok_or_else(|| invalid_manifest_error("manifest byte total overflow"))?;
    }
    for file in manifest.timestamp_materials.iter().flat_map(|item| {
        std::iter::once(&item.request)
            .chain(std::iter::once(&item.response))
            .chain(item.certificate_chain_der.iter())
            .chain(item.revocation_crl_der.iter())
    }) {
        validate_file_identity(file)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid_manifest_error("manifest file count overflow"))?;
        total = total
            .checked_add(file.byte_length)
            .ok_or_else(|| invalid_manifest_error("manifest byte total overflow"))?;
    }
    if count > MAX_REPRODUCTION_FILE_COUNT || total > MAX_REPRODUCTION_PACKAGE_BYTES {
        return invalid_manifest("reproduction package exceeds the supported aggregate bound");
    }
    Ok((count, total))
}

fn validate_file_identity(
    file: &DomainStudyReproductionFileIdentity,
) -> Result<(), DomainStudyReproductionError> {
    if !is_canonical_sha256(&file.sha256)
        || file.byte_length == 0
        || file.byte_length > MAX_REPRODUCTION_FILE_BYTES
    {
        return invalid_manifest("retained file identity or byte length is invalid");
    }
    Ok(())
}

fn aggregate_digest<'a>(
    domain: &[u8],
    digests: impl Iterator<Item = &'a str>,
) -> Result<String, DomainStudyReproductionError> {
    let decoded = digests
        .map(|value| {
            decode_sha256(value)
                .ok_or_else(|| invalid_manifest_error("aggregate member digest is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = u32::try_from(decoded.len())
        .map_err(|_| invalid_manifest_error("aggregate member count exceeds u32"))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(count.to_be_bytes());
    for digest in decoded {
        hasher.update(digest);
    }
    Ok(hex_bytes(&hasher.finalize()))
}

fn validate_json_bound(
    value: &str,
    maximum: usize,
    label: &str,
) -> Result<(), DomainStudyReproductionError> {
    if value.is_empty() || value.len() > maximum {
        return invalid_manifest(format!("{label} JSON is empty or exceeds its bound"));
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if !is_canonical_sha256(value) {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid_manifest<T>(message: impl Into<String>) -> Result<T, DomainStudyReproductionError> {
    Err(invalid_manifest_error(message))
}

fn invalid_manifest_error(message: impl Into<String>) -> DomainStudyReproductionError {
    DomainStudyReproductionError::InvalidManifest(message.into())
}
