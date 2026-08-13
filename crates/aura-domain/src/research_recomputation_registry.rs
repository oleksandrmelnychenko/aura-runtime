//! Append-only registry evidence for independent recomputation attempts.
//!
//! The registry is an additive control around one complete recomputation
//! bundle. It establishes the integrity of one submitted prefix relative to a
//! caller-retained checkpoint. It cannot prove that an operator disclosed
//! every real-world attempt or did not show a competing successor elsewhere.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    domain_study_result_canonical_json, domain_study_result_canonical_sha256, is_canonical_sha256,
    validate_domain_study_independent_recomputation, DomainModuleEvidence, DomainModuleId,
    DomainStudyBuildProvenance, DomainStudyDetachedSignature, DomainStudyEvidenceStatus,
    DomainStudyOutcomeStatus, DomainStudyRecomputationClaimCeiling, DomainStudyRecomputationError,
    DomainStudyRecomputationEvidenceBundle, DomainStudyRecomputationReport,
    DomainStudyRecomputationStatus, DomainStudyRecomputationTrustPolicy,
    DomainStudyReproductionFileIdentity, DomainStudyResultError, DomainStudyTimestampProtocol,
    DomainStudyTrustPolicy, DomainStudyTrustedKey,
};

/// Supported recomputation-attempt registry trust-policy schema.
pub const DOMAIN_STUDY_RECOMPUTATION_REGISTRY_TRUST_POLICY_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_attempt_registry_trust_policy.v1";
/// Supported recomputation-attempt registry evidence schema.
pub const DOMAIN_STUDY_RECOMPUTATION_REGISTRY_EVIDENCE_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_attempt_registry_evidence.v1";
/// Supported signed registry-entry schema.
pub const DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ENTRY_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_attempt_registry_entry.v1";
/// Supported witnessed registry-checkpoint schema.
pub const DOMAIN_STUDY_RECOMPUTATION_REGISTRY_CHECKPOINT_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_attempt_registry_checkpoint.v1";
/// Supported persisted registry accepted-anchor schema.
pub const DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ACCEPTED_ANCHOR_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_attempt_registry_accepted_anchor.v1";
/// Supported registry-checkpoint timestamp-verification schema.
pub const DOMAIN_STUDY_RECOMPUTATION_REGISTRY_TIMESTAMP_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_attempt_registry_timestamp_verification.v1";

const MAX_REGISTRY_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_REGISTRY_ENTRIES: usize = 4_096;
const MAX_TIMESTAMP_ACCURACY_MICROS: u64 = 5 * 60 * 1_000_000;
const MAX_TIMESTAMP_REQUEST_BYTES: u64 = 64 * 1_024;
const MAX_TIMESTAMP_RESPONSE_BYTES: u64 = 1_024 * 1_024;
const MAX_TIMESTAMP_SIGNER_CERTIFICATE_BYTES: u64 = 256 * 1_024;
const MAX_TIMESTAMP_CERTIFICATE_BYTES: u64 = 4 * 1_024 * 1_024;
const MAX_TIMESTAMP_CHAIN_BYTES: u64 = (8 * 1_024 * 1_024) + (256 * 1_024);
const MAX_TIMESTAMP_CRL_BYTES: u64 = 4 * 1_024 * 1_024;
const MAX_TIMESTAMP_CRL_SET_BYTES: u64 = 16 * 1_024 * 1_024;
const MIN_TIMESTAMP_CHAIN_CERTIFICATES: usize = 2;
const MAX_TIMESTAMP_CHAIN_CERTIFICATES: usize = 7;
const MAX_TIMESTAMP_REVOCATION_CRLS: usize = 6;

const REGISTRY_ENTRY_DOMAIN: &[u8] = b"aura.domain.recomputation-attempt-registry-entry.v1\0";
const REGISTRY_CHECKPOINT_OPERATOR_DOMAIN: &[u8] =
    b"aura.domain.recomputation-attempt-registry-checkpoint-operator.v1\0";
const REGISTRY_CHECKPOINT_WITNESS_DOMAIN: &[u8] =
    b"aura.domain.recomputation-attempt-registry-checkpoint-witness.v1\0";
const REGISTRY_TIMESTAMP_DOMAIN: &[u8] =
    b"aura.domain.recomputation-attempt-registry-trusted-timestamp.v1\0";
const REGISTRY_ENTRIES_AGGREGATE_DOMAIN: &[u8] =
    b"aura.domain.recomputation-attempt-registry-entries.v1\0";
const REGISTRY_ACCEPTED_ANCHOR_DOMAIN: &[u8] =
    b"aura.domain.recomputation-attempt-registry-accepted-anchor.v1\0";
const CERTIFICATE_CHAIN_DOMAIN: &[u8] = b"aura.domain.rfc3161-certificate-chain.v1\0";
const REVOCATION_EVIDENCE_DOMAIN: &[u8] = b"aura.domain.rfc3161-revocation-evidence.v1\0";

/// Error returned when a recomputation registry view is malformed or untrusted.
#[derive(Debug, Error)]
pub enum DomainStudyRecomputationRegistryError {
    /// The complete underlying recomputation chain failed validation.
    #[error("invalid underlying independent recomputation: {0}")]
    InvalidRecomputation(#[from] DomainStudyRecomputationError),
    /// A canonical binding could not be calculated.
    #[error("invalid recomputation registry binding: {0}")]
    InvalidResult(#[from] DomainStudyResultError),
    /// Registry JSON does not match its strict typed schema.
    #[error("invalid recomputation registry JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A registry trust, state, chronology, privacy, or signature invariant failed.
    #[error("invalid recomputation registry evidence: {0}")]
    InvalidEvidence(String),
}

/// Fixed trust roots for one append-only recomputation-attempt registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyRecomputationRegistryTrustPolicy {
    /// Schema identity.
    pub schema_version: String,
    /// Stable identity of the registry whose trust roots are fixed here.
    pub registry_id: String,
    /// Key signing every registry entry and the operator checkpoint role.
    pub operator: DomainStudyTrustedKey,
    /// Independent key witnessing the exact checkpoint claims.
    pub witness: DomainStudyTrustedKey,
    /// Separate key signing verified RFC 3161 checkpoint-time claims.
    pub timestamp_verifier: DomainStudyTrustedKey,
    /// Allowed TSA subject-public-key-info digest.
    pub trusted_tsa_spki_sha256: String,
    /// Allowed RFC 3161 policy object identifier.
    pub trusted_tsa_policy_oid: String,
}

/// Exact immutable data registered before one intended attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationAttemptRegistered {
    /// Domain whose exact policy evidence the attempt evaluates.
    pub domain_id: DomainModuleId,
    /// Stable original study identity.
    pub study_id: String,
    /// Stable original result identity.
    pub result_id: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Canonical frozen-plan digest.
    pub plan_canonical_sha256: String,
    /// Canonical trusted plan-timestamp receipt digest.
    pub plan_timestamp_sha256: String,
    /// Canonical signed custodian-authorization digest.
    pub custodian_authorization_sha256: String,
    /// Canonical custodian-authorization timestamp digest.
    pub custodian_authorization_timestamp_sha256: String,
    /// Canonical signed independent-reproducer authorization digest.
    pub reproducer_authorization_sha256: String,
    /// Canonical independent-reproducer authorization timestamp digest.
    pub reproducer_authorization_timestamp_sha256: String,
    /// Exact run identifier derived by the underlying recomputation contract.
    pub run_id: String,
    /// Declared investigation deadline; a late terminal record remains evidence.
    pub terminal_due_at_ms: u64,
}

/// Exact immutable data closing one registered attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationAttemptTerminal {
    /// Domain whose exact policy evidence the attempt evaluates.
    pub domain_id: DomainModuleId,
    /// Stable original study identity.
    pub study_id: String,
    /// Stable original result identity.
    pub result_id: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Canonical frozen-plan digest.
    pub plan_canonical_sha256: String,
    /// Canonical trusted plan-timestamp receipt digest.
    pub plan_timestamp_sha256: String,
    /// Canonical signed custodian-authorization digest.
    pub custodian_authorization_sha256: String,
    /// Canonical custodian-authorization timestamp digest.
    pub custodian_authorization_timestamp_sha256: String,
    /// Canonical signed independent-reproducer authorization digest.
    pub reproducer_authorization_sha256: String,
    /// Canonical independent-reproducer authorization timestamp digest.
    pub reproducer_authorization_timestamp_sha256: String,
    /// Exact run identifier derived by the underlying recomputation contract.
    pub run_id: String,
    /// Declared investigation deadline copied from registration.
    pub terminal_due_at_ms: u64,
    /// Canonical signed registration-entry digest being closed.
    pub registration_entry_sha256: String,
    /// Canonical complete recomputation-evidence digest.
    pub recomputation_evidence_canonical_sha256: String,
    /// Canonical signed final recomputation-manifest digest.
    pub final_manifest_canonical_sha256: String,
    /// Core-derived terminal recomputation status.
    pub status: DomainStudyRecomputationStatus,
}

/// Closed semantic event carried by one registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "event_kind",
    content = "event",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DomainStudyRecomputationRegistryEvent {
    /// Registers one intended attempt under a fixed plan and authorization chain.
    AttemptRegistered(DomainStudyRecomputationAttemptRegistered),
    /// Permanently records the terminal evidence and outcome for that attempt.
    AttemptTerminal(DomainStudyRecomputationAttemptTerminal),
}

/// Operator-signed claims for one contiguous registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationRegistryEntryClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable registry identity.
    pub registry_id: String,
    /// Canonical digest of the fixed registry trust policy.
    pub registry_trust_policy_canonical_sha256: String,
    /// Zero-based contiguous position in the submitted full prefix.
    pub sequence: u64,
    /// Canonical previous signed-entry digest, or `None` for sequence zero.
    pub previous_entry_sha256: Option<String>,
    /// Closed typed registry event.
    pub event: DomainStudyRecomputationRegistryEvent,
    /// Operator-declared append time; this is not independently trusted time.
    pub recorded_at_ms: u64,
    /// Must remain false.
    pub raw_content_exported: bool,
    /// Must remain false.
    pub public_distribution_permitted: bool,
}

/// One signed recomputation-attempt registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudySignedRecomputationRegistryEntry {
    /// Operator-signed entry claims.
    pub claims: DomainStudyRecomputationRegistryEntryClaims,
    /// Detached registry-operator signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Claims signed by both the operator and independent checkpoint witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationRegistryCheckpointClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable registry identity.
    pub registry_id: String,
    /// Canonical fixed registry trust-policy digest.
    pub registry_trust_policy_canonical_sha256: String,
    /// Number of signed entries committed by this checkpoint.
    pub entry_count: u64,
    /// Canonical signed-entry digest at the committed chain head.
    pub head_entry_sha256: Option<String>,
    /// Domain-framed aggregate of all ordered signed-entry digests.
    pub entries_aggregate_sha256: String,
    /// Domain-framed digest of the caller-retained predecessor accepted anchor.
    pub previous_accepted_anchor_sha256: Option<String>,
    /// Entry count committed by the predecessor checkpoint.
    pub previous_entry_count: u64,
    /// Chain head committed by the predecessor checkpoint.
    pub previous_head_entry_sha256: Option<String>,
    /// Entry aggregate committed by the predecessor checkpoint.
    pub previous_entries_aggregate_sha256: Option<String>,
    /// Number of registered attempts without a terminal entry in this prefix.
    pub pending_attempt_count: u64,
    /// Declared checkpoint completion time; trusted order comes from RFC 3161.
    pub completed_at_ms: u64,
    /// Must remain false.
    pub raw_content_exported: bool,
    /// Must remain false.
    pub public_distribution_permitted: bool,
}

/// Exact checkpoint claims signed under independent operator and witness roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudySignedRecomputationRegistryCheckpoint {
    /// Claims shared by both signatures.
    pub claims: DomainStudyRecomputationRegistryCheckpointClaims,
    /// Registry-operator signature.
    pub operator_signature: DomainStudyDetachedSignature,
    /// Independent checkpoint-witness signature.
    pub witness_signature: DomainStudyDetachedSignature,
}

/// Caller-retained anchor accepted for the next append-only validation.
///
/// Genesis pins the exact registry trust policy before the first entry.
/// Every later anchor retains both independently signed checkpoint claims and
/// their trusted-time receipt so rollback and cross-checkpoint chronology can
/// be revalidated instead of trusting unsigned caller-supplied claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "anchor_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DomainStudyRecomputationRegistryAcceptedAnchor {
    /// Explicit caller-approved empty bootstrap anchor.
    Genesis {
        /// Schema identity.
        schema_version: String,
        /// Empty checkpoint claims binding the initial trust policy.
        checkpoint: DomainStudyRecomputationRegistryCheckpointClaims,
    },
    /// Previously validated operator-and-witness checkpoint with trusted time.
    Witnessed {
        /// Schema identity.
        schema_version: String,
        /// Complete signed predecessor checkpoint.
        checkpoint: Box<DomainStudySignedRecomputationRegistryCheckpoint>,
        /// Trusted timestamp that covered the complete signed checkpoint.
        checkpoint_timestamp: DomainStudyRecomputationRegistryTimestampReceipt,
    },
}

/// Closed subject kind covered by the separate registry timestamp schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationRegistryTimestampSubjectKind {
    /// Complete operator-and-witness-signed registry checkpoint.
    RegistryCheckpoint,
}

/// Claims emitted by the registry-specific RFC 3161 verification adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationRegistryTimestampClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Covered registry artifact kind.
    pub subject_kind: DomainStudyRecomputationRegistryTimestampSubjectKind,
    /// Canonical SHA-256 of the complete signed checkpoint.
    pub subject_canonical_sha256: String,
    /// Verified timestamp protocol.
    pub protocol: DomainStudyTimestampProtocol,
    /// Floor of trusted generation time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Microseconds discarded below the millisecond boundary.
    pub gen_time_submillisecond_micros: u16,
    /// RFC 3161 accuracy bound in microseconds.
    pub accuracy_micros: u64,
    /// Digest of the nonce-bearing DER request.
    pub request_sha256: String,
    /// Digest of the original DER response.
    pub response_sha256: String,
    /// Digest of the selected signer-to-anchor DER chain.
    pub certificate_chain_sha256: String,
    /// Digest of the complete CRL evidence set.
    pub revocation_evidence_sha256: String,
    /// Verified TSA subject-public-key-info digest.
    pub tsa_spki_sha256: String,
    /// Verified RFC 3161 policy object identifier.
    pub tsa_policy_oid: String,
}

/// Signed trusted timestamp receipt for one witnessed registry checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationRegistryTimestampReceipt {
    /// Signed trusted-time claims.
    pub claims: DomainStudyRecomputationRegistryTimestampClaims,
    /// Signature from the registry timestamp-verifier key.
    pub signature: DomainStudyDetachedSignature,
}

/// Original material retained for the registry-checkpoint timestamp receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationRegistryTimestampMaterial {
    /// Covered registry artifact kind.
    pub subject_kind: DomainStudyRecomputationRegistryTimestampSubjectKind,
    /// Original nonce-bearing DER request.
    pub request: DomainStudyReproductionFileIdentity,
    /// Original DER response.
    pub response: DomainStudyReproductionFileIdentity,
    /// Exact selected DER chain ordered signer to trust anchor.
    pub certificate_chain_der: Vec<DomainStudyReproductionFileIdentity>,
    /// Exact complete CRL DER set sorted by SHA-256.
    pub revocation_crl_der: Vec<DomainStudyReproductionFileIdentity>,
}

/// Complete verification input for one submitted witnessed registry view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationRegistryEvidenceBundle {
    /// Schema identity.
    pub schema_version: String,
    /// Complete bounded signed prefix from entry zero through the checkpoint.
    pub entries: Vec<DomainStudySignedRecomputationRegistryEntry>,
    /// Operator-and-witness-signed checkpoint over the prefix.
    pub checkpoint: DomainStudySignedRecomputationRegistryCheckpoint,
    /// Trusted timestamp covering the complete signed checkpoint.
    pub checkpoint_timestamp: DomainStudyRecomputationRegistryTimestampReceipt,
    /// Original path-free retained timestamp material.
    pub checkpoint_timestamp_material: DomainStudyRecomputationRegistryTimestampMaterial,
}

/// Content-free report for a validated recomputation registry view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyRecomputationRegistryReport {
    /// Stable registry identity.
    pub registry_id: String,
    /// Canonical registry trust-policy digest pinned from genesis.
    pub registry_trust_policy_canonical_sha256: String,
    /// Stable target study identity.
    pub study_id: String,
    /// Stable target result identity.
    pub result_id: String,
    /// Stable target recomputation identity.
    pub recomputation_id: String,
    /// Stable target run identity.
    pub run_id: String,
    /// Core-derived target recomputation status.
    pub status: DomainStudyRecomputationStatus,
    /// Claim ceiling inherited unchanged from the underlying recomputation.
    pub recomputation_claim_ceiling: DomainStudyRecomputationClaimCeiling,
    /// Original evidence maturity inherited without upgrade.
    pub original_evidence_status: DomainStudyEvidenceStatus,
    /// Original frozen outcome inherited without replacement.
    pub original_outcome_status: DomainStudyOutcomeStatus,
    /// Zero-based registration entry position for the target.
    pub target_registration_sequence: u64,
    /// Zero-based terminal entry position for the target.
    pub target_terminal_sequence: u64,
    /// Whether operator-declared append time was within the signed deadline.
    ///
    /// This is not independently trusted time and must not be reported as
    /// cryptographic deadline compliance.
    pub target_terminal_within_operator_declared_deadline: bool,
    /// True only when the current trusted checkpoint interval ends no later
    /// than the signed terminal deadline.
    pub terminal_deadline_compliance_proven: bool,
    /// Exact number of entries committed by the current checkpoint.
    pub entry_count: u64,
    /// Exact current chain-head digest.
    pub head_entry_sha256: String,
    /// Exact current ordered-entry aggregate digest.
    pub entries_aggregate_sha256: String,
    /// Canonical digest of the complete signed current checkpoint.
    pub checkpoint_canonical_sha256: String,
    /// Canonical digest of the checkpoint trusted-time receipt.
    pub checkpoint_timestamp_canonical_sha256: String,
    /// Domain-framed digest of the accepted anchor supplied by the caller.
    pub previous_accepted_anchor_sha256: String,
    /// Persistable signed-and-timestamped anchor for the next validation.
    pub next_accepted_anchor: DomainStudyRecomputationRegistryAcceptedAnchor,
    /// Domain-framed digest of `next_accepted_anchor` for atomic CAS persistence.
    pub next_accepted_anchor_sha256: String,
    /// Number of still-open registrations in the submitted prefix.
    pub pending_attempt_count: u64,
    /// True after the complete submitted prefix and state machine validate.
    pub submitted_prefix_integrity_established: bool,
    /// True after exact preservation of the caller-retained prefix validates.
    pub append_only_extension_from_previous_checkpoint: bool,
    /// True only after the target complete recomputation is revalidated and joined.
    pub target_terminal_core_verified: bool,
    /// Always false in v1 because entries lack independent inclusion time.
    pub pre_start_registration_proven: bool,
    /// Always false for one submitted view without external cross-monitoring.
    pub global_non_equivocation_established: bool,
    /// Always false: same-data recomputation is not new-sample replication.
    pub scientific_replication_established: bool,
    /// Always false: registry evidence cannot activate product policy.
    pub policy_activation_authorized: bool,
    /// Always false: validation never authorizes disclosure.
    pub public_distribution_permitted: bool,
}

#[derive(Serialize)]
struct SignedClaims<'a, T> {
    key_id: &'a str,
    claims: &'a T,
}

#[derive(Debug, Clone, Copy)]
struct TrustedTimeIntervalMicros {
    earliest_us: u64,
    latest_us: u64,
}

#[derive(Debug)]
struct ValidatedRegistryPrefix {
    entry_digests: Vec<String>,
    pending_attempt_count: u64,
    target_registration_sequence: u64,
    target_terminal_sequence: u64,
    target_terminal_within_deadline: bool,
    target_terminal_due_at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct ValidatedAcceptedAnchor<'a> {
    checkpoint: &'a DomainStudyRecomputationRegistryCheckpointClaims,
    trusted_time: Option<TrustedTimeIntervalMicros>,
}

#[derive(Debug)]
struct RegisteredAttemptState {
    registration: DomainStudyRecomputationAttemptRegistered,
    entry_sha256: String,
    sequence: u64,
    terminal_sequence: Option<u64>,
}

#[derive(Debug, Default)]
struct RegistryArtifactUniqueness {
    recomputation_ids: HashSet<String>,
    run_ids: HashSet<String>,
    plan_digests: HashSet<String>,
    recomputation_evidence_digests: HashSet<String>,
    final_manifest_digests: HashSet<String>,
}

impl RegistryArtifactUniqueness {
    fn register(&mut self, registered: &DomainStudyRecomputationAttemptRegistered) -> bool {
        if self
            .recomputation_ids
            .contains(&registered.recomputation_id)
            || self.run_ids.contains(&registered.run_id)
            || self
                .plan_digests
                .contains(&registered.plan_canonical_sha256)
        {
            return false;
        }
        self.recomputation_ids
            .insert(registered.recomputation_id.clone());
        self.run_ids.insert(registered.run_id.clone());
        self.plan_digests
            .insert(registered.plan_canonical_sha256.clone());
        true
    }

    fn record_terminal(&mut self, terminal: &DomainStudyRecomputationAttemptTerminal) -> bool {
        if self
            .recomputation_evidence_digests
            .contains(&terminal.recomputation_evidence_canonical_sha256)
            || self
                .final_manifest_digests
                .contains(&terminal.final_manifest_canonical_sha256)
        {
            return false;
        }
        self.recomputation_evidence_digests
            .insert(terminal.recomputation_evidence_canonical_sha256.clone());
        self.final_manifest_digests
            .insert(terminal.final_manifest_canonical_sha256.clone());
        true
    }
}

/// Produces the operator registry-entry signing payload.
pub fn domain_study_recomputation_registry_entry_signing_payload(
    claims: &DomainStudyRecomputationRegistryEntryClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationRegistryError> {
    signing_payload(REGISTRY_ENTRY_DOMAIN, claims, key_id)
}

/// Produces the operator checkpoint signing payload.
pub fn domain_study_recomputation_registry_checkpoint_operator_signing_payload(
    claims: &DomainStudyRecomputationRegistryCheckpointClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationRegistryError> {
    signing_payload(REGISTRY_CHECKPOINT_OPERATOR_DOMAIN, claims, key_id)
}

/// Produces the independent witness checkpoint signing payload.
pub fn domain_study_recomputation_registry_checkpoint_witness_signing_payload(
    claims: &DomainStudyRecomputationRegistryCheckpointClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationRegistryError> {
    signing_payload(REGISTRY_CHECKPOINT_WITNESS_DOMAIN, claims, key_id)
}

/// Produces the registry-checkpoint trusted-timestamp signing payload.
pub fn domain_study_recomputation_registry_timestamp_signing_payload(
    claims: &DomainStudyRecomputationRegistryTimestampClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationRegistryError> {
    signing_payload(REGISTRY_TIMESTAMP_DOMAIN, claims, key_id)
}

/// Returns the domain-framed aggregate digest of ordered signed entries.
pub fn domain_study_recomputation_registry_entries_aggregate_sha256(
    entries: &[DomainStudySignedRecomputationRegistryEntry],
) -> Result<String, DomainStudyRecomputationRegistryError> {
    let digests = entries
        .iter()
        .map(domain_study_result_canonical_sha256)
        .collect::<Result<Vec<_>, _>>()?;
    aggregate_digest(
        REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
        digests.iter().map(String::as_str),
    )
}

/// Returns the domain-framed digest used for accepted-anchor CAS lineage.
pub fn domain_study_recomputation_registry_accepted_anchor_sha256(
    anchor: &DomainStudyRecomputationRegistryAcceptedAnchor,
) -> Result<String, DomainStudyRecomputationRegistryError> {
    let canonical = domain_study_result_canonical_json(anchor)?;
    let mut hasher = Sha256::new();
    hasher.update(REGISTRY_ACCEPTED_ANCHOR_DOMAIN);
    hasher.update(canonical);
    Ok(hex_bytes(&hasher.finalize()))
}

/// Builds a caller-owned empty checkpoint that pins the registry trust policy.
///
/// Accepting and retaining this genesis claims object remains an explicit
/// governance action; normal validation never creates an implicit anchor.
pub fn domain_study_recomputation_registry_genesis_checkpoint(
    trust_policy: &DomainStudyRecomputationRegistryTrustPolicy,
) -> Result<DomainStudyRecomputationRegistryAcceptedAnchor, DomainStudyRecomputationRegistryError> {
    validate_registry_policy_shape(trust_policy)?;
    let trust_digest = domain_study_result_canonical_sha256(trust_policy)?;
    let empty_aggregate = aggregate_digest(
        REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
        std::iter::empty::<&str>(),
    )?;
    Ok(DomainStudyRecomputationRegistryAcceptedAnchor::Genesis {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ACCEPTED_ANCHOR_SCHEMA_VERSION
            .to_string(),
        checkpoint: DomainStudyRecomputationRegistryCheckpointClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_CHECKPOINT_SCHEMA_VERSION
                .to_string(),
            registry_id: trust_policy.registry_id.clone(),
            registry_trust_policy_canonical_sha256: trust_digest,
            entry_count: 0,
            head_entry_sha256: None,
            entries_aggregate_sha256: empty_aggregate,
            previous_accepted_anchor_sha256: None,
            previous_entry_count: 0,
            previous_head_entry_sha256: None,
            previous_entries_aggregate_sha256: None,
            pending_attempt_count: 0,
            completed_at_ms: 0,
            raw_content_exported: false,
            public_distribution_permitted: false,
        },
    })
}

/// Validates one complete recomputation and its witnessed append-only registry view.
#[expect(
    clippy::too_many_arguments,
    reason = "the boundary keeps all independently governed evidence and trust inputs explicit"
)]
pub fn validate_domain_study_recomputation_registry(
    preregistration_json: &str,
    result_evidence_json: &str,
    reproduction_manifest_json: &str,
    recomputation_evidence_json: &str,
    registry_evidence_json: &str,
    expected_policy_evidence: &DomainModuleEvidence,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    original_trust_policy: &DomainStudyTrustPolicy,
    recomputation_trust_policy: &DomainStudyRecomputationTrustPolicy,
    registry_trust_policy: &DomainStudyRecomputationRegistryTrustPolicy,
    previous_anchor: &DomainStudyRecomputationRegistryAcceptedAnchor,
) -> Result<DomainStudyRecomputationRegistryReport, DomainStudyRecomputationRegistryError> {
    if registry_evidence_json.is_empty() || registry_evidence_json.len() > MAX_REGISTRY_JSON_BYTES {
        return invalid("registry evidence JSON is empty or exceeds the 16 MiB bound");
    }

    let recomputation_report = validate_domain_study_independent_recomputation(
        preregistration_json,
        result_evidence_json,
        reproduction_manifest_json,
        recomputation_evidence_json,
        expected_policy_evidence,
        expected_build_provenance,
        additional_known_seed_sha256,
        original_trust_policy,
        recomputation_trust_policy,
    )?;
    validate_registry_trust_policy(
        registry_trust_policy,
        original_trust_policy,
        recomputation_trust_policy,
    )?;

    let registry: DomainStudyRecomputationRegistryEvidenceBundle =
        serde_json::from_str(registry_evidence_json)?;
    if registry.schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_EVIDENCE_SCHEMA_VERSION
        || registry.entries.is_empty()
        || registry.entries.len() > MAX_REGISTRY_ENTRIES
    {
        return invalid("registry evidence schema or entry count is outside the v1 bound");
    }
    let recomputation: DomainStudyRecomputationEvidenceBundle =
        serde_json::from_str(recomputation_evidence_json)?;
    let trust_digest = domain_study_result_canonical_sha256(registry_trust_policy)?;

    let validated_anchor =
        validate_previous_anchor(previous_anchor, registry_trust_policy, &trust_digest)?;
    let previous_accepted_anchor_sha256 =
        domain_study_recomputation_registry_accepted_anchor_sha256(previous_anchor)?;
    let previous_checkpoint = validated_anchor.checkpoint;
    let validated_prefix = validate_registry_entries(
        &registry.entries,
        registry_trust_policy,
        &trust_digest,
        expected_policy_evidence.module_id,
        &recomputation,
        &recomputation_report,
    )?;
    validate_prefix_anchor(
        &registry.entries,
        &validated_prefix.entry_digests,
        previous_checkpoint,
    )?;

    let checkpoint = &registry.checkpoint;
    validate_current_checkpoint(
        checkpoint,
        registry_trust_policy,
        &trust_digest,
        previous_checkpoint,
        &previous_accepted_anchor_sha256,
        &validated_prefix,
    )?;
    let checkpoint_sha256 = domain_study_result_canonical_sha256(checkpoint)?;
    let checkpoint_time = validate_checkpoint_timestamp(
        &registry.checkpoint_timestamp,
        &checkpoint_sha256,
        registry_trust_policy,
    )?;
    if let Some(previous_time) = validated_anchor.trusted_time {
        ensure_strictly_after(
            previous_time,
            checkpoint_time,
            "registry checkpoint extension",
        )?;
    }
    let final_time = trusted_interval_from_claims(
        recomputation.final_manifest_timestamp.claims.issued_at_ms,
        recomputation
            .final_manifest_timestamp
            .claims
            .gen_time_submillisecond_micros,
        recomputation
            .final_manifest_timestamp
            .claims
            .accuracy_micros,
    )?;
    ensure_strictly_after(final_time, checkpoint_time, "registry checkpoint")?;
    validate_checkpoint_declared_time(
        checkpoint.claims.completed_at_ms,
        previous_checkpoint.completed_at_ms,
        registry
            .entries
            .last()
            .map_or(0, |entry| entry.claims.recorded_at_ms),
        final_time,
        checkpoint_time,
    )?;
    validate_checkpoint_timestamp_material(
        &registry.checkpoint_timestamp_material,
        &registry.checkpoint_timestamp,
    )?;

    let next_accepted_anchor = DomainStudyRecomputationRegistryAcceptedAnchor::Witnessed {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ACCEPTED_ANCHOR_SCHEMA_VERSION
            .to_string(),
        checkpoint: Box::new(registry.checkpoint.clone()),
        checkpoint_timestamp: registry.checkpoint_timestamp.clone(),
    };
    let next_accepted_anchor_sha256 =
        domain_study_recomputation_registry_accepted_anchor_sha256(&next_accepted_anchor)?;

    Ok(DomainStudyRecomputationRegistryReport {
        registry_id: registry_trust_policy.registry_id.clone(),
        registry_trust_policy_canonical_sha256: trust_digest,
        study_id: recomputation_report.study_id,
        result_id: recomputation_report.result_id,
        recomputation_id: recomputation_report.recomputation_id,
        run_id: recomputation_report.run_id,
        status: recomputation_report.status,
        recomputation_claim_ceiling: recomputation_report.claim_ceiling,
        original_evidence_status: recomputation_report.original_evidence_status,
        original_outcome_status: recomputation_report.original_outcome_status,
        target_registration_sequence: validated_prefix.target_registration_sequence,
        target_terminal_sequence: validated_prefix.target_terminal_sequence,
        target_terminal_within_operator_declared_deadline: validated_prefix
            .target_terminal_within_deadline,
        terminal_deadline_compliance_proven: trusted_deadline_compliance(
            checkpoint_time,
            validated_prefix.target_terminal_due_at_ms,
        ),
        entry_count: checkpoint.claims.entry_count,
        head_entry_sha256: checkpoint
            .claims
            .head_entry_sha256
            .clone()
            .ok_or_else(|| invalid_error("nonempty checkpoint has no chain head"))?,
        entries_aggregate_sha256: checkpoint.claims.entries_aggregate_sha256.clone(),
        checkpoint_canonical_sha256: checkpoint_sha256,
        checkpoint_timestamp_canonical_sha256: domain_study_result_canonical_sha256(
            &registry.checkpoint_timestamp,
        )?,
        previous_accepted_anchor_sha256,
        next_accepted_anchor,
        next_accepted_anchor_sha256,
        pending_attempt_count: validated_prefix.pending_attempt_count,
        submitted_prefix_integrity_established: true,
        append_only_extension_from_previous_checkpoint: true,
        target_terminal_core_verified: true,
        pre_start_registration_proven: false,
        global_non_equivocation_established: false,
        scientific_replication_established: false,
        policy_activation_authorized: false,
        public_distribution_permitted: false,
    })
}

fn validate_registry_entries(
    entries: &[DomainStudySignedRecomputationRegistryEntry],
    trust: &DomainStudyRecomputationRegistryTrustPolicy,
    trust_digest: &str,
    expected_domain_id: DomainModuleId,
    recomputation: &DomainStudyRecomputationEvidenceBundle,
    report: &DomainStudyRecomputationReport,
) -> Result<ValidatedRegistryPrefix, DomainStudyRecomputationRegistryError> {
    let target = target_binding(recomputation, report, expected_domain_id)?;
    let mut states = HashMap::<String, RegisteredAttemptState>::new();
    let mut uniqueness = RegistryArtifactUniqueness::default();
    let mut entry_digests = Vec::with_capacity(entries.len());
    let mut previous_digest: Option<String> = None;
    let mut previous_recorded_at_ms = 0_u64;
    let mut target_registration_sequence = None;
    let mut target_terminal_sequence = None;
    let mut target_terminal_within_deadline = false;
    let mut target_terminal_due_at_ms = None;

    for (index, signed_entry) in entries.iter().enumerate() {
        let claims = &signed_entry.claims;
        let sequence =
            u64::try_from(index).map_err(|_| invalid_error("registry sequence exceeds u64"))?;
        if claims.schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ENTRY_SCHEMA_VERSION
            || claims.registry_id != trust.registry_id
            || claims.registry_trust_policy_canonical_sha256 != trust_digest
            || claims.sequence != sequence
            || claims.previous_entry_sha256 != previous_digest
            || !declared_entry_time_is_monotonic(
                index,
                previous_recorded_at_ms,
                claims.recorded_at_ms,
            )
            || claims.raw_content_exported
            || claims.public_distribution_permitted
        {
            return invalid(
                "registry entry header, order, policy, time, or privacy flag is invalid",
            );
        }
        verify_signed_claims(
            REGISTRY_ENTRY_DOMAIN,
            claims,
            &signed_entry.signature,
            &trust.operator,
            "registry entry",
        )?;
        let entry_digest = domain_study_result_canonical_sha256(signed_entry)?;

        match &claims.event {
            DomainStudyRecomputationRegistryEvent::AttemptRegistered(registered) => {
                validate_registered_shape(registered)?;
                if !uniqueness.register(registered) {
                    return invalid(
                        "registry contains a duplicate recomputation, run, or plan registration",
                    );
                }
                if registered.terminal_due_at_ms <= claims.recorded_at_ms {
                    return invalid(
                        "registered terminal deadline is not after its declared append time",
                    );
                }
                if target_registration_matches(registered, &target.registered)
                    && target_registration_sequence.replace(sequence).is_some()
                {
                    return invalid("target registration is duplicated or bound to another domain");
                }
                states.insert(
                    registered.recomputation_id.clone(),
                    RegisteredAttemptState {
                        registration: registered.clone(),
                        entry_sha256: entry_digest.clone(),
                        sequence,
                        terminal_sequence: None,
                    },
                );
            }
            DomainStudyRecomputationRegistryEvent::AttemptTerminal(terminal) => {
                validate_terminal_shape(terminal)?;
                if !uniqueness.record_terminal(terminal) {
                    return invalid(
                        "registry reuses terminal recomputation evidence or final-manifest bytes",
                    );
                }
                let state = states
                    .get_mut(&terminal.recomputation_id)
                    .ok_or_else(|| invalid_error("terminal registry entry has no registration"))?;
                if state.terminal_sequence.is_some()
                    || !terminal_matches_registration(terminal, state)
                    || claims.recorded_at_ms
                        < entries[state.sequence as usize].claims.recorded_at_ms
                {
                    return invalid(
                        "terminal registry entry duplicates or changes its registration",
                    );
                }
                state.terminal_sequence = Some(sequence);
                if target_terminal_matches(terminal, &target.terminal) {
                    if state.sequence
                        != target_registration_sequence.ok_or_else(|| {
                            invalid_error("target terminal precedes its exact target registration")
                        })?
                        || target_terminal_sequence.replace(sequence).is_some()
                    {
                        return invalid("target terminal is duplicated or bound to another domain");
                    }
                    target_terminal_within_deadline =
                        claims.recorded_at_ms <= terminal.terminal_due_at_ms;
                    target_terminal_due_at_ms = Some(terminal.terminal_due_at_ms);
                }
            }
        }

        previous_recorded_at_ms = claims.recorded_at_ms;
        previous_digest = Some(entry_digest.clone());
        entry_digests.push(entry_digest);
    }

    let pending_attempt_count = u64::try_from(
        states
            .values()
            .filter(|state| state.terminal_sequence.is_none())
            .count(),
    )
    .map_err(|_| invalid_error("pending attempt count exceeds u64"))?;
    Ok(ValidatedRegistryPrefix {
        entry_digests,
        pending_attempt_count,
        target_registration_sequence: target_registration_sequence
            .ok_or_else(|| invalid_error("target recomputation registration is absent"))?,
        target_terminal_sequence: target_terminal_sequence
            .ok_or_else(|| invalid_error("target recomputation terminal entry is absent"))?,
        target_terminal_within_deadline,
        target_terminal_due_at_ms: target_terminal_due_at_ms
            .ok_or_else(|| invalid_error("target terminal deadline is absent"))?,
    })
}

fn declared_entry_time_is_monotonic(index: usize, previous_at_ms: u64, current_at_ms: u64) -> bool {
    current_at_ms > 0 && (index == 0 || current_at_ms >= previous_at_ms)
}

struct TargetBinding {
    registered: DomainStudyRecomputationAttemptRegistered,
    terminal: DomainStudyRecomputationAttemptTerminal,
}

fn target_binding(
    recomputation: &DomainStudyRecomputationEvidenceBundle,
    report: &DomainStudyRecomputationReport,
    expected_domain_id: DomainModuleId,
) -> Result<TargetBinding, DomainStudyRecomputationRegistryError> {
    let registered = DomainStudyRecomputationAttemptRegistered {
        domain_id: expected_domain_id,
        study_id: report.study_id.clone(),
        result_id: report.result_id.clone(),
        recomputation_id: report.recomputation_id.clone(),
        plan_canonical_sha256: report.plan_canonical_sha256.clone(),
        plan_timestamp_sha256: domain_study_result_canonical_sha256(&recomputation.plan_timestamp)?,
        custodian_authorization_sha256: domain_study_result_canonical_sha256(
            &recomputation.custodian_authorization,
        )?,
        custodian_authorization_timestamp_sha256: domain_study_result_canonical_sha256(
            &recomputation.custodian_authorization_timestamp,
        )?,
        reproducer_authorization_sha256: domain_study_result_canonical_sha256(
            &recomputation.reproducer_authorization,
        )?,
        reproducer_authorization_timestamp_sha256: domain_study_result_canonical_sha256(
            &recomputation.reproducer_authorization_timestamp,
        )?,
        run_id: report.run_id.clone(),
        terminal_due_at_ms: 0,
    };
    let terminal = DomainStudyRecomputationAttemptTerminal {
        domain_id: registered.domain_id,
        study_id: registered.study_id.clone(),
        result_id: registered.result_id.clone(),
        recomputation_id: registered.recomputation_id.clone(),
        plan_canonical_sha256: registered.plan_canonical_sha256.clone(),
        plan_timestamp_sha256: registered.plan_timestamp_sha256.clone(),
        custodian_authorization_sha256: registered.custodian_authorization_sha256.clone(),
        custodian_authorization_timestamp_sha256: registered
            .custodian_authorization_timestamp_sha256
            .clone(),
        reproducer_authorization_sha256: registered.reproducer_authorization_sha256.clone(),
        reproducer_authorization_timestamp_sha256: registered
            .reproducer_authorization_timestamp_sha256
            .clone(),
        run_id: registered.run_id.clone(),
        terminal_due_at_ms: 0,
        registration_entry_sha256: String::new(),
        recomputation_evidence_canonical_sha256: report
            .recomputation_evidence_canonical_sha256
            .clone(),
        final_manifest_canonical_sha256: report.final_manifest_canonical_sha256.clone(),
        status: report.status,
    };
    Ok(TargetBinding {
        registered,
        terminal,
    })
}

fn validate_registered_shape(
    registered: &DomainStudyRecomputationAttemptRegistered,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if !safe_token(&registered.study_id)
        || !safe_token(&registered.result_id)
        || !safe_token(&registered.recomputation_id)
        || !is_canonical_sha256(&registered.plan_canonical_sha256)
        || !is_canonical_sha256(&registered.plan_timestamp_sha256)
        || !is_canonical_sha256(&registered.custodian_authorization_sha256)
        || !is_canonical_sha256(&registered.custodian_authorization_timestamp_sha256)
        || !is_canonical_sha256(&registered.reproducer_authorization_sha256)
        || !is_canonical_sha256(&registered.reproducer_authorization_timestamp_sha256)
        || !is_canonical_sha256(&registered.run_id)
        || registered.terminal_due_at_ms == 0
    {
        return invalid("attempt registration identity or digest is malformed");
    }
    Ok(())
}

fn validate_terminal_shape(
    terminal: &DomainStudyRecomputationAttemptTerminal,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    validate_registered_shape(&DomainStudyRecomputationAttemptRegistered {
        domain_id: terminal.domain_id,
        study_id: terminal.study_id.clone(),
        result_id: terminal.result_id.clone(),
        recomputation_id: terminal.recomputation_id.clone(),
        plan_canonical_sha256: terminal.plan_canonical_sha256.clone(),
        plan_timestamp_sha256: terminal.plan_timestamp_sha256.clone(),
        custodian_authorization_sha256: terminal.custodian_authorization_sha256.clone(),
        custodian_authorization_timestamp_sha256: terminal
            .custodian_authorization_timestamp_sha256
            .clone(),
        reproducer_authorization_sha256: terminal.reproducer_authorization_sha256.clone(),
        reproducer_authorization_timestamp_sha256: terminal
            .reproducer_authorization_timestamp_sha256
            .clone(),
        run_id: terminal.run_id.clone(),
        terminal_due_at_ms: terminal.terminal_due_at_ms,
    })?;
    if !is_canonical_sha256(&terminal.registration_entry_sha256)
        || !is_canonical_sha256(&terminal.recomputation_evidence_canonical_sha256)
        || !is_canonical_sha256(&terminal.final_manifest_canonical_sha256)
    {
        return invalid("attempt terminal binding digest is malformed");
    }
    Ok(())
}

fn terminal_matches_registration(
    terminal: &DomainStudyRecomputationAttemptTerminal,
    state: &RegisteredAttemptState,
) -> bool {
    let registered = &state.registration;
    terminal.domain_id == registered.domain_id
        && terminal.study_id == registered.study_id
        && terminal.result_id == registered.result_id
        && terminal.recomputation_id == registered.recomputation_id
        && terminal.plan_canonical_sha256 == registered.plan_canonical_sha256
        && terminal.plan_timestamp_sha256 == registered.plan_timestamp_sha256
        && terminal.custodian_authorization_sha256 == registered.custodian_authorization_sha256
        && terminal.custodian_authorization_timestamp_sha256
            == registered.custodian_authorization_timestamp_sha256
        && terminal.reproducer_authorization_sha256 == registered.reproducer_authorization_sha256
        && terminal.reproducer_authorization_timestamp_sha256
            == registered.reproducer_authorization_timestamp_sha256
        && terminal.run_id == registered.run_id
        && terminal.terminal_due_at_ms == registered.terminal_due_at_ms
        && terminal.registration_entry_sha256 == state.entry_sha256
}

fn target_registration_matches(
    candidate: &DomainStudyRecomputationAttemptRegistered,
    expected: &DomainStudyRecomputationAttemptRegistered,
) -> bool {
    candidate.domain_id == expected.domain_id
        && candidate.study_id == expected.study_id
        && candidate.result_id == expected.result_id
        && candidate.recomputation_id == expected.recomputation_id
        && candidate.plan_canonical_sha256 == expected.plan_canonical_sha256
        && candidate.plan_timestamp_sha256 == expected.plan_timestamp_sha256
        && candidate.custodian_authorization_sha256 == expected.custodian_authorization_sha256
        && candidate.custodian_authorization_timestamp_sha256
            == expected.custodian_authorization_timestamp_sha256
        && candidate.reproducer_authorization_sha256 == expected.reproducer_authorization_sha256
        && candidate.reproducer_authorization_timestamp_sha256
            == expected.reproducer_authorization_timestamp_sha256
        && candidate.run_id == expected.run_id
}

fn target_terminal_matches(
    candidate: &DomainStudyRecomputationAttemptTerminal,
    expected: &DomainStudyRecomputationAttemptTerminal,
) -> bool {
    candidate.domain_id == expected.domain_id
        && candidate.study_id == expected.study_id
        && candidate.result_id == expected.result_id
        && candidate.recomputation_id == expected.recomputation_id
        && candidate.plan_canonical_sha256 == expected.plan_canonical_sha256
        && candidate.plan_timestamp_sha256 == expected.plan_timestamp_sha256
        && candidate.custodian_authorization_sha256 == expected.custodian_authorization_sha256
        && candidate.custodian_authorization_timestamp_sha256
            == expected.custodian_authorization_timestamp_sha256
        && candidate.reproducer_authorization_sha256 == expected.reproducer_authorization_sha256
        && candidate.reproducer_authorization_timestamp_sha256
            == expected.reproducer_authorization_timestamp_sha256
        && candidate.run_id == expected.run_id
        && candidate.recomputation_evidence_canonical_sha256
            == expected.recomputation_evidence_canonical_sha256
        && candidate.final_manifest_canonical_sha256 == expected.final_manifest_canonical_sha256
        && candidate.status == expected.status
}

fn validate_previous_anchor<'a>(
    anchor: &'a DomainStudyRecomputationRegistryAcceptedAnchor,
    trust: &DomainStudyRecomputationRegistryTrustPolicy,
    trust_digest: &str,
) -> Result<ValidatedAcceptedAnchor<'a>, DomainStudyRecomputationRegistryError> {
    match anchor {
        DomainStudyRecomputationRegistryAcceptedAnchor::Genesis {
            schema_version,
            checkpoint,
        } => {
            if schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ACCEPTED_ANCHOR_SCHEMA_VERSION
            {
                return invalid("registry accepted-anchor schema is unsupported");
            }
            validate_previous_checkpoint_shape(checkpoint, trust, trust_digest)?;
            if checkpoint.entry_count != 0 {
                return invalid("registry genesis anchor is not empty");
            }
            Ok(ValidatedAcceptedAnchor {
                checkpoint,
                trusted_time: None,
            })
        }
        DomainStudyRecomputationRegistryAcceptedAnchor::Witnessed {
            schema_version,
            checkpoint,
            checkpoint_timestamp,
        } => {
            if schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ACCEPTED_ANCHOR_SCHEMA_VERSION
            {
                return invalid("registry accepted-anchor schema is unsupported");
            }
            validate_previous_checkpoint_shape(&checkpoint.claims, trust, trust_digest)?;
            if checkpoint.claims.entry_count == 0 {
                return invalid("witnessed registry anchor cannot be empty");
            }
            verify_signed_claims(
                REGISTRY_CHECKPOINT_OPERATOR_DOMAIN,
                &checkpoint.claims,
                &checkpoint.operator_signature,
                &trust.operator,
                "retained registry operator checkpoint",
            )?;
            verify_signed_claims(
                REGISTRY_CHECKPOINT_WITNESS_DOMAIN,
                &checkpoint.claims,
                &checkpoint.witness_signature,
                &trust.witness,
                "retained registry witness checkpoint",
            )?;
            let checkpoint_sha256 = domain_study_result_canonical_sha256(checkpoint)?;
            let trusted_time =
                validate_checkpoint_timestamp(checkpoint_timestamp, &checkpoint_sha256, trust)?;
            let declared_us = checkpoint
                .claims
                .completed_at_ms
                .checked_mul(1_000)
                .ok_or_else(|| invalid_error("retained checkpoint declared time overflows"))?;
            if declared_us > trusted_time.earliest_us {
                return invalid(
                    "retained checkpoint declared time may postdate its trusted interval",
                );
            }
            Ok(ValidatedAcceptedAnchor {
                checkpoint: &checkpoint.claims,
                trusted_time: Some(trusted_time),
            })
        }
    }
}

fn validate_previous_checkpoint_shape(
    checkpoint: &DomainStudyRecomputationRegistryCheckpointClaims,
    trust: &DomainStudyRecomputationRegistryTrustPolicy,
    trust_digest: &str,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    let empty_aggregate = aggregate_digest(
        REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
        std::iter::empty::<&str>(),
    )?;
    let count_valid =
        usize::try_from(checkpoint.entry_count).is_ok_and(|count| count <= MAX_REGISTRY_ENTRIES);
    let genesis_shape_valid = checkpoint.entry_count != 0
        || (checkpoint.head_entry_sha256.is_none()
            && checkpoint.entries_aggregate_sha256 == empty_aggregate
            && checkpoint.previous_accepted_anchor_sha256.is_none()
            && checkpoint.previous_entry_count == 0
            && checkpoint.previous_head_entry_sha256.is_none()
            && checkpoint.previous_entries_aggregate_sha256.is_none()
            && checkpoint.pending_attempt_count == 0
            && checkpoint.completed_at_ms == 0);
    let non_genesis_shape_valid = checkpoint.entry_count == 0
        || (checkpoint.completed_at_ms > 0
            && checkpoint.previous_entry_count < checkpoint.entry_count
            && checkpoint
                .previous_accepted_anchor_sha256
                .as_deref()
                .is_some_and(is_canonical_sha256)
            && checkpoint
                .previous_entries_aggregate_sha256
                .as_deref()
                .is_some_and(is_canonical_sha256)
            && ((checkpoint.previous_entry_count == 0
                && checkpoint.previous_head_entry_sha256.is_none())
                || (checkpoint.previous_entry_count > 0
                    && checkpoint
                        .previous_head_entry_sha256
                        .as_deref()
                        .is_some_and(is_canonical_sha256))));
    if checkpoint.schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_CHECKPOINT_SCHEMA_VERSION
        || checkpoint.registry_id != trust.registry_id
        || checkpoint.registry_trust_policy_canonical_sha256 != trust_digest
        || !count_valid
        || !is_canonical_sha256(&checkpoint.entries_aggregate_sha256)
        || checkpoint.raw_content_exported
        || checkpoint.public_distribution_permitted
        || !genesis_shape_valid
        || !non_genesis_shape_valid
        || (checkpoint.entry_count > 0
            && checkpoint
                .head_entry_sha256
                .as_deref()
                .is_none_or(|digest| !is_canonical_sha256(digest)))
        || checkpoint.pending_attempt_count > checkpoint.entry_count
    {
        return invalid("previous registry checkpoint is not a valid accepted anchor");
    }
    Ok(())
}

fn validate_prefix_anchor(
    entries: &[DomainStudySignedRecomputationRegistryEntry],
    entry_digests: &[String],
    previous: &DomainStudyRecomputationRegistryCheckpointClaims,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    let previous_count = usize::try_from(previous.entry_count)
        .map_err(|_| invalid_error("previous checkpoint entry count exceeds usize"))?;
    if previous_count > entries.len() {
        return invalid("submitted registry view is truncated before the accepted checkpoint");
    }
    let expected_head = previous_count
        .checked_sub(1)
        .map(|index| entry_digests[index].clone());
    let expected_aggregate = aggregate_digest(
        REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
        entry_digests[..previous_count].iter().map(String::as_str),
    )?;
    let expected_pending = pending_attempt_count(&entries[..previous_count])?;
    let predecessor_count = usize::try_from(previous.previous_entry_count)
        .map_err(|_| invalid_error("predecessor checkpoint entry count exceeds usize"))?;
    if predecessor_count > previous_count {
        return invalid("accepted checkpoint predecessor exceeds its committed prefix");
    }
    let expected_predecessor_head = predecessor_count
        .checked_sub(1)
        .map(|index| entry_digests[index].clone());
    let expected_predecessor_aggregate = aggregate_digest(
        REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
        entry_digests[..predecessor_count]
            .iter()
            .map(String::as_str),
    )?;
    if previous.head_entry_sha256 != expected_head
        || previous.entries_aggregate_sha256 != expected_aggregate
        || previous.pending_attempt_count != expected_pending
        || (previous_count > 0
            && (previous.previous_head_entry_sha256 != expected_predecessor_head
                || previous.previous_entries_aggregate_sha256.as_deref()
                    != Some(expected_predecessor_aggregate.as_str())))
    {
        return invalid("submitted registry view rewrites the accepted prefix");
    }
    Ok(())
}

fn validate_current_checkpoint(
    checkpoint: &DomainStudySignedRecomputationRegistryCheckpoint,
    trust: &DomainStudyRecomputationRegistryTrustPolicy,
    trust_digest: &str,
    previous: &DomainStudyRecomputationRegistryCheckpointClaims,
    previous_anchor_sha256: &str,
    prefix: &ValidatedRegistryPrefix,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    let claims = &checkpoint.claims;
    let entry_count = u64::try_from(prefix.entry_digests.len())
        .map_err(|_| invalid_error("current entry count exceeds u64"))?;
    let expected_head = prefix.entry_digests.last().cloned();
    let expected_aggregate = aggregate_digest(
        REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
        prefix.entry_digests.iter().map(String::as_str),
    )?;
    if claims.schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_CHECKPOINT_SCHEMA_VERSION
        || claims.registry_id != trust.registry_id
        || claims.registry_trust_policy_canonical_sha256 != trust_digest
        || claims.entry_count != entry_count
        || !checkpoint_is_strict_target_extension(
            claims.entry_count,
            prefix.target_terminal_sequence,
            previous.entry_count,
        )
        || claims.head_entry_sha256 != expected_head
        || claims.entries_aggregate_sha256 != expected_aggregate
        || claims.previous_accepted_anchor_sha256.as_deref() != Some(previous_anchor_sha256)
        || claims.previous_entry_count != previous.entry_count
        || claims.previous_head_entry_sha256 != previous.head_entry_sha256
        || claims.previous_entries_aggregate_sha256.as_deref()
            != Some(previous.entries_aggregate_sha256.as_str())
        || claims.pending_attempt_count != prefix.pending_attempt_count
        || claims.completed_at_ms == 0
        || claims.completed_at_ms < previous.completed_at_ms
        || claims.raw_content_exported
        || claims.public_distribution_permitted
    {
        return invalid("current registry checkpoint does not exactly bind its prefix or anchor");
    }
    verify_signed_claims(
        REGISTRY_CHECKPOINT_OPERATOR_DOMAIN,
        claims,
        &checkpoint.operator_signature,
        &trust.operator,
        "registry operator checkpoint",
    )?;
    verify_signed_claims(
        REGISTRY_CHECKPOINT_WITNESS_DOMAIN,
        claims,
        &checkpoint.witness_signature,
        &trust.witness,
        "registry witness checkpoint",
    )?;
    Ok(())
}

fn checkpoint_is_strict_target_extension(
    current_entry_count: u64,
    target_terminal_sequence: u64,
    previous_entry_count: u64,
) -> bool {
    current_entry_count > previous_entry_count
        && target_terminal_sequence >= previous_entry_count
        && target_terminal_sequence < current_entry_count
}

fn pending_attempt_count(
    entries: &[DomainStudySignedRecomputationRegistryEntry],
) -> Result<u64, DomainStudyRecomputationRegistryError> {
    let mut pending = HashSet::new();
    for entry in entries {
        match &entry.claims.event {
            DomainStudyRecomputationRegistryEvent::AttemptRegistered(registered) => {
                if !pending.insert(registered.recomputation_id.as_str()) {
                    return invalid("accepted registry prefix repeats a pending registration");
                }
            }
            DomainStudyRecomputationRegistryEvent::AttemptTerminal(terminal) => {
                if !pending.remove(terminal.recomputation_id.as_str()) {
                    return invalid("accepted registry prefix contains an invalid terminal state");
                }
            }
        }
    }
    u64::try_from(pending.len()).map_err(|_| invalid_error("pending attempt count exceeds u64"))
}

fn validate_registry_trust_policy(
    policy: &DomainStudyRecomputationRegistryTrustPolicy,
    original: &DomainStudyTrustPolicy,
    recomputation: &DomainStudyRecomputationTrustPolicy,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    validate_registry_policy_shape(policy)?;
    let registry_keys = [
        &policy.operator,
        &policy.witness,
        &policy.timestamp_verifier,
    ];
    let recomputation_keys = [
        &recomputation.evidence_custodian_authorizer,
        &recomputation.independent_reproducer_authorizer,
        &recomputation.executor,
        &recomputation.timestamp_verifier,
        &recomputation.final_manifest_signer,
    ];
    let mut key_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for key in [
        &original.preregistration_signer,
        &original.timestamp_verifier,
        &original.adjudicator,
        &original.final_manifest_signer,
    ]
    .into_iter()
    .chain(original.reviewers.iter().map(|reviewer| &reviewer.key))
    .chain(recomputation_keys)
    .chain(registry_keys)
    {
        if !key_ids.insert(key.key_id.as_str()) || !public_keys.insert(key.public_key_hex.as_str())
        {
            return invalid(
                "all original, recomputation, and registry roles require distinct keys",
            );
        }
    }
    Ok(())
}

fn validate_registry_policy_shape(
    policy: &DomainStudyRecomputationRegistryTrustPolicy,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if policy.schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_TRUST_POLICY_SCHEMA_VERSION
        || !safe_token(&policy.registry_id)
        || !is_canonical_sha256(&policy.trusted_tsa_spki_sha256)
        || !safe_oid(&policy.trusted_tsa_policy_oid)
    {
        return invalid("registry trust-policy identity or TSA policy is invalid");
    }
    let mut key_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for key in [
        &policy.operator,
        &policy.witness,
        &policy.timestamp_verifier,
    ] {
        validate_trusted_key(key)?;
        if !key_ids.insert(key.key_id.as_str()) || !public_keys.insert(key.public_key_hex.as_str())
        {
            return invalid(
                "registry operator, witness, and timestamp roles require distinct keys",
            );
        }
    }
    Ok(())
}

fn validate_checkpoint_timestamp(
    receipt: &DomainStudyRecomputationRegistryTimestampReceipt,
    expected_subject_sha256: &str,
    trust: &DomainStudyRecomputationRegistryTrustPolicy,
) -> Result<TrustedTimeIntervalMicros, DomainStudyRecomputationRegistryError> {
    let claims = &receipt.claims;
    if claims.schema_version != DOMAIN_STUDY_RECOMPUTATION_REGISTRY_TIMESTAMP_SCHEMA_VERSION
        || claims.subject_kind
            != DomainStudyRecomputationRegistryTimestampSubjectKind::RegistryCheckpoint
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
        || claims.tsa_spki_sha256 != trust.trusted_tsa_spki_sha256
        || claims.tsa_policy_oid != trust.trusted_tsa_policy_oid
    {
        return invalid("registry checkpoint timestamp is malformed or outside policy");
    }
    verify_signed_claims(
        REGISTRY_TIMESTAMP_DOMAIN,
        claims,
        &receipt.signature,
        &trust.timestamp_verifier,
        "registry checkpoint timestamp",
    )?;
    trusted_interval_from_claims(
        claims.issued_at_ms,
        claims.gen_time_submillisecond_micros,
        claims.accuracy_micros,
    )
}

fn validate_checkpoint_declared_time(
    completed_at_ms: u64,
    previous_completed_at_ms: u64,
    last_entry_recorded_at_ms: u64,
    final_time: TrustedTimeIntervalMicros,
    checkpoint_time: TrustedTimeIntervalMicros,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    let completed_us = completed_at_ms
        .checked_mul(1_000)
        .ok_or_else(|| invalid_error("registry checkpoint declared time overflows"))?;
    let previous_us = previous_completed_at_ms
        .checked_mul(1_000)
        .ok_or_else(|| invalid_error("previous checkpoint declared time overflows"))?;
    if completed_at_ms < last_entry_recorded_at_ms
        || completed_us <= final_time.latest_us
        || completed_us <= previous_us
        || completed_us > checkpoint_time.earliest_us
        || previous_us >= checkpoint_time.earliest_us
    {
        return invalid("registry checkpoint declared time is outside the trusted sequence");
    }
    Ok(())
}

fn trusted_deadline_compliance(
    checkpoint_time: TrustedTimeIntervalMicros,
    terminal_due_at_ms: u64,
) -> bool {
    terminal_due_at_ms
        .checked_add(1)
        .and_then(|exclusive_ms| exclusive_ms.checked_mul(1_000))
        .and_then(|exclusive_us| exclusive_us.checked_sub(1))
        .is_some_and(|inclusive_due_us| checkpoint_time.latest_us <= inclusive_due_us)
}

fn validate_checkpoint_timestamp_material(
    material: &DomainStudyRecomputationRegistryTimestampMaterial,
    receipt: &DomainStudyRecomputationRegistryTimestampReceipt,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if material.subject_kind
        != DomainStudyRecomputationRegistryTimestampSubjectKind::RegistryCheckpoint
        || material.request.sha256 != receipt.claims.request_sha256
        || material.response.sha256 != receipt.claims.response_sha256
    {
        return invalid("registry timestamp material does not match its receipt");
    }
    validate_file_identity(&material.request, MAX_TIMESTAMP_REQUEST_BYTES)?;
    validate_file_identity(&material.response, MAX_TIMESTAMP_RESPONSE_BYTES)?;
    validate_timestamp_members(
        &material.certificate_chain_der,
        MIN_TIMESTAMP_CHAIN_CERTIFICATES,
        MAX_TIMESTAMP_CHAIN_CERTIFICATES,
        false,
        MAX_TIMESTAMP_CERTIFICATE_BYTES,
        MAX_TIMESTAMP_CHAIN_BYTES,
    )?;
    if material.certificate_chain_der[0].byte_length > MAX_TIMESTAMP_SIGNER_CERTIFICATE_BYTES {
        return invalid("registry TSA signer certificate exceeds its adapter bound");
    }
    validate_timestamp_members(
        &material.revocation_crl_der,
        1,
        MAX_TIMESTAMP_REVOCATION_CRLS,
        true,
        MAX_TIMESTAMP_CRL_BYTES,
        MAX_TIMESTAMP_CRL_SET_BYTES,
    )?;
    if material.revocation_crl_der.len() + 1 != material.certificate_chain_der.len()
        || aggregate_digest(
            CERTIFICATE_CHAIN_DOMAIN,
            material
                .certificate_chain_der
                .iter()
                .map(|item| item.sha256.as_str()),
        )? != receipt.claims.certificate_chain_sha256
        || aggregate_digest(
            REVOCATION_EVIDENCE_DOMAIN,
            material
                .revocation_crl_der
                .iter()
                .map(|item| item.sha256.as_str()),
        )? != receipt.claims.revocation_evidence_sha256
    {
        return invalid("registry timestamp chain or CRL evidence is incomplete");
    }
    Ok(())
}

fn validate_timestamp_members(
    members: &[DomainStudyReproductionFileIdentity],
    minimum: usize,
    maximum: usize,
    sorted: bool,
    maximum_member_bytes: u64,
    maximum_total_bytes: u64,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if !(minimum..=maximum).contains(&members.len()) {
        return invalid("registry timestamp material count is outside its bound");
    }
    let mut seen = HashSet::new();
    let mut previous = None;
    let mut total_bytes = 0_u64;
    for member in members {
        validate_file_identity(member, maximum_member_bytes)?;
        total_bytes = total_bytes
            .checked_add(member.byte_length)
            .ok_or_else(|| invalid_error("registry timestamp byte total overflows"))?;
        if !seen.insert(member.sha256.as_str())
            || (sorted && previous.is_some_and(|value: &str| value >= member.sha256.as_str()))
        {
            return invalid("registry timestamp material is duplicated or unsorted");
        }
        previous = Some(member.sha256.as_str());
    }
    if total_bytes > maximum_total_bytes {
        return invalid("registry timestamp material exceeds its aggregate adapter bound");
    }
    Ok(())
}

fn validate_file_identity(
    file: &DomainStudyReproductionFileIdentity,
    maximum_bytes: u64,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if !is_canonical_sha256(&file.sha256)
        || file.byte_length == 0
        || file.byte_length > maximum_bytes
    {
        return invalid("registry retained-file identity is invalid");
    }
    Ok(())
}

fn trusted_interval_from_claims(
    issued_at_ms: u64,
    submillisecond_micros: u16,
    accuracy_micros: u64,
) -> Result<TrustedTimeIntervalMicros, DomainStudyRecomputationRegistryError> {
    let exact = issued_at_ms
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(u64::from(submillisecond_micros)))
        .ok_or_else(|| invalid_error("registry timestamp generation time overflows"))?;
    let earliest_us = exact
        .checked_sub(accuracy_micros)
        .ok_or_else(|| invalid_error("registry timestamp interval underflows"))?;
    let latest_us = exact
        .checked_add(accuracy_micros)
        .ok_or_else(|| invalid_error("registry timestamp interval overflows"))?;
    Ok(TrustedTimeIntervalMicros {
        earliest_us,
        latest_us,
    })
}

fn ensure_strictly_after(
    previous: TrustedTimeIntervalMicros,
    current: TrustedTimeIntervalMicros,
    label: &str,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if previous.latest_us >= current.earliest_us {
        return invalid(format!("{label} trusted interval overlaps its predecessor"));
    }
    Ok(())
}

fn validate_trusted_key(
    key: &DomainStudyTrustedKey,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if !safe_token(&key.key_id) {
        return invalid("trusted registry key identifier is invalid");
    }
    let public_key = decode_hex_array::<32>(&key.public_key_hex)
        .ok_or_else(|| invalid_error("trusted registry public key is malformed"))?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| invalid_error("trusted registry public key is invalid"))?;
    Ok(())
}

fn verify_signed_claims<T: Serialize>(
    domain: &[u8],
    claims: &T,
    signature: &DomainStudyDetachedSignature,
    trusted_key: &DomainStudyTrustedKey,
    label: &str,
) -> Result<(), DomainStudyRecomputationRegistryError> {
    if signature.key_id != trusted_key.key_id {
        return invalid(format!("{label} key identifier is not trusted"));
    }
    let public_key = decode_hex_array::<32>(&trusted_key.public_key_hex)
        .ok_or_else(|| invalid_error(format!("{label} public key is malformed")))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| invalid_error(format!("{label} public key is invalid")))?;
    let signature_bytes = decode_hex_array::<64>(&signature.signature_hex)
        .ok_or_else(|| invalid_error(format!("{label} signature is malformed")))?;
    let payload = signing_payload(domain, claims, &signature.key_id)?;
    verifying_key
        .verify_strict(&payload, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| invalid_error(format!("{label} signature verification failed")))
}

fn signing_payload<T: Serialize>(
    domain: &[u8],
    claims: &T,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationRegistryError> {
    if !safe_token(key_id) {
        return invalid("registry signing key identifier is invalid");
    }
    let mut payload = domain.to_vec();
    payload.extend(domain_study_result_canonical_json(&SignedClaims {
        key_id,
        claims,
    })?);
    Ok(payload)
}

fn aggregate_digest<'a>(
    domain: &[u8],
    digests: impl Iterator<Item = &'a str>,
) -> Result<String, DomainStudyRecomputationRegistryError> {
    let decoded = digests
        .map(|value| {
            decode_hex_array::<32>(value)
                .ok_or_else(|| invalid_error("aggregate digest is malformed"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = u32::try_from(decoded.len())
        .map_err(|_| invalid_error("aggregate digest count exceeds u32"))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(count.to_be_bytes());
    for digest in decoded {
        hasher.update(digest);
    }
    Ok(hex_bytes(&hasher.finalize()))
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
    matches!(first, 0..=2)
        && (first == 2 || components[1].parse::<u8>().is_ok_and(|second| second <= 39))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DomainStudyRecomputationRegistryError> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> DomainStudyRecomputationRegistryError {
    DomainStudyRecomputationRegistryError::InvalidEvidence(message.into())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn trusted_key(key_id: &str, byte: u8) -> (DomainStudyTrustedKey, SigningKey) {
        let signing = SigningKey::from_bytes(&[byte; 32]);
        (
            DomainStudyTrustedKey {
                key_id: key_id.to_string(),
                public_key_hex: hex_bytes(signing.verifying_key().as_bytes()),
            },
            signing,
        )
    }

    fn policy() -> DomainStudyRecomputationRegistryTrustPolicy {
        DomainStudyRecomputationRegistryTrustPolicy {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_TRUST_POLICY_SCHEMA_VERSION
                .to_string(),
            registry_id: "registry_test".to_string(),
            operator: trusted_key("registry_operator", 1).0,
            witness: trusted_key("registry_witness", 2).0,
            timestamp_verifier: trusted_key("registry_timestamp", 3).0,
            trusted_tsa_spki_sha256: "a".repeat(64),
            trusted_tsa_policy_oid: "1.3.6.1.4.1.57264.1".to_string(),
        }
    }

    fn registered() -> DomainStudyRecomputationAttemptRegistered {
        DomainStudyRecomputationAttemptRegistered {
            domain_id: DomainModuleId::Kids,
            study_id: "study_test".to_string(),
            result_id: "result_test".to_string(),
            recomputation_id: "recomputation_test".to_string(),
            plan_canonical_sha256: "a".repeat(64),
            plan_timestamp_sha256: "b".repeat(64),
            custodian_authorization_sha256: "c".repeat(64),
            custodian_authorization_timestamp_sha256: "d".repeat(64),
            reproducer_authorization_sha256: "a".repeat(64),
            reproducer_authorization_timestamp_sha256: "b".repeat(64),
            run_id: "c".repeat(64),
            terminal_due_at_ms: 20,
        }
    }

    #[test]
    fn signing_wire_matches_closed_python_adapter_domain() {
        let trust_digest = domain_study_result_canonical_sha256(&policy()).expect("trust digest");
        let claims = DomainStudyRecomputationRegistryEntryClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ENTRY_SCHEMA_VERSION.to_string(),
            registry_id: "registry_test".to_string(),
            registry_trust_policy_canonical_sha256: trust_digest,
            sequence: 0,
            previous_entry_sha256: None,
            event: DomainStudyRecomputationRegistryEvent::AttemptRegistered(registered()),
            recorded_at_ms: 10,
            raw_content_exported: false,
            public_distribution_permitted: false,
        };
        let payload =
            domain_study_recomputation_registry_entry_signing_payload(&claims, "registry_operator")
                .expect("payload");
        assert!(payload.starts_with(REGISTRY_ENTRY_DOMAIN));
        assert_eq!(
            &payload[REGISTRY_ENTRY_DOMAIN.len()..],
            domain_study_result_canonical_json(&SignedClaims {
                key_id: "registry_operator",
                claims: &claims,
            })
            .expect("canonical signed claims")
        );
    }

    #[test]
    fn event_wrapper_rejects_unknown_sibling_fields() {
        let event_json = format!(
            "{{\"event_kind\":\"attempt_registered\",\"event\":{},\"extra\":1}}",
            String::from_utf8(
                domain_study_result_canonical_json(&registered()).expect("registered JSON")
            )
            .expect("UTF-8 JSON")
        );
        assert!(
            serde_json::from_str::<DomainStudyRecomputationRegistryEvent>(&event_json).is_err()
        );
    }

    #[test]
    fn declared_entry_order_allows_atomic_appends_in_one_millisecond() {
        assert!(declared_entry_time_is_monotonic(0, 0, 100));
        assert!(declared_entry_time_is_monotonic(1, 100, 100));
        assert!(!declared_entry_time_is_monotonic(1, 100, 99));
        assert!(!declared_entry_time_is_monotonic(0, 0, 0));
    }

    #[test]
    fn python_openssl_registry_entry_signature_verifies_with_dalek() {
        let claims = DomainStudyRecomputationRegistryEntryClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ENTRY_SCHEMA_VERSION.to_string(),
            registry_id: "registry_2026_01".to_string(),
            registry_trust_policy_canonical_sha256: "d".repeat(64),
            sequence: 0,
            previous_entry_sha256: None,
            event: DomainStudyRecomputationRegistryEvent::AttemptRegistered(
                DomainStudyRecomputationAttemptRegistered {
                    domain_id: DomainModuleId::Kids,
                    study_id: "study_2026_01".to_string(),
                    result_id: "result_2026_01".to_string(),
                    recomputation_id: "recomputation_2026_01".to_string(),
                    plan_canonical_sha256: "a".repeat(64),
                    plan_timestamp_sha256: "b".repeat(64),
                    custodian_authorization_sha256: "c".repeat(64),
                    custodian_authorization_timestamp_sha256: "d".repeat(64),
                    reproducer_authorization_sha256: "a".repeat(64),
                    reproducer_authorization_timestamp_sha256: "b".repeat(64),
                    run_id: "c".repeat(64),
                    terminal_due_at_ms: 1_780_003_600_000,
                },
            ),
            recorded_at_ms: 1_780_000_000_000,
            raw_content_exported: false,
            public_distribution_permitted: false,
        };
        let payload =
            domain_study_recomputation_registry_entry_signing_payload(&claims, "registry_operator")
                .expect("registry entry signing payload");
        let public_key = decode_hex_array::<32>(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .expect("fixed public key");
        let signature = decode_hex_array::<64>(
            "f13e037d1d8a8ded7f0a807745846990ee78d19dd2772e75987ca61e0581089dd87908b38fa1746a996b109effec1921b8ba42c075fba2c697e0408eeab95404",
        )
        .expect("fixed Python/OpenSSL signature");
        VerifyingKey::from_bytes(&public_key)
            .expect("valid fixed public key")
            .verify_strict(&payload, &Signature::from_bytes(&signature))
            .expect("Python/OpenSSL registry signature must verify in Rust");
    }

    #[test]
    fn python_openssl_registry_timestamp_signature_verifies_with_dalek() {
        let claims = DomainStudyRecomputationRegistryTimestampClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_TIMESTAMP_SCHEMA_VERSION
                .to_string(),
            subject_kind: DomainStudyRecomputationRegistryTimestampSubjectKind::RegistryCheckpoint,
            subject_canonical_sha256: "a".repeat(64),
            protocol: DomainStudyTimestampProtocol::Rfc3161TrustedChain,
            issued_at_ms: 1_780_000_000_000,
            gen_time_submillisecond_micros: 999,
            accuracy_micros: 1_000,
            request_sha256: "b".repeat(64),
            response_sha256: "c".repeat(64),
            certificate_chain_sha256: "d".repeat(64),
            revocation_evidence_sha256: "a".repeat(64),
            tsa_spki_sha256: "b".repeat(64),
            tsa_policy_oid: "1.3.6.1.4.1.57264.1".to_string(),
        };
        let payload = domain_study_recomputation_registry_timestamp_signing_payload(
            &claims,
            "registry_timestamp_verifier",
        )
        .expect("registry timestamp signing payload");
        let public_key = decode_hex_array::<32>(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .expect("fixed public key");
        let signature = decode_hex_array::<64>(
            "926e8806a9de434cd73ceff55e37aa4e4154f011697aa299cdf71b818a200702cb9b577f145f2a1a6e4dab6f1c4bbd52c22c3463b2a3e01cb42dbf3fe94ed70f",
        )
        .expect("fixed Python/OpenSSL signature");
        VerifyingKey::from_bytes(&public_key)
            .expect("valid fixed public key")
            .verify_strict(&payload, &Signature::from_bytes(&signature))
            .expect("Python/OpenSSL registry timestamp signature must verify in Rust");
    }

    #[test]
    fn python_openssl_checkpoint_role_signatures_verify_with_dalek() {
        let claims = DomainStudyRecomputationRegistryCheckpointClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_CHECKPOINT_SCHEMA_VERSION
                .to_string(),
            registry_id: "registry_2026_01".to_string(),
            registry_trust_policy_canonical_sha256: "d".repeat(64),
            entry_count: 2,
            head_entry_sha256: Some("a".repeat(64)),
            entries_aggregate_sha256: "b".repeat(64),
            previous_accepted_anchor_sha256: Some("c".repeat(64)),
            previous_entry_count: 0,
            previous_head_entry_sha256: None,
            previous_entries_aggregate_sha256: Some("d".repeat(64)),
            pending_attempt_count: 0,
            completed_at_ms: 1_780_000_001_000,
            raw_content_exported: false,
            public_distribution_permitted: false,
        };
        let public_key = decode_hex_array::<32>(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .expect("fixed public key");
        let verifying_key = VerifyingKey::from_bytes(&public_key).expect("valid fixed public key");
        let operator_payload =
            domain_study_recomputation_registry_checkpoint_operator_signing_payload(
                &claims,
                "registry_operator",
            )
            .expect("operator checkpoint payload");
        let operator_signature = decode_hex_array::<64>(
            "9a70be41bcef1035f9839886a32d165dfe44e88964270db2a5c3db2591d8db07c757e2e94c44c7e270a9943ddd641ec11be39310678b41c65fef461b8f2d5c02",
        )
        .expect("fixed operator signature");
        verifying_key
            .verify_strict(
                &operator_payload,
                &Signature::from_bytes(&operator_signature),
            )
            .expect("Python/OpenSSL operator checkpoint signature must verify in Rust");

        let witness_payload =
            domain_study_recomputation_registry_checkpoint_witness_signing_payload(
                &claims,
                "registry_witness",
            )
            .expect("witness checkpoint payload");
        let witness_signature = decode_hex_array::<64>(
            "1b352780c9443dfff9b6c16c822b77a2e47eb19e31a41f8714cf465af7636e26a7ae987720330d2438693888d91a726ef406dd46d2a7aa5a456ba6ddce67ae05",
        )
        .expect("fixed witness signature");
        verifying_key
            .verify_strict(&witness_payload, &Signature::from_bytes(&witness_signature))
            .expect("Python/OpenSSL witness checkpoint signature must verify in Rust");
    }

    #[test]
    fn genesis_pins_trust_policy_and_has_the_exact_empty_aggregate() {
        let policy = policy();
        let genesis = domain_study_recomputation_registry_genesis_checkpoint(&policy)
            .expect("genesis checkpoint");
        let DomainStudyRecomputationRegistryAcceptedAnchor::Genesis { checkpoint, .. } = &genesis
        else {
            panic!("expected genesis anchor");
        };
        assert_eq!(checkpoint.entry_count, 0);
        assert_eq!(checkpoint.head_entry_sha256, None);
        assert_eq!(checkpoint.previous_accepted_anchor_sha256, None);
        assert_eq!(
            checkpoint.registry_trust_policy_canonical_sha256,
            domain_study_result_canonical_sha256(&policy).expect("policy digest")
        );
        assert_eq!(
            checkpoint.entries_aggregate_sha256,
            aggregate_digest(
                REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
                std::iter::empty::<&str>()
            )
            .expect("empty aggregate")
        );

        let trust_digest = domain_study_result_canonical_sha256(&policy).expect("policy digest");
        let mut malformed = genesis;
        let DomainStudyRecomputationRegistryAcceptedAnchor::Genesis { checkpoint, .. } =
            &mut malformed
        else {
            panic!("expected genesis anchor");
        };
        checkpoint.completed_at_ms = 1;
        assert!(validate_previous_anchor(&malformed, &policy, &trust_digest).is_err());
    }

    #[test]
    fn accepted_anchor_rejects_truncation_and_prefix_rewrite() {
        let trust = policy();
        let trust_digest = domain_study_result_canonical_sha256(&trust).expect("trust digest");
        let (_, signing) = trusted_key("registry_operator", 1);
        let claims = DomainStudyRecomputationRegistryEntryClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ENTRY_SCHEMA_VERSION.to_string(),
            registry_id: trust.registry_id.clone(),
            registry_trust_policy_canonical_sha256: trust_digest.clone(),
            sequence: 0,
            previous_entry_sha256: None,
            event: DomainStudyRecomputationRegistryEvent::AttemptRegistered(registered()),
            recorded_at_ms: 10,
            raw_content_exported: false,
            public_distribution_permitted: false,
        };
        let payload = domain_study_recomputation_registry_entry_signing_payload(
            &claims,
            &trust.operator.key_id,
        )
        .expect("payload");
        let entry = DomainStudySignedRecomputationRegistryEntry {
            claims,
            signature: DomainStudyDetachedSignature {
                key_id: trust.operator.key_id.clone(),
                signature_hex: hex_bytes(&signing.sign(&payload).to_bytes()),
            },
        };
        let digest = domain_study_result_canonical_sha256(&entry).expect("entry digest");
        let anchor = DomainStudyRecomputationRegistryCheckpointClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_CHECKPOINT_SCHEMA_VERSION
                .to_string(),
            registry_id: trust.registry_id.clone(),
            registry_trust_policy_canonical_sha256: trust_digest,
            entry_count: 1,
            head_entry_sha256: Some(digest.clone()),
            entries_aggregate_sha256: aggregate_digest(
                REGISTRY_ENTRIES_AGGREGATE_DOMAIN,
                std::iter::once(digest.as_str()),
            )
            .expect("aggregate"),
            previous_accepted_anchor_sha256: None,
            previous_entry_count: 0,
            previous_head_entry_sha256: None,
            previous_entries_aggregate_sha256: None,
            pending_attempt_count: 1,
            completed_at_ms: 11,
            raw_content_exported: false,
            public_distribution_permitted: false,
        };
        assert!(validate_prefix_anchor(&[], &[], &anchor).is_err());

        let mut wrong_digest = digest;
        wrong_digest.replace_range(0..1, "f");
        assert!(validate_prefix_anchor(&[entry], &[wrong_digest], &anchor).is_err());

        let mut wrong_pending = anchor;
        wrong_pending.pending_attempt_count = 0;
        assert!(validate_prefix_anchor(
            &[DomainStudySignedRecomputationRegistryEntry {
                claims: DomainStudyRecomputationRegistryEntryClaims {
                    schema_version: DOMAIN_STUDY_RECOMPUTATION_REGISTRY_ENTRY_SCHEMA_VERSION
                        .to_string(),
                    registry_id: trust.registry_id,
                    registry_trust_policy_canonical_sha256: wrong_pending
                        .registry_trust_policy_canonical_sha256
                        .clone(),
                    sequence: 0,
                    previous_entry_sha256: None,
                    event: DomainStudyRecomputationRegistryEvent::AttemptRegistered(registered()),
                    recorded_at_ms: 10,
                    raw_content_exported: false,
                    public_distribution_permitted: false,
                },
                signature: DomainStudyDetachedSignature {
                    key_id: "irrelevant_after_full_validation".to_string(),
                    signature_hex: "0".repeat(128),
                },
            }],
            &[wrong_pending
                .head_entry_sha256
                .clone()
                .expect("anchor head")],
            &wrong_pending,
        )
        .is_err());
    }

    #[test]
    fn terminal_must_preserve_every_registered_field_and_registration_digest() {
        let registration = registered();
        let state = RegisteredAttemptState {
            registration: registration.clone(),
            entry_sha256: "d".repeat(64),
            sequence: 0,
            terminal_sequence: None,
        };
        let mut terminal = DomainStudyRecomputationAttemptTerminal {
            domain_id: registration.domain_id,
            study_id: registration.study_id.clone(),
            result_id: registration.result_id.clone(),
            recomputation_id: registration.recomputation_id.clone(),
            plan_canonical_sha256: registration.plan_canonical_sha256.clone(),
            plan_timestamp_sha256: registration.plan_timestamp_sha256.clone(),
            custodian_authorization_sha256: registration.custodian_authorization_sha256.clone(),
            custodian_authorization_timestamp_sha256: registration
                .custodian_authorization_timestamp_sha256
                .clone(),
            reproducer_authorization_sha256: registration.reproducer_authorization_sha256.clone(),
            reproducer_authorization_timestamp_sha256: registration
                .reproducer_authorization_timestamp_sha256
                .clone(),
            run_id: registration.run_id.clone(),
            terminal_due_at_ms: registration.terminal_due_at_ms,
            registration_entry_sha256: state.entry_sha256.clone(),
            recomputation_evidence_canonical_sha256: "a".repeat(64),
            final_manifest_canonical_sha256: "b".repeat(64),
            status: DomainStudyRecomputationStatus::AggregateExactMatch,
        };
        assert!(terminal_matches_registration(&terminal, &state));
        terminal.terminal_due_at_ms += 1;
        assert!(!terminal_matches_registration(&terminal, &state));
    }

    #[test]
    fn registry_artifacts_cannot_be_reused_under_new_attempt_identifiers() {
        let first = registered();
        let mut uniqueness = RegistryArtifactUniqueness::default();
        assert!(uniqueness.register(&first));

        let mut duplicate_plan = first.clone();
        duplicate_plan.recomputation_id = "another_recomputation".to_string();
        duplicate_plan.run_id = "d".repeat(64);
        assert!(!uniqueness.register(&duplicate_plan));

        let terminal = DomainStudyRecomputationAttemptTerminal {
            domain_id: first.domain_id,
            study_id: first.study_id.clone(),
            result_id: first.result_id.clone(),
            recomputation_id: first.recomputation_id.clone(),
            plan_canonical_sha256: first.plan_canonical_sha256.clone(),
            plan_timestamp_sha256: first.plan_timestamp_sha256.clone(),
            custodian_authorization_sha256: first.custodian_authorization_sha256.clone(),
            custodian_authorization_timestamp_sha256: first
                .custodian_authorization_timestamp_sha256
                .clone(),
            reproducer_authorization_sha256: first.reproducer_authorization_sha256.clone(),
            reproducer_authorization_timestamp_sha256: first
                .reproducer_authorization_timestamp_sha256
                .clone(),
            run_id: first.run_id.clone(),
            terminal_due_at_ms: first.terminal_due_at_ms,
            registration_entry_sha256: "d".repeat(64),
            recomputation_evidence_canonical_sha256: "a".repeat(64),
            final_manifest_canonical_sha256: "b".repeat(64),
            status: DomainStudyRecomputationStatus::AggregateExactMatch,
        };
        assert!(uniqueness.record_terminal(&terminal));
        let mut duplicate_evidence = terminal;
        duplicate_evidence.recomputation_id = "another_recomputation".to_string();
        duplicate_evidence.run_id = "d".repeat(64);
        duplicate_evidence.final_manifest_canonical_sha256 = "c".repeat(64);
        assert!(!uniqueness.record_terminal(&duplicate_evidence));
    }

    #[test]
    fn checkpoint_must_add_the_target_terminal_after_the_retained_anchor() {
        assert!(checkpoint_is_strict_target_extension(2, 1, 0));
        assert!(checkpoint_is_strict_target_extension(3, 2, 2));
        assert!(!checkpoint_is_strict_target_extension(2, 1, 2));
        assert!(!checkpoint_is_strict_target_extension(3, 1, 2));
        assert!(!checkpoint_is_strict_target_extension(3, 3, 2));
    }

    #[test]
    fn trusted_deadline_proof_uses_inclusive_end_of_millisecond_and_checks_overflow() {
        let checkpoint = TrustedTimeIntervalMicros {
            earliest_us: 10_000,
            latest_us: 10_999,
        };
        assert!(trusted_deadline_compliance(checkpoint, 10));
        let one_microsecond_late = TrustedTimeIntervalMicros {
            earliest_us: 10_000,
            latest_us: 11_000,
        };
        assert!(!trusted_deadline_compliance(one_microsecond_late, 10));
        assert!(!trusted_deadline_compliance(checkpoint, u64::MAX));
    }
}
