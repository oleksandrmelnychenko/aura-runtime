//! Independent aggregate-recomputation evidence for domain studies.
//!
//! This module validates one preregistered, authorized, timestamped attempt to
//! recompute the content-free aggregate result from a private reproduction
//! package. An exact match is an independent computational-reproduction
//! candidate. It is not a scientific replication on a new sample and does not
//! prove that a process actually ran outside the declared trust environment.

use std::collections::HashSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    domain_study_result_canonical_json, domain_study_result_canonical_sha256, is_canonical_sha256,
    research_result::domain_study_recomputed_outcome_status,
    validate_domain_study_reproduction_manifest, DomainModuleEvidence, DomainStudyBuildProvenance,
    DomainStudyDetachedSignature, DomainStudyEvidenceStatus, DomainStudyOutcomeStatus,
    DomainStudyPreregistration, DomainStudyReproductionError, DomainStudyReproductionFileIdentity,
    DomainStudyReproductionManifest, DomainStudyResultError, DomainStudyResultEvidenceBundle,
    DomainStudyResultMetrics, DomainStudyTimestampProtocol, DomainStudyTrustPolicy,
    DomainStudyTrustedKey,
};

/// Supported recomputation trust-policy schema.
pub const DOMAIN_STUDY_RECOMPUTATION_TRUST_POLICY_SCHEMA_VERSION: &str =
    "aura.domain.independent_recomputation_trust_policy.v1";
/// Supported aggregate-recomputation plan schema.
pub const DOMAIN_STUDY_RECOMPUTATION_PLAN_SCHEMA_VERSION: &str =
    "aura.domain.aggregate_recomputation_plan.v1";
/// Supported private execution-specification schema.
pub const DOMAIN_STUDY_RECOMPUTATION_EXECUTION_SPECIFICATION_SCHEMA_VERSION: &str =
    "aura.domain.aggregate_recomputation_execution_specification.v1";
/// Supported evidence-custodian authorization schema.
pub const DOMAIN_STUDY_RECOMPUTATION_CUSTODIAN_AUTHORIZATION_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_custodian_authorization.v1";
/// Supported independent-reproducer authorization schema.
pub const DOMAIN_STUDY_RECOMPUTATION_REPRODUCER_AUTHORIZATION_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_reproducer_authorization.v1";
/// Supported execution-start commitment schema.
pub const DOMAIN_STUDY_RECOMPUTATION_START_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_execution_start.v1";
/// Supported no-deviation declaration schema.
pub const DOMAIN_STUDY_RECOMPUTATION_NO_DEVIATION_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_no_deviation_manifest.v1";
/// Supported execution-attestation schema.
pub const DOMAIN_STUDY_RECOMPUTATION_EXECUTION_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_execution_attestation.v1";
/// Supported normalized aggregate-result schema.
pub const DOMAIN_STUDY_RECOMPUTATION_NORMALIZED_RESULT_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_normalized_aggregate_result.v1";
/// Supported deterministic comparison schema.
pub const DOMAIN_STUDY_RECOMPUTATION_COMPARISON_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_comparison.v1";
/// Supported recomputation final-manifest schema.
pub const DOMAIN_STUDY_RECOMPUTATION_FINAL_MANIFEST_SCHEMA_VERSION: &str =
    "aura.domain.recomputation_final_manifest.v1";
/// Supported complete recomputation-evidence schema.
pub const DOMAIN_STUDY_RECOMPUTATION_EVIDENCE_SCHEMA_VERSION: &str =
    "aura.domain.independent_recomputation_evidence.v1";
/// Supported recomputation timestamp-receipt schema.
pub const DOMAIN_STUDY_RECOMPUTATION_TIMESTAMP_SCHEMA_VERSION: &str =
    "aura.domain.independent_recomputation_timestamp_verification.v1";

const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_TIMESTAMP_ACCURACY_MICROS: u64 = 5 * 60 * 1_000_000;
const MAX_COMMAND_ARGUMENTS: usize = 64;
const MAX_COMMAND_ARGUMENT_BYTES: usize = 1_024;
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

const CUSTODIAN_AUTHORIZATION_DOMAIN: &[u8] =
    b"aura.domain.recomputation-custodian-authorization.v1\0";
const REPRODUCER_AUTHORIZATION_DOMAIN: &[u8] =
    b"aura.domain.recomputation-reproducer-authorization.v1\0";
const EXECUTION_START_DOMAIN: &[u8] = b"aura.domain.recomputation-execution-start.v1\0";
const EXECUTION_ATTESTATION_DOMAIN: &[u8] = b"aura.domain.recomputation-execution-attestation.v1\0";
const FINAL_MANIFEST_DOMAIN: &[u8] = b"aura.domain.recomputation-final-manifest.v1\0";
const TRUSTED_TIMESTAMP_DOMAIN: &[u8] =
    b"aura.domain.independent-recomputation-trusted-timestamp.v1\0";
const RUN_ID_DOMAIN: &[u8] = b"aura.domain.recomputation-run-id.v1\0";
const CERTIFICATE_CHAIN_DOMAIN: &[u8] = b"aura.domain.rfc3161-certificate-chain.v1\0";
const REVOCATION_EVIDENCE_DOMAIN: &[u8] = b"aura.domain.rfc3161-revocation-evidence.v1\0";

/// Error returned when recomputation evidence is malformed or untrusted.
#[derive(Debug, Error)]
pub enum DomainStudyRecomputationError {
    /// The bound private reproduction package failed validation.
    #[error("invalid bound domain-study reproduction package: {0}")]
    InvalidReproduction(#[from] DomainStudyReproductionError),
    /// A canonical result binding could not be calculated.
    #[error("invalid bound domain-study result: {0}")]
    InvalidResult(#[from] DomainStudyResultError),
    /// A supplied JSON document does not match its strict typed schema.
    #[error("invalid domain-study recomputation JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A trust, signature, chronology, privacy, or comparison invariant failed.
    #[error("invalid domain-study recomputation evidence: {0}")]
    InvalidEvidence(String),
}

/// Trust roots for the independent aggregate-recomputation workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyRecomputationTrustPolicy {
    /// Schema identity.
    pub schema_version: String,
    /// Key authorizing controlled access to the private evidence package.
    pub evidence_custodian_authorizer: DomainStudyTrustedKey,
    /// Salted commitment to the custodian affiliation record.
    pub evidence_custodian_affiliation_commitment_sha256: String,
    /// Key accepting the frozen plan for the independent reproducer.
    pub independent_reproducer_authorizer: DomainStudyTrustedKey,
    /// Salted commitment to the independent reproducer affiliation record.
    pub independent_reproducer_affiliation_commitment_sha256: String,
    /// Separate operational key signing start and execution attestations.
    pub executor: DomainStudyTrustedKey,
    /// Affiliation commitment expected for the executor.
    pub executor_affiliation_commitment_sha256: String,
    /// Key used only by the recomputation RFC 3161 adapter.
    pub timestamp_verifier: DomainStudyTrustedKey,
    /// Allowed TSA subject-public-key-info digest.
    pub trusted_tsa_spki_sha256: String,
    /// Allowed RFC 3161 policy object identifier.
    pub trusted_tsa_policy_oid: String,
    /// Independent key signing the terminal recomputation manifest.
    pub final_manifest_signer: DomainStudyTrustedKey,
}

/// Network boundary fixed for the aggregate recomputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationNetworkPolicy {
    /// No network input is admissible during the fixed attempt.
    DenyAll,
}

/// Closed normalization rule supported by this schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationNormalizationProfile {
    /// Exact metrics, agreement IEEE-754 bits, and frozen outcome.
    MetricsAgreementBitsOutcomeV1,
}

/// Private, typed execution specification fixed before authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationExecutionSpecification {
    /// Schema identity.
    pub schema_version: String,
    /// Structured executable and arguments; no shell command string is accepted.
    pub command_argv: Vec<String>,
    /// Digest of the bounded runner implementation.
    pub runner_sha256: String,
    /// Digest of the exact typed comparator implementation.
    pub comparator_sha256: String,
    /// Evaluated source-tree identity.
    pub source_tree_sha256: String,
    /// Evaluated executable identity.
    pub evaluated_binary_sha256: String,
    /// Exact analysis implementation and environment lock.
    pub analysis_environment_sha256: String,
    /// Content-addressed operating-system, architecture, and hardware class.
    pub hardware_class_sha256: String,
    /// Explicit allowlisted environment manifest.
    pub environment_allowlist_sha256: String,
    /// Complete known-seed registry identity.
    pub known_seed_registry_sha256: String,
    /// Fixed agreement bootstrap seed identity.
    pub agreement_bootstrap_seed_sha256: String,
    /// Fixed network boundary.
    pub network_policy: DomainStudyRecomputationNetworkPolicy,
    /// Maximum wall-clock duration accepted by the runner.
    pub maximum_wall_clock_ms: u64,
    /// Maximum CPU duration accepted by the runner.
    pub maximum_cpu_time_ms: u64,
    /// Maximum resident memory accepted by the runner.
    pub maximum_rss_bytes: u64,
    /// Maximum aggregate output bytes accepted by the runner.
    pub maximum_output_bytes: u64,
}

/// Canonical plan approved before access and execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationPlan {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Stable original study identity.
    pub study_id: String,
    /// Stable original result identity.
    pub result_id: String,
    /// Canonical original preregistration digest.
    pub original_preregistration_canonical_sha256: String,
    /// Canonical original aggregate-result digest.
    pub original_result_bundle_sha256: String,
    /// Canonical original signed final-manifest digest.
    pub original_final_manifest_sha256: String,
    /// Canonical complete original evidence-bundle digest.
    pub original_evidence_bundle_canonical_sha256: String,
    /// Canonical private reproduction-package digest.
    pub reproduction_manifest_canonical_sha256: String,
    /// Canonical original result trust-policy digest.
    pub original_trust_policy_canonical_sha256: String,
    /// Canonical recomputation trust-policy digest.
    pub recomputation_trust_policy_canonical_sha256: String,
    /// Fully typed private execution specification.
    pub execution_specification: DomainStudyRecomputationExecutionSpecification,
    /// Closed normalization rule.
    pub normalization_profile: DomainStudyRecomputationNormalizationProfile,
    /// Must be one for this submitted bundle; global uniqueness needs a registry.
    pub planned_attempt_count: u8,
    /// Must be false for the v1 confirmatory contract.
    pub deviations_permitted: bool,
    /// Must be false for the private input contract.
    pub raw_content_export_permitted: bool,
    /// Must be false; validation never authorizes public disclosure.
    pub public_distribution_permitted: bool,
}

/// Claims signed by the controlled evidence custodian.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationCustodianAuthorizationClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Canonical plan digest.
    pub plan_canonical_sha256: String,
    /// Trusted timestamp receipt covering the canonical plan.
    pub plan_timestamp_sha256: String,
    /// Only executor key authorized for this attempt.
    pub authorized_executor_key_id: String,
    /// Expected custodian affiliation commitment.
    pub affiliation_commitment_sha256: String,
    /// Content-addressed governance, access, retention, and disclosure scope.
    pub governance_scope_sha256: String,
    /// Random 256-bit custodian contribution encoded as lowercase hexadecimal.
    pub authorization_nonce_hex: String,
    /// Last declared millisecond at which the start commitment remains allowed.
    pub valid_until_ms: u64,
    /// Declared signing time; trusted order comes from RFC 3161.
    pub authorized_at_ms: u64,
    /// Must remain false.
    pub raw_content_export_permitted: bool,
    /// Must remain false.
    pub public_distribution_permitted: bool,
}

/// Custodian-signed access authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudySignedRecomputationCustodianAuthorization {
    /// Signed authorization claims.
    pub claims: DomainStudyRecomputationCustodianAuthorizationClaims,
    /// Detached custodian signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Claims signed by the independent reproducer before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationReproducerAuthorizationClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Canonical plan digest.
    pub plan_canonical_sha256: String,
    /// Canonical signed custodian-authorization digest.
    pub custodian_authorization_sha256: String,
    /// Trusted timestamp covering the custodian authorization.
    pub custodian_authorization_timestamp_sha256: String,
    /// Only executor key accepted for this attempt.
    pub authorized_executor_key_id: String,
    /// Expected independent-reproducer affiliation commitment.
    pub affiliation_commitment_sha256: String,
    /// Content-addressed independence and conflict-of-interest declaration.
    pub independence_record_sha256: String,
    /// Random 256-bit reproducer contribution encoded as lowercase hexadecimal.
    pub acceptance_nonce_hex: String,
    /// Last declared millisecond at which the start commitment remains allowed.
    pub valid_until_ms: u64,
    /// Declared acceptance time; trusted order comes from RFC 3161.
    pub accepted_at_ms: u64,
    /// Must remain false.
    pub raw_content_export_permitted: bool,
    /// Must remain false.
    pub public_distribution_permitted: bool,
}

/// Independent-reproducer-signed plan acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudySignedRecomputationReproducerAuthorization {
    /// Signed acceptance claims.
    pub claims: DomainStudyRecomputationReproducerAuthorizationClaims,
    /// Detached reproducer authorization signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Claims fixing the exact single attempt before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationStartClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Domain-separated identifier derived from plan and both nonces.
    pub run_id: String,
    /// Must be zero in the single-attempt v1 protocol.
    pub attempt_ordinal: u8,
    /// Canonical plan digest.
    pub plan_canonical_sha256: String,
    /// Canonical custodian authorization digest.
    pub custodian_authorization_sha256: String,
    /// Custodian authorization timestamp digest.
    pub custodian_authorization_timestamp_sha256: String,
    /// Canonical reproducer authorization digest.
    pub reproducer_authorization_sha256: String,
    /// Reproducer authorization timestamp digest.
    pub reproducer_authorization_timestamp_sha256: String,
    /// Canonical private reproduction-package digest observed by the executor.
    pub observed_reproduction_manifest_canonical_sha256: String,
    /// Canonical plan execution-specification digest observed by the executor.
    pub observed_execution_specification_canonical_sha256: String,
    /// Declared commitment time; trusted order comes from RFC 3161.
    pub committed_at_ms: u64,
}

/// Executor-signed commitment fixing the exact attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudySignedRecomputationStart {
    /// Signed start claims.
    pub claims: DomainStudyRecomputationStartClaims,
    /// Detached executor signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Mandatory declaration for the no-deviation v1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationNoDeviationManifest {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Stable run identity.
    pub run_id: String,
    /// Must be true to declare the inventory complete.
    pub complete_inventory_declared: bool,
    /// Must be zero for v1.
    pub deviation_count: u8,
}

/// Terminal execution disposition attested by the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationExecutionDisposition {
    /// Runner claims a successful zero-exit aggregate recomputation.
    Succeeded,
    /// Runner claims a terminal failed attempt with no normalized result.
    Failed,
}

/// Closed failure classification for a terminal failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationFailureKind {
    /// The process returned a nonzero exit code.
    ProcessExit,
    /// The process terminated through a signal.
    ProcessSignal,
    /// The bounded runner failed before a process result was available.
    RunnerFailure,
    /// A required immutable input was unavailable.
    InputUnavailable,
    /// A required output was unavailable or incomplete.
    OutputUnavailable,
}

/// Claims signed by the executor after the single terminal attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationExecutionClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Stable run identity.
    pub run_id: String,
    /// Must remain zero.
    pub attempt_ordinal: u8,
    /// Canonical plan digest.
    pub plan_canonical_sha256: String,
    /// Canonical signed start-commitment digest.
    pub signed_start_commitment_sha256: String,
    /// Trusted timestamp covering the signed start commitment.
    pub start_timestamp_sha256: String,
    /// Observed private reproduction-package digest.
    pub observed_reproduction_manifest_canonical_sha256: String,
    /// Observed canonical execution-specification digest.
    pub observed_execution_specification_canonical_sha256: String,
    /// Terminal execution disposition.
    pub disposition: DomainStudyRecomputationExecutionDisposition,
    /// Process exit code when one exists.
    pub process_exit_code: Option<i32>,
    /// Failure classification for a failed attempt.
    pub failure_kind: Option<DomainStudyRecomputationFailureKind>,
    /// Digest of the complete private output-artifact manifest.
    pub output_artifact_manifest_sha256: String,
    /// Digest of the complete private execution transcript.
    pub execution_transcript_sha256: String,
    /// Canonical no-deviation-manifest digest.
    pub no_deviation_manifest_canonical_sha256: String,
    /// Canonical normalized result digest only for successful execution.
    pub normalized_result_canonical_sha256: Option<String>,
    /// Executor-reported wall-clock duration for this terminal attempt.
    pub observed_wall_clock_ms: u64,
    /// Executor-reported CPU time consumed by this terminal attempt.
    pub observed_cpu_time_ms: u64,
    /// Executor-reported peak resident memory in bytes.
    pub observed_peak_rss_bytes: u64,
    /// Executor-reported aggregate output size in bytes.
    pub observed_output_bytes: u64,
    /// Executor-declared start time.
    pub declared_started_at_ms: u64,
    /// Executor-declared completion time.
    pub declared_completed_at_ms: u64,
    /// Must remain false in the content-free evidence bundle.
    pub raw_content_exported: bool,
}

/// Executor-signed execution attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudySignedRecomputationExecution {
    /// Signed execution claims.
    pub claims: DomainStudyRecomputationExecutionClaims,
    /// Detached executor signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Exact content-free aggregate result used by the comparator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationNormalizedResult {
    /// Schema identity.
    pub schema_version: String,
    /// All integer aggregate counts in the original result schema.
    pub metrics: DomainStudyResultMetrics,
    /// Exact IEEE-754 bits for nominal agreement, when defined.
    pub agreement_f64_bits: Option<u64>,
    /// Exact IEEE-754 bits for the conservative agreement lower bound.
    pub agreement_95_lower_f64_bits: Option<u64>,
    /// Frozen primary outcome recomputed by the original validator.
    pub outcome_status: DomainStudyOutcomeStatus,
    /// Must remain false.
    pub raw_content_exported: bool,
    /// Must remain false.
    pub reviewer_identifiers_exported: bool,
}

/// Core-computed status of the submitted single attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationStatus {
    /// A structurally valid signed failed attempt was submitted.
    ExecutionFailed,
    /// Successful execution produced a different normalized aggregate result.
    NormalizedMismatch,
    /// Successful execution exactly matched all normalized aggregate fields.
    AggregateExactMatch,
}

/// Deterministic comparison generated and rechecked by the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationComparison {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Stable run identity.
    pub run_id: String,
    /// Canonical plan digest.
    pub plan_canonical_sha256: String,
    /// Canonical signed execution-attestation digest.
    pub signed_execution_attestation_sha256: String,
    /// Canonical normalized original result digest.
    pub original_normalized_result_canonical_sha256: String,
    /// Canonical normalized recomputed result digest, if execution succeeded.
    pub recomputed_normalized_result_canonical_sha256: Option<String>,
    /// Core-derived comparison status.
    pub status: DomainStudyRecomputationStatus,
}

/// Claims signed by the terminal independent verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationFinalManifestClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Stable run identity.
    pub run_id: String,
    /// Canonical plan digest.
    pub plan_canonical_sha256: String,
    /// Plan timestamp digest.
    pub plan_timestamp_sha256: String,
    /// Canonical signed custodian authorization digest.
    pub custodian_authorization_sha256: String,
    /// Custodian authorization timestamp digest.
    pub custodian_authorization_timestamp_sha256: String,
    /// Canonical signed reproducer authorization digest.
    pub reproducer_authorization_sha256: String,
    /// Reproducer authorization timestamp digest.
    pub reproducer_authorization_timestamp_sha256: String,
    /// Canonical signed start commitment digest.
    pub signed_start_commitment_sha256: String,
    /// Start timestamp digest.
    pub start_timestamp_sha256: String,
    /// Canonical signed execution-attestation digest.
    pub signed_execution_attestation_sha256: String,
    /// Execution timestamp digest.
    pub execution_timestamp_sha256: String,
    /// Canonical no-deviation-manifest digest.
    pub no_deviation_manifest_canonical_sha256: String,
    /// Canonical deterministic comparison digest.
    pub comparison_canonical_sha256: String,
    /// Comparison timestamp digest.
    pub comparison_timestamp_sha256: String,
    /// Canonical recomputation trust-policy digest.
    pub recomputation_trust_policy_canonical_sha256: String,
    /// Core-derived status.
    pub status: DomainStudyRecomputationStatus,
    /// Declared manifest completion time.
    pub completed_at_ms: u64,
    /// Must remain false.
    pub raw_content_exported: bool,
    /// Must remain false.
    pub public_distribution_permitted: bool,
}

/// Signed terminal recomputation manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudySignedRecomputationFinalManifest {
    /// Signed terminal claims.
    pub claims: DomainStudyRecomputationFinalManifestClaims,
    /// Detached terminal-verifier signature.
    pub signature: DomainStudyDetachedSignature,
}

/// Kind of recomputation artifact covered by the separate timestamp schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationTimestampSubjectKind {
    /// Canonical unsigned plan.
    RecomputationPlan,
    /// Signed evidence-custodian authorization.
    EvidenceCustodianAuthorization,
    /// Signed independent-reproducer authorization.
    IndependentReproducerAuthorization,
    /// Signed executor start commitment.
    ExecutionStartCommitment,
    /// Signed executor execution attestation.
    ExecutionAttestation,
    /// Core-computed deterministic comparison.
    ComparisonReceipt,
    /// Signed terminal recomputation manifest.
    RecomputationFinalManifest,
}

/// Claims emitted by the separate recomputation RFC 3161 adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationTimestampClaims {
    /// Schema identity.
    pub schema_version: String,
    /// Covered recomputation artifact kind.
    pub subject_kind: DomainStudyRecomputationTimestampSubjectKind,
    /// Canonical SHA-256 of the complete covered artifact.
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

/// Signed recomputation timestamp-verification receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationTimestampReceipt {
    /// Signed trusted-time claims.
    pub claims: DomainStudyRecomputationTimestampClaims,
    /// Signature from the recomputation timestamp-verifier key.
    pub signature: DomainStudyDetachedSignature,
}

/// Original material retained for one recomputation timestamp receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationTimestampMaterial {
    /// Covered recomputation artifact kind.
    pub subject_kind: DomainStudyRecomputationTimestampSubjectKind,
    /// Original nonce-bearing DER request.
    pub request: DomainStudyReproductionFileIdentity,
    /// Original DER response.
    pub response: DomainStudyReproductionFileIdentity,
    /// Exact selected DER chain ordered signer to trust anchor.
    pub certificate_chain_der: Vec<DomainStudyReproductionFileIdentity>,
    /// Exact complete CRL DER set sorted by SHA-256.
    pub revocation_crl_der: Vec<DomainStudyReproductionFileIdentity>,
}

/// Complete private verification input for one submitted recomputation attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStudyRecomputationEvidenceBundle {
    /// Schema identity.
    pub schema_version: String,
    /// Canonical frozen plan.
    pub plan: DomainStudyRecomputationPlan,
    /// Trusted timestamp covering the plan.
    pub plan_timestamp: DomainStudyRecomputationTimestampReceipt,
    /// Custodian-signed access authorization.
    pub custodian_authorization: DomainStudySignedRecomputationCustodianAuthorization,
    /// Trusted timestamp covering the custodian authorization.
    pub custodian_authorization_timestamp: DomainStudyRecomputationTimestampReceipt,
    /// Independent-reproducer plan acceptance.
    pub reproducer_authorization: DomainStudySignedRecomputationReproducerAuthorization,
    /// Trusted timestamp covering independent acceptance.
    pub reproducer_authorization_timestamp: DomainStudyRecomputationTimestampReceipt,
    /// Executor-signed start commitment.
    pub start_commitment: DomainStudySignedRecomputationStart,
    /// Trusted timestamp covering the start commitment.
    pub start_timestamp: DomainStudyRecomputationTimestampReceipt,
    /// Mandatory no-deviation declaration.
    pub no_deviation_manifest: DomainStudyRecomputationNoDeviationManifest,
    /// Executor-signed terminal execution attestation.
    pub execution_attestation: DomainStudySignedRecomputationExecution,
    /// Trusted timestamp covering the execution attestation.
    pub execution_timestamp: DomainStudyRecomputationTimestampReceipt,
    /// Normalized result only for a claimed successful execution.
    pub normalized_result: Option<DomainStudyRecomputationNormalizedResult>,
    /// Deterministic core comparison supplied for exact rechecking.
    pub comparison: DomainStudyRecomputationComparison,
    /// Trusted timestamp covering the comparison.
    pub comparison_timestamp: DomainStudyRecomputationTimestampReceipt,
    /// Signed terminal manifest.
    pub final_manifest: DomainStudySignedRecomputationFinalManifest,
    /// Trusted timestamp covering the terminal manifest.
    pub final_manifest_timestamp: DomainStudyRecomputationTimestampReceipt,
    /// Path-free original material for all seven new timestamp receipts.
    pub timestamp_materials: Vec<DomainStudyRecomputationTimestampMaterial>,
}

/// Maximum scientific claim supported by the successful report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStudyRecomputationClaimCeiling {
    /// A trusted key attested one submitted recomputation attempt.
    SubmittedRecomputationAttemptAttestation,
    /// One submitted run exactly matched the frozen aggregate result.
    IndependentComputationalReproductionCandidate,
}

/// Content-free report for one validated submitted recomputation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainStudyRecomputationReport {
    /// Stable study identity.
    pub study_id: String,
    /// Stable original result identity.
    pub result_id: String,
    /// Stable recomputation identity.
    pub recomputation_id: String,
    /// Stable submitted run identity.
    pub run_id: String,
    /// Core-derived status.
    pub status: DomainStudyRecomputationStatus,
    /// Maximum bounded claim supported by the status.
    pub claim_ceiling: DomainStudyRecomputationClaimCeiling,
    /// Original evidence maturity; never raised by this validator.
    pub original_evidence_status: DomainStudyEvidenceStatus,
    /// Original frozen outcome; never replaced by this validator.
    pub original_outcome_status: DomainStudyOutcomeStatus,
    /// Canonical reproduction-package digest.
    pub reproduction_manifest_canonical_sha256: String,
    /// Canonical recomputation plan digest.
    pub plan_canonical_sha256: String,
    /// Canonical deterministic comparison digest.
    pub comparison_canonical_sha256: String,
    /// Canonical signed terminal-manifest digest.
    pub final_manifest_canonical_sha256: String,
    /// Canonical digest of the complete submitted recomputation-evidence bundle.
    pub recomputation_evidence_canonical_sha256: String,
    /// True only for exact aggregate equality.
    pub aggregate_exact_match: bool,
    /// Always false: same-data recomputation is not a new-sample replication.
    pub scientific_replication_established: bool,
    /// Always false: research evidence cannot activate product policy.
    pub policy_activation_authorized: bool,
    /// Always false: this report never authorizes disclosure.
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

/// Produces the custodian-authorization signing payload.
pub fn domain_study_recomputation_custodian_authorization_signing_payload(
    claims: &DomainStudyRecomputationCustodianAuthorizationClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationError> {
    signing_payload(CUSTODIAN_AUTHORIZATION_DOMAIN, claims, key_id)
}

/// Produces the independent-reproducer authorization signing payload.
pub fn domain_study_recomputation_reproducer_authorization_signing_payload(
    claims: &DomainStudyRecomputationReproducerAuthorizationClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationError> {
    signing_payload(REPRODUCER_AUTHORIZATION_DOMAIN, claims, key_id)
}

/// Produces the execution-start signing payload.
pub fn domain_study_recomputation_start_signing_payload(
    claims: &DomainStudyRecomputationStartClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationError> {
    signing_payload(EXECUTION_START_DOMAIN, claims, key_id)
}

/// Produces the execution-attestation signing payload.
pub fn domain_study_recomputation_execution_signing_payload(
    claims: &DomainStudyRecomputationExecutionClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationError> {
    signing_payload(EXECUTION_ATTESTATION_DOMAIN, claims, key_id)
}

/// Produces the terminal recomputation-manifest signing payload.
pub fn domain_study_recomputation_final_manifest_signing_payload(
    claims: &DomainStudyRecomputationFinalManifestClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationError> {
    signing_payload(FINAL_MANIFEST_DOMAIN, claims, key_id)
}

/// Produces the separate recomputation timestamp-receipt signing payload.
pub fn domain_study_recomputation_timestamp_signing_payload(
    claims: &DomainStudyRecomputationTimestampClaims,
    key_id: &str,
) -> Result<Vec<u8>, DomainStudyRecomputationError> {
    signing_payload(TRUSTED_TIMESTAMP_DOMAIN, claims, key_id)
}

/// Derives the single run identifier from the plan and both random contributions.
pub fn domain_study_recomputation_run_id(
    plan_canonical_sha256: &str,
    authorization_nonce_hex: &str,
    acceptance_nonce_hex: &str,
) -> Result<String, DomainStudyRecomputationError> {
    let plan = decode_sha256(plan_canonical_sha256)
        .ok_or_else(|| invalid_error("recomputation plan digest is malformed"))?;
    let custodian = decode_sha256(authorization_nonce_hex)
        .ok_or_else(|| invalid_error("custodian authorization nonce is malformed"))?;
    let reproducer = decode_sha256(acceptance_nonce_hex)
        .ok_or_else(|| invalid_error("reproducer acceptance nonce is malformed"))?;
    if custodian == [0_u8; 32] || reproducer == [0_u8; 32] || custodian == reproducer {
        return invalid("run identifier requires two distinct nonzero 256-bit nonce contributions");
    }
    let mut hasher = Sha256::new();
    hasher.update(RUN_ID_DOMAIN);
    hasher.update(plan);
    hasher.update(custodian);
    hasher.update(reproducer);
    Ok(hex_bytes(&hasher.finalize()))
}

/// Builds the exact normalized original result after its chain is validated.
pub fn domain_study_recomputation_normalized_result(
    result: &crate::DomainStudyResultBundle,
    outcome_status: DomainStudyOutcomeStatus,
) -> DomainStudyRecomputationNormalizedResult {
    DomainStudyRecomputationNormalizedResult {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_NORMALIZED_RESULT_SCHEMA_VERSION.to_string(),
        metrics: result.metrics.clone(),
        agreement_f64_bits: result.review_agreement_analysis.agreement.map(f64::to_bits),
        agreement_95_lower_f64_bits: result
            .review_agreement_analysis
            .agreement_95_lower
            .map(f64::to_bits),
        outcome_status,
        raw_content_exported: false,
        reviewer_identifiers_exported: false,
    }
}

/// Validates one complete submitted independent aggregate-recomputation chain.
#[expect(
    clippy::too_many_arguments,
    reason = "the trust boundary keeps independently governed evidence inputs explicit"
)]
pub fn validate_domain_study_independent_recomputation(
    preregistration_json: &str,
    result_evidence_json: &str,
    reproduction_manifest_json: &str,
    recomputation_evidence_json: &str,
    expected_policy_evidence: &DomainModuleEvidence,
    expected_build_provenance: &DomainStudyBuildProvenance,
    additional_known_seed_sha256: &[&str],
    original_trust_policy: &DomainStudyTrustPolicy,
    recomputation_trust_policy: &DomainStudyRecomputationTrustPolicy,
) -> Result<DomainStudyRecomputationReport, DomainStudyRecomputationError> {
    if recomputation_evidence_json.is_empty() || recomputation_evidence_json.len() > MAX_JSON_BYTES
    {
        return invalid("recomputation evidence JSON is empty or exceeds the 8 MiB bound");
    }
    validate_recomputation_trust_policy(recomputation_trust_policy, original_trust_policy)?;
    let reproduction_report = validate_domain_study_reproduction_manifest(
        preregistration_json,
        result_evidence_json,
        reproduction_manifest_json,
        expected_policy_evidence,
        expected_build_provenance,
        additional_known_seed_sha256,
        original_trust_policy,
    )?;
    let preregistration: DomainStudyPreregistration = serde_json::from_str(preregistration_json)?;
    let original_evidence: DomainStudyResultEvidenceBundle =
        serde_json::from_str(result_evidence_json)?;
    let reproduction_manifest: DomainStudyReproductionManifest =
        serde_json::from_str(reproduction_manifest_json)?;
    let recomputation: DomainStudyRecomputationEvidenceBundle =
        serde_json::from_str(recomputation_evidence_json)?;
    if recomputation.schema_version != DOMAIN_STUDY_RECOMPUTATION_EVIDENCE_SCHEMA_VERSION {
        return invalid("recomputation evidence schema is unsupported");
    }

    let original_evidence_sha256 = domain_study_result_canonical_sha256(&original_evidence)?;
    let recomputation_evidence_sha256 = domain_study_result_canonical_sha256(&recomputation)?;
    let original_trust_sha256 = domain_study_result_canonical_sha256(original_trust_policy)?;
    let recomputation_trust_sha256 =
        domain_study_result_canonical_sha256(recomputation_trust_policy)?;
    let plan = &recomputation.plan;
    let plan_sha256 = domain_study_result_canonical_sha256(plan)?;
    let execution_specification_sha256 =
        domain_study_result_canonical_sha256(&plan.execution_specification)?;
    validate_plan(
        plan,
        &preregistration,
        &original_evidence,
        &reproduction_manifest,
        &reproduction_report,
        &original_evidence_sha256,
        &original_trust_sha256,
        &recomputation_trust_sha256,
    )?;

    let original_final_time = trusted_interval_from_claims(
        original_evidence
            .final_manifest_timestamp
            .claims
            .issued_at_ms,
        original_evidence
            .final_manifest_timestamp
            .claims
            .gen_time_submillisecond_micros,
        original_evidence
            .final_manifest_timestamp
            .claims
            .accuracy_micros,
    )?;
    let plan_time = validate_timestamp(
        &recomputation.plan_timestamp,
        DomainStudyRecomputationTimestampSubjectKind::RecomputationPlan,
        &plan_sha256,
        recomputation_trust_policy,
    )?;
    ensure_strictly_after(original_final_time, plan_time, "recomputation plan")?;

    let plan_timestamp_sha256 =
        domain_study_result_canonical_sha256(&recomputation.plan_timestamp)?;
    let custodian = &recomputation.custodian_authorization;
    let expected_custodian_claims = DomainStudyRecomputationCustodianAuthorizationClaims {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_CUSTODIAN_AUTHORIZATION_SCHEMA_VERSION
            .to_string(),
        recomputation_id: plan.recomputation_id.clone(),
        plan_canonical_sha256: plan_sha256.clone(),
        plan_timestamp_sha256: plan_timestamp_sha256.clone(),
        authorized_executor_key_id: recomputation_trust_policy.executor.key_id.clone(),
        affiliation_commitment_sha256: recomputation_trust_policy
            .evidence_custodian_affiliation_commitment_sha256
            .clone(),
        governance_scope_sha256: custodian.claims.governance_scope_sha256.clone(),
        authorization_nonce_hex: custodian.claims.authorization_nonce_hex.clone(),
        valid_until_ms: custodian.claims.valid_until_ms,
        authorized_at_ms: custodian.claims.authorized_at_ms,
        raw_content_export_permitted: false,
        public_distribution_permitted: false,
    };
    if custodian.claims != expected_custodian_claims
        || !is_canonical_sha256(&custodian.claims.governance_scope_sha256)
        || !is_nonzero_sha256(&custodian.claims.authorization_nonce_hex)
        || custodian.claims.authorized_at_ms == 0
        || custodian.claims.valid_until_ms <= custodian.claims.authorized_at_ms
    {
        return invalid("custodian authorization does not exactly bind the frozen plan");
    }
    verify_signed_claims(
        CUSTODIAN_AUTHORIZATION_DOMAIN,
        &custodian.claims,
        &custodian.signature,
        &recomputation_trust_policy.evidence_custodian_authorizer,
        "recomputation custodian authorization",
    )?;
    let custodian_sha256 = domain_study_result_canonical_sha256(custodian)?;
    let custodian_time = validate_timestamp(
        &recomputation.custodian_authorization_timestamp,
        DomainStudyRecomputationTimestampSubjectKind::EvidenceCustodianAuthorization,
        &custodian_sha256,
        recomputation_trust_policy,
    )?;
    ensure_strictly_after(plan_time, custodian_time, "custodian authorization")?;
    validate_declared_time(
        custodian.claims.authorized_at_ms,
        plan_time,
        custodian_time,
        "custodian authorization",
    )?;

    let custodian_timestamp_sha256 =
        domain_study_result_canonical_sha256(&recomputation.custodian_authorization_timestamp)?;
    let reproducer = &recomputation.reproducer_authorization;
    let expected_reproducer_claims = DomainStudyRecomputationReproducerAuthorizationClaims {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_REPRODUCER_AUTHORIZATION_SCHEMA_VERSION
            .to_string(),
        recomputation_id: plan.recomputation_id.clone(),
        plan_canonical_sha256: plan_sha256.clone(),
        custodian_authorization_sha256: custodian_sha256.clone(),
        custodian_authorization_timestamp_sha256: custodian_timestamp_sha256.clone(),
        authorized_executor_key_id: recomputation_trust_policy.executor.key_id.clone(),
        affiliation_commitment_sha256: recomputation_trust_policy
            .independent_reproducer_affiliation_commitment_sha256
            .clone(),
        independence_record_sha256: reproducer.claims.independence_record_sha256.clone(),
        acceptance_nonce_hex: reproducer.claims.acceptance_nonce_hex.clone(),
        valid_until_ms: reproducer.claims.valid_until_ms,
        accepted_at_ms: reproducer.claims.accepted_at_ms,
        raw_content_export_permitted: false,
        public_distribution_permitted: false,
    };
    if reproducer.claims != expected_reproducer_claims
        || !is_canonical_sha256(&reproducer.claims.independence_record_sha256)
        || !is_nonzero_sha256(&reproducer.claims.acceptance_nonce_hex)
        || reproducer.claims.acceptance_nonce_hex == custodian.claims.authorization_nonce_hex
        || reproducer.claims.accepted_at_ms == 0
        || reproducer.claims.valid_until_ms <= reproducer.claims.accepted_at_ms
    {
        return invalid("independent-reproducer authorization does not bind the prior chain");
    }
    verify_signed_claims(
        REPRODUCER_AUTHORIZATION_DOMAIN,
        &reproducer.claims,
        &reproducer.signature,
        &recomputation_trust_policy.independent_reproducer_authorizer,
        "independent-reproducer authorization",
    )?;
    let reproducer_sha256 = domain_study_result_canonical_sha256(reproducer)?;
    let reproducer_time = validate_timestamp(
        &recomputation.reproducer_authorization_timestamp,
        DomainStudyRecomputationTimestampSubjectKind::IndependentReproducerAuthorization,
        &reproducer_sha256,
        recomputation_trust_policy,
    )?;
    ensure_strictly_after(
        custodian_time,
        reproducer_time,
        "independent-reproducer authorization",
    )?;
    validate_declared_time(
        reproducer.claims.accepted_at_ms,
        custodian_time,
        reproducer_time,
        "independent-reproducer authorization",
    )?;

    let run_id = domain_study_recomputation_run_id(
        &plan_sha256,
        &custodian.claims.authorization_nonce_hex,
        &reproducer.claims.acceptance_nonce_hex,
    )?;
    let reproducer_timestamp_sha256 =
        domain_study_result_canonical_sha256(&recomputation.reproducer_authorization_timestamp)?;
    let expected_start_claims = DomainStudyRecomputationStartClaims {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_START_SCHEMA_VERSION.to_string(),
        recomputation_id: plan.recomputation_id.clone(),
        run_id: run_id.clone(),
        attempt_ordinal: 0,
        plan_canonical_sha256: plan_sha256.clone(),
        custodian_authorization_sha256: custodian_sha256.clone(),
        custodian_authorization_timestamp_sha256: custodian_timestamp_sha256.clone(),
        reproducer_authorization_sha256: reproducer_sha256.clone(),
        reproducer_authorization_timestamp_sha256: reproducer_timestamp_sha256.clone(),
        observed_reproduction_manifest_canonical_sha256: reproduction_report
            .reproduction_manifest_canonical_sha256
            .clone(),
        observed_execution_specification_canonical_sha256: execution_specification_sha256.clone(),
        committed_at_ms: recomputation.start_commitment.claims.committed_at_ms,
    };
    if recomputation.start_commitment.claims != expected_start_claims
        || recomputation.start_commitment.claims.committed_at_ms == 0
    {
        return invalid("execution-start commitment does not bind the authorized attempt");
    }
    verify_signed_claims(
        EXECUTION_START_DOMAIN,
        &recomputation.start_commitment.claims,
        &recomputation.start_commitment.signature,
        &recomputation_trust_policy.executor,
        "recomputation execution-start commitment",
    )?;
    let start_sha256 = domain_study_result_canonical_sha256(&recomputation.start_commitment)?;
    let start_time = validate_timestamp(
        &recomputation.start_timestamp,
        DomainStudyRecomputationTimestampSubjectKind::ExecutionStartCommitment,
        &start_sha256,
        recomputation_trust_policy,
    )?;
    ensure_strictly_after(reproducer_time, start_time, "execution-start commitment")?;
    validate_declared_time(
        recomputation.start_commitment.claims.committed_at_ms,
        reproducer_time,
        start_time,
        "execution-start commitment",
    )?;
    let valid_until_us = custodian
        .claims
        .valid_until_ms
        .min(reproducer.claims.valid_until_ms)
        .checked_mul(1_000)
        .ok_or_else(|| invalid_error("authorization expiry overflows microseconds"))?;
    if start_time.latest_us > valid_until_us {
        return invalid("execution start is not provably within both authorization windows");
    }

    let no_deviation = &recomputation.no_deviation_manifest;
    if no_deviation.schema_version != DOMAIN_STUDY_RECOMPUTATION_NO_DEVIATION_SCHEMA_VERSION
        || no_deviation.recomputation_id != plan.recomputation_id
        || no_deviation.run_id != run_id
        || !no_deviation.complete_inventory_declared
        || no_deviation.deviation_count != 0
    {
        return invalid("v1 requires a complete, explicitly empty deviation manifest");
    }
    let no_deviation_sha256 = domain_study_result_canonical_sha256(no_deviation)?;
    let start_timestamp_sha256 =
        domain_study_result_canonical_sha256(&recomputation.start_timestamp)?;
    validate_execution_claims(
        &recomputation.execution_attestation.claims,
        plan,
        &run_id,
        &plan_sha256,
        &start_sha256,
        &start_timestamp_sha256,
        &reproduction_report.reproduction_manifest_canonical_sha256,
        &execution_specification_sha256,
        &no_deviation_sha256,
        recomputation.normalized_result.as_ref(),
    )?;
    verify_signed_claims(
        EXECUTION_ATTESTATION_DOMAIN,
        &recomputation.execution_attestation.claims,
        &recomputation.execution_attestation.signature,
        &recomputation_trust_policy.executor,
        "recomputation execution attestation",
    )?;
    let execution_sha256 =
        domain_study_result_canonical_sha256(&recomputation.execution_attestation)?;
    let execution_time = validate_timestamp(
        &recomputation.execution_timestamp,
        DomainStudyRecomputationTimestampSubjectKind::ExecutionAttestation,
        &execution_sha256,
        recomputation_trust_policy,
    )?;
    ensure_strictly_after(start_time, execution_time, "execution attestation")?;
    validate_execution_declared_times(
        &recomputation.execution_attestation.claims,
        start_time,
        execution_time,
    )?;

    let original_normalized = domain_study_recomputation_normalized_result(
        &original_evidence.result,
        reproduction_report.outcome_status,
    );
    validate_normalized_result(
        &original_normalized,
        &preregistration,
        &original_evidence.result.metrics.review_coverage,
    )?;
    if let Some(normalized) = &recomputation.normalized_result {
        validate_normalized_result(
            normalized,
            &preregistration,
            &original_evidence.result.metrics.review_coverage,
        )?;
    }
    let original_normalized_sha256 = domain_study_result_canonical_sha256(&original_normalized)?;
    let recomputed_normalized_sha256 = recomputation
        .normalized_result
        .as_ref()
        .map(domain_study_result_canonical_sha256)
        .transpose()?;
    let status = match recomputation.execution_attestation.claims.disposition {
        DomainStudyRecomputationExecutionDisposition::Failed => {
            DomainStudyRecomputationStatus::ExecutionFailed
        }
        DomainStudyRecomputationExecutionDisposition::Succeeded
            if recomputation.normalized_result.as_ref() == Some(&original_normalized) =>
        {
            DomainStudyRecomputationStatus::AggregateExactMatch
        }
        DomainStudyRecomputationExecutionDisposition::Succeeded => {
            DomainStudyRecomputationStatus::NormalizedMismatch
        }
    };
    let expected_comparison = DomainStudyRecomputationComparison {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_COMPARISON_SCHEMA_VERSION.to_string(),
        recomputation_id: plan.recomputation_id.clone(),
        run_id: run_id.clone(),
        plan_canonical_sha256: plan_sha256.clone(),
        signed_execution_attestation_sha256: execution_sha256.clone(),
        original_normalized_result_canonical_sha256: original_normalized_sha256,
        recomputed_normalized_result_canonical_sha256: recomputed_normalized_sha256,
        status,
    };
    if recomputation.comparison != expected_comparison {
        return invalid("submitted comparison is not the exact core-derived comparison");
    }
    let comparison_sha256 = domain_study_result_canonical_sha256(&expected_comparison)?;
    let comparison_time = validate_timestamp(
        &recomputation.comparison_timestamp,
        DomainStudyRecomputationTimestampSubjectKind::ComparisonReceipt,
        &comparison_sha256,
        recomputation_trust_policy,
    )?;
    ensure_strictly_after(execution_time, comparison_time, "core comparison")?;

    let execution_timestamp_sha256 =
        domain_study_result_canonical_sha256(&recomputation.execution_timestamp)?;
    let comparison_timestamp_sha256 =
        domain_study_result_canonical_sha256(&recomputation.comparison_timestamp)?;
    let expected_final_claims = DomainStudyRecomputationFinalManifestClaims {
        schema_version: DOMAIN_STUDY_RECOMPUTATION_FINAL_MANIFEST_SCHEMA_VERSION.to_string(),
        recomputation_id: plan.recomputation_id.clone(),
        run_id: run_id.clone(),
        plan_canonical_sha256: plan_sha256.clone(),
        plan_timestamp_sha256,
        custodian_authorization_sha256: custodian_sha256,
        custodian_authorization_timestamp_sha256: custodian_timestamp_sha256,
        reproducer_authorization_sha256: reproducer_sha256,
        reproducer_authorization_timestamp_sha256: reproducer_timestamp_sha256,
        signed_start_commitment_sha256: start_sha256,
        start_timestamp_sha256,
        signed_execution_attestation_sha256: execution_sha256,
        execution_timestamp_sha256,
        no_deviation_manifest_canonical_sha256: no_deviation_sha256,
        comparison_canonical_sha256: comparison_sha256.clone(),
        comparison_timestamp_sha256,
        recomputation_trust_policy_canonical_sha256: recomputation_trust_sha256,
        status,
        completed_at_ms: recomputation.final_manifest.claims.completed_at_ms,
        raw_content_exported: false,
        public_distribution_permitted: false,
    };
    if recomputation.final_manifest.claims != expected_final_claims
        || recomputation.final_manifest.claims.completed_at_ms == 0
    {
        return invalid("terminal recomputation manifest does not bind the complete chain");
    }
    verify_signed_claims(
        FINAL_MANIFEST_DOMAIN,
        &recomputation.final_manifest.claims,
        &recomputation.final_manifest.signature,
        &recomputation_trust_policy.final_manifest_signer,
        "recomputation final manifest",
    )?;
    let final_manifest_sha256 =
        domain_study_result_canonical_sha256(&recomputation.final_manifest)?;
    let final_time = validate_timestamp(
        &recomputation.final_manifest_timestamp,
        DomainStudyRecomputationTimestampSubjectKind::RecomputationFinalManifest,
        &final_manifest_sha256,
        recomputation_trust_policy,
    )?;
    ensure_strictly_after(comparison_time, final_time, "recomputation final manifest")?;
    validate_declared_time(
        recomputation.final_manifest.claims.completed_at_ms,
        comparison_time,
        final_time,
        "recomputation final manifest",
    )?;

    validate_timestamp_materials(&recomputation.timestamp_materials, &recomputation)?;

    Ok(DomainStudyRecomputationReport {
        study_id: reproduction_report.study_id,
        result_id: reproduction_report.result_id,
        recomputation_id: plan.recomputation_id.clone(),
        run_id,
        status,
        claim_ceiling: if status == DomainStudyRecomputationStatus::AggregateExactMatch {
            DomainStudyRecomputationClaimCeiling::IndependentComputationalReproductionCandidate
        } else {
            DomainStudyRecomputationClaimCeiling::SubmittedRecomputationAttemptAttestation
        },
        original_evidence_status: reproduction_report.evidence_status,
        original_outcome_status: reproduction_report.outcome_status,
        reproduction_manifest_canonical_sha256: reproduction_report
            .reproduction_manifest_canonical_sha256,
        plan_canonical_sha256: plan_sha256,
        comparison_canonical_sha256: comparison_sha256,
        final_manifest_canonical_sha256: final_manifest_sha256,
        recomputation_evidence_canonical_sha256: recomputation_evidence_sha256,
        aggregate_exact_match: status == DomainStudyRecomputationStatus::AggregateExactMatch,
        scientific_replication_established: false,
        policy_activation_authorized: false,
        public_distribution_permitted: false,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "the plan binding check keeps every independently validated predecessor explicit"
)]
fn validate_plan(
    plan: &DomainStudyRecomputationPlan,
    preregistration: &DomainStudyPreregistration,
    original_evidence: &DomainStudyResultEvidenceBundle,
    reproduction_manifest: &DomainStudyReproductionManifest,
    reproduction_report: &crate::DomainStudyReproductionReport,
    original_evidence_sha256: &str,
    original_trust_sha256: &str,
    recomputation_trust_sha256: &str,
) -> Result<(), DomainStudyRecomputationError> {
    if plan.schema_version != DOMAIN_STUDY_RECOMPUTATION_PLAN_SCHEMA_VERSION
        || !safe_token(&plan.recomputation_id)
        || plan.study_id != reproduction_report.study_id
        || plan.result_id != reproduction_report.result_id
        || plan.original_preregistration_canonical_sha256
            != reproduction_manifest.preregistration_canonical_sha256
        || plan.original_result_bundle_sha256 != reproduction_manifest.result_bundle_sha256
        || plan.original_final_manifest_sha256 != reproduction_manifest.final_manifest_sha256
        || plan.original_evidence_bundle_canonical_sha256 != original_evidence_sha256
        || plan.reproduction_manifest_canonical_sha256
            != reproduction_report.reproduction_manifest_canonical_sha256
        || plan.original_trust_policy_canonical_sha256 != original_trust_sha256
        || plan.recomputation_trust_policy_canonical_sha256 != recomputation_trust_sha256
        || plan.normalization_profile
            != DomainStudyRecomputationNormalizationProfile::MetricsAgreementBitsOutcomeV1
        || plan.planned_attempt_count != 1
        || plan.deviations_permitted
        || plan.raw_content_export_permitted
        || plan.public_distribution_permitted
        || reproduction_manifest.study_id != plan.study_id
        || original_evidence.result.result_id != plan.result_id
    {
        return invalid("recomputation plan does not exactly bind the validated original chain");
    }
    validate_execution_specification(
        &plan.execution_specification,
        preregistration,
        original_evidence,
    )
}

fn validate_execution_specification(
    specification: &DomainStudyRecomputationExecutionSpecification,
    preregistration: &DomainStudyPreregistration,
    original_evidence: &DomainStudyResultEvidenceBundle,
) -> Result<(), DomainStudyRecomputationError> {
    if specification.schema_version
        != DOMAIN_STUDY_RECOMPUTATION_EXECUTION_SPECIFICATION_SCHEMA_VERSION
        || specification.command_argv.is_empty()
        || specification.command_argv.len() > MAX_COMMAND_ARGUMENTS
        || specification.command_argv.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > MAX_COMMAND_ARGUMENT_BYTES
                || argument.chars().any(char::is_control)
        })
        || !is_canonical_sha256(&specification.runner_sha256)
        || !is_canonical_sha256(&specification.comparator_sha256)
        || specification.source_tree_sha256 != preregistration.build_provenance.source_tree_sha256
        || specification.evaluated_binary_sha256 != preregistration.build_provenance.binary_sha256
        || specification.analysis_environment_sha256
            != original_evidence.result.analysis_environment_sha256
        || !is_canonical_sha256(&specification.hardware_class_sha256)
        || !is_canonical_sha256(&specification.environment_allowlist_sha256)
        || specification.known_seed_registry_sha256
            != preregistration.dataset.known_seed_registry_sha256
        || specification.agreement_bootstrap_seed_sha256
            != preregistration
                .analysis
                .inter_rater_agreement_bootstrap_seed_sha256
        || specification.network_policy != DomainStudyRecomputationNetworkPolicy::DenyAll
        || specification.maximum_wall_clock_ms == 0
        || specification.maximum_cpu_time_ms == 0
        || specification.maximum_rss_bytes == 0
        || specification.maximum_output_bytes == 0
    {
        return invalid("recomputation execution specification is malformed or unbound");
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the internal binding check names every signed predecessor explicitly"
)]
fn validate_execution_claims(
    claims: &DomainStudyRecomputationExecutionClaims,
    plan: &DomainStudyRecomputationPlan,
    run_id: &str,
    plan_sha256: &str,
    start_sha256: &str,
    start_timestamp_sha256: &str,
    reproduction_manifest_sha256: &str,
    execution_specification_sha256: &str,
    no_deviation_sha256: &str,
    normalized_result: Option<&DomainStudyRecomputationNormalizedResult>,
) -> Result<(), DomainStudyRecomputationError> {
    let normalized_sha256 = normalized_result
        .map(domain_study_result_canonical_sha256)
        .transpose()?;
    let declared_wall_clock_ms = claims
        .declared_completed_at_ms
        .checked_sub(claims.declared_started_at_ms)
        .ok_or_else(|| invalid_error("declared execution duration underflows"))?;
    if claims.schema_version != DOMAIN_STUDY_RECOMPUTATION_EXECUTION_SCHEMA_VERSION
        || claims.recomputation_id != plan.recomputation_id
        || claims.run_id != run_id
        || claims.attempt_ordinal != 0
        || claims.plan_canonical_sha256 != plan_sha256
        || claims.signed_start_commitment_sha256 != start_sha256
        || claims.start_timestamp_sha256 != start_timestamp_sha256
        || claims.observed_reproduction_manifest_canonical_sha256 != reproduction_manifest_sha256
        || claims.observed_execution_specification_canonical_sha256
            != execution_specification_sha256
        || claims.no_deviation_manifest_canonical_sha256 != no_deviation_sha256
        || claims.normalized_result_canonical_sha256 != normalized_sha256
        || claims.observed_wall_clock_ms != declared_wall_clock_ms
        || !is_canonical_sha256(&claims.output_artifact_manifest_sha256)
        || !is_canonical_sha256(&claims.execution_transcript_sha256)
        || claims.declared_started_at_ms == 0
        || claims.declared_completed_at_ms < claims.declared_started_at_ms
        || claims.raw_content_exported
    {
        return invalid("execution attestation is malformed or does not bind the fixed attempt");
    }
    if !execution_disposition_valid(
        claims,
        &plan.execution_specification,
        normalized_result.is_some(),
    ) {
        return invalid("execution disposition, exit code, failure, and result are inconsistent");
    }
    Ok(())
}

fn execution_disposition_valid(
    claims: &DomainStudyRecomputationExecutionClaims,
    specification: &DomainStudyRecomputationExecutionSpecification,
    has_normalized_result: bool,
) -> bool {
    match claims.disposition {
        DomainStudyRecomputationExecutionDisposition::Succeeded => {
            claims.process_exit_code == Some(0)
                && claims.failure_kind.is_none()
                && has_normalized_result
                && claims.observed_wall_clock_ms <= specification.maximum_wall_clock_ms
                && claims.observed_cpu_time_ms <= specification.maximum_cpu_time_ms
                && claims.observed_peak_rss_bytes <= specification.maximum_rss_bytes
                && claims.observed_output_bytes <= specification.maximum_output_bytes
        }
        DomainStudyRecomputationExecutionDisposition::Failed => {
            !has_normalized_result
                && match (claims.failure_kind, claims.process_exit_code) {
                    (Some(DomainStudyRecomputationFailureKind::ProcessExit), Some(code)) => {
                        code != 0
                    }
                    (
                        Some(
                            DomainStudyRecomputationFailureKind::ProcessSignal
                            | DomainStudyRecomputationFailureKind::RunnerFailure
                            | DomainStudyRecomputationFailureKind::InputUnavailable
                            | DomainStudyRecomputationFailureKind::OutputUnavailable,
                        ),
                        None,
                    ) => true,
                    _ => false,
                }
        }
    }
}

fn validate_normalized_result(
    normalized: &DomainStudyRecomputationNormalizedResult,
    preregistration: &DomainStudyPreregistration,
    expected_review_coverage: &crate::DomainStudyReviewCoverage,
) -> Result<(), DomainStudyRecomputationError> {
    if normalized.schema_version != DOMAIN_STUDY_RECOMPUTATION_NORMALIZED_RESULT_SCHEMA_VERSION
        || normalized.raw_content_exported
        || normalized.reviewer_identifiers_exported
        || !valid_agreement_bits(
            normalized.agreement_f64_bits,
            normalized.agreement_95_lower_f64_bits,
        )
    {
        return invalid("normalized aggregate result is malformed or privacy-unsafe");
    }
    let agreement = normalized.agreement_f64_bits.map(f64::from_bits);
    let agreement_lower = normalized.agreement_95_lower_f64_bits.map(f64::from_bits);
    let outcome = domain_study_recomputed_outcome_status(
        &normalized.metrics,
        agreement,
        agreement_lower,
        preregistration,
        expected_review_coverage,
    )?;
    if normalized.outcome_status != outcome {
        return invalid("normalized outcome is not derived from the frozen analysis plan");
    }
    Ok(())
}

fn valid_agreement_bits(point_bits: Option<u64>, lower_bits: Option<u64>) -> bool {
    let point = point_bits.map(f64::from_bits);
    let lower = lower_bits.map(f64::from_bits);
    let valid = |value: f64| {
        value.is_finite()
            && (-1.0..=1.0).contains(&value)
            && !(value == 0.0 && value.is_sign_negative())
    };
    point.is_none_or(valid)
        && lower.is_none_or(valid)
        && match (point, lower) {
            (Some(point), Some(lower)) => lower <= point,
            (None, Some(_)) => false,
            _ => true,
        }
}

fn validate_recomputation_trust_policy(
    policy: &DomainStudyRecomputationTrustPolicy,
    original: &DomainStudyTrustPolicy,
) -> Result<(), DomainStudyRecomputationError> {
    if policy.schema_version != DOMAIN_STUDY_RECOMPUTATION_TRUST_POLICY_SCHEMA_VERSION
        || !is_canonical_sha256(&policy.evidence_custodian_affiliation_commitment_sha256)
        || !is_canonical_sha256(&policy.independent_reproducer_affiliation_commitment_sha256)
        || policy.executor_affiliation_commitment_sha256
            != policy.independent_reproducer_affiliation_commitment_sha256
        || policy.evidence_custodian_affiliation_commitment_sha256
            == policy.independent_reproducer_affiliation_commitment_sha256
        || !is_canonical_sha256(&policy.trusted_tsa_spki_sha256)
        || !safe_oid(&policy.trusted_tsa_policy_oid)
    {
        return invalid("recomputation trust policy identity or affiliation is invalid");
    }
    let recomputation_keys = [
        &policy.evidence_custodian_authorizer,
        &policy.independent_reproducer_authorizer,
        &policy.executor,
        &policy.timestamp_verifier,
        &policy.final_manifest_signer,
    ];
    for key in recomputation_keys {
        validate_trusted_key(key)?;
    }
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
    {
        if !key_ids.insert(key.key_id.as_str()) || !public_keys.insert(key.public_key_hex.as_str())
        {
            return invalid("all original and recomputation evidence roles require distinct keys");
        }
    }
    if original.reviewers.iter().any(|reviewer| {
        reviewer.affiliation_commitment_sha256
            == policy.independent_reproducer_affiliation_commitment_sha256
    }) {
        return invalid("independent reproducer affiliation overlaps an original reviewer");
    }
    Ok(())
}

fn validate_trusted_key(key: &DomainStudyTrustedKey) -> Result<(), DomainStudyRecomputationError> {
    if !safe_token(&key.key_id) {
        return invalid("trusted recomputation key identifier is invalid");
    }
    let public_key = decode_hex_array::<32>(&key.public_key_hex)
        .ok_or_else(|| invalid_error("trusted recomputation public key is malformed"))?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| invalid_error("trusted recomputation public key is invalid"))?;
    Ok(())
}

fn validate_timestamp(
    receipt: &DomainStudyRecomputationTimestampReceipt,
    expected_kind: DomainStudyRecomputationTimestampSubjectKind,
    expected_subject_sha256: &str,
    trust: &DomainStudyRecomputationTrustPolicy,
) -> Result<TrustedTimeIntervalMicros, DomainStudyRecomputationError> {
    let claims = &receipt.claims;
    if claims.schema_version != DOMAIN_STUDY_RECOMPUTATION_TIMESTAMP_SCHEMA_VERSION
        || claims.subject_kind != expected_kind
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
        return invalid("recomputation trusted timestamp is malformed or outside policy");
    }
    verify_signed_claims(
        TRUSTED_TIMESTAMP_DOMAIN,
        claims,
        &receipt.signature,
        &trust.timestamp_verifier,
        "recomputation trusted timestamp",
    )?;
    trusted_interval_from_claims(
        claims.issued_at_ms,
        claims.gen_time_submillisecond_micros,
        claims.accuracy_micros,
    )
}

fn trusted_interval_from_claims(
    issued_at_ms: u64,
    submillisecond_micros: u16,
    accuracy_micros: u64,
) -> Result<TrustedTimeIntervalMicros, DomainStudyRecomputationError> {
    let exact = issued_at_ms
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(u64::from(submillisecond_micros)))
        .ok_or_else(|| invalid_error("trusted timestamp generation time overflows"))?;
    let earliest_us = exact
        .checked_sub(accuracy_micros)
        .ok_or_else(|| invalid_error("trusted timestamp interval underflows"))?;
    let latest_us = exact
        .checked_add(accuracy_micros)
        .ok_or_else(|| invalid_error("trusted timestamp interval overflows"))?;
    Ok(TrustedTimeIntervalMicros {
        earliest_us,
        latest_us,
    })
}

fn ensure_strictly_after(
    previous: TrustedTimeIntervalMicros,
    current: TrustedTimeIntervalMicros,
    label: &str,
) -> Result<(), DomainStudyRecomputationError> {
    if previous.latest_us >= current.earliest_us {
        return invalid(format!("{label} trusted interval overlaps its predecessor"));
    }
    Ok(())
}

fn validate_declared_time(
    declared_at_ms: u64,
    previous: TrustedTimeIntervalMicros,
    current: TrustedTimeIntervalMicros,
    label: &str,
) -> Result<(), DomainStudyRecomputationError> {
    let declared_us = declared_at_ms
        .checked_mul(1_000)
        .ok_or_else(|| invalid_error(format!("{label} declared time overflows")))?;
    if declared_us <= previous.latest_us || declared_us > current.latest_us {
        return invalid(format!(
            "{label} declared time is outside the trusted sequence"
        ));
    }
    Ok(())
}

fn validate_execution_declared_times(
    claims: &DomainStudyRecomputationExecutionClaims,
    start: TrustedTimeIntervalMicros,
    execution: TrustedTimeIntervalMicros,
) -> Result<(), DomainStudyRecomputationError> {
    let started = claims
        .declared_started_at_ms
        .checked_mul(1_000)
        .ok_or_else(|| invalid_error("declared execution start overflows"))?;
    let completed = claims
        .declared_completed_at_ms
        .checked_mul(1_000)
        .ok_or_else(|| invalid_error("declared execution completion overflows"))?;
    if started <= start.latest_us || completed < started || completed > execution.latest_us {
        return invalid("declared execution interval is inconsistent with trusted document order");
    }
    Ok(())
}

fn validate_timestamp_materials(
    materials: &[DomainStudyRecomputationTimestampMaterial],
    evidence: &DomainStudyRecomputationEvidenceBundle,
) -> Result<(), DomainStudyRecomputationError> {
    let expected = [
        (
            DomainStudyRecomputationTimestampSubjectKind::RecomputationPlan,
            &evidence.plan_timestamp,
        ),
        (
            DomainStudyRecomputationTimestampSubjectKind::EvidenceCustodianAuthorization,
            &evidence.custodian_authorization_timestamp,
        ),
        (
            DomainStudyRecomputationTimestampSubjectKind::IndependentReproducerAuthorization,
            &evidence.reproducer_authorization_timestamp,
        ),
        (
            DomainStudyRecomputationTimestampSubjectKind::ExecutionStartCommitment,
            &evidence.start_timestamp,
        ),
        (
            DomainStudyRecomputationTimestampSubjectKind::ExecutionAttestation,
            &evidence.execution_timestamp,
        ),
        (
            DomainStudyRecomputationTimestampSubjectKind::ComparisonReceipt,
            &evidence.comparison_timestamp,
        ),
        (
            DomainStudyRecomputationTimestampSubjectKind::RecomputationFinalManifest,
            &evidence.final_manifest_timestamp,
        ),
    ];
    if materials.len() != expected.len() {
        return invalid("recomputation timestamp material inventory must contain seven groups");
    }
    for (material, (expected_kind, receipt)) in materials.iter().zip(expected) {
        if material.subject_kind != expected_kind
            || material.request.sha256 != receipt.claims.request_sha256
            || material.response.sha256 != receipt.claims.response_sha256
        {
            return invalid("recomputation timestamp material does not match its receipt");
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
            return invalid("recomputation TSA signer certificate exceeds its adapter bound");
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
            return invalid("recomputation timestamp chain or CRL evidence is incomplete");
        }
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
) -> Result<(), DomainStudyRecomputationError> {
    if !(minimum..=maximum).contains(&members.len()) {
        return invalid("recomputation timestamp material count is outside its bound");
    }
    let mut seen = HashSet::new();
    let mut previous = None;
    let mut total_bytes = 0_u64;
    for member in members {
        validate_file_identity(member, maximum_member_bytes)?;
        total_bytes = total_bytes
            .checked_add(member.byte_length)
            .ok_or_else(|| invalid_error("recomputation timestamp byte total overflows"))?;
        if !seen.insert(member.sha256.as_str())
            || (sorted && previous.is_some_and(|value: &str| value >= member.sha256.as_str()))
        {
            return invalid("recomputation timestamp material is duplicated or unsorted");
        }
        previous = Some(member.sha256.as_str());
    }
    if total_bytes > maximum_total_bytes {
        return invalid("recomputation timestamp material exceeds its aggregate adapter bound");
    }
    Ok(())
}

fn validate_file_identity(
    file: &DomainStudyReproductionFileIdentity,
    maximum_bytes: u64,
) -> Result<(), DomainStudyRecomputationError> {
    if !is_canonical_sha256(&file.sha256)
        || file.byte_length == 0
        || file.byte_length > maximum_bytes
    {
        return invalid("recomputation retained-file identity is invalid");
    }
    Ok(())
}

fn aggregate_digest<'a>(
    domain: &[u8],
    digests: impl Iterator<Item = &'a str>,
) -> Result<String, DomainStudyRecomputationError> {
    let decoded = digests
        .map(|value| decode_sha256(value).ok_or_else(|| invalid_error("digest is malformed")))
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

fn verify_signed_claims<T: Serialize>(
    domain: &[u8],
    claims: &T,
    signature: &DomainStudyDetachedSignature,
    trusted_key: &DomainStudyTrustedKey,
    label: &str,
) -> Result<(), DomainStudyRecomputationError> {
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
) -> Result<Vec<u8>, DomainStudyRecomputationError> {
    if !safe_token(key_id) {
        return invalid("recomputation signing key identifier is invalid");
    }
    let mut payload = domain.to_vec();
    payload.extend(domain_study_result_canonical_json(&SignedClaims {
        key_id,
        claims,
    })?);
    Ok(payload)
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    decode_hex_array(value)
}

fn is_nonzero_sha256(value: &str) -> bool {
    decode_sha256(value).is_some_and(|bytes| bytes.iter().any(|byte| *byte != 0))
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

fn invalid<T>(message: impl Into<String>) -> Result<T, DomainStudyRecomputationError> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> DomainStudyRecomputationError {
    DomainStudyRecomputationError::InvalidEvidence(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution_claims() -> DomainStudyRecomputationExecutionClaims {
        DomainStudyRecomputationExecutionClaims {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_EXECUTION_SCHEMA_VERSION.to_string(),
            recomputation_id: "recomputation_test".to_string(),
            run_id: "a".repeat(64),
            attempt_ordinal: 0,
            plan_canonical_sha256: "b".repeat(64),
            signed_start_commitment_sha256: "c".repeat(64),
            start_timestamp_sha256: "d".repeat(64),
            observed_reproduction_manifest_canonical_sha256: "a".repeat(64),
            observed_execution_specification_canonical_sha256: "b".repeat(64),
            disposition: DomainStudyRecomputationExecutionDisposition::Succeeded,
            process_exit_code: Some(0),
            failure_kind: None,
            output_artifact_manifest_sha256: "c".repeat(64),
            execution_transcript_sha256: "d".repeat(64),
            no_deviation_manifest_canonical_sha256: "a".repeat(64),
            normalized_result_canonical_sha256: Some("b".repeat(64)),
            observed_wall_clock_ms: 1,
            observed_cpu_time_ms: 1,
            observed_peak_rss_bytes: 1,
            observed_output_bytes: 1,
            declared_started_at_ms: 1,
            declared_completed_at_ms: 2,
            raw_content_exported: false,
        }
    }

    #[test]
    fn trusted_microsecond_intervals_round_outward_and_must_not_touch() {
        let interval = trusted_interval_from_claims(1_000, 999, 1_000).expect("interval");
        assert_eq!(interval.earliest_us, 999_999);
        assert_eq!(interval.latest_us, 1_001_999);

        let touching = TrustedTimeIntervalMicros {
            earliest_us: interval.latest_us,
            latest_us: interval.latest_us + 1,
        };
        assert!(ensure_strictly_after(interval, touching, "touching").is_err());
        let separated = TrustedTimeIntervalMicros {
            earliest_us: interval.latest_us + 1,
            latest_us: interval.latest_us + 2,
        };
        ensure_strictly_after(interval, separated, "separated").expect("strict separation");
    }

    #[test]
    fn execution_failure_kind_and_exit_code_are_unambiguous() {
        let mut claims = execution_claims();
        let specification = DomainStudyRecomputationExecutionSpecification {
            schema_version: DOMAIN_STUDY_RECOMPUTATION_EXECUTION_SPECIFICATION_SCHEMA_VERSION
                .to_string(),
            command_argv: vec!["runner".to_string()],
            runner_sha256: "a".repeat(64),
            comparator_sha256: "b".repeat(64),
            source_tree_sha256: "c".repeat(64),
            evaluated_binary_sha256: "d".repeat(64),
            analysis_environment_sha256: "a".repeat(64),
            hardware_class_sha256: "b".repeat(64),
            environment_allowlist_sha256: "c".repeat(64),
            known_seed_registry_sha256: "d".repeat(64),
            agreement_bootstrap_seed_sha256: "a".repeat(64),
            network_policy: DomainStudyRecomputationNetworkPolicy::DenyAll,
            maximum_wall_clock_ms: 1,
            maximum_cpu_time_ms: 1,
            maximum_rss_bytes: 1,
            maximum_output_bytes: 1,
        };
        assert!(execution_disposition_valid(&claims, &specification, true));
        assert!(!execution_disposition_valid(&claims, &specification, false));

        claims.disposition = DomainStudyRecomputationExecutionDisposition::Failed;
        claims.failure_kind = Some(DomainStudyRecomputationFailureKind::ProcessExit);
        claims.process_exit_code = Some(17);
        assert!(execution_disposition_valid(&claims, &specification, false));
        assert!(!execution_disposition_valid(&claims, &specification, true));

        claims.failure_kind = Some(DomainStudyRecomputationFailureKind::ProcessSignal);
        assert!(!execution_disposition_valid(&claims, &specification, false));
        claims.process_exit_code = None;
        claims.observed_wall_clock_ms = 2;
        assert!(execution_disposition_valid(&claims, &specification, false));

        claims.disposition = DomainStudyRecomputationExecutionDisposition::Succeeded;
        claims.failure_kind = None;
        claims.process_exit_code = Some(0);
        for field in 0..4 {
            claims.observed_wall_clock_ms = 1;
            claims.observed_cpu_time_ms = 1;
            claims.observed_peak_rss_bytes = 1;
            claims.observed_output_bytes = 1;
            match field {
                0 => claims.observed_wall_clock_ms = 2,
                1 => claims.observed_cpu_time_ms = 2,
                2 => claims.observed_peak_rss_bytes = 2,
                3 => claims.observed_output_bytes = 2,
                _ => unreachable!(),
            }
            assert!(!execution_disposition_valid(&claims, &specification, true));
        }
    }

    #[test]
    fn run_identifier_binds_both_independent_nonce_contributions() {
        let first =
            domain_study_recomputation_run_id(&"a".repeat(64), &"b".repeat(64), &"c".repeat(64))
                .expect("first run id");
        let second =
            domain_study_recomputation_run_id(&"a".repeat(64), &"b".repeat(64), &"d".repeat(64))
                .expect("second run id");

        assert_ne!(first, second);
        assert!(is_canonical_sha256(&first));
        assert!(is_canonical_sha256(&second));
        assert!(domain_study_recomputation_run_id(
            &"a".repeat(64),
            &"0".repeat(64),
            &"c".repeat(64)
        )
        .is_err());
        assert!(domain_study_recomputation_run_id(
            &"a".repeat(64),
            &"b".repeat(64),
            &"b".repeat(64)
        )
        .is_err());
    }

    #[test]
    fn retained_timestamp_material_uses_exact_adapter_bounds() {
        let identity = |digest: char, byte_length| DomainStudyReproductionFileIdentity {
            sha256: digest.to_string().repeat(64),
            byte_length,
        };

        validate_file_identity(
            &identity('a', MAX_TIMESTAMP_REQUEST_BYTES),
            MAX_TIMESTAMP_REQUEST_BYTES,
        )
        .expect("maximum request");
        assert!(validate_file_identity(
            &identity('a', MAX_TIMESTAMP_REQUEST_BYTES + 1),
            MAX_TIMESTAMP_REQUEST_BYTES,
        )
        .is_err());

        let maximum_chain = vec![
            identity('a', MAX_TIMESTAMP_SIGNER_CERTIFICATE_BYTES),
            identity('b', MAX_TIMESTAMP_CERTIFICATE_BYTES),
            identity('c', MAX_TIMESTAMP_CERTIFICATE_BYTES),
        ];
        validate_timestamp_members(
            &maximum_chain,
            MIN_TIMESTAMP_CHAIN_CERTIFICATES,
            MAX_TIMESTAMP_CHAIN_CERTIFICATES,
            false,
            MAX_TIMESTAMP_CERTIFICATE_BYTES,
            MAX_TIMESTAMP_CHAIN_BYTES,
        )
        .expect("maximum selected chain");
        let mut oversized_chain = maximum_chain;
        oversized_chain.push(identity('d', 1));
        assert!(validate_timestamp_members(
            &oversized_chain,
            MIN_TIMESTAMP_CHAIN_CERTIFICATES,
            MAX_TIMESTAMP_CHAIN_CERTIFICATES,
            false,
            MAX_TIMESTAMP_CERTIFICATE_BYTES,
            MAX_TIMESTAMP_CHAIN_BYTES,
        )
        .is_err());

        let oversized_crl_set = ['a', 'b', 'c', 'd', 'e']
            .into_iter()
            .map(|digest| identity(digest, MAX_TIMESTAMP_CRL_BYTES))
            .collect::<Vec<_>>();
        assert!(validate_timestamp_members(
            &oversized_crl_set,
            1,
            MAX_TIMESTAMP_REVOCATION_CRLS,
            true,
            MAX_TIMESTAMP_CRL_BYTES,
            MAX_TIMESTAMP_CRL_SET_BYTES,
        )
        .is_err());
    }
}
