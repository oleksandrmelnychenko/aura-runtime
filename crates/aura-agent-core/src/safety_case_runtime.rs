//! Instance-local projection from analyzer output into longitudinal safety cases.
//!
//! The host owns canonical event identity. This module never derives identity
//! from message text and never retains text, explanations, signal payloads, or
//! UI verdicts. Its bounded source ledger is also the pre-analysis idempotency
//! barrier: callers must preflight, or use `AgentRuntime`'s integrated canonical
//! analysis method, before mutating analyzer context.

use std::collections::{HashMap, HashSet};
use std::fmt;

use aura_agent_policy::safety_case::{
    ConversationEventKey, GuardianReportingPolicy, IdentifierError, RiskScore, SafetyCase,
    SafetyCaseCommand, SafetyCaseConstructionError, SafetyCaseDecision, SafetyCaseId,
    SafetyCasePolicy, SafetyCaseReducer, SafetyCaseReducerError, SafetyCaseSeverity,
    SafetyCaseStatus, SafetyCaseSubjectKey, SafetyObservation, SafetyObservationError,
    SafetyObservationId, SafetyReasonCode, SourceEventId, SourceEventKey,
};
use aura_core::{Action, AnalysisResult, ThreatType};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

const DEFAULT_MAX_CASES: usize = 256;
const MAX_CONFIGURED_CASES: usize = 4_096;
const DEFAULT_MAX_SOURCE_RECEIPTS: usize = 65_536;
const MAX_CONFIGURED_SOURCE_RECEIPTS: usize = 1_048_576;
/// Release limit shared by the runtime, FFI import/export, and host store.
pub const SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES: usize = 1024 * 1024;
// A single accepted event can add one receipt, one observation, up to sixteen
// 128-byte reason codes, a new case envelope, and a guardian report containing
// up to sixteen maximally escaped opaque source references. Those public model
// bounds total well below 64 KiB. Reserving 256 KiB keeps the guarantee robust
// against JSON field/schema overhead without relying on observed averages.
const SAFETY_CASE_ACCOUNT_INGEST_RESERVE_BYTES: usize = 256 * 1024;
const MIN_CONFIGURED_ACCOUNT_STATE_BYTES: usize = SAFETY_CASE_ACCOUNT_INGEST_RESERVE_BYTES * 2;
const LEGACY_SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION: &str = "aura.safety_case_runtime.v1";
/// Schema version for encrypted host persistence of [`SafetyCaseRuntime`].
pub const SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION: &str = "aura.safety_case_runtime.v2";

const fn default_max_account_state_bytes() -> usize {
    SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES
}

/// Monotonic identity of one case episode within an account/subject/threat lineage.
///
/// Generation zero is the legacy initial episode. Advancing the generation is
/// always an explicit host-authorized registry operation; ingestion never does
/// so automatically.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct SafetyCaseGeneration(u64);

impl SafetyCaseGeneration {
    /// Legacy-compatible first case episode.
    pub const INITIAL: Self = Self(0);

    /// Creates a generation from its persisted integer representation.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the persisted integer representation.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Opaque account partition used only to prevent cross-account state mixing.
///
/// The value must be a stable, high-entropy host token (or a keyed token of the
/// account identifier). It must not contain account names, addresses, message
/// text, or other display data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafetyAccountKey(String);

impl SafetyAccountKey {
    /// Creates a bounded account partition key.
    pub fn new(value: impl Into<String>) -> Result<Self, SafetyAccountKeyError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SafetyAccountKeyError::Empty);
        }
        if value.len() > 256 {
            return Err(SafetyAccountKeyError::TooLong { max_bytes: 256 });
        }
        if value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(SafetyAccountKeyError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the opaque key without transferring ownership.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SafetyAccountKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SafetyAccountKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for SafetyAccountKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SafetyAccountKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validation error for [`SafetyAccountKey`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyAccountKeyError {
    /// The key was empty.
    #[error("safety account key must not be empty")]
    Empty,
    /// The UTF-8 representation exceeded the release bound.
    #[error("safety account key exceeds {max_bytes} bytes")]
    TooLong {
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
    },
    /// The key contained whitespace or a control character.
    #[error("safety account key contains whitespace or control characters")]
    InvalidCharacter,
}

/// Host-owned identity required for exactly-once safety-case ingestion.
///
/// The runtime derives case and observation identifiers only from these opaque
/// components after the threat family is known. It never hashes message text.
/// Edits must increment `revision`; timestamps are not identity fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyCaseIngestIdentity {
    account_key: SafetyAccountKey,
    subject_key: SafetyCaseSubjectKey,
    source_event: SourceEventKey,
    occurred_at_ms: u64,
    observed_at_ms: u64,
}

impl SafetyCaseIngestIdentity {
    /// Creates an identity from validated, content-free host identifiers.
    pub const fn new(
        account_key: SafetyAccountKey,
        subject_key: SafetyCaseSubjectKey,
        conversation_key: ConversationEventKey,
        event_id: SourceEventId,
        revision: u32,
        occurred_at_ms: u64,
        observed_at_ms: u64,
    ) -> Self {
        Self {
            account_key,
            subject_key,
            source_event: SourceEventKey::new(conversation_key, event_id, revision),
            occurred_at_ms,
            observed_at_ms,
        }
    }

    /// Returns the account partition.
    pub const fn account_key(&self) -> &SafetyAccountKey {
        &self.account_key
    }

    /// Returns the account-scoped protected subject.
    pub const fn subject_key(&self) -> &SafetyCaseSubjectKey {
        &self.subject_key
    }

    /// Returns the canonical source-event key.
    pub const fn source_event(&self) -> &SourceEventKey {
        &self.source_event
    }

    /// Returns when the source event occurred.
    pub const fn occurred_at_ms(&self) -> u64 {
        self.occurred_at_ms
    }

    /// Returns when analysis observes the event.
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
}

/// Why analyzer output produced no longitudinal observation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCaseIgnoredReason {
    /// No threat family was detected.
    NoThreat,
    /// The analyzer explicitly allowed the event.
    NonActionable,
    /// The event carried no positive risk index.
    ZeroRisk,
}

/// Content-free receipt retained for canonical duplicate suppression.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SafetyCaseSourceReceipt {
    /// The event was analyzed but intentionally did not enter case state.
    Ignored(SafetyCaseIgnoredReason),
    /// The observation was accepted or exactly deduplicated by the reducer.
    Applied {
        /// Stable case identifier.
        case_id: SafetyCaseId,
        /// Case revision after the original reduction.
        case_revision: u64,
        /// Case lifecycle state after the original reduction.
        status: SafetyCaseStatus,
    },
    /// Analysis completed, but the projection or reduction was rejected.
    ///
    /// The detailed error is returned only on the first attempt. Retaining this
    /// marker prevents a retry from mutating analyzer context a second time.
    Rejected,
}

/// Result of a source-ledger preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyCaseSourcePreflight {
    /// The event has not yet been processed and source-ledger capacity exists.
    Ready,
    /// This exact account/conversation/event/revision was already processed.
    Duplicate(SafetyCaseSourceReceipt),
    /// A newer revision of this event was already processed.
    Stale {
        /// Highest revision accepted for the canonical event.
        latest_revision: u32,
    },
}

/// Result of projecting one analyzer result into case state.
#[derive(Debug, Clone)]
pub enum SafetyCaseIngestOutcome {
    /// No observation or case was created.
    Ignored(SafetyCaseIgnoredReason),
    /// The deterministic reducer accepted the observation.
    Reduced(Box<SafetyCaseDecision>),
    /// The canonical source ledger suppressed a repeated ingestion.
    DuplicateIgnored(SafetyCaseSourceReceipt),
    /// A newer edit was already processed, so this older revision was ignored.
    StaleIgnored {
        /// Highest revision accepted for the canonical event.
        latest_revision: u32,
    },
}

/// Idempotent result of purging one account partition from native memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyCaseAccountRemoval {
    removed_cases: usize,
    removed_source_receipts: usize,
}

impl SafetyCaseAccountRemoval {
    /// Returns the number of removed longitudinal cases.
    pub const fn removed_cases(self) -> usize {
        self.removed_cases
    }

    /// Returns the number of removed exactly-once source receipts.
    pub const fn removed_source_receipts(self) -> usize {
        self.removed_source_receipts
    }
}

/// Whether an explicit successor activation changed the active case lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyCaseSuccessorActivationDisposition {
    /// A new empty generation became the active route.
    Activated,
    /// The same predecessor had already activated this generation.
    AlreadyActivated,
}

/// Content-free result of explicitly activating one successor generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyCaseSuccessorActivationOutcome {
    disposition: SafetyCaseSuccessorActivationDisposition,
    predecessor_case_id: SafetyCaseId,
    predecessor_generation: SafetyCaseGeneration,
    successor_case_id: SafetyCaseId,
    successor_generation: SafetyCaseGeneration,
    activated_at_ms: u64,
}

impl SafetyCaseSuccessorActivationOutcome {
    /// Returns whether this call activated the route or observed a prior activation.
    pub const fn disposition(&self) -> SafetyCaseSuccessorActivationDisposition {
        self.disposition
    }

    /// Returns the terminal case that authorized the successor.
    pub const fn predecessor_case_id(&self) -> &SafetyCaseId {
        &self.predecessor_case_id
    }

    /// Returns the terminal predecessor generation.
    pub const fn predecessor_generation(&self) -> SafetyCaseGeneration {
        self.predecessor_generation
    }

    /// Returns the deterministic identifier reserved for the successor case.
    pub const fn successor_case_id(&self) -> &SafetyCaseId {
        &self.successor_case_id
    }

    /// Returns the newly active successor generation.
    pub const fn successor_generation(&self) -> SafetyCaseGeneration {
        self.successor_generation
    }

    /// Returns the persisted activation timestamp.
    pub const fn activated_at_ms(&self) -> u64 {
        self.activated_at_ms
    }
}

/// Bounded, instance-local safety-case runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyCaseRuntimeConfig {
    case_policy: SafetyCasePolicy,
    max_cases: usize,
    max_source_receipts: usize,
    #[serde(default = "default_max_account_state_bytes")]
    max_account_state_bytes: usize,
}

impl SafetyCaseRuntimeConfig {
    /// Replaces the reducer policy after validating its persisted fields.
    pub fn with_case_policy(
        mut self,
        case_policy: SafetyCasePolicy,
    ) -> Result<Self, SafetyCaseRuntimeError> {
        case_policy.validate()?;
        self.case_policy = case_policy;
        Ok(self)
    }

    /// Sets the hard number of retained case generations across all lineages.
    pub fn with_max_cases(mut self, maximum: usize) -> Result<Self, SafetyCaseRuntimeError> {
        validate_capacity("safety cases", maximum, MAX_CONFIGURED_CASES)?;
        self.max_cases = maximum;
        Ok(self)
    }

    /// Sets the hard exactly-once receipt capacity.
    ///
    /// Capacity exhaustion is returned during preflight, before analysis can
    /// mutate conversation or Kids context.
    pub fn with_max_source_receipts(
        mut self,
        maximum: usize,
    ) -> Result<Self, SafetyCaseRuntimeError> {
        validate_capacity(
            "safety source receipts",
            maximum,
            MAX_CONFIGURED_SOURCE_RECEIPTS,
        )?;
        self.max_source_receipts = maximum;
        Ok(self)
    }

    /// Sets the compact-JSON persistence budget for one account partition.
    pub fn with_max_account_state_bytes(
        mut self,
        maximum: usize,
    ) -> Result<Self, SafetyCaseRuntimeError> {
        validate_account_state_byte_budget(maximum)?;
        self.max_account_state_bytes = maximum;
        Ok(self)
    }
}

impl Default for SafetyCaseRuntimeConfig {
    fn default() -> Self {
        let guardian_reporting = GuardianReportingPolicy::default()
            .with_report_on_open(false)
            .with_report_on_escalation(false)
            .with_report_on_urgent(false)
            .with_report_on_resolution(false)
            .with_urgent_cooldown_bypass(false);
        Self {
            case_policy: SafetyCasePolicy::default().with_guardian_reporting(guardian_reporting),
            max_cases: DEFAULT_MAX_CASES,
            max_source_receipts: DEFAULT_MAX_SOURCE_RECEIPTS,
            max_account_state_bytes: SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES,
        }
    }
}

/// Error from safety-case projection, validation, or bounded storage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyCaseRuntimeError {
    /// A configured capacity was zero or exceeded its release maximum.
    #[error("{field} must be in 1..={maximum}; received {actual}")]
    InvalidCapacity {
        /// Configuration field.
        field: &'static str,
        /// Supplied value.
        actual: usize,
        /// Maximum supported value.
        maximum: usize,
    },
    /// A configured persistence budget cannot maintain the pre-analysis reserve.
    #[error(
        "safety account state byte budget must be in {minimum}..={maximum}; received {actual}"
    )]
    InvalidAccountStateByteBudget {
        /// Supplied compact-JSON byte budget.
        actual: usize,
        /// Smallest supported budget.
        minimum: usize,
        /// Release maximum shared with the native boundary.
        maximum: usize,
    },
    /// The case reducer policy was invalid.
    #[error(transparent)]
    InvalidPolicy(#[from] aura_agent_policy::safety_case::SafetyCasePolicyError),
    /// An analyzer score was NaN, infinite, or outside `0..=1`.
    #[error("analysis score must be finite and in 0..=1")]
    InvalidAnalysisScore,
    /// The analyzer observation timestamp predates its canonical source event.
    #[error("safety case observation timestamp predates the source event")]
    InvalidIngestTimestamps,
    /// An analyzer reason code did not satisfy the machine-code contract.
    #[error(transparent)]
    InvalidIdentifier(#[from] IdentifierError),
    /// Observation construction or validation failed.
    #[error(transparent)]
    InvalidObservation(#[from] SafetyObservationError),
    /// Empty case construction failed.
    #[error(transparent)]
    InvalidCase(#[from] SafetyCaseConstructionError),
    /// Deterministic reduction rejected the command or persisted state.
    #[error(transparent)]
    Reduction(#[from] SafetyCaseReducerError),
    /// No additional exactly-once receipts can be accepted.
    #[error("safety source receipt capacity of {maximum} is exhausted")]
    SourceReceiptCapacityExceeded {
        /// Configured hard capacity.
        maximum: usize,
    },
    /// No additional cases can be opened without explicit host cleanup.
    #[error("safety case registry capacity of {maximum} is exhausted")]
    CaseCapacityExceeded {
        /// Configured hard capacity.
        maximum: usize,
    },
    /// Accepting another canonical event would violate durable persistence.
    #[error(
        "safety account state byte budget of {maximum} is exhausted: current compact state is {current} bytes and {required_reserve} bytes must remain reserved"
    )]
    AccountStateByteBudgetExceeded {
        /// Configured per-account limit.
        maximum: usize,
        /// Current or candidate compact-JSON size.
        current: usize,
        /// Required pre-analysis growth reserve, or zero for an exact candidate.
        required_reserve: usize,
    },
    /// The host's combined SafetyCase and context persistence envelope is full.
    #[error(
        "combined canonical state byte budget of {maximum} is exhausted: current encoded state is {current} bytes and {required_reserve} bytes must remain reserved"
    )]
    CombinedPersistenceByteBudgetExceeded {
        /// Host envelope limit.
        maximum: usize,
        /// Current or candidate combined encoded size.
        current: usize,
        /// Space required before analysis for a durable rejected receipt.
        required_reserve: usize,
    },
    /// A persistence-guard rollback could not restore an exported snapshot.
    #[error("canonical analyzer context rollback failed")]
    CanonicalContextRollbackFailed,
    /// Compact persistence serialization unexpectedly failed.
    #[error("failed to serialize safety account state: {0}")]
    StateSerialization(String),
    /// One case key was presented with a different case identifier.
    #[error("canonical case key was reused with a different case id")]
    CaseIdentityMismatch,
    /// One case identifier was reused by another account, subject, or threat.
    #[error("safety case id was reused for another case key")]
    CaseIdentityCollision,
    /// One observation identifier was reused for another source event.
    #[error("safety observation id was reused for another source event")]
    ObservationIdentityCollision,
    /// The in-memory indexes disagree, indicating corrupt runtime state.
    #[error("safety case runtime indexes are inconsistent")]
    InconsistentIndex,
    /// The persisted runtime schema is newer or otherwise unsupported.
    #[error("unsupported safety case runtime schema: {0}")]
    UnsupportedStateSchema(String),
    /// Persisted bounded state violates a runtime invariant.
    #[error("invalid persisted safety case runtime: {0}")]
    InvalidPersistedState(&'static str),
    /// Host persistence attempted to mix account partitions.
    #[error("safety case state contains another account partition")]
    AccountPartitionMismatch,
    /// An account snapshot uses a different reducer configuration while other
    /// account partitions are already resident in the runtime.
    #[error("safety case account state configuration does not match the active runtime")]
    AccountConfigurationMismatch,
    /// A requested lifecycle transition predates the current case state.
    #[error("safety case lifecycle timestamp predates the current case state")]
    InvalidLifecycleTimestamp,
    /// The supplied optimistic case generation does not match the predecessor.
    #[error(
        "safety case generation mismatch: expected {expected}, current predecessor generation is {actual}"
    )]
    CaseGenerationMismatch {
        /// Host-supplied optimistic generation.
        expected: u64,
        /// Generation stored for the predecessor case.
        actual: u64,
    },
    /// The supplied optimistic case revision does not match the predecessor.
    #[error(
        "safety case revision mismatch: expected {expected}, current predecessor revision is {actual}"
    )]
    CaseRevisionMismatch {
        /// Host-supplied optimistic revision.
        expected: u64,
        /// Revision stored for the predecessor case.
        actual: u64,
    },
    /// A successor can only be activated from the currently active terminal case.
    #[error("safety case successor predecessor is not the active terminal case")]
    InvalidSuccessorPredecessor,
    /// A successor activation timestamp predates the terminal predecessor state.
    #[error("safety case successor activation timestamp predates the predecessor state")]
    InvalidSuccessorActivationTimestamp,
    /// The monotonic successor generation cannot be represented by `u64`.
    #[error("safety case generation overflow")]
    CaseGenerationOverflow,
    /// The requested case does not exist in this runtime.
    #[error("safety case was not found")]
    CaseNotFound,
    /// Observation commands must pass through canonical source ingestion.
    #[error("direct observation commands are forbidden; use ingest_analysis")]
    DirectObservationCommandForbidden,
    /// A future lifecycle command is not supported by this runtime version.
    #[error("unsupported safety case lifecycle command")]
    UnsupportedLifecycleCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CaseRegistryKey {
    account_key: SafetyAccountKey,
    subject_key: SafetyCaseSubjectKey,
    threat_type: ThreatType,
    generation: SafetyCaseGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ActiveCaseRouteKey {
    account_key: SafetyAccountKey,
    subject_key: SafetyCaseSubjectKey,
    threat_type: ThreatType,
}

#[derive(Debug, Clone)]
struct ActiveCaseGeneration {
    generation: SafetyCaseGeneration,
    activated_from_case_id: Option<SafetyCaseId>,
    activated_from_case_revision: Option<u64>,
    activated_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CanonicalSourceKey {
    account_key: SafetyAccountKey,
    subject_key: SafetyCaseSubjectKey,
    source_event: SourceEventKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CanonicalEventKey {
    account_key: SafetyAccountKey,
    subject_key: SafetyCaseSubjectKey,
    conversation_key: ConversationEventKey,
    event_id: SourceEventId,
}

#[derive(Debug, Clone)]
struct SourceLedgerEntry {
    receipt: SafetyCaseSourceReceipt,
    observation_id: Option<SafetyObservationId>,
}

/// Versioned, content-free state intended for host encryption at rest.
///
/// Fields are private so callers cannot bypass import validation. Serialize the
/// value with the host's bounded codec, encrypt the resulting bytes per account,
/// and call [`SafetyCaseRuntime::import_account_state`] after decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedSafetyCaseRuntimeState {
    schema_version: String,
    /// Present for per-account exports, including snapshots with no entries.
    /// This prevents an empty encrypted container from being restored into a
    /// different account partition by a buggy host.
    account_partition: Option<SafetyAccountKey>,
    config: SafetyCaseRuntimeConfig,
    cases: Vec<PersistedCaseEntry>,
    #[serde(default)]
    active_case_generations: Vec<PersistedActiveCaseGenerationEntry>,
    source_receipts: Vec<PersistedSourceReceiptEntry>,
}

impl ExportedSafetyCaseRuntimeState {
    /// Returns the wire schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the number of persisted cases.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }

    /// Returns the number of persisted canonical receipts.
    pub fn source_receipt_count(&self) -> usize {
        self.source_receipts.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedCaseEntry {
    account_key: SafetyAccountKey,
    #[serde(default)]
    case_generation: SafetyCaseGeneration,
    case: SafetyCase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedActiveCaseGenerationEntry {
    account_key: SafetyAccountKey,
    subject_key: SafetyCaseSubjectKey,
    threat_type: ThreatType,
    generation: SafetyCaseGeneration,
    activated_from_case_id: Option<SafetyCaseId>,
    activated_from_case_revision: Option<u64>,
    activated_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSourceReceiptEntry {
    account_key: SafetyAccountKey,
    subject_key: SafetyCaseSubjectKey,
    source_event: SourceEventKey,
    receipt: SafetyCaseSourceReceipt,
    observation_id: Option<SafetyObservationId>,
}

/// Bounded case registry and canonical source ledger owned by one Agent runtime.
#[derive(Clone, Default)]
pub struct SafetyCaseRuntime {
    config: SafetyCaseRuntimeConfig,
    cases: HashMap<CaseRegistryKey, SafetyCase>,
    case_ids: HashMap<SafetyCaseId, CaseRegistryKey>,
    active_case_generations: HashMap<ActiveCaseRouteKey, ActiveCaseGeneration>,
    source_receipts: HashMap<CanonicalSourceKey, SourceLedgerEntry>,
    latest_revisions: HashMap<CanonicalEventKey, u32>,
    observation_ids: HashMap<SafetyObservationId, CanonicalSourceKey>,
}

impl SafetyCaseRuntime {
    /// Creates an empty runtime after validating configuration.
    pub fn new(config: SafetyCaseRuntimeConfig) -> Result<Self, SafetyCaseRuntimeError> {
        config.case_policy.validate()?;
        validate_capacity("safety cases", config.max_cases, MAX_CONFIGURED_CASES)?;
        validate_capacity(
            "safety source receipts",
            config.max_source_receipts,
            MAX_CONFIGURED_SOURCE_RECEIPTS,
        )?;
        validate_account_state_byte_budget(config.max_account_state_bytes)?;
        Ok(Self {
            config,
            cases: HashMap::new(),
            case_ids: HashMap::new(),
            active_case_generations: HashMap::new(),
            source_receipts: HashMap::new(),
            latest_revisions: HashMap::new(),
            observation_ids: HashMap::new(),
        })
    }

    /// Checks exactly-once state and capacity without mutating the runtime.
    ///
    /// Hosts that call an analyzer separately must require `Ready` before
    /// analysis. Prefer `AgentRuntime::analyze_local_with_canonical_safety_case`,
    /// which performs this check and context mutation atomically under `&mut`.
    pub fn preflight_source(
        &self,
        identity: &SafetyCaseIngestIdentity,
    ) -> Result<SafetyCaseSourcePreflight, SafetyCaseRuntimeError> {
        if identity.observed_at_ms < identity.occurred_at_ms {
            return Err(SafetyCaseRuntimeError::InvalidIngestTimestamps);
        }
        let source_key = canonical_source_key(identity);
        if let Some(entry) = self.source_receipts.get(&source_key) {
            return Ok(SafetyCaseSourcePreflight::Duplicate(entry.receipt.clone()));
        }
        let event_key = canonical_event_key(identity);
        if let Some(latest_revision) = self.latest_revisions.get(&event_key) {
            if *latest_revision >= identity.source_event.revision() {
                return Ok(SafetyCaseSourcePreflight::Stale {
                    latest_revision: *latest_revision,
                });
            }
        }
        if self.source_receipts.len() >= self.config.max_source_receipts {
            return Err(SafetyCaseRuntimeError::SourceReceiptCapacityExceeded {
                maximum: self.config.max_source_receipts,
            });
        }
        self.ensure_account_ingest_reserve(&identity.account_key)?;
        Ok(SafetyCaseSourcePreflight::Ready)
    }

    /// Projects a previously analyzed result and reduces it into case state.
    ///
    /// This function reads only structured threat, action, score, confidence,
    /// and reason-code fields. It never retains the `AnalysisResult` itself.
    /// Every first attempt receives a content-free receipt, including ignored
    /// and rejected projections, so retries can be suppressed before analysis.
    pub fn ingest_analysis(
        &mut self,
        identity: &SafetyCaseIngestIdentity,
        result: &AnalysisResult,
    ) -> Result<SafetyCaseIngestOutcome, SafetyCaseRuntimeError> {
        match self.preflight_source(identity)? {
            SafetyCaseSourcePreflight::Duplicate(receipt) => {
                return Ok(SafetyCaseIngestOutcome::DuplicateIgnored(receipt));
            }
            SafetyCaseSourcePreflight::Stale { latest_revision } => {
                return Ok(SafetyCaseIngestOutcome::StaleIgnored { latest_revision });
            }
            SafetyCaseSourcePreflight::Ready => {}
        }

        let source_key = canonical_source_key(identity);
        let mut candidate = self.clone();
        let ingestion = candidate.ingest_new_source(identity, result, &source_key);
        match ingestion {
            Ok((outcome, receipt, observation_id)) => {
                candidate.remember_source(source_key.clone(), receipt, observation_id);
                if let Err(error) =
                    candidate.ensure_account_state_within_budget(&identity.account_key)
                {
                    // Analysis has already mutated context. Retain a small,
                    // durable rejected receipt so a retry cannot replay it.
                    self.remember_source(source_key, SafetyCaseSourceReceipt::Rejected, None);
                    return Err(error);
                }
                *self = candidate;
                Ok(outcome)
            }
            Err(error) => {
                self.remember_source(source_key, SafetyCaseSourceReceipt::Rejected, None);
                Err(error)
            }
        }
    }

    pub(crate) fn remember_rejected_source(
        &mut self,
        identity: &SafetyCaseIngestIdentity,
    ) -> Result<(), SafetyCaseRuntimeError> {
        match self.preflight_source(identity)? {
            SafetyCaseSourcePreflight::Ready => {
                self.remember_source(
                    canonical_source_key(identity),
                    SafetyCaseSourceReceipt::Rejected,
                    None,
                );
                Ok(())
            }
            SafetyCaseSourcePreflight::Duplicate(_) | SafetyCaseSourcePreflight::Stale { .. } => {
                Err(SafetyCaseRuntimeError::InconsistentIndex)
            }
        }
    }

    /// Returns a case by its content-free, deterministically derived identifier.
    pub fn case_by_id(&self, case_id: &SafetyCaseId) -> Option<&SafetyCase> {
        self.case_ids
            .get(case_id)
            .and_then(|key| self.cases.get(key))
    }

    /// Returns the persisted episode generation for a case identifier.
    pub fn case_generation_by_id(&self, case_id: &SafetyCaseId) -> Option<SafetyCaseGeneration> {
        self.case_ids.get(case_id).map(|key| key.generation)
    }

    /// Explicitly advances one active terminal lineage to an empty successor.
    ///
    /// This method never decides *when* a successor should be activated. The
    /// caller owns that policy decision and supplies optimistic generation and
    /// revision guards. Repeating the same activation is idempotent.
    pub fn activate_successor(
        &mut self,
        account_key: &SafetyAccountKey,
        predecessor_case_id: &SafetyCaseId,
        expected_generation: SafetyCaseGeneration,
        expected_case_revision: u64,
        activated_at_ms: u64,
    ) -> Result<SafetyCaseSuccessorActivationOutcome, SafetyCaseRuntimeError> {
        if activated_at_ms == 0 {
            return Err(SafetyCaseRuntimeError::InvalidSuccessorActivationTimestamp);
        }
        let case_key = self
            .case_ids
            .get(predecessor_case_id)
            .cloned()
            .ok_or(SafetyCaseRuntimeError::CaseNotFound)?;
        if &case_key.account_key != account_key {
            return Err(SafetyCaseRuntimeError::CaseNotFound);
        }
        if case_key.generation != expected_generation {
            return Err(SafetyCaseRuntimeError::CaseGenerationMismatch {
                expected: expected_generation.value(),
                actual: case_key.generation.value(),
            });
        }
        let predecessor = self
            .cases
            .get(&case_key)
            .ok_or(SafetyCaseRuntimeError::InconsistentIndex)?;
        let route_key = active_route_key_from_case_key(&case_key);
        let active = self
            .active_case_generations
            .get(&route_key)
            .ok_or(SafetyCaseRuntimeError::InconsistentIndex)?;
        let successor_value = expected_generation
            .value()
            .checked_add(1)
            .ok_or(SafetyCaseRuntimeError::CaseGenerationOverflow)?;
        let successor_generation = SafetyCaseGeneration::new(successor_value);
        let successor_case_id = derive_case_id_for(
            account_key,
            predecessor.subject_key(),
            predecessor.threat_type(),
            successor_generation,
        )?;

        if active.generation == successor_generation
            && active.activated_from_case_id.as_ref() == Some(predecessor_case_id)
            && active.activated_from_case_revision == Some(expected_case_revision)
        {
            return Ok(SafetyCaseSuccessorActivationOutcome {
                disposition: SafetyCaseSuccessorActivationDisposition::AlreadyActivated,
                predecessor_case_id: predecessor_case_id.clone(),
                predecessor_generation: expected_generation,
                successor_case_id,
                successor_generation,
                activated_at_ms: active
                    .activated_at_ms
                    .ok_or(SafetyCaseRuntimeError::InconsistentIndex)?,
            });
        }
        if predecessor.revision() != expected_case_revision {
            return Err(SafetyCaseRuntimeError::CaseRevisionMismatch {
                expected: expected_case_revision,
                actual: predecessor.revision(),
            });
        }
        if active.generation != expected_generation || !predecessor.status().is_terminal() {
            return Err(SafetyCaseRuntimeError::InvalidSuccessorPredecessor);
        }
        if activated_at_ms < predecessor.updated_at_ms() {
            return Err(SafetyCaseRuntimeError::InvalidSuccessorActivationTimestamp);
        }
        if self.retained_case_slot_count()? >= self.config.max_cases {
            return Err(SafetyCaseRuntimeError::CaseCapacityExceeded {
                maximum: self.config.max_cases,
            });
        }
        if self.case_ids.contains_key(&successor_case_id) {
            return Err(SafetyCaseRuntimeError::CaseIdentityCollision);
        }

        let mut candidate = self.clone();
        candidate.active_case_generations.insert(
            route_key,
            ActiveCaseGeneration {
                generation: successor_generation,
                activated_from_case_id: Some(predecessor_case_id.clone()),
                activated_from_case_revision: Some(expected_case_revision),
                activated_at_ms: Some(activated_at_ms),
            },
        );
        candidate.ensure_account_state_within_budget(account_key)?;
        *self = candidate;
        Ok(SafetyCaseSuccessorActivationOutcome {
            disposition: SafetyCaseSuccessorActivationDisposition::Activated,
            predecessor_case_id: predecessor_case_id.clone(),
            predecessor_generation: expected_generation,
            successor_case_id,
            successor_generation,
            activated_at_ms,
        })
    }

    /// Returns all retained cases in unspecified order.
    pub fn cases(&self) -> impl Iterator<Item = &SafetyCase> {
        self.cases.values()
    }

    /// Returns the number of retained cases.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }

    /// Returns the number of canonical receipts, including ignored events.
    pub fn source_receipt_count(&self) -> usize {
        self.source_receipts.len()
    }

    /// Returns the active deterministic reducer policy.
    pub const fn case_policy(&self) -> &SafetyCasePolicy {
        &self.config.case_policy
    }

    /// Applies a non-observation lifecycle command to an existing case.
    ///
    /// Observation commands are rejected because bypassing the canonical
    /// source ledger would break exactly-once and stale-revision guarantees.
    pub fn apply_lifecycle_command(
        &mut self,
        case_id: &SafetyCaseId,
        command: SafetyCaseCommand,
    ) -> Result<SafetyCaseDecision, SafetyCaseRuntimeError> {
        match &command {
            SafetyCaseCommand::ApplyObservation { .. } => {
                return Err(SafetyCaseRuntimeError::DirectObservationCommandForbidden);
            }
            SafetyCaseCommand::Resolve { .. }
            | SafetyCaseCommand::Dismiss { .. }
            | SafetyCaseCommand::FlushDeferredGuardianReport { .. }
            | SafetyCaseCommand::AcknowledgeGuardianReport { .. } => {}
            _ => return Err(SafetyCaseRuntimeError::UnsupportedLifecycleCommand),
        }
        let case_key = self
            .case_ids
            .get(case_id)
            .cloned()
            .ok_or(SafetyCaseRuntimeError::CaseNotFound)?;
        let case = self
            .cases
            .get(&case_key)
            .ok_or(SafetyCaseRuntimeError::InconsistentIndex)?;
        validate_lifecycle_timestamp(case, &command)?;
        let reduction = SafetyCaseReducer::reduce(case, command, &self.config.case_policy)?;
        let (case, decision) = reduction.into_parts();
        let account_key = case_key.account_key.clone();
        let mut candidate = self.clone();
        candidate.cases.insert(case_key, case);
        candidate.ensure_account_state_within_budget(&account_key)?;
        *self = candidate;
        Ok(decision)
    }

    /// Applies a lifecycle command only when the case belongs to the supplied
    /// account partition. Cross-account lookup is reported as not found.
    pub fn apply_account_lifecycle_command(
        &mut self,
        account_key: &SafetyAccountKey,
        case_id: &SafetyCaseId,
        command: SafetyCaseCommand,
    ) -> Result<SafetyCaseDecision, SafetyCaseRuntimeError> {
        let case_key = self
            .case_ids
            .get(case_id)
            .ok_or(SafetyCaseRuntimeError::CaseNotFound)?;
        if &case_key.account_key != account_key {
            return Err(SafetyCaseRuntimeError::CaseNotFound);
        }
        self.apply_lifecycle_command(case_id, command)
    }

    fn ensure_account_ingest_reserve(
        &self,
        account_key: &SafetyAccountKey,
    ) -> Result<(), SafetyCaseRuntimeError> {
        let current = self.serialized_account_state_len(account_key)?;
        let maximum_before_ingest = self
            .config
            .max_account_state_bytes
            .saturating_sub(SAFETY_CASE_ACCOUNT_INGEST_RESERVE_BYTES);
        if current > maximum_before_ingest {
            return Err(SafetyCaseRuntimeError::AccountStateByteBudgetExceeded {
                maximum: self.config.max_account_state_bytes,
                current,
                required_reserve: SAFETY_CASE_ACCOUNT_INGEST_RESERVE_BYTES,
            });
        }
        Ok(())
    }

    fn retained_case_slot_count(&self) -> Result<usize, SafetyCaseRuntimeError> {
        let pending_successors = self
            .active_case_generations
            .iter()
            .filter(|(route_key, active)| {
                !self.cases.contains_key(&CaseRegistryKey {
                    account_key: route_key.account_key.clone(),
                    subject_key: route_key.subject_key.clone(),
                    threat_type: route_key.threat_type,
                    generation: active.generation,
                })
            })
            .count();
        self.cases.len().checked_add(pending_successors).ok_or(
            SafetyCaseRuntimeError::CaseCapacityExceeded {
                maximum: self.config.max_cases,
            },
        )
    }

    fn ensure_account_state_within_budget(
        &self,
        account_key: &SafetyAccountKey,
    ) -> Result<(), SafetyCaseRuntimeError> {
        let current = self.serialized_account_state_len(account_key)?;
        if current > self.config.max_account_state_bytes {
            return Err(SafetyCaseRuntimeError::AccountStateByteBudgetExceeded {
                maximum: self.config.max_account_state_bytes,
                current,
                required_reserve: 0,
            });
        }
        Ok(())
    }

    fn serialized_account_state_len(
        &self,
        account_key: &SafetyAccountKey,
    ) -> Result<usize, SafetyCaseRuntimeError> {
        serde_json::to_vec(&self.export_account_state(account_key))
            .map(|bytes| bytes.len())
            .map_err(|error| SafetyCaseRuntimeError::StateSerialization(error.to_string()))
    }

    fn validate_all_account_state_budgets(&self) -> Result<(), SafetyCaseRuntimeError> {
        let mut accounts = HashSet::new();
        accounts.extend(self.cases.keys().map(|key| key.account_key.clone()));
        accounts.extend(
            self.active_case_generations
                .keys()
                .map(|key| key.account_key.clone()),
        );
        accounts.extend(
            self.source_receipts
                .keys()
                .map(|key| key.account_key.clone()),
        );
        for account_key in accounts {
            self.ensure_account_state_within_budget(&account_key)?;
        }
        Ok(())
    }

    /// Exports deterministic, content-free state for host encryption.
    ///
    /// The export contains opaque routing keys, structured observations, case
    /// lifecycle state, and exact/stale-revision receipts. It never contains an
    /// analyzer result, raw message, explanation, or UI verdict.
    pub fn export_state(&self) -> ExportedSafetyCaseRuntimeState {
        let mut cases: Vec<_> = self
            .cases
            .iter()
            .map(|(key, case)| PersistedCaseEntry {
                account_key: key.account_key.clone(),
                case_generation: key.generation,
                case: case.clone(),
            })
            .collect();
        cases.sort_by(|left, right| {
            left.account_key
                .cmp(&right.account_key)
                .then_with(|| left.case.subject_key().cmp(right.case.subject_key()))
                .then_with(|| {
                    threat_identity_tag(left.case.threat_type())
                        .cmp(threat_identity_tag(right.case.threat_type()))
                })
                .then_with(|| left.case_generation.cmp(&right.case_generation))
        });

        let mut active_case_generations: Vec<_> = self
            .active_case_generations
            .iter()
            .map(|(key, active)| PersistedActiveCaseGenerationEntry {
                account_key: key.account_key.clone(),
                subject_key: key.subject_key.clone(),
                threat_type: key.threat_type,
                generation: active.generation,
                activated_from_case_id: active.activated_from_case_id.clone(),
                activated_from_case_revision: active.activated_from_case_revision,
                activated_at_ms: active.activated_at_ms,
            })
            .collect();
        active_case_generations.sort_by(|left, right| {
            left.account_key
                .cmp(&right.account_key)
                .then_with(|| left.subject_key.cmp(&right.subject_key))
                .then_with(|| {
                    threat_identity_tag(left.threat_type)
                        .cmp(threat_identity_tag(right.threat_type))
                })
        });

        let mut source_receipts: Vec<_> = self
            .source_receipts
            .iter()
            .map(|(key, entry)| PersistedSourceReceiptEntry {
                account_key: key.account_key.clone(),
                subject_key: key.subject_key.clone(),
                source_event: key.source_event.clone(),
                receipt: entry.receipt.clone(),
                observation_id: entry.observation_id.clone(),
            })
            .collect();
        source_receipts.sort_by(|left, right| {
            left.account_key
                .cmp(&right.account_key)
                .then_with(|| left.subject_key.cmp(&right.subject_key))
                .then_with(|| left.source_event.cmp(&right.source_event))
        });

        ExportedSafetyCaseRuntimeState {
            schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
            account_partition: None,
            config: self.config.clone(),
            cases,
            active_case_generations,
            source_receipts,
        }
    }

    /// Exports only one account partition for per-account encryption.
    pub fn export_account_state(
        &self,
        account_key: &SafetyAccountKey,
    ) -> ExportedSafetyCaseRuntimeState {
        let mut state = self.export_state();
        state
            .cases
            .retain(|entry| &entry.account_key == account_key);
        state
            .active_case_generations
            .retain(|entry| &entry.account_key == account_key);
        state
            .source_receipts
            .retain(|entry| &entry.account_key == account_key);
        state.account_partition = Some(account_key.clone());
        state
    }

    /// Replaces runtime state after validating schemas, capacities, reducer
    /// invariants, derived identities, receipt coverage, and all rebuilt indexes.
    ///
    /// The current state is left unchanged on failure.
    pub fn import_state(
        &mut self,
        state: &ExportedSafetyCaseRuntimeState,
    ) -> Result<(), SafetyCaseRuntimeError> {
        let is_legacy = state.schema_version == LEGACY_SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION;
        if !is_legacy && state.schema_version != SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION {
            return Err(SafetyCaseRuntimeError::UnsupportedStateSchema(
                state.schema_version.clone(),
            ));
        }
        if is_legacy
            && (!state.active_case_generations.is_empty()
                || state
                    .cases
                    .iter()
                    .any(|entry| entry.case_generation != SafetyCaseGeneration::INITIAL))
        {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "legacy state contains successor-generation fields",
            ));
        }
        let mut candidate = Self::new(state.config.clone())?;
        if state.account_partition.is_some() {
            let serialized_len = serde_json::to_vec(state)
                .map_err(|error| SafetyCaseRuntimeError::StateSerialization(error.to_string()))?
                .len();
            if serialized_len > candidate.config.max_account_state_bytes {
                return Err(SafetyCaseRuntimeError::AccountStateByteBudgetExceeded {
                    maximum: candidate.config.max_account_state_bytes,
                    current: serialized_len,
                    required_reserve: 0,
                });
            }
        }
        if state.cases.len() > candidate.config.max_cases {
            return Err(SafetyCaseRuntimeError::CaseCapacityExceeded {
                maximum: candidate.config.max_cases,
            });
        }
        if state.active_case_generations.len() > candidate.config.max_cases {
            return Err(SafetyCaseRuntimeError::CaseCapacityExceeded {
                maximum: candidate.config.max_cases,
            });
        }
        if state.source_receipts.len() > candidate.config.max_source_receipts {
            return Err(SafetyCaseRuntimeError::SourceReceiptCapacityExceeded {
                maximum: candidate.config.max_source_receipts,
            });
        }

        for entry in &state.cases {
            candidate.import_case(entry)?;
        }
        if is_legacy {
            candidate.rebuild_legacy_active_case_generations()?;
        } else {
            for entry in &state.active_case_generations {
                candidate.import_active_case_generation(entry)?;
            }
        }
        for entry in &state.source_receipts {
            candidate.import_source_receipt(entry)?;
        }
        candidate.validate_case_generation_lineages()?;
        if candidate.retained_case_slot_count()? > candidate.config.max_cases {
            return Err(SafetyCaseRuntimeError::CaseCapacityExceeded {
                maximum: candidate.config.max_cases,
            });
        }
        candidate.validate_receipt_coverage()?;
        candidate.validate_all_account_state_budgets()?;
        *self = candidate;
        Ok(())
    }

    /// Replaces one account partition from its encrypted container while
    /// preserving any other resident account partitions.
    pub fn import_account_state(
        &mut self,
        account_key: &SafetyAccountKey,
        state: &ExportedSafetyCaseRuntimeState,
    ) -> Result<(), SafetyCaseRuntimeError> {
        if state.account_partition.as_ref() != Some(account_key)
            || state
                .cases
                .iter()
                .any(|entry| &entry.account_key != account_key)
            || state
                .active_case_generations
                .iter()
                .any(|entry| &entry.account_key != account_key)
            || state
                .source_receipts
                .iter()
                .any(|entry| &entry.account_key != account_key)
        {
            return Err(SafetyCaseRuntimeError::AccountPartitionMismatch);
        }

        let mut normalized = Self::default();
        normalized.import_state(state)?;

        let contains_other_accounts = self.cases.keys().any(|key| &key.account_key != account_key)
            || self
                .active_case_generations
                .keys()
                .any(|key| &key.account_key != account_key)
            || self
                .source_receipts
                .keys()
                .any(|key| &key.account_key != account_key);
        if !contains_other_accounts {
            *self = normalized;
            return Ok(());
        }
        if self.config != normalized.config {
            return Err(SafetyCaseRuntimeError::AccountConfigurationMismatch);
        }

        let mut merged = self.export_state();
        merged
            .cases
            .retain(|entry| &entry.account_key != account_key);
        merged
            .active_case_generations
            .retain(|entry| &entry.account_key != account_key);
        merged
            .source_receipts
            .retain(|entry| &entry.account_key != account_key);
        let normalized_account = normalized.export_account_state(account_key);
        merged.cases.extend(normalized_account.cases);
        merged
            .active_case_generations
            .extend(normalized_account.active_case_generations);
        merged
            .source_receipts
            .extend(normalized_account.source_receipts);
        self.import_state(&merged)
    }

    /// Removes all case state and dedupe receipts for one account partition.
    ///
    /// This is intended for logout, unlink, or crypto-shred workflows. It makes
    /// previously seen events eligible for analysis again if the account is
    /// subsequently recreated with the same opaque key.
    pub fn remove_account(&mut self, account_key: &SafetyAccountKey) -> SafetyCaseAccountRemoval {
        let removed_case_ids: Vec<_> = self
            .cases
            .iter()
            .filter(|(key, _)| &key.account_key == account_key)
            .map(|(_, case)| case.case_id().clone())
            .collect();
        let removed_cases = removed_case_ids.len();
        self.cases.retain(|key, _| &key.account_key != account_key);
        for case_id in removed_case_ids {
            self.case_ids.remove(&case_id);
        }
        self.active_case_generations
            .retain(|key, _| &key.account_key != account_key);

        let removed_sources: Vec<_> = self
            .source_receipts
            .keys()
            .filter(|key| &key.account_key == account_key)
            .cloned()
            .collect();
        let removed_source_receipts = removed_sources.len();
        self.observation_ids
            .retain(|_, source| &source.account_key != account_key);
        for source in removed_sources {
            self.source_receipts.remove(&source);
        }
        self.latest_revisions
            .retain(|key, _| &key.account_key != account_key);
        SafetyCaseAccountRemoval {
            removed_cases,
            removed_source_receipts,
        }
    }

    /// Clears all cases and canonical ingestion receipts.
    pub fn clear(&mut self) {
        self.cases.clear();
        self.case_ids.clear();
        self.active_case_generations.clear();
        self.source_receipts.clear();
        self.latest_revisions.clear();
        self.observation_ids.clear();
    }

    fn ingest_new_source(
        &mut self,
        identity: &SafetyCaseIngestIdentity,
        result: &AnalysisResult,
        source_key: &CanonicalSourceKey,
    ) -> Result<
        (
            SafetyCaseIngestOutcome,
            SafetyCaseSourceReceipt,
            Option<SafetyObservationId>,
        ),
        SafetyCaseRuntimeError,
    > {
        let route_key = ActiveCaseRouteKey {
            account_key: identity.account_key.clone(),
            subject_key: identity.subject_key.clone(),
            threat_type: result.threat_type,
        };
        let generation = self
            .active_case_generations
            .get(&route_key)
            .map_or(SafetyCaseGeneration::INITIAL, |active| active.generation);
        let case_id = derive_case_id(identity, result.threat_type, generation)?;
        let observation_id = derive_observation_id(identity, result.threat_type)?;
        let Some(observation) = project_observation(identity, &observation_id, result)? else {
            let reason = ignored_reason(result);
            return Ok((
                SafetyCaseIngestOutcome::Ignored(reason),
                SafetyCaseSourceReceipt::Ignored(reason),
                None,
            ));
        };

        if self
            .observation_ids
            .get(&observation_id)
            .is_some_and(|indexed_source| indexed_source != source_key)
        {
            return Err(SafetyCaseRuntimeError::ObservationIdentityCollision);
        }

        let case_key = CaseRegistryKey {
            account_key: identity.account_key.clone(),
            subject_key: identity.subject_key.clone(),
            threat_type: result.threat_type,
            generation,
        };

        if let Some(indexed_key) = self.case_ids.get(&case_id) {
            if indexed_key != &case_key {
                return Err(SafetyCaseRuntimeError::CaseIdentityCollision);
            }
        }

        let existing_case = self.cases.get(&case_key);
        if let Some(case) = existing_case {
            if case.case_id() != &case_id {
                return Err(SafetyCaseRuntimeError::CaseIdentityMismatch);
            }
        } else if !self.active_case_generations.contains_key(&route_key)
            && self.retained_case_slot_count()? >= self.config.max_cases
        {
            return Err(SafetyCaseRuntimeError::CaseCapacityExceeded {
                maximum: self.config.max_cases,
            });
        }

        let reduction = match existing_case {
            Some(case) => SafetyCaseReducer::reduce(
                case,
                SafetyCaseCommand::ApplyObservation { observation },
                &self.config.case_policy,
            )?,
            None => {
                let case = SafetyCase::new(
                    case_id,
                    identity.subject_key.clone(),
                    result.threat_type,
                    identity.observed_at_ms,
                )?;
                SafetyCaseReducer::reduce(
                    &case,
                    SafetyCaseCommand::ApplyObservation { observation },
                    &self.config.case_policy,
                )?
            }
        };
        let (case, decision) = reduction.into_parts();
        let receipt = SafetyCaseSourceReceipt::Applied {
            case_id: case.case_id().clone(),
            case_revision: case.revision(),
            status: case.status(),
        };
        self.case_ids
            .insert(case.case_id().clone(), case_key.clone());
        self.active_case_generations
            .entry(route_key)
            .or_insert(ActiveCaseGeneration {
                generation,
                activated_from_case_id: None,
                activated_from_case_revision: None,
                activated_at_ms: None,
            });
        self.observation_ids
            .insert(observation_id.clone(), source_key.clone());
        self.cases.insert(case_key, case);
        Ok((
            SafetyCaseIngestOutcome::Reduced(Box::new(decision)),
            receipt,
            Some(observation_id),
        ))
    }

    fn remember_source(
        &mut self,
        source_key: CanonicalSourceKey,
        receipt: SafetyCaseSourceReceipt,
        observation_id: Option<SafetyObservationId>,
    ) {
        let event_key = CanonicalEventKey {
            account_key: source_key.account_key.clone(),
            subject_key: source_key.subject_key.clone(),
            conversation_key: source_key.source_event.conversation_key().clone(),
            event_id: source_key.source_event.event_id().clone(),
        };
        self.latest_revisions
            .insert(event_key, source_key.source_event.revision());
        self.source_receipts.insert(
            source_key,
            SourceLedgerEntry {
                receipt,
                observation_id,
            },
        );
    }

    fn import_case(&mut self, entry: &PersistedCaseEntry) -> Result<(), SafetyCaseRuntimeError> {
        let case = &entry.case;
        let first_observation = case.observations().first().cloned().ok_or(
            SafetyCaseRuntimeError::InvalidPersistedState("case has no observations"),
        )?;
        SafetyCaseReducer::reduce(
            case,
            SafetyCaseCommand::ApplyObservation {
                observation: first_observation,
            },
            &self.config.case_policy,
        )?;

        let expected_case_id = derive_case_id_for(
            &entry.account_key,
            case.subject_key(),
            case.threat_type(),
            entry.case_generation,
        )?;
        if case.case_id() != &expected_case_id {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "case id does not match its content-free identity",
            ));
        }
        let key = CaseRegistryKey {
            account_key: entry.account_key.clone(),
            subject_key: case.subject_key().clone(),
            threat_type: case.threat_type(),
            generation: entry.case_generation,
        };
        if self.cases.contains_key(&key) || self.case_ids.contains_key(case.case_id()) {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "duplicate case identity",
            ));
        }
        self.case_ids.insert(case.case_id().clone(), key.clone());
        self.cases.insert(key, case.clone());
        Ok(())
    }

    fn rebuild_legacy_active_case_generations(&mut self) -> Result<(), SafetyCaseRuntimeError> {
        for case_key in self.cases.keys() {
            if case_key.generation != SafetyCaseGeneration::INITIAL {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "legacy case uses a successor generation",
                ));
            }
            let route_key = active_route_key_from_case_key(case_key);
            if self
                .active_case_generations
                .insert(
                    route_key,
                    ActiveCaseGeneration {
                        generation: SafetyCaseGeneration::INITIAL,
                        activated_from_case_id: None,
                        activated_from_case_revision: None,
                        activated_at_ms: None,
                    },
                )
                .is_some()
            {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "legacy state contains duplicate case lineage",
                ));
            }
        }
        Ok(())
    }

    fn import_active_case_generation(
        &mut self,
        entry: &PersistedActiveCaseGenerationEntry,
    ) -> Result<(), SafetyCaseRuntimeError> {
        if entry.threat_type == ThreatType::None {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "active case lineage has no threat family",
            ));
        }
        let activation_fields_present = (
            entry.activated_from_case_id.is_some(),
            entry.activated_from_case_revision.is_some(),
            entry.activated_at_ms.is_some(),
        );
        let activation_shape_valid = if entry.generation == SafetyCaseGeneration::INITIAL {
            activation_fields_present == (false, false, false)
        } else {
            activation_fields_present == (true, true, true)
        };
        if !activation_shape_valid {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "active case lineage activation metadata is incomplete",
            ));
        }
        let key = ActiveCaseRouteKey {
            account_key: entry.account_key.clone(),
            subject_key: entry.subject_key.clone(),
            threat_type: entry.threat_type,
        };
        if self
            .active_case_generations
            .insert(
                key,
                ActiveCaseGeneration {
                    generation: entry.generation,
                    activated_from_case_id: entry.activated_from_case_id.clone(),
                    activated_from_case_revision: entry.activated_from_case_revision,
                    activated_at_ms: entry.activated_at_ms,
                },
            )
            .is_some()
        {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "duplicate active case lineage",
            ));
        }
        Ok(())
    }

    fn validate_case_generation_lineages(&self) -> Result<(), SafetyCaseRuntimeError> {
        for (route_key, active) in &self.active_case_generations {
            let mut lineage: Vec<_> = self
                .cases
                .iter()
                .filter(|(case_key, _)| {
                    case_key.account_key == route_key.account_key
                        && case_key.subject_key == route_key.subject_key
                        && case_key.threat_type == route_key.threat_type
                })
                .collect();
            lineage.sort_by_key(|(case_key, _)| case_key.generation);
            let Some((first_key, _)) = lineage.first() else {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "active case lineage has no predecessor case",
                ));
            };
            if first_key.generation != SafetyCaseGeneration::INITIAL {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "case lineage does not begin at generation zero",
                ));
            }
            for pair in lineage.windows(2) {
                let previous = pair[0].0.generation.value();
                let expected = previous
                    .checked_add(1)
                    .ok_or(SafetyCaseRuntimeError::CaseGenerationOverflow)?;
                if pair[1].0.generation.value() != expected {
                    return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                        "case lineage generations are not contiguous",
                    ));
                }
            }
            let (latest_key, _) = lineage
                .last()
                .ok_or(SafetyCaseRuntimeError::InconsistentIndex)?;
            if latest_key.generation > active.generation
                || active.generation.value() > latest_key.generation.value().saturating_add(1)
            {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "active case generation is inconsistent with retained lineage",
                ));
            }
            if lineage.iter().any(|(case_key, case)| {
                case_key.generation < active.generation && !case.status().is_terminal()
            }) {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "older case generation is not terminal",
                ));
            }

            if active.generation == SafetyCaseGeneration::INITIAL {
                if active.activated_from_case_id.is_some()
                    || active.activated_from_case_revision.is_some()
                    || active.activated_at_ms.is_some()
                {
                    return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                        "initial case generation contains activation metadata",
                    ));
                }
                continue;
            }
            let predecessor_generation = SafetyCaseGeneration::new(
                active
                    .generation
                    .value()
                    .checked_sub(1)
                    .ok_or(SafetyCaseRuntimeError::CaseGenerationOverflow)?,
            );
            let (_, predecessor) = lineage
                .iter()
                .find(|(case_key, _)| case_key.generation == predecessor_generation)
                .ok_or(SafetyCaseRuntimeError::InvalidPersistedState(
                    "active case generation is missing its predecessor",
                ))?;
            let activated_from_case_id = active.activated_from_case_id.as_ref().ok_or(
                SafetyCaseRuntimeError::InvalidPersistedState(
                    "active case generation is missing predecessor identity",
                ),
            )?;
            let activated_from_case_revision = active.activated_from_case_revision.ok_or(
                SafetyCaseRuntimeError::InvalidPersistedState(
                    "active case generation is missing predecessor revision",
                ),
            )?;
            let activated_at_ms =
                active
                    .activated_at_ms
                    .ok_or(SafetyCaseRuntimeError::InvalidPersistedState(
                        "active case generation is missing activation timestamp",
                    ))?;
            if predecessor.case_id() != activated_from_case_id
                || activated_from_case_revision == 0
                || activated_from_case_revision > predecessor.revision()
                || activated_at_ms == 0
                || !predecessor.status().is_terminal()
                || predecessor
                    .closed_at_ms()
                    .is_none_or(|closed_at_ms| activated_at_ms < closed_at_ms)
            {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "active case generation predecessor metadata is invalid",
                ));
            }
        }

        if self.cases.keys().any(|case_key| {
            !self
                .active_case_generations
                .contains_key(&active_route_key_from_case_key(case_key))
        }) {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "case is missing its active lineage route",
            ));
        }
        Ok(())
    }

    fn import_source_receipt(
        &mut self,
        entry: &PersistedSourceReceiptEntry,
    ) -> Result<(), SafetyCaseRuntimeError> {
        let source_key = CanonicalSourceKey {
            account_key: entry.account_key.clone(),
            subject_key: entry.subject_key.clone(),
            source_event: entry.source_event.clone(),
        };
        if self.source_receipts.contains_key(&source_key) {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "duplicate canonical source receipt",
            ));
        }

        match (&entry.receipt, &entry.observation_id) {
            (
                SafetyCaseSourceReceipt::Applied {
                    case_id,
                    case_revision,
                    status,
                },
                Some(observation_id),
            ) => {
                let case = self.case_by_id(case_id).ok_or(
                    SafetyCaseRuntimeError::InvalidPersistedState(
                        "applied receipt references a missing case",
                    ),
                )?;
                let case_key = self
                    .case_ids
                    .get(case_id)
                    .ok_or(SafetyCaseRuntimeError::InconsistentIndex)?;
                if case_key.account_key != entry.account_key
                    || case.subject_key() != &entry.subject_key
                    || *case_revision == 0
                    || *case_revision > case.revision()
                    || status.is_terminal()
                {
                    return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                        "applied receipt routing or revision is invalid",
                    ));
                }
                let expected_observation_id = derive_observation_id_for(
                    &entry.account_key,
                    &entry.subject_key,
                    &entry.source_event,
                    case.threat_type(),
                )?;
                if observation_id != &expected_observation_id
                    || !case.observations().iter().any(|observation| {
                        observation.observation_id() == observation_id
                            && observation.source_event() == &entry.source_event
                    })
                {
                    return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                        "applied receipt does not match a case observation",
                    ));
                }
                if self
                    .observation_ids
                    .insert(observation_id.clone(), source_key.clone())
                    .is_some()
                {
                    return Err(SafetyCaseRuntimeError::ObservationIdentityCollision);
                }
            }
            (SafetyCaseSourceReceipt::Applied { .. }, None) => {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "applied receipt is missing its observation id",
                ));
            }
            (_, Some(_)) => {
                return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                    "non-applied receipt contains an observation id",
                ));
            }
            (_, None) => {}
        }

        let event_key = CanonicalEventKey {
            account_key: entry.account_key.clone(),
            subject_key: entry.subject_key.clone(),
            conversation_key: entry.source_event.conversation_key().clone(),
            event_id: entry.source_event.event_id().clone(),
        };
        self.latest_revisions
            .entry(event_key)
            .and_modify(|latest| *latest = (*latest).max(entry.source_event.revision()))
            .or_insert(entry.source_event.revision());
        self.source_receipts.insert(
            source_key,
            SourceLedgerEntry {
                receipt: entry.receipt.clone(),
                observation_id: entry.observation_id.clone(),
            },
        );
        Ok(())
    }

    fn validate_receipt_coverage(&self) -> Result<(), SafetyCaseRuntimeError> {
        let observation_count = self
            .cases
            .values()
            .try_fold(0usize, |count, case| {
                count.checked_add(case.observations().len())
            })
            .ok_or(SafetyCaseRuntimeError::InvalidPersistedState(
                "observation count overflow",
            ))?;
        if observation_count != self.observation_ids.len() {
            return Err(SafetyCaseRuntimeError::InvalidPersistedState(
                "case observations are not exactly covered by source receipts",
            ));
        }
        Ok(())
    }
}

fn validate_lifecycle_timestamp(
    case: &SafetyCase,
    command: &SafetyCaseCommand,
) -> Result<(), SafetyCaseRuntimeError> {
    let predates_state = match command {
        SafetyCaseCommand::Resolve { at_ms, reason_code } => {
            let is_idempotent = case.status() == SafetyCaseStatus::Resolved
                && case.closed_reason_code() == Some(reason_code);
            !is_idempotent && *at_ms < case.updated_at_ms()
        }
        SafetyCaseCommand::Dismiss { at_ms, reason_code } => {
            let is_idempotent = case.status() == SafetyCaseStatus::Dismissed
                && case.closed_reason_code() == Some(reason_code);
            !is_idempotent && *at_ms < case.updated_at_ms()
        }
        _ => false,
    };
    if predates_state {
        return Err(SafetyCaseRuntimeError::InvalidLifecycleTimestamp);
    }
    Ok(())
}

fn validate_capacity(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), SafetyCaseRuntimeError> {
    if actual == 0 || actual > maximum {
        return Err(SafetyCaseRuntimeError::InvalidCapacity {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn validate_account_state_byte_budget(actual: usize) -> Result<(), SafetyCaseRuntimeError> {
    if !(MIN_CONFIGURED_ACCOUNT_STATE_BYTES..=SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES).contains(&actual)
    {
        return Err(SafetyCaseRuntimeError::InvalidAccountStateByteBudget {
            actual,
            minimum: MIN_CONFIGURED_ACCOUNT_STATE_BYTES,
            maximum: SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES,
        });
    }
    Ok(())
}

fn canonical_source_key(identity: &SafetyCaseIngestIdentity) -> CanonicalSourceKey {
    CanonicalSourceKey {
        account_key: identity.account_key.clone(),
        subject_key: identity.subject_key.clone(),
        source_event: identity.source_event.clone(),
    }
}

fn canonical_event_key(identity: &SafetyCaseIngestIdentity) -> CanonicalEventKey {
    CanonicalEventKey {
        account_key: identity.account_key.clone(),
        subject_key: identity.subject_key.clone(),
        conversation_key: identity.source_event.conversation_key().clone(),
        event_id: identity.source_event.event_id().clone(),
    }
}

fn active_route_key_from_case_key(case_key: &CaseRegistryKey) -> ActiveCaseRouteKey {
    ActiveCaseRouteKey {
        account_key: case_key.account_key.clone(),
        subject_key: case_key.subject_key.clone(),
        threat_type: case_key.threat_type,
    }
}

fn project_observation(
    identity: &SafetyCaseIngestIdentity,
    observation_id: &SafetyObservationId,
    result: &AnalysisResult,
) -> Result<Option<SafetyObservation>, SafetyCaseRuntimeError> {
    if result.threat_type == ThreatType::None || result.action == Action::Allow {
        return Ok(None);
    }
    if !result.score.is_finite() || !(0.0..=1.0).contains(&result.score) {
        return Err(SafetyCaseRuntimeError::InvalidAnalysisScore);
    }
    if result.score == 0.0 {
        return Ok(None);
    }

    let basis_points = (f64::from(result.score) * 10_000.0).round() as u16;
    let risk_score =
        RiskScore::new(basis_points).map_err(|_| SafetyCaseRuntimeError::InvalidAnalysisScore)?;
    let reason_codes = result
        .reason_codes
        .iter()
        .map(|code| SafetyReasonCode::new(code.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let observation = SafetyObservation::new(
        observation_id.clone(),
        identity.source_event.clone(),
        identity.occurred_at_ms,
        identity.observed_at_ms,
        result.threat_type,
        map_severity(result.action, result.score),
        result.confidence,
        risk_score,
    )?
    .with_reason_codes(reason_codes)?;
    Ok(Some(observation))
}

fn derive_case_id(
    identity: &SafetyCaseIngestIdentity,
    threat_type: ThreatType,
    generation: SafetyCaseGeneration,
) -> Result<SafetyCaseId, IdentifierError> {
    derive_case_id_for(
        &identity.account_key,
        &identity.subject_key,
        threat_type,
        generation,
    )
}

fn derive_case_id_for(
    account_key: &SafetyAccountKey,
    subject_key: &SafetyCaseSubjectKey,
    threat_type: ThreatType,
    generation: SafetyCaseGeneration,
) -> Result<SafetyCaseId, IdentifierError> {
    let digest = if generation == SafetyCaseGeneration::INITIAL {
        derive_content_free_digest(
            b"aura.safety_case.case_id.v1",
            &[
                account_key.as_ref().as_bytes(),
                subject_key.as_ref().as_bytes(),
                threat_identity_tag(threat_type),
            ],
        )
    } else {
        let generation_bytes = generation.value().to_be_bytes();
        derive_content_free_digest(
            b"aura.safety_case.case_id.v2",
            &[
                account_key.as_ref().as_bytes(),
                subject_key.as_ref().as_bytes(),
                threat_identity_tag(threat_type),
                &generation_bytes,
            ],
        )
    };
    SafetyCaseId::new(format!("case_{digest}"))
}

fn derive_observation_id(
    identity: &SafetyCaseIngestIdentity,
    threat_type: ThreatType,
) -> Result<SafetyObservationId, IdentifierError> {
    derive_observation_id_for(
        &identity.account_key,
        &identity.subject_key,
        &identity.source_event,
        threat_type,
    )
}

fn derive_observation_id_for(
    account_key: &SafetyAccountKey,
    subject_key: &SafetyCaseSubjectKey,
    source_event: &SourceEventKey,
    threat_type: ThreatType,
) -> Result<SafetyObservationId, IdentifierError> {
    let revision = source_event.revision().to_be_bytes();
    let digest = derive_content_free_digest(
        b"aura.safety_case.observation_id.v1",
        &[
            account_key.as_ref().as_bytes(),
            subject_key.as_ref().as_bytes(),
            source_event.conversation_key().as_ref().as_bytes(),
            source_event.event_id().as_ref().as_bytes(),
            &revision,
            threat_identity_tag(threat_type),
        ],
    );
    SafetyObservationId::new(format!("observation_{digest}"))
}

fn derive_content_free_digest(domain: &[u8], components: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        let length = u64::try_from(component.len()).unwrap_or(u64::MAX);
        hasher.update(length.to_be_bytes());
        hasher.update(component);
    }
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn threat_identity_tag(threat_type: ThreatType) -> &'static [u8] {
    match threat_type {
        ThreatType::None => b"none",
        ThreatType::Bullying => b"bullying",
        ThreatType::Grooming => b"grooming",
        ThreatType::Explicit => b"explicit",
        ThreatType::Threat => b"threat",
        ThreatType::SelfHarm => b"self_harm",
        ThreatType::Spam => b"spam",
        ThreatType::Scam => b"scam",
        ThreatType::Phishing => b"phishing",
        ThreatType::Manipulation => b"manipulation",
        ThreatType::Nsfw => b"nsfw",
        ThreatType::HateSpeech => b"hate_speech",
        ThreatType::Doxxing => b"doxxing",
        ThreatType::PiiLeakage => b"pii_leakage",
        ThreatType::Propaganda => b"propaganda",
        ThreatType::OpsecViolation => b"opsec_violation",
        ThreatType::Psyops => b"psyops",
        ThreatType::MilitarySocialEng => b"military_social_eng",
        ThreatType::CoordinateLeak => b"coordinate_leak",
    }
}

fn ignored_reason(result: &AnalysisResult) -> SafetyCaseIgnoredReason {
    if result.threat_type == ThreatType::None {
        SafetyCaseIgnoredReason::NoThreat
    } else if result.action == Action::Allow {
        SafetyCaseIgnoredReason::NonActionable
    } else {
        SafetyCaseIgnoredReason::ZeroRisk
    }
}

fn map_severity(action: Action, score: f32) -> SafetyCaseSeverity {
    if action == Action::Block || score >= 0.90 {
        SafetyCaseSeverity::Critical
    } else if matches!(action, Action::Warn | Action::Blur) || score >= 0.70 {
        SafetyCaseSeverity::High
    } else if action == Action::Mark || score >= 0.40 {
        SafetyCaseSeverity::Elevated
    } else {
        SafetyCaseSeverity::Informational
    }
}
