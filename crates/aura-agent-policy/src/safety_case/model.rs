use std::fmt;

use aura_contracts::{Confidence, ThreatType};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Schema version for persisted [`SafetyObservation`] values.
pub const SAFETY_OBSERVATION_SCHEMA_VERSION: &str = "aura.safety_observation.v1";
/// Schema version for persisted [`SafetyCase`] values.
pub const SAFETY_CASE_SCHEMA_VERSION: &str = "aura.safety_case.v1";
/// Schema version for [`SafetyCaseDecision`] values.
pub const SAFETY_CASE_DECISION_SCHEMA_VERSION: &str = "aura.safety_case_decision.v1";
/// Schema version for [`GuardianReport`] values.
pub const GUARDIAN_REPORT_SCHEMA_VERSION: &str = "aura.guardian_report.v1";

const MAX_OPAQUE_ID_BYTES: usize = 256;
const MAX_REASON_CODE_BYTES: usize = 128;
const MAX_OBSERVATION_REASON_CODES: usize = 16;

/// Error returned when an opaque domain identifier is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentifierError {
    /// The identifier is empty.
    #[error("{kind} must not be empty")]
    Empty {
        /// Identifier kind used in diagnostics.
        kind: &'static str,
    },
    /// The identifier exceeds the bounded wire size.
    #[error("{kind} exceeds {max_bytes} bytes")]
    TooLong {
        /// Identifier kind used in diagnostics.
        kind: &'static str,
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
    },
    /// The identifier contains whitespace or control characters.
    #[error("{kind} contains whitespace or control characters")]
    InvalidCharacter {
        /// Identifier kind used in diagnostics.
        kind: &'static str,
    },
}

fn validate_opaque_id(kind: &'static str, value: String) -> Result<String, IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty { kind });
    }
    if value.len() > MAX_OPAQUE_ID_BYTES {
        return Err(IdentifierError::TooLong {
            kind,
            max_bytes: MAX_OPAQUE_ID_BYTES,
        });
    }
    if value.chars().any(|character| {
        character.is_control() || character.is_whitespace()
    }) {
        return Err(IdentifierError::InvalidCharacter { kind });
    }
    Ok(value)
}

macro_rules! define_opaque_id {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated opaque identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                validate_opaque_id($kind, value.into()).map(Self)
            }

            /// Returns the identifier without exposing ownership.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentifierError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_opaque_id!(
    /// Stable identifier for one safety case.
    SafetyCaseId,
    "safety case id"
);
define_opaque_id!(
    /// Stable identifier for one analyzer observation.
    SafetyObservationId,
    "safety observation id"
);
define_opaque_id!(
    /// Opaque account-scoped subject key used to route a case.
    SafetyCaseSubjectKey,
    "safety case subject key"
);
define_opaque_id!(
    /// Opaque conversation key. It must not contain conversation content.
    ConversationEventKey,
    "conversation event key"
);
define_opaque_id!(
    /// Stable source event identifier. It must not contain message content.
    SourceEventId,
    "source event id"
);

/// Machine-readable policy reason code.
///
/// The restricted alphabet deliberately prevents this field from becoming a
/// free-form verdict or user-facing explanation channel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafetyReasonCode(String);

impl SafetyReasonCode {
    /// Creates a validated reason code such as `kids.grooming.secrecy`.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentifierError::Empty {
                kind: "safety reason code",
            });
        }
        if value.len() > MAX_REASON_CODE_BYTES {
            return Err(IdentifierError::TooLong {
                kind: "safety reason code",
                max_bytes: MAX_REASON_CODE_BYTES,
            });
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        }) {
            return Err(IdentifierError::InvalidCharacter {
                kind: "safety reason code",
            });
        }
        Ok(Self(value))
    }

    /// Returns the stable reason-code value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafetyReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for SafetyReasonCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SafetyReasonCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Error returned when a basis-point risk score is outside its valid range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("risk score {value} exceeds the maximum of 10000 basis points")]
pub struct RiskScoreError {
    /// Rejected value.
    pub value: u16,
}

/// Bounded risk index in basis points (`0..=10_000`).
///
/// This type is intentionally not named a probability. A detector score must
/// not be presented as calibrated risk unless a separate calibration contract
/// establishes that meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RiskScore(u16);

impl RiskScore {
    /// Zero risk-index basis points.
    pub const ZERO: Self = Self(0);

    /// Creates a bounded risk index.
    pub fn new(basis_points: u16) -> Result<Self, RiskScoreError> {
        if basis_points > 10_000 {
            return Err(RiskScoreError {
                value: basis_points,
            });
        }
        Ok(Self(basis_points))
    }

    /// Returns the risk index in basis points.
    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

impl Serialize for RiskScore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for RiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Ordered case severity used for lifecycle transitions.
#[non_exhaustive]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCaseSeverity {
    /// A weak observation that is retained only for context.
    #[default]
    Informational,
    /// A meaningful pattern that may open a case.
    Elevated,
    /// A strong or progressing pattern that may escalate a case.
    High,
    /// A time-sensitive pattern that may require urgent review.
    Critical,
}

/// Lifecycle state of a safety case.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCaseStatus {
    /// Context is accumulating without a product-facing case.
    #[default]
    Observing,
    /// A case is open for continued assessment.
    Open,
    /// The case has progressed beyond its opening state.
    Escalated,
    /// The case requires urgent review under the active policy.
    Urgent,
    /// The concern was addressed or is no longer active.
    Resolved,
    /// The case was closed as irrelevant, erroneous, or out of scope.
    Dismissed,
}

impl SafetyCaseStatus {
    /// Returns whether no further observation may be applied to this case.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Resolved | Self::Dismissed)
    }
}

/// Stable identity of the source event that produced an observation.
///
/// The revision is part of the key, so a message edit is a new source event
/// while re-processing the same revision is idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceEventKey {
    conversation_key: ConversationEventKey,
    event_id: SourceEventId,
    revision: u32,
}

impl SourceEventKey {
    /// Creates an account-scoped source event key.
    pub const fn new(
        conversation_key: ConversationEventKey,
        event_id: SourceEventId,
        revision: u32,
    ) -> Self {
        Self {
            conversation_key,
            event_id,
            revision,
        }
    }

    /// Returns the opaque conversation component.
    pub const fn conversation_key(&self) -> &ConversationEventKey {
        &self.conversation_key
    }

    /// Returns the stable event identifier.
    pub const fn event_id(&self) -> &SourceEventId {
        &self.event_id
    }

    /// Returns the source-event revision.
    pub const fn revision(&self) -> u32 {
        self.revision
    }
}

/// Structured, content-free analyzer observation consumed by the case reducer.
///
/// Raw message text, explanations, and display verdicts are deliberately not
/// part of this contract. Product surfaces must be derived from case policy,
/// not copied from a per-message detector result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyObservation {
    schema_version: String,
    observation_id: SafetyObservationId,
    source_event: SourceEventKey,
    occurred_at_ms: u64,
    observed_at_ms: u64,
    threat_type: ThreatType,
    severity: SafetyCaseSeverity,
    confidence: Confidence,
    risk_score: RiskScore,
    reason_codes: Vec<SafetyReasonCode>,
}

/// Error returned when constructing or validating an observation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyObservationError {
    /// The observation uses an unsupported persisted schema.
    #[error("unsupported safety observation schema: {0}")]
    UnsupportedSchema(String),
    /// `ThreatType::None` cannot open or update a case.
    #[error("safety observation threat type must not be none")]
    MissingThreat,
    /// Too many reason codes were attached to one observation.
    #[error("safety observation has {actual} reason codes; maximum is {maximum}")]
    TooManyReasonCodes {
        /// Number of supplied reason codes.
        actual: usize,
        /// Maximum accepted reason codes.
        maximum: usize,
    },
    /// Deserialized reason codes are not sorted and unique.
    #[error("safety observation reason codes must be sorted and unique")]
    NonCanonicalReasonCodes,
    /// Analyzer emission time predates the source event.
    #[error("safety observation timestamp predates its source event")]
    InvalidTimestamps,
}

impl SafetyObservation {
    /// Creates a structured observation with no reason codes.
    #[expect(clippy::too_many_arguments, reason = "all fields form the stable observation identity")]
    pub fn new(
        observation_id: SafetyObservationId,
        source_event: SourceEventKey,
        occurred_at_ms: u64,
        observed_at_ms: u64,
        threat_type: ThreatType,
        severity: SafetyCaseSeverity,
        confidence: Confidence,
        risk_score: RiskScore,
    ) -> Result<Self, SafetyObservationError> {
        if threat_type == ThreatType::None {
            return Err(SafetyObservationError::MissingThreat);
        }
        if observed_at_ms < occurred_at_ms {
            return Err(SafetyObservationError::InvalidTimestamps);
        }
        Ok(Self {
            schema_version: SAFETY_OBSERVATION_SCHEMA_VERSION.to_string(),
            observation_id,
            source_event,
            occurred_at_ms,
            observed_at_ms,
            threat_type,
            severity,
            confidence,
            risk_score,
            reason_codes: Vec::new(),
        })
    }

    /// Adds canonical, bounded reason codes to the observation.
    ///
    /// Codes are sorted and deduplicated so equivalent detector output has the
    /// same persisted form regardless of detector iteration order.
    pub fn with_reason_codes(
        mut self,
        mut reason_codes: Vec<SafetyReasonCode>,
    ) -> Result<Self, SafetyObservationError> {
        reason_codes.sort();
        reason_codes.dedup();
        if reason_codes.len() > MAX_OBSERVATION_REASON_CODES {
            return Err(SafetyObservationError::TooManyReasonCodes {
                actual: reason_codes.len(),
                maximum: MAX_OBSERVATION_REASON_CODES,
            });
        }
        self.reason_codes = reason_codes;
        Ok(self)
    }

    /// Validates a deserialized observation before reduction.
    pub fn validate(&self) -> Result<(), SafetyObservationError> {
        if self.schema_version != SAFETY_OBSERVATION_SCHEMA_VERSION {
            return Err(SafetyObservationError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        if self.threat_type == ThreatType::None {
            return Err(SafetyObservationError::MissingThreat);
        }
        if self.observed_at_ms < self.occurred_at_ms {
            return Err(SafetyObservationError::InvalidTimestamps);
        }
        if self.reason_codes.len() > MAX_OBSERVATION_REASON_CODES {
            return Err(SafetyObservationError::TooManyReasonCodes {
                actual: self.reason_codes.len(),
                maximum: MAX_OBSERVATION_REASON_CODES,
            });
        }
        if self
            .reason_codes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(SafetyObservationError::NonCanonicalReasonCodes);
        }
        Ok(())
    }

    /// Returns the persisted observation schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the observation identifier.
    pub const fn observation_id(&self) -> &SafetyObservationId {
        &self.observation_id
    }

    /// Returns the exactly-once source key.
    pub const fn source_event(&self) -> &SourceEventKey {
        &self.source_event
    }

    /// Returns when the source event occurred.
    pub const fn occurred_at_ms(&self) -> u64 {
        self.occurred_at_ms
    }

    /// Returns when the analyzer emitted the observation.
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    /// Returns the observation threat family.
    pub const fn threat_type(&self) -> ThreatType {
        self.threat_type
    }

    /// Returns the lifecycle severity signal.
    pub const fn severity(&self) -> SafetyCaseSeverity {
        self.severity
    }

    /// Returns detector confidence.
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the bounded risk index.
    pub const fn risk_score(&self) -> RiskScore {
        self.risk_score
    }

    /// Returns machine-readable reason codes.
    pub fn reason_codes(&self) -> &[SafetyReasonCode] {
        &self.reason_codes
    }

    pub(crate) fn semantically_matches(&self, other: &Self) -> bool {
        self.source_event == other.source_event
            && self.occurred_at_ms == other.occurred_at_ms
            && self.observed_at_ms == other.observed_at_ms
            && self.threat_type == other.threat_type
            && self.severity == other.severity
            && self.confidence == other.confidence
            && self.risk_score == other.risk_score
            && self.reason_codes == other.reason_codes
    }
}

/// Reason a guardian report exists.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianReportTrigger {
    /// The case crossed its opening threshold.
    CaseOpened,
    /// The case crossed its escalation threshold.
    CaseEscalated,
    /// The case crossed its urgent threshold.
    UrgentReview,
    /// The case was resolved after previously being open.
    CaseResolved,
}

/// Stable idempotency key for guardian report delivery.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuardianReportKey {
    case_id: SafetyCaseId,
    transition_revision: u64,
}

impl GuardianReportKey {
    pub(crate) const fn new(case_id: SafetyCaseId, transition_revision: u64) -> Self {
        Self {
            case_id,
            transition_revision,
        }
    }

    /// Returns the case identifier.
    pub const fn case_id(&self) -> &SafetyCaseId {
        &self.case_id
    }

    /// Returns the case revision that generated this report.
    pub const fn transition_revision(&self) -> u64 {
        self.transition_revision
    }
}

/// Privacy-bounded report for a guardian transport.
///
/// The report contains only case state, machine-readable codes, and opaque
/// evidence references. The host may resolve evidence only under its separate
/// consent, access-control, and retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianReport {
    pub(crate) schema_version: String,
    pub(crate) key: GuardianReportKey,
    pub(crate) subject_key: SafetyCaseSubjectKey,
    pub(crate) trigger: GuardianReportTrigger,
    pub(crate) queued_at_ms: u64,
    pub(crate) threat_type: ThreatType,
    pub(crate) case_status: SafetyCaseStatus,
    pub(crate) severity: SafetyCaseSeverity,
    pub(crate) confidence: Confidence,
    pub(crate) peak_risk_score: RiskScore,
    pub(crate) first_observed_at_ms: Option<u64>,
    pub(crate) last_observed_at_ms: Option<u64>,
    pub(crate) observation_count: u32,
    pub(crate) reason_codes: Vec<SafetyReasonCode>,
    pub(crate) evidence: Vec<SourceEventKey>,
}

impl GuardianReport {
    /// Returns the guardian-report schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the stable delivery idempotency key.
    pub const fn key(&self) -> &GuardianReportKey {
        &self.key
    }

    /// Returns the account-scoped routing key.
    pub const fn subject_key(&self) -> &SafetyCaseSubjectKey {
        &self.subject_key
    }

    /// Returns why the report was generated.
    pub const fn trigger(&self) -> GuardianReportTrigger {
        self.trigger
    }

    /// Returns when delivery became ready.
    pub const fn queued_at_ms(&self) -> u64 {
        self.queued_at_ms
    }

    /// Returns the case threat family.
    pub const fn threat_type(&self) -> ThreatType {
        self.threat_type
    }

    /// Returns the case status captured in the report.
    pub const fn case_status(&self) -> SafetyCaseStatus {
        self.case_status
    }

    /// Returns the peak case severity.
    pub const fn severity(&self) -> SafetyCaseSeverity {
        self.severity
    }

    /// Returns the strongest confidence seen in the case.
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the peak bounded risk index.
    pub const fn peak_risk_score(&self) -> RiskScore {
        self.peak_risk_score
    }

    /// Returns the number of accepted observations.
    pub const fn observation_count(&self) -> u32 {
        self.observation_count
    }

    /// Returns when the first retained observation occurred.
    pub const fn first_observed_at_ms(&self) -> Option<u64> {
        self.first_observed_at_ms
    }

    /// Returns when the latest retained observation occurred.
    pub const fn last_observed_at_ms(&self) -> Option<u64> {
        self.last_observed_at_ms
    }

    /// Returns machine-readable report reasons.
    pub fn reason_codes(&self) -> &[SafetyReasonCode] {
        &self.reason_codes
    }

    /// Returns bounded opaque evidence references.
    pub fn evidence(&self) -> &[SourceEventKey] {
        &self.evidence
    }
}

/// Receipt for the last guardian report confirmed by the host transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianDeliveryReceipt {
    pub(crate) key: GuardianReportKey,
    pub(crate) delivered_at_ms: u64,
}

impl GuardianDeliveryReceipt {
    /// Returns the delivered report key.
    pub const fn key(&self) -> &GuardianReportKey {
        &self.key
    }

    /// Returns the host-confirmed delivery timestamp.
    pub const fn delivered_at_ms(&self) -> u64 {
        self.delivered_at_ms
    }
}

/// A report transition retained until its cooldown expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredGuardianReport {
    pub(crate) trigger: GuardianReportTrigger,
    pub(crate) transition_revision: u64,
    pub(crate) transition_at_ms: u64,
    pub(crate) eligible_at_ms: u64,
}

impl DeferredGuardianReport {
    /// Returns the retained transition kind.
    pub const fn trigger(&self) -> GuardianReportTrigger {
        self.trigger
    }

    /// Returns when the retained report may be queued.
    pub const fn eligible_at_ms(&self) -> u64 {
        self.eligible_at_ms
    }

    /// Returns the case revision that produced the retained transition.
    pub const fn transition_revision(&self) -> u64 {
        self.transition_revision
    }

    /// Returns when the retained transition occurred.
    pub const fn transition_at_ms(&self) -> u64 {
        self.transition_at_ms
    }
}

/// Persistable state of one threat-family case for one protected subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCase {
    pub(crate) schema_version: String,
    pub(crate) case_id: SafetyCaseId,
    pub(crate) subject_key: SafetyCaseSubjectKey,
    pub(crate) threat_type: ThreatType,
    pub(crate) status: SafetyCaseStatus,
    pub(crate) severity: SafetyCaseSeverity,
    pub(crate) peak_risk_score: RiskScore,
    pub(crate) confidence: Confidence,
    pub(crate) created_at_ms: u64,
    pub(crate) updated_at_ms: u64,
    pub(crate) first_observed_at_ms: Option<u64>,
    pub(crate) last_observed_at_ms: Option<u64>,
    pub(crate) closed_at_ms: Option<u64>,
    pub(crate) revision: u64,
    pub(crate) observations: Vec<SafetyObservation>,
    pub(crate) reason_codes: Vec<SafetyReasonCode>,
    pub(crate) closed_reason_code: Option<SafetyReasonCode>,
    pub(crate) pending_guardian_report: Option<GuardianReport>,
    pub(crate) deferred_guardian_report: Option<DeferredGuardianReport>,
    pub(crate) last_guardian_delivery: Option<GuardianDeliveryReceipt>,
}

/// Error returned while creating a safety case.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyCaseConstructionError {
    /// A case must be bound to a concrete threat family.
    #[error("safety case threat type must not be none")]
    MissingThreat,
}

impl SafetyCase {
    /// Creates an empty observing case.
    pub fn new(
        case_id: SafetyCaseId,
        subject_key: SafetyCaseSubjectKey,
        threat_type: ThreatType,
        created_at_ms: u64,
    ) -> Result<Self, SafetyCaseConstructionError> {
        if threat_type == ThreatType::None {
            return Err(SafetyCaseConstructionError::MissingThreat);
        }
        Ok(Self {
            schema_version: SAFETY_CASE_SCHEMA_VERSION.to_string(),
            case_id,
            subject_key,
            threat_type,
            status: SafetyCaseStatus::Observing,
            severity: SafetyCaseSeverity::Informational,
            peak_risk_score: RiskScore::ZERO,
            confidence: Confidence::Low,
            created_at_ms,
            updated_at_ms: created_at_ms,
            first_observed_at_ms: None,
            last_observed_at_ms: None,
            closed_at_ms: None,
            revision: 0,
            observations: Vec::new(),
            reason_codes: Vec::new(),
            closed_reason_code: None,
            pending_guardian_report: None,
            deferred_guardian_report: None,
            last_guardian_delivery: None,
        })
    }

    /// Returns the persisted schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the stable case identifier.
    pub const fn case_id(&self) -> &SafetyCaseId {
        &self.case_id
    }

    /// Returns the account-scoped subject key.
    pub const fn subject_key(&self) -> &SafetyCaseSubjectKey {
        &self.subject_key
    }

    /// Returns the case threat family.
    pub const fn threat_type(&self) -> ThreatType {
        self.threat_type
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> SafetyCaseStatus {
        self.status
    }

    /// Returns the peak severity seen by the case.
    pub const fn severity(&self) -> SafetyCaseSeverity {
        self.severity
    }

    /// Returns the peak bounded risk index.
    pub const fn peak_risk_score(&self) -> RiskScore {
        self.peak_risk_score
    }

    /// Returns the strongest confidence seen by the case.
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the current optimistic-concurrency revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns when the case state was created.
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Returns the latest command timestamp reflected by the case.
    pub const fn updated_at_ms(&self) -> u64 {
        self.updated_at_ms
    }

    /// Returns the earliest accepted source-event timestamp.
    pub const fn first_observed_at_ms(&self) -> Option<u64> {
        self.first_observed_at_ms
    }

    /// Returns the latest accepted source-event timestamp.
    pub const fn last_observed_at_ms(&self) -> Option<u64> {
        self.last_observed_at_ms
    }

    /// Returns when the case entered a terminal state.
    pub const fn closed_at_ms(&self) -> Option<u64> {
        self.closed_at_ms
    }

    /// Returns the machine-readable terminal reason, if closed.
    pub const fn closed_reason_code(&self) -> Option<&SafetyReasonCode> {
        self.closed_reason_code.as_ref()
    }

    /// Returns all accepted content-free observations.
    pub fn observations(&self) -> &[SafetyObservation] {
        &self.observations
    }

    /// Returns canonical case-level reason codes.
    pub fn reason_codes(&self) -> &[SafetyReasonCode] {
        &self.reason_codes
    }

    /// Returns the report waiting for host delivery, if any.
    pub const fn pending_guardian_report(&self) -> Option<&GuardianReport> {
        self.pending_guardian_report.as_ref()
    }

    /// Returns the report transition waiting for cooldown expiry, if any.
    pub const fn deferred_guardian_report(&self) -> Option<&DeferredGuardianReport> {
        self.deferred_guardian_report.as_ref()
    }

    /// Returns the last host-confirmed guardian delivery.
    pub const fn last_guardian_delivery(&self) -> Option<&GuardianDeliveryReceipt> {
        self.last_guardian_delivery.as_ref()
    }
}

/// Domain event emitted by a successful reduction.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SafetyCaseEvent {
    /// A new observation was accepted into the case.
    ObservationAccepted {
        /// Accepted observation identifier.
        observation_id: SafetyObservationId,
        /// New case revision.
        case_revision: u64,
    },
    /// The case crossed a lifecycle boundary.
    StatusChanged {
        /// Status before the transition.
        from: SafetyCaseStatus,
        /// Status after the transition.
        to: SafetyCaseStatus,
        /// Timestamp supplied by the triggering command.
        at_ms: u64,
        /// New case revision.
        case_revision: u64,
    },
    /// A guardian report became ready for transport.
    GuardianReportQueued {
        /// Idempotent report key.
        report_key: GuardianReportKey,
    },
    /// A guardian report was retained until cooldown expiry.
    GuardianReportDeferred {
        /// Transition waiting for delivery.
        trigger: GuardianReportTrigger,
        /// Earliest eligible timestamp.
        eligible_at_ms: u64,
    },
    /// A lower-priority pending report was replaced by a stronger transition.
    GuardianReportSuperseded {
        /// Replaced report key.
        previous_report_key: GuardianReportKey,
        /// Replacement report key.
        replacement_report_key: GuardianReportKey,
    },
    /// The host confirmed delivery of a queued report.
    GuardianReportDelivered {
        /// Delivered report key.
        report_key: GuardianReportKey,
        /// Host-confirmed timestamp.
        delivered_at_ms: u64,
    },
}

/// High-level result of reducing one command.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCaseDecisionOutcome {
    /// State changed and the revision advanced.
    Updated,
    /// The exact observation was already accepted.
    DuplicateIgnored,
    /// The command was valid but did not change state.
    NoChange,
}

/// Guardian delivery instruction produced by the reducer.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuardianReportDirective {
    /// This reduction does not require guardian delivery.
    NotRequired,
    /// A newly created report should be delivered idempotently.
    Queue {
        /// Structured report to enqueue.
        report: GuardianReport,
    },
    /// A previously queued report remains pending and may be retried.
    Pending {
        /// Existing idempotent report.
        report: GuardianReport,
    },
    /// Delivery is retained until the reported timestamp.
    Deferred {
        /// Transition waiting for delivery.
        trigger: GuardianReportTrigger,
        /// Earliest delivery timestamp.
        eligible_at_ms: u64,
    },
}

/// Product-neutral decision for one case command.
///
/// It intentionally contains no per-message UI action or free-form verdict.
/// Child and guardian surfaces must consume the case lifecycle and apply their
/// own versioned product policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCaseDecision {
    pub(crate) schema_version: String,
    pub(crate) case_id: SafetyCaseId,
    pub(crate) case_revision: u64,
    pub(crate) status: SafetyCaseStatus,
    pub(crate) outcome: SafetyCaseDecisionOutcome,
    pub(crate) events: Vec<SafetyCaseEvent>,
    pub(crate) guardian_report: GuardianReportDirective,
}

impl SafetyCaseDecision {
    /// Returns the decision schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the case identifier.
    pub const fn case_id(&self) -> &SafetyCaseId {
        &self.case_id
    }

    /// Returns the case revision after reduction.
    pub const fn case_revision(&self) -> u64 {
        self.case_revision
    }

    /// Returns the current lifecycle status.
    pub const fn status(&self) -> SafetyCaseStatus {
        self.status
    }

    /// Returns whether the command updated, deduplicated, or left state unchanged.
    pub const fn outcome(&self) -> SafetyCaseDecisionOutcome {
        self.outcome
    }

    /// Returns emitted domain events.
    pub fn events(&self) -> &[SafetyCaseEvent] {
        &self.events
    }

    /// Returns the guardian delivery instruction.
    pub const fn guardian_report(&self) -> &GuardianReportDirective {
        &self.guardian_report
    }
}

/// Atomic output of a deterministic case reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCaseReduction {
    case: SafetyCase,
    decision: SafetyCaseDecision,
}

impl SafetyCaseReduction {
    pub(crate) const fn new(case: SafetyCase, decision: SafetyCaseDecision) -> Self {
        Self { case, decision }
    }

    /// Returns the updated case.
    pub const fn case(&self) -> &SafetyCase {
        &self.case
    }

    /// Returns the product-neutral decision.
    pub const fn decision(&self) -> &SafetyCaseDecision {
        &self.decision
    }

    /// Splits the reduction into owned state and decision values.
    pub fn into_parts(self) -> (SafetyCase, SafetyCaseDecision) {
        (self.case, self.decision)
    }
}
