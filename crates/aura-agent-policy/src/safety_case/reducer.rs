use std::collections::HashSet;

use aura_contracts::{Confidence, ThreatType};
use serde::{Deserialize, Serialize};

use super::model::{
    DeferredGuardianReport, GuardianDeliveryReceipt, GuardianReport, GuardianReportDirective,
    GuardianReportKey, GuardianReportTrigger, RiskScore, SafetyCase, SafetyCaseDecision,
    SafetyCaseDecisionOutcome, SafetyCaseEvent, SafetyCaseReduction, SafetyCaseSeverity,
    SafetyCaseStatus, SafetyObservation, SafetyObservationError, SafetyReasonCode,
    GUARDIAN_REPORT_SCHEMA_VERSION, SAFETY_CASE_DECISION_SCHEMA_VERSION,
    SAFETY_CASE_SCHEMA_VERSION,
};

const DEFAULT_MAX_OBSERVATIONS: usize = 256;
const MAX_CONFIGURED_OBSERVATIONS: usize = 4_096;
const DEFAULT_MAX_CASE_REASON_CODES: usize = 32;
const MAX_CONFIGURED_CASE_REASON_CODES: usize = 128;
const DEFAULT_GUARDIAN_EVIDENCE_LIMIT: usize = 5;
const MAX_GUARDIAN_EVIDENCE_LIMIT: usize = 16;
const DEFAULT_GUARDIAN_COOLDOWN_MS: u64 = 30 * 60 * 1_000;

/// Schema version for persisted [`SafetyCasePolicy`] values.
pub const SAFETY_CASE_POLICY_SCHEMA_VERSION: &str = "aura.safety_case_policy.v1";

fn default_policy_schema_version() -> String {
    SAFETY_CASE_POLICY_SCHEMA_VERSION.to_string()
}

fn default_max_observations() -> usize {
    DEFAULT_MAX_OBSERVATIONS
}

fn default_max_case_reason_codes() -> usize {
    DEFAULT_MAX_CASE_REASON_CODES
}

/// Lifecycle severity thresholds applied by [`SafetyCaseReducer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SafetyCaseThresholds {
    open_at: SafetyCaseSeverity,
    escalate_at: SafetyCaseSeverity,
    urgent_at: SafetyCaseSeverity,
}

impl SafetyCaseThresholds {
    /// Creates ordered lifecycle thresholds.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyCasePolicyError::InvalidThresholdOrder`] when thresholds
    /// are not monotonically increasing.
    pub fn new(
        open_at: SafetyCaseSeverity,
        escalate_at: SafetyCaseSeverity,
        urgent_at: SafetyCaseSeverity,
    ) -> Result<Self, SafetyCasePolicyError> {
        let thresholds = Self {
            open_at,
            escalate_at,
            urgent_at,
        };
        thresholds.validate()?;
        Ok(thresholds)
    }

    /// Returns the opening threshold.
    pub const fn open_at(self) -> SafetyCaseSeverity {
        self.open_at
    }

    /// Returns the escalation threshold.
    pub const fn escalate_at(self) -> SafetyCaseSeverity {
        self.escalate_at
    }

    /// Returns the urgent-review threshold.
    pub const fn urgent_at(self) -> SafetyCaseSeverity {
        self.urgent_at
    }

    fn validate(self) -> Result<(), SafetyCasePolicyError> {
        if self.open_at > self.escalate_at || self.escalate_at > self.urgent_at {
            return Err(SafetyCasePolicyError::InvalidThresholdOrder);
        }
        Ok(())
    }
}

impl Default for SafetyCaseThresholds {
    fn default() -> Self {
        Self {
            open_at: SafetyCaseSeverity::Elevated,
            escalate_at: SafetyCaseSeverity::High,
            urgent_at: SafetyCaseSeverity::Critical,
        }
    }
}

/// Guardian reporting rules for lifecycle transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardianReportingPolicy {
    cooldown_ms: u64,
    evidence_limit: usize,
    report_on_open: bool,
    report_on_escalation: bool,
    report_on_urgent: bool,
    report_on_resolution: bool,
    urgent_bypasses_cooldown: bool,
}

impl GuardianReportingPolicy {
    /// Sets the minimum interval between host-confirmed guardian deliveries.
    pub fn with_cooldown_ms(mut self, cooldown_ms: u64) -> Self {
        self.cooldown_ms = cooldown_ms;
        self
    }

    /// Sets the maximum number of opaque event references in one report.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyCasePolicyError::InvalidEvidenceLimit`] for zero or a
    /// value above the release bound.
    pub fn with_evidence_limit(
        mut self,
        evidence_limit: usize,
    ) -> Result<Self, SafetyCasePolicyError> {
        validate_evidence_limit(evidence_limit)?;
        self.evidence_limit = evidence_limit;
        Ok(self)
    }

    /// Enables or disables reports when a case opens.
    pub fn with_report_on_open(mut self, enabled: bool) -> Self {
        self.report_on_open = enabled;
        self
    }

    /// Enables or disables reports when a case escalates.
    pub fn with_report_on_escalation(mut self, enabled: bool) -> Self {
        self.report_on_escalation = enabled;
        self
    }

    /// Enables or disables urgent guardian reports.
    pub fn with_report_on_urgent(mut self, enabled: bool) -> Self {
        self.report_on_urgent = enabled;
        self
    }

    /// Enables or disables resolution reports.
    pub fn with_report_on_resolution(mut self, enabled: bool) -> Self {
        self.report_on_resolution = enabled;
        self
    }

    /// Configures whether urgent transitions bypass the normal cooldown.
    pub fn with_urgent_cooldown_bypass(mut self, enabled: bool) -> Self {
        self.urgent_bypasses_cooldown = enabled;
        self
    }

    /// Returns the configured cooldown interval.
    pub const fn cooldown_ms(&self) -> u64 {
        self.cooldown_ms
    }

    /// Returns the evidence-reference limit.
    pub const fn evidence_limit(&self) -> usize {
        self.evidence_limit
    }

    fn is_enabled_for(&self, trigger: GuardianReportTrigger) -> bool {
        match trigger {
            GuardianReportTrigger::CaseOpened => self.report_on_open,
            GuardianReportTrigger::CaseEscalated => self.report_on_escalation,
            GuardianReportTrigger::UrgentReview => self.report_on_urgent,
            GuardianReportTrigger::CaseResolved => self.report_on_resolution,
        }
    }

    fn validate(&self) -> Result<(), SafetyCasePolicyError> {
        validate_evidence_limit(self.evidence_limit)
    }
}

impl Default for GuardianReportingPolicy {
    fn default() -> Self {
        Self {
            cooldown_ms: DEFAULT_GUARDIAN_COOLDOWN_MS,
            evidence_limit: DEFAULT_GUARDIAN_EVIDENCE_LIMIT,
            report_on_open: true,
            report_on_escalation: true,
            report_on_urgent: true,
            report_on_resolution: true,
            urgent_bypasses_cooldown: true,
        }
    }
}

/// Version-one policy for case reduction and guardian delivery.
///
/// The policy is passed explicitly to every reduction. It contains no ambient
/// clock, random source, global memory, or product UI action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCasePolicy {
    #[serde(default = "default_policy_schema_version")]
    schema_version: String,
    #[serde(default)]
    thresholds: SafetyCaseThresholds,
    #[serde(default)]
    guardian_reporting: GuardianReportingPolicy,
    #[serde(default = "default_max_observations")]
    max_observations: usize,
    #[serde(default = "default_max_case_reason_codes")]
    max_case_reason_codes: usize,
}

impl SafetyCasePolicy {
    /// Returns the persisted policy schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Replaces lifecycle severity thresholds.
    pub fn with_thresholds(mut self, thresholds: SafetyCaseThresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Replaces guardian reporting policy.
    pub fn with_guardian_reporting(mut self, reporting: GuardianReportingPolicy) -> Self {
        self.guardian_reporting = reporting;
        self
    }

    /// Sets the hard case observation capacity.
    ///
    /// Exhausting the capacity returns an error instead of silently evicting
    /// dedupe receipts. The host must resolve the case or start a successor.
    pub fn with_max_observations(
        mut self,
        max_observations: usize,
    ) -> Result<Self, SafetyCasePolicyError> {
        validate_capacity(
            "max observations",
            max_observations,
            MAX_CONFIGURED_OBSERVATIONS,
        )?;
        self.max_observations = max_observations;
        Ok(self)
    }

    /// Sets the maximum distinct reason codes retained by a case.
    pub fn with_max_case_reason_codes(
        mut self,
        maximum: usize,
    ) -> Result<Self, SafetyCasePolicyError> {
        validate_capacity(
            "max case reason codes",
            maximum,
            MAX_CONFIGURED_CASE_REASON_CODES,
        )?;
        self.max_case_reason_codes = maximum;
        Ok(self)
    }

    /// Returns lifecycle thresholds.
    pub const fn thresholds(&self) -> SafetyCaseThresholds {
        self.thresholds
    }

    /// Returns guardian reporting policy.
    pub const fn guardian_reporting(&self) -> &GuardianReportingPolicy {
        &self.guardian_reporting
    }

    /// Validates values loaded from persisted configuration.
    pub fn validate(&self) -> Result<(), SafetyCasePolicyError> {
        if self.schema_version != SAFETY_CASE_POLICY_SCHEMA_VERSION {
            return Err(SafetyCasePolicyError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        self.thresholds.validate()?;
        self.guardian_reporting.validate()?;
        validate_capacity(
            "max observations",
            self.max_observations,
            MAX_CONFIGURED_OBSERVATIONS,
        )?;
        validate_capacity(
            "max case reason codes",
            self.max_case_reason_codes,
            MAX_CONFIGURED_CASE_REASON_CODES,
        )
    }
}

impl Default for SafetyCasePolicy {
    fn default() -> Self {
        Self {
            schema_version: SAFETY_CASE_POLICY_SCHEMA_VERSION.to_string(),
            thresholds: SafetyCaseThresholds::default(),
            guardian_reporting: GuardianReportingPolicy::default(),
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_case_reason_codes: DEFAULT_MAX_CASE_REASON_CODES,
        }
    }
}

/// Error returned for an invalid reducer policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyCasePolicyError {
    /// The persisted policy schema is unsupported.
    #[error("unsupported safety case policy schema: {0}")]
    UnsupportedSchema(String),
    /// Lifecycle thresholds are not monotonically increasing.
    #[error("case thresholds must satisfy open <= escalate <= urgent")]
    InvalidThresholdOrder,
    /// A bounded collection capacity is zero or above its release maximum.
    #[error("{field} must be in 1..={maximum}; received {actual}")]
    InvalidCapacity {
        /// Policy field name.
        field: &'static str,
        /// Configured value.
        actual: usize,
        /// Maximum supported value.
        maximum: usize,
    },
    /// The guardian evidence limit is outside the privacy bound.
    #[error("guardian evidence limit must be in 1..={maximum}; received {actual}")]
    InvalidEvidenceLimit {
        /// Configured value.
        actual: usize,
        /// Maximum supported value.
        maximum: usize,
    },
}

fn validate_capacity(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), SafetyCasePolicyError> {
    if actual == 0 || actual > maximum {
        return Err(SafetyCasePolicyError::InvalidCapacity {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn validate_evidence_limit(actual: usize) -> Result<(), SafetyCasePolicyError> {
    if actual == 0 || actual > MAX_GUARDIAN_EVIDENCE_LIMIT {
        return Err(SafetyCasePolicyError::InvalidEvidenceLimit {
            actual,
            maximum: MAX_GUARDIAN_EVIDENCE_LIMIT,
        });
    }
    Ok(())
}

/// Explicit command accepted by the deterministic case reducer.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SafetyCaseCommand {
    /// Apply one structured analyzer observation.
    ApplyObservation {
        /// Content-free observation to reduce.
        observation: SafetyObservation,
    },
    /// Resolve an open, escalated, or urgent case.
    Resolve {
        /// Caller-supplied transition timestamp.
        at_ms: u64,
        /// Machine-readable resolution reason.
        reason_code: SafetyReasonCode,
    },
    /// Dismiss a case as erroneous, irrelevant, or out of scope.
    Dismiss {
        /// Caller-supplied transition timestamp.
        at_ms: u64,
        /// Machine-readable dismissal reason.
        reason_code: SafetyReasonCode,
    },
    /// Queue a deferred report after its cooldown expires.
    FlushDeferredGuardianReport {
        /// Caller-supplied evaluation timestamp.
        at_ms: u64,
    },
    /// Record successful delivery by the host transport.
    AcknowledgeGuardianReport {
        /// Idempotency key returned with the queued report.
        report_key: GuardianReportKey,
        /// Host-confirmed delivery timestamp.
        delivered_at_ms: u64,
    },
}

/// Error returned by [`SafetyCaseReducer::reduce`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyCaseReducerError {
    /// The supplied policy is invalid.
    #[error(transparent)]
    InvalidPolicy(#[from] SafetyCasePolicyError),
    /// The persisted case schema is unsupported.
    #[error("unsupported safety case schema: {0}")]
    UnsupportedCaseSchema(String),
    /// A persisted observation is invalid.
    #[error(transparent)]
    InvalidObservation(#[from] SafetyObservationError),
    /// A persisted or incoming observation belongs to another threat family.
    #[error("observation threat {actual:?} does not match case threat {expected:?}")]
    ThreatMismatch {
        /// Case threat family.
        expected: ThreatType,
        /// Observation threat family.
        actual: ThreatType,
    },
    /// One observation ID was reused with different structured data.
    #[error("observation id collision: {0}")]
    ObservationIdCollision(String),
    /// One source event revision produced conflicting observations.
    #[error("source event revision collision: {0}")]
    SourceEventCollision(String),
    /// Applying an observation would exceed the exact dedupe capacity.
    #[error("case observation capacity of {maximum} is exhausted")]
    ObservationCapacityExceeded {
        /// Configured hard capacity.
        maximum: usize,
    },
    /// Applying reason codes would exceed the bounded case capacity.
    #[error("case reason-code capacity of {maximum} is exhausted")]
    ReasonCodeCapacityExceeded {
        /// Configured hard capacity.
        maximum: usize,
    },
    /// The requested lifecycle transition is invalid.
    #[error("invalid safety case transition from {from:?} via {command}")]
    InvalidTransition {
        /// Current case status.
        from: SafetyCaseStatus,
        /// Stable command label.
        command: &'static str,
    },
    /// A pending report must be handled before this delivery command.
    #[error("guardian report key does not match the pending report")]
    GuardianReportKeyMismatch,
    /// A delivery acknowledgment predates the report queue time.
    #[error("guardian delivery timestamp predates report queue time")]
    InvalidDeliveryTimestamp,
    /// A persisted case violates a release invariant.
    #[error("invalid persisted safety case: {0}")]
    InvalidPersistedCase(&'static str),
    /// The optimistic-concurrency revision cannot advance further.
    #[error("safety case revision overflow")]
    RevisionOverflow,
}

/// Pure, deterministic reducer for one [`SafetyCase`].
///
/// For identical case state, command, and policy, `reduce` returns an identical
/// result. The original case is borrowed and remains unchanged on error.
#[derive(Debug, Default, Clone, Copy)]
pub struct SafetyCaseReducer;

impl SafetyCaseReducer {
    /// Applies one explicit command to a case.
    ///
    /// # Errors
    ///
    /// Returns [`SafetyCaseReducerError`] when the persisted state, policy,
    /// command transition, dedupe identity, or bounded capacity is invalid.
    pub fn reduce(
        case: &SafetyCase,
        command: SafetyCaseCommand,
        policy: &SafetyCasePolicy,
    ) -> Result<SafetyCaseReduction, SafetyCaseReducerError> {
        policy.validate()?;
        validate_case(case, policy)?;

        match command {
            SafetyCaseCommand::ApplyObservation { observation } => {
                reduce_observation(case, observation, policy)
            }
            SafetyCaseCommand::Resolve { at_ms, reason_code } => {
                reduce_resolution(case, at_ms, reason_code, policy)
            }
            SafetyCaseCommand::Dismiss { at_ms, reason_code } => {
                reduce_dismissal(case, at_ms, reason_code)
            }
            SafetyCaseCommand::FlushDeferredGuardianReport { at_ms } => {
                reduce_report_flush(case, at_ms, policy)
            }
            SafetyCaseCommand::AcknowledgeGuardianReport {
                report_key,
                delivered_at_ms,
            } => reduce_report_acknowledgment(case, report_key, delivered_at_ms, policy),
        }
    }
}

fn validate_case(
    case: &SafetyCase,
    policy: &SafetyCasePolicy,
) -> Result<(), SafetyCaseReducerError> {
    if case.schema_version != SAFETY_CASE_SCHEMA_VERSION {
        return Err(SafetyCaseReducerError::UnsupportedCaseSchema(
            case.schema_version.clone(),
        ));
    }
    if case.threat_type == ThreatType::None {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "threat type is none",
        ));
    }
    if case.observations.len() > policy.max_observations {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "observation capacity exceeded",
        ));
    }
    if case.reason_codes.len() > policy.max_case_reason_codes {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "reason-code capacity exceeded",
        ));
    }
    if case.status.is_terminal() != case.closed_at_ms.is_some() {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "terminal status and closed timestamp disagree",
        ));
    }
    if case.status.is_terminal() != case.closed_reason_code.is_some() {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "terminal status and close reason disagree",
        ));
    }
    if case.updated_at_ms < case.created_at_ms {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "updated timestamp predates creation",
        ));
    }
    if case.reason_codes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "case reason codes are not sorted and unique",
        ));
    }
    if let Some(report) = &case.pending_guardian_report {
        if report.schema_version != GUARDIAN_REPORT_SCHEMA_VERSION {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report schema is unsupported",
            ));
        }
        if report.key.case_id() != &case.case_id {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report belongs to another case",
            ));
        }
        if report.subject_key != case.subject_key || report.threat_type != case.threat_type {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report routing does not match the case",
            ));
        }
        if report.key.transition_revision() > case.revision {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report revision is ahead of the case",
            ));
        }
        if report.queued_at_ms > case.updated_at_ms {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report transition is inconsistent",
            ));
        }
        if report.evidence.len() > MAX_GUARDIAN_EVIDENCE_LIMIT {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report evidence limit exceeded",
            ));
        }
        if report.reason_codes.len() > policy.max_case_reason_codes
            || report
                .reason_codes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report reason codes are invalid",
            ));
        }
        if report
            .reason_codes
            .iter()
            .any(|code| !case.reason_codes.contains(code))
        {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report contains an unknown reason code",
            ));
        }
        let mut report_evidence = HashSet::with_capacity(report.evidence.len());
        if report.evidence.iter().any(|source_event| {
            !report_evidence.insert(source_event)
                || !case
                    .observations
                    .iter()
                    .any(|observation| observation.source_event() == source_event)
        }) {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report contains invalid evidence",
            ));
        }
        if usize::try_from(report.observation_count)
            .map_or(true, |count| count > case.observations.len())
            || report.severity > case.severity
            || report.confidence > case.confidence
            || report.peak_risk_score > case.peak_risk_score
        {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "pending report snapshot is ahead of the case",
            ));
        }
    }
    if let Some(deferred) = &case.deferred_guardian_report {
        if deferred.transition_revision > case.revision
            || deferred.eligible_at_ms < deferred.transition_at_ms
            || deferred.transition_at_ms > case.updated_at_ms
        {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "deferred report transition is inconsistent",
            ));
        }
    }
    if let Some(delivery) = &case.last_guardian_delivery {
        if delivery.key.case_id() != &case.case_id {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "guardian delivery belongs to another case",
            ));
        }
        if delivery.key.transition_revision() > case.revision {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "guardian delivery revision is ahead of the case",
            ));
        }
        if delivery.delivered_at_ms > case.updated_at_ms {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "guardian delivery timestamp is ahead of the case",
            ));
        }
        if case
            .pending_guardian_report
            .as_ref()
            .is_some_and(|report| report.key == delivery.key)
        {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "delivered guardian report is still pending",
            ));
        }
    }

    let mut observation_ids = HashSet::with_capacity(case.observations.len());
    let mut source_events = HashSet::with_capacity(case.observations.len());
    for observation in &case.observations {
        observation.validate()?;
        validate_observation_threat(case, observation)?;
        if observation.observed_at_ms() > case.updated_at_ms {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "observation timestamp is ahead of the case",
            ));
        }
        if !observation_ids.insert(observation.observation_id())
            || !source_events.insert(observation.source_event())
        {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "duplicate observation identity",
            ));
        }
        if observation
            .reason_codes()
            .iter()
            .any(|code| !case.reason_codes.contains(code))
        {
            return Err(SafetyCaseReducerError::InvalidPersistedCase(
                "case is missing an observation reason code",
            ));
        }
    }
    let expected_first = case
        .observations
        .iter()
        .map(SafetyObservation::occurred_at_ms)
        .min();
    let expected_last = case
        .observations
        .iter()
        .map(SafetyObservation::occurred_at_ms)
        .max();
    if case.first_observed_at_ms != expected_first || case.last_observed_at_ms != expected_last {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "observation time bounds are inconsistent",
        ));
    }
    let expected_severity = case
        .observations
        .iter()
        .map(SafetyObservation::severity)
        .max()
        .unwrap_or(SafetyCaseSeverity::Informational);
    if case.severity != expected_severity {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "peak severity is inconsistent",
        ));
    }
    let expected_risk_score = case
        .observations
        .iter()
        .map(SafetyObservation::risk_score)
        .max()
        .unwrap_or(RiskScore::ZERO);
    if case.peak_risk_score != expected_risk_score {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "peak risk score is inconsistent",
        ));
    }
    let expected_confidence = case
        .observations
        .iter()
        .map(SafetyObservation::confidence)
        .max()
        .unwrap_or(Confidence::Low);
    if case.confidence != expected_confidence {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "peak confidence is inconsistent",
        ));
    }
    if !case.status.is_terminal()
        && case.status != status_for_severity(case.severity, policy.thresholds)
    {
        return Err(SafetyCaseReducerError::InvalidPersistedCase(
            "status does not match peak severity",
        ));
    }
    Ok(())
}

fn reduce_observation(
    case: &SafetyCase,
    observation: SafetyObservation,
    policy: &SafetyCasePolicy,
) -> Result<SafetyCaseReduction, SafetyCaseReducerError> {
    observation.validate()?;
    validate_observation_threat(case, &observation)?;

    if let Some(existing) = case
        .observations
        .iter()
        .find(|existing| existing.observation_id() == observation.observation_id())
    {
        if existing == &observation {
            return Ok(unchanged_reduction(
                case,
                SafetyCaseDecisionOutcome::DuplicateIgnored,
            ));
        }
        return Err(SafetyCaseReducerError::ObservationIdCollision(
            observation.observation_id().to_string(),
        ));
    }

    if let Some(existing) = case
        .observations
        .iter()
        .find(|existing| existing.source_event() == observation.source_event())
    {
        if existing.semantically_matches(&observation) {
            return Ok(unchanged_reduction(
                case,
                SafetyCaseDecisionOutcome::DuplicateIgnored,
            ));
        }
        return Err(SafetyCaseReducerError::SourceEventCollision(format!(
            "{}:{}:{}",
            observation.source_event().conversation_key(),
            observation.source_event().event_id(),
            observation.source_event().revision(),
        )));
    }

    if case.status.is_terminal() {
        return Err(SafetyCaseReducerError::InvalidTransition {
            from: case.status,
            command: "apply_observation",
        });
    }
    if case.observations.len() >= policy.max_observations {
        return Err(SafetyCaseReducerError::ObservationCapacityExceeded {
            maximum: policy.max_observations,
        });
    }
    validate_reason_code_union(case, observation.reason_codes(), policy)?;

    let old_status = case.status;
    let mut next = case.clone();
    next.revision = next_revision(case.revision)?;
    next.updated_at_ms = next.updated_at_ms.max(observation.observed_at_ms());
    next.first_observed_at_ms = Some(
        next.first_observed_at_ms
            .map_or(observation.occurred_at_ms(), |timestamp| {
                timestamp.min(observation.occurred_at_ms())
            }),
    );
    next.last_observed_at_ms = Some(
        next.last_observed_at_ms
            .map_or(observation.occurred_at_ms(), |timestamp| {
                timestamp.max(observation.occurred_at_ms())
            }),
    );
    next.severity = next.severity.max(observation.severity());
    next.peak_risk_score = next.peak_risk_score.max(observation.risk_score());
    next.confidence = next.confidence.max(observation.confidence());
    merge_reason_codes(&mut next.reason_codes, observation.reason_codes());
    let observation_id = observation.observation_id().clone();
    let transition_at_ms = observation.observed_at_ms();
    next.observations.push(observation);
    next.status = status_for_severity(next.severity, policy.thresholds);

    let mut events = vec![SafetyCaseEvent::ObservationAccepted {
        observation_id,
        case_revision: next.revision,
    }];
    let transition_trigger = if next.status != old_status {
        events.push(SafetyCaseEvent::StatusChanged {
            from: old_status,
            to: next.status,
            at_ms: transition_at_ms,
            case_revision: next.revision,
        });
        trigger_for_status(next.status)
    } else {
        None
    };

    let guardian_report = match transition_trigger {
        Some(trigger) => {
            plan_guardian_report(&mut next, trigger, transition_at_ms, policy, &mut events)
        }
        None => existing_report_directive(&next),
    };
    Ok(updated_reduction(next, events, guardian_report))
}

fn reduce_resolution(
    case: &SafetyCase,
    at_ms: u64,
    reason_code: SafetyReasonCode,
    policy: &SafetyCasePolicy,
) -> Result<SafetyCaseReduction, SafetyCaseReducerError> {
    if case.status == SafetyCaseStatus::Resolved
        && case.closed_reason_code.as_ref() == Some(&reason_code)
    {
        return Ok(unchanged_reduction(
            case,
            SafetyCaseDecisionOutcome::NoChange,
        ));
    }
    if !matches!(
        case.status,
        SafetyCaseStatus::Open | SafetyCaseStatus::Escalated | SafetyCaseStatus::Urgent
    ) {
        return Err(SafetyCaseReducerError::InvalidTransition {
            from: case.status,
            command: "resolve",
        });
    }
    let retain_reason_code = case.reason_codes.contains(&reason_code)
        || case.reason_codes.len() < policy.max_case_reason_codes;
    let mut next = case.clone();
    let old_status = next.status;
    next.revision = next_revision(next.revision)?;
    next.status = SafetyCaseStatus::Resolved;
    next.closed_at_ms = Some(at_ms);
    next.closed_reason_code = Some(reason_code.clone());
    next.updated_at_ms = next.updated_at_ms.max(at_ms);
    if retain_reason_code {
        merge_reason_codes(&mut next.reason_codes, std::slice::from_ref(&reason_code));
    }

    let mut events = vec![SafetyCaseEvent::StatusChanged {
        from: old_status,
        to: next.status,
        at_ms,
        case_revision: next.revision,
    }];
    let guardian_report = plan_guardian_report(
        &mut next,
        GuardianReportTrigger::CaseResolved,
        at_ms,
        policy,
        &mut events,
    );
    Ok(updated_reduction(next, events, guardian_report))
}

fn reduce_dismissal(
    case: &SafetyCase,
    at_ms: u64,
    reason_code: SafetyReasonCode,
) -> Result<SafetyCaseReduction, SafetyCaseReducerError> {
    if case.status == SafetyCaseStatus::Dismissed
        && case.closed_reason_code.as_ref() == Some(&reason_code)
    {
        return Ok(unchanged_reduction(
            case,
            SafetyCaseDecisionOutcome::NoChange,
        ));
    }
    if case.status.is_terminal() {
        return Err(SafetyCaseReducerError::InvalidTransition {
            from: case.status,
            command: "dismiss",
        });
    }

    let mut next = case.clone();
    let old_status = next.status;
    next.revision = next_revision(next.revision)?;
    next.status = SafetyCaseStatus::Dismissed;
    next.closed_at_ms = Some(at_ms);
    next.closed_reason_code = Some(reason_code);
    next.updated_at_ms = next.updated_at_ms.max(at_ms);
    next.pending_guardian_report = None;
    next.deferred_guardian_report = None;

    let events = vec![SafetyCaseEvent::StatusChanged {
        from: old_status,
        to: next.status,
        at_ms,
        case_revision: next.revision,
    }];
    Ok(updated_reduction(
        next,
        events,
        GuardianReportDirective::NotRequired,
    ))
}

fn reduce_report_flush(
    case: &SafetyCase,
    at_ms: u64,
    policy: &SafetyCasePolicy,
) -> Result<SafetyCaseReduction, SafetyCaseReducerError> {
    if case.pending_guardian_report.is_some() {
        return Ok(unchanged_reduction(
            case,
            SafetyCaseDecisionOutcome::NoChange,
        ));
    }
    let Some(deferred) = &case.deferred_guardian_report else {
        return Ok(unchanged_reduction(
            case,
            SafetyCaseDecisionOutcome::NoChange,
        ));
    };
    if at_ms < deferred.eligible_at_ms {
        return Ok(unchanged_reduction(
            case,
            SafetyCaseDecisionOutcome::NoChange,
        ));
    }

    let mut next = case.clone();
    let deferred = next.deferred_guardian_report.take().ok_or(
        SafetyCaseReducerError::InvalidPersistedCase(
            "deferred report disappeared during reduction",
        ),
    )?;
    next.revision = next_revision(next.revision)?;
    next.updated_at_ms = next.updated_at_ms.max(at_ms);
    let report = build_guardian_report(
        &next,
        deferred.trigger,
        deferred.transition_revision,
        at_ms,
        policy.guardian_reporting.evidence_limit,
    );
    next.pending_guardian_report = Some(report.clone());
    let events = vec![SafetyCaseEvent::GuardianReportQueued {
        report_key: report.key.clone(),
    }];
    Ok(updated_reduction(
        next,
        events,
        GuardianReportDirective::Queue { report },
    ))
}

fn reduce_report_acknowledgment(
    case: &SafetyCase,
    report_key: GuardianReportKey,
    delivered_at_ms: u64,
    policy: &SafetyCasePolicy,
) -> Result<SafetyCaseReduction, SafetyCaseReducerError> {
    if case
        .last_guardian_delivery
        .as_ref()
        .is_some_and(|receipt| receipt.key == report_key)
    {
        return Ok(unchanged_reduction(
            case,
            SafetyCaseDecisionOutcome::NoChange,
        ));
    }
    let Some(pending) = &case.pending_guardian_report else {
        return Err(SafetyCaseReducerError::GuardianReportKeyMismatch);
    };
    if pending.key != report_key {
        return Err(SafetyCaseReducerError::GuardianReportKeyMismatch);
    }
    if delivered_at_ms < pending.queued_at_ms {
        return Err(SafetyCaseReducerError::InvalidDeliveryTimestamp);
    }
    if case
        .last_guardian_delivery
        .as_ref()
        .is_some_and(|receipt| delivered_at_ms < receipt.delivered_at_ms)
    {
        return Err(SafetyCaseReducerError::InvalidDeliveryTimestamp);
    }

    let mut next = case.clone();
    next.revision = next_revision(next.revision)?;
    next.updated_at_ms = next.updated_at_ms.max(delivered_at_ms);
    next.pending_guardian_report = None;
    next.last_guardian_delivery = Some(GuardianDeliveryReceipt {
        key: report_key.clone(),
        delivered_at_ms,
    });
    if let Some(deferred) = &mut next.deferred_guardian_report {
        deferred.eligible_at_ms = deferred
            .eligible_at_ms
            .max(delivered_at_ms.saturating_add(policy.guardian_reporting.cooldown_ms));
    }
    let events = vec![SafetyCaseEvent::GuardianReportDelivered {
        report_key,
        delivered_at_ms,
    }];
    let directive = next.deferred_guardian_report.as_ref().map_or(
        GuardianReportDirective::NotRequired,
        |deferred| GuardianReportDirective::Deferred {
            trigger: deferred.trigger,
            eligible_at_ms: deferred.eligible_at_ms,
        },
    );
    Ok(updated_reduction(next, events, directive))
}

fn validate_observation_threat(
    case: &SafetyCase,
    observation: &SafetyObservation,
) -> Result<(), SafetyCaseReducerError> {
    if observation.threat_type() != case.threat_type {
        return Err(SafetyCaseReducerError::ThreatMismatch {
            expected: case.threat_type,
            actual: observation.threat_type(),
        });
    }
    Ok(())
}

fn validate_reason_code_union(
    case: &SafetyCase,
    incoming: &[SafetyReasonCode],
    policy: &SafetyCasePolicy,
) -> Result<(), SafetyCaseReducerError> {
    let additional = incoming
        .iter()
        .filter(|code| !case.reason_codes.contains(code))
        .count();
    if case.reason_codes.len().saturating_add(additional) > policy.max_case_reason_codes {
        return Err(SafetyCaseReducerError::ReasonCodeCapacityExceeded {
            maximum: policy.max_case_reason_codes,
        });
    }
    Ok(())
}

fn merge_reason_codes(target: &mut Vec<SafetyReasonCode>, incoming: &[SafetyReasonCode]) {
    for code in incoming {
        if !target.contains(code) {
            target.push(code.clone());
        }
    }
    target.sort();
}

fn status_for_severity(
    severity: SafetyCaseSeverity,
    thresholds: SafetyCaseThresholds,
) -> SafetyCaseStatus {
    if severity >= thresholds.urgent_at {
        SafetyCaseStatus::Urgent
    } else if severity >= thresholds.escalate_at {
        SafetyCaseStatus::Escalated
    } else if severity >= thresholds.open_at {
        SafetyCaseStatus::Open
    } else {
        SafetyCaseStatus::Observing
    }
}

fn trigger_for_status(status: SafetyCaseStatus) -> Option<GuardianReportTrigger> {
    match status {
        SafetyCaseStatus::Open => Some(GuardianReportTrigger::CaseOpened),
        SafetyCaseStatus::Escalated => Some(GuardianReportTrigger::CaseEscalated),
        SafetyCaseStatus::Urgent => Some(GuardianReportTrigger::UrgentReview),
        SafetyCaseStatus::Observing | SafetyCaseStatus::Resolved | SafetyCaseStatus::Dismissed => {
            None
        }
    }
}

fn plan_guardian_report(
    case: &mut SafetyCase,
    trigger: GuardianReportTrigger,
    transition_at_ms: u64,
    policy: &SafetyCasePolicy,
    events: &mut Vec<SafetyCaseEvent>,
) -> GuardianReportDirective {
    let reporting = &policy.guardian_reporting;
    if !reporting.is_enabled_for(trigger) {
        return existing_report_directive(case);
    }

    if let Some(pending) = case.pending_guardian_report.clone() {
        if guardian_trigger_priority(trigger) <= guardian_trigger_priority(pending.trigger) {
            if trigger == GuardianReportTrigger::CaseResolved {
                let deferred = DeferredGuardianReport {
                    trigger,
                    transition_revision: case.revision,
                    transition_at_ms,
                    eligible_at_ms: transition_at_ms,
                };
                case.deferred_guardian_report = Some(deferred);
                events.push(SafetyCaseEvent::GuardianReportDeferred {
                    trigger,
                    eligible_at_ms: transition_at_ms,
                });
            }
            return GuardianReportDirective::Pending { report: pending };
        }
    }

    let bypasses_cooldown =
        trigger == GuardianReportTrigger::UrgentReview && reporting.urgent_bypasses_cooldown;
    let cooldown_until = case.last_guardian_delivery.as_ref().map(|receipt| {
        receipt
            .delivered_at_ms
            .saturating_add(reporting.cooldown_ms)
    });
    if !bypasses_cooldown
        && cooldown_until.is_some_and(|eligible_at_ms| transition_at_ms < eligible_at_ms)
    {
        let eligible_at_ms = cooldown_until.unwrap_or(transition_at_ms);
        let deferred = DeferredGuardianReport {
            trigger,
            transition_revision: case.revision,
            transition_at_ms,
            eligible_at_ms,
        };
        let should_replace = case
            .deferred_guardian_report
            .as_ref()
            .is_none_or(|existing| {
                guardian_trigger_priority(trigger) >= guardian_trigger_priority(existing.trigger)
            });
        if should_replace {
            case.deferred_guardian_report = Some(deferred);
            events.push(SafetyCaseEvent::GuardianReportDeferred {
                trigger,
                eligible_at_ms,
            });
        }
        return case.deferred_guardian_report.as_ref().map_or(
            GuardianReportDirective::NotRequired,
            |retained| GuardianReportDirective::Deferred {
                trigger: retained.trigger,
                eligible_at_ms: retained.eligible_at_ms,
            },
        );
    }

    let report = build_guardian_report(
        case,
        trigger,
        case.revision,
        transition_at_ms,
        reporting.evidence_limit,
    );
    if let Some(previous) = case.pending_guardian_report.replace(report.clone()) {
        events.push(SafetyCaseEvent::GuardianReportSuperseded {
            previous_report_key: previous.key,
            replacement_report_key: report.key.clone(),
        });
    } else {
        events.push(SafetyCaseEvent::GuardianReportQueued {
            report_key: report.key.clone(),
        });
    }
    case.deferred_guardian_report = None;
    GuardianReportDirective::Queue { report }
}

fn build_guardian_report(
    case: &SafetyCase,
    trigger: GuardianReportTrigger,
    transition_revision: u64,
    queued_at_ms: u64,
    evidence_limit: usize,
) -> GuardianReport {
    let evidence_start = case.observations.len().saturating_sub(evidence_limit);
    let evidence = case.observations[evidence_start..]
        .iter()
        .map(|observation| observation.source_event().clone())
        .collect();
    GuardianReport {
        schema_version: GUARDIAN_REPORT_SCHEMA_VERSION.to_string(),
        key: GuardianReportKey::new(case.case_id.clone(), transition_revision),
        subject_key: case.subject_key.clone(),
        trigger,
        queued_at_ms,
        threat_type: case.threat_type,
        case_status: case.status,
        severity: case.severity,
        confidence: case.confidence,
        peak_risk_score: case.peak_risk_score,
        first_observed_at_ms: case.first_observed_at_ms,
        last_observed_at_ms: case.last_observed_at_ms,
        observation_count: u32::try_from(case.observations.len()).unwrap_or(u32::MAX),
        reason_codes: case.reason_codes.clone(),
        evidence,
    }
}

fn guardian_trigger_priority(trigger: GuardianReportTrigger) -> u8 {
    match trigger {
        GuardianReportTrigger::CaseResolved => 1,
        GuardianReportTrigger::CaseOpened => 2,
        GuardianReportTrigger::CaseEscalated => 3,
        GuardianReportTrigger::UrgentReview => 4,
    }
}

fn existing_report_directive(case: &SafetyCase) -> GuardianReportDirective {
    if let Some(report) = &case.pending_guardian_report {
        return GuardianReportDirective::Pending {
            report: report.clone(),
        };
    }
    if let Some(deferred) = &case.deferred_guardian_report {
        return GuardianReportDirective::Deferred {
            trigger: deferred.trigger,
            eligible_at_ms: deferred.eligible_at_ms,
        };
    }
    GuardianReportDirective::NotRequired
}

fn unchanged_reduction(
    case: &SafetyCase,
    outcome: SafetyCaseDecisionOutcome,
) -> SafetyCaseReduction {
    let decision = SafetyCaseDecision {
        schema_version: SAFETY_CASE_DECISION_SCHEMA_VERSION.to_string(),
        case_id: case.case_id.clone(),
        case_revision: case.revision,
        status: case.status,
        outcome,
        events: Vec::new(),
        guardian_report: existing_report_directive(case),
    };
    SafetyCaseReduction::new(case.clone(), decision)
}

fn updated_reduction(
    case: SafetyCase,
    events: Vec<SafetyCaseEvent>,
    guardian_report: GuardianReportDirective,
) -> SafetyCaseReduction {
    let decision = SafetyCaseDecision {
        schema_version: SAFETY_CASE_DECISION_SCHEMA_VERSION.to_string(),
        case_id: case.case_id.clone(),
        case_revision: case.revision,
        status: case.status,
        outcome: SafetyCaseDecisionOutcome::Updated,
        events,
        guardian_report,
    };
    SafetyCaseReduction::new(case, decision)
}

fn next_revision(revision: u64) -> Result<u64, SafetyCaseReducerError> {
    revision
        .checked_add(1)
        .ok_or(SafetyCaseReducerError::RevisionOverflow)
}

#[cfg(test)]
mod tests {
    use aura_contracts::{Confidence, ThreatType};

    use super::{GuardianReportingPolicy, SafetyCaseCommand, SafetyCasePolicy, SafetyCaseReducer};
    use crate::safety_case::{
        ConversationEventKey, GuardianReportDirective, RiskScore, SafetyCase, SafetyCaseId,
        SafetyCaseSeverity, SafetyCaseStatus, SafetyCaseSubjectKey, SafetyObservation,
        SafetyObservationId, SafetyReasonCode, SourceEventId, SourceEventKey,
    };

    fn case() -> SafetyCase {
        SafetyCase::new(
            SafetyCaseId::new("case-1").unwrap(),
            SafetyCaseSubjectKey::new("subject-1").unwrap(),
            ThreatType::Grooming,
            1_000,
        )
        .unwrap()
    }

    fn observation(
        id: &str,
        event_id: &str,
        severity: SafetyCaseSeverity,
        observed_at_ms: u64,
    ) -> SafetyObservation {
        SafetyObservation::new(
            SafetyObservationId::new(id).unwrap(),
            SourceEventKey::new(
                ConversationEventKey::new("conversation-1").unwrap(),
                SourceEventId::new(event_id).unwrap(),
                1,
            ),
            observed_at_ms - 10,
            observed_at_ms,
            ThreatType::Grooming,
            severity,
            Confidence::High,
            RiskScore::new(8_500).unwrap(),
        )
        .unwrap()
        .with_reason_codes(vec![SafetyReasonCode::new("kids.grooming.secrecy").unwrap()])
        .unwrap()
    }

    #[test]
    fn reduce_is_deterministic_for_identical_input() {
        let case = case();
        let command = SafetyCaseCommand::ApplyObservation {
            observation: observation("observation-1", "event-1", SafetyCaseSeverity::High, 2_000),
        };

        let first = SafetyCaseReducer::reduce(&case, command.clone(), &SafetyCasePolicy::default());
        let second = SafetyCaseReducer::reduce(&case, command, &SafetyCasePolicy::default());

        assert_eq!(first, second);
    }

    #[test]
    fn duplicate_observation_is_ignored_without_revision_change() {
        let observation = observation(
            "observation-1",
            "event-1",
            SafetyCaseSeverity::Elevated,
            2_000,
        );
        let first = SafetyCaseReducer::reduce(
            &case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation.clone(),
            },
            &SafetyCasePolicy::default(),
        )
        .unwrap();

        let duplicate = SafetyCaseReducer::reduce(
            first.case(),
            SafetyCaseCommand::ApplyObservation { observation },
            &SafetyCasePolicy::default(),
        )
        .unwrap();

        assert_eq!(duplicate.case().revision(), first.case().revision());
    }

    #[test]
    fn elevated_observation_opens_case_and_queues_one_report() {
        let reduction = SafetyCaseReducer::reduce(
            &case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-1",
                    "event-1",
                    SafetyCaseSeverity::Elevated,
                    2_000,
                ),
            },
            &SafetyCasePolicy::default(),
        )
        .unwrap();

        assert!(matches!(
            reduction.decision().guardian_report(),
            GuardianReportDirective::Queue { .. }
        ));
    }

    #[test]
    fn escalation_inside_cooldown_is_deferred() {
        let policy = SafetyCasePolicy::default()
            .with_guardian_reporting(GuardianReportingPolicy::default().with_cooldown_ms(60_000));
        let opened = SafetyCaseReducer::reduce(
            &case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-1",
                    "event-1",
                    SafetyCaseSeverity::Elevated,
                    2_000,
                ),
            },
            &policy,
        )
        .unwrap();
        let report_key = opened
            .case()
            .pending_guardian_report()
            .unwrap()
            .key()
            .clone();
        let delivered = SafetyCaseReducer::reduce(
            opened.case(),
            SafetyCaseCommand::AcknowledgeGuardianReport {
                report_key,
                delivered_at_ms: 2_100,
            },
            &policy,
        )
        .unwrap();

        let escalated = SafetyCaseReducer::reduce(
            delivered.case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-2",
                    "event-2",
                    SafetyCaseSeverity::High,
                    3_000,
                ),
            },
            &policy,
        )
        .unwrap();

        assert!(matches!(
            escalated.decision().guardian_report(),
            GuardianReportDirective::Deferred { .. }
        ));
    }

    #[test]
    fn urgent_transition_bypasses_cooldown() {
        let policy = SafetyCasePolicy::default()
            .with_guardian_reporting(GuardianReportingPolicy::default().with_cooldown_ms(60_000));
        let opened = SafetyCaseReducer::reduce(
            &case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-1",
                    "event-1",
                    SafetyCaseSeverity::Elevated,
                    2_000,
                ),
            },
            &policy,
        )
        .unwrap();
        let report_key = opened
            .case()
            .pending_guardian_report()
            .unwrap()
            .key()
            .clone();
        let delivered = SafetyCaseReducer::reduce(
            opened.case(),
            SafetyCaseCommand::AcknowledgeGuardianReport {
                report_key,
                delivered_at_ms: 2_100,
            },
            &policy,
        )
        .unwrap();

        let urgent = SafetyCaseReducer::reduce(
            delivered.case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-2",
                    "event-2",
                    SafetyCaseSeverity::Critical,
                    3_000,
                ),
            },
            &policy,
        )
        .unwrap();

        assert!(matches!(
            urgent.decision().guardian_report(),
            GuardianReportDirective::Queue { .. }
        ));
    }

    #[test]
    fn resolved_case_rejects_new_observation() {
        let opened = SafetyCaseReducer::reduce(
            &case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-1",
                    "event-1",
                    SafetyCaseSeverity::Elevated,
                    2_000,
                ),
            },
            &SafetyCasePolicy::default(),
        )
        .unwrap();
        let resolved = SafetyCaseReducer::reduce(
            opened.case(),
            SafetyCaseCommand::Resolve {
                at_ms: 3_000,
                reason_code: SafetyReasonCode::new("guardian.resolved").unwrap(),
            },
            &SafetyCasePolicy::default(),
        )
        .unwrap();

        let result = SafetyCaseReducer::reduce(
            resolved.case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-2",
                    "event-2",
                    SafetyCaseSeverity::High,
                    4_000,
                ),
            },
            &SafetyCasePolicy::default(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn informational_observation_stays_internal() {
        let reduction = SafetyCaseReducer::reduce(
            &case(),
            SafetyCaseCommand::ApplyObservation {
                observation: observation(
                    "observation-1",
                    "event-1",
                    SafetyCaseSeverity::Informational,
                    2_000,
                ),
            },
            &SafetyCasePolicy::default(),
        )
        .unwrap();

        assert_eq!(reduction.case().status(), SafetyCaseStatus::Observing);
    }
}
