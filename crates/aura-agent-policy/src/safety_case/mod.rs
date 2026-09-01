//! Versioned, product-neutral safety case domain.
//!
//! A message-level detector result becomes a content-free
//! [`SafetyObservation`](crate::safety_case::SafetyObservation). The
//! deterministic [`SafetyCaseReducer`](crate::safety_case::SafetyCaseReducer)
//! folds observations and explicit lifecycle commands into a bounded
//! [`SafetyCase`](crate::safety_case::SafetyCase). Guardian reports are
//! created only for configured case transitions and carry opaque evidence
//! references instead of raw message content or free-form verdicts.

mod execution_policy;
mod model;
mod reducer;

pub use execution_policy::{
    GuardianDeliveryClass, GuardianExecutionMode, GuardianExecutionPolicy,
    GuardianExecutionPolicyError, GuardianExecutionRule, GuardianReportExecutionBinding,
};

pub use model::{
    ConversationEventKey, DeferredGuardianReport, GuardianDeliveryReceipt,
    GuardianPreparationReceipt, GuardianReport, GuardianReportDirective, GuardianReportKey,
    GuardianReportObservationVolumeBand, GuardianReportTrigger, GuardianSuppressionReceipt,
    IdentifierError, RiskScore, RiskScoreError, SafetyCase, SafetyCaseConstructionError,
    SafetyCaseDecision, SafetyCaseDecisionOutcome, SafetyCaseEvent, SafetyCaseId,
    SafetyCaseReduction, SafetyCaseSeverity, SafetyCaseStatus, SafetyCaseSubjectKey,
    SafetyObservation, SafetyObservationError, SafetyObservationId, SafetyReasonCode,
    SourceEventId, SourceEventKey, GUARDIAN_REPORT_SCHEMA_VERSION,
    SAFETY_CASE_DECISION_SCHEMA_VERSION, SAFETY_CASE_SCHEMA_VERSION,
    SAFETY_OBSERVATION_SCHEMA_VERSION,
};
pub use reducer::{
    SafetyCaseCommand, SafetyCasePolicy, SafetyCasePolicyError, SafetyCaseReducer,
    SafetyCaseReducerError, SafetyCaseThresholds, SAFETY_CASE_POLICY_SCHEMA_VERSION,
};
