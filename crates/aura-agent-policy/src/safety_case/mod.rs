//! Versioned, product-neutral safety case domain.
//!
//! A message-level detector result becomes a content-free [`SafetyObservation`].
//! The deterministic [`SafetyCaseReducer`] folds observations and explicit
//! lifecycle commands into a bounded [`SafetyCase`]. Guardian reports are
//! created only for configured case transitions and carry opaque evidence
//! references instead of raw message content or free-form verdicts.

mod model;
mod reducer;

pub use model::{
    ConversationEventKey, DeferredGuardianReport, GuardianDeliveryReceipt, GuardianReport,
    GuardianReportDirective, GuardianReportKey, GuardianReportTrigger, IdentifierError, RiskScore,
    RiskScoreError, SafetyCase, SafetyCaseConstructionError, SafetyCaseDecision,
    SafetyCaseDecisionOutcome, SafetyCaseEvent, SafetyCaseId, SafetyCaseReduction,
    SafetyCaseSeverity, SafetyCaseStatus, SafetyCaseSubjectKey, SafetyObservation,
    SafetyObservationError, SafetyObservationId, SafetyReasonCode, SourceEventId, SourceEventKey,
    GUARDIAN_REPORT_SCHEMA_VERSION, SAFETY_CASE_DECISION_SCHEMA_VERSION,
    SAFETY_CASE_SCHEMA_VERSION, SAFETY_OBSERVATION_SCHEMA_VERSION,
};
pub use reducer::{
    GuardianReportingPolicy, SafetyCaseCommand, SafetyCasePolicy, SafetyCasePolicyError,
    SafetyCaseReducer, SafetyCaseReducerError, SafetyCaseThresholds,
    SAFETY_CASE_POLICY_SCHEMA_VERSION,
};
