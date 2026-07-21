//! Signed execution-policy projection consumed by the Safety Case reducer.
//!
//! Signature and authority verification happen at the host authority boundary.
//! Native code receives the exact canonical signed wire, validates every field
//! it executes, enforces an account-scoped monotonic floor, and persists these
//! types with the case state. Reports retain the exact policy/rule/artifact
//! binding that authorized their transition.

use aura_contracts::{Confidence, ThreatType};
use serde::{Deserialize, Serialize};

use super::{
    GuardianReportTrigger, SafetyCase, SafetyCaseSeverity, SafetyCaseStatus, SafetyReasonCode,
};

const MAX_POLICY_RULES: usize = 64;
const MAX_REPORT_REASON_CODES: usize = 16;
const MAX_EVIDENCE_COMMITMENTS: usize = 16;

/// Native execution behavior selected by a verified signed policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianExecutionMode {
    /// Maintain local longitudinal cases without creating Guardian reports.
    ShadowCases,
    /// Create reports only for exact matching signed rules.
    CaseTransitions,
}

/// Privacy-bounded delivery class retained in a Guardian report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianDeliveryClass {
    NeedsAttention,
    Urgent,
}

/// One validated rule from a signed execution-policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianExecutionRule {
    pub rule_id: String,
    pub risk_family: ThreatType,
    pub trigger: GuardianReportTrigger,
    pub required_case_status: SafetyCaseStatus,
    pub minimum_severity: SafetyCaseSeverity,
    pub minimum_confidence: Confidence,
    pub minimum_observation_count: u32,
    pub minimum_peak_risk_basis_points: u16,
    pub cooldown_ms: u64,
    pub urgent_bypasses_cooldown: bool,
    pub maximum_report_reason_codes: usize,
    pub maximum_evidence_commitments: usize,
    pub allowed_report_reason_codes: Vec<SafetyReasonCode>,
    pub delivery_class: Option<GuardianDeliveryClass>,
    pub rule_digest: [u8; 32],
}

impl GuardianExecutionRule {
    /// Validates all release bounds and deterministic matching invariants.
    pub fn validate(&self) -> Result<(), GuardianExecutionPolicyError> {
        validate_authority_identifier("execution rule id", &self.rule_id)?;
        if self.risk_family == ThreatType::None {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "rule risk family is none",
            ));
        }
        let status_matches_trigger = match self.trigger {
            GuardianReportTrigger::CaseOpened => {
                self.required_case_status == SafetyCaseStatus::Open
            }
            GuardianReportTrigger::CaseEscalated => {
                self.required_case_status == SafetyCaseStatus::Escalated
            }
            GuardianReportTrigger::UrgentReview => {
                self.required_case_status == SafetyCaseStatus::Urgent
            }
            GuardianReportTrigger::CaseResolved => matches!(
                self.required_case_status,
                SafetyCaseStatus::Resolved | SafetyCaseStatus::Dismissed
            ),
        };
        if !status_matches_trigger {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "rule trigger and required status disagree",
            ));
        }
        if self.minimum_observation_count == 0 {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "minimum observation count is zero",
            ));
        }
        if self.maximum_report_reason_codes == 0
            || self.maximum_report_reason_codes > MAX_REPORT_REASON_CODES
        {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "report reason-code limit is outside release bounds",
            ));
        }
        if self.maximum_evidence_commitments > MAX_EVIDENCE_COMMITMENTS {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "evidence commitment limit exceeds release bound",
            ));
        }
        if self.allowed_report_reason_codes.len() > self.maximum_report_reason_codes
            || self
                .allowed_report_reason_codes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "allowed report reason codes are not canonical",
            ));
        }
        if self.urgent_bypasses_cooldown && self.trigger != GuardianReportTrigger::UrgentReview {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "only an urgent rule may bypass cooldown",
            ));
        }
        if self.trigger == GuardianReportTrigger::UrgentReview
            && self.minimum_severity != SafetyCaseSeverity::Critical
        {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "urgent trigger requires critical severity",
            ));
        }
        if matches!(
            (self.trigger, self.delivery_class),
            (
                GuardianReportTrigger::UrgentReview,
                Some(GuardianDeliveryClass::NeedsAttention)
            ) | (
                GuardianReportTrigger::CaseOpened
                    | GuardianReportTrigger::CaseEscalated
                    | GuardianReportTrigger::CaseResolved,
                Some(GuardianDeliveryClass::Urgent)
            )
        ) {
            return Err(GuardianExecutionPolicyError::InvalidRule(
                "urgent delivery class and trigger must match exactly",
            ));
        }
        validate_digest("execution rule digest", &self.rule_digest)
    }

    pub(crate) fn matches(&self, case: &SafetyCase, trigger: GuardianReportTrigger) -> bool {
        self.delivery_class.is_some()
            && self.risk_family == case.threat_type()
            && self.trigger == trigger
            && self.required_case_status == case.status()
            && case.severity() >= self.minimum_severity
            && confidence_rank(case.confidence()) >= confidence_rank(self.minimum_confidence)
            && u32::try_from(case.observations().len())
                .is_ok_and(|count| count >= self.minimum_observation_count)
            && case.peak_risk_score().basis_points() >= self.minimum_peak_risk_basis_points
    }
}

/// Exact native projection of the currently applied signed policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianExecutionPolicy {
    pub authority_lineage_id: String,
    pub policy_epoch: u64,
    pub policy_version: String,
    pub policy_assertion_digest: [u8; 32],
    pub runtime_capabilities_digest: [u8; 32],
    pub model_manifest_digest: [u8; 32],
    pub execution_policy_trust_keyring_digest: [u8; 32],
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub execution_mode: GuardianExecutionMode,
    pub rules: Vec<GuardianExecutionRule>,
}

impl GuardianExecutionPolicy {
    /// Validates canonical ordering and rejects ambiguous rule scopes.
    pub fn validate(&self) -> Result<(), GuardianExecutionPolicyError> {
        validate_authority_identifier(
            "execution policy authority lineage",
            &self.authority_lineage_id,
        )?;
        validate_authority_identifier("execution policy version", &self.policy_version)?;
        if self.policy_epoch == 0 {
            return Err(GuardianExecutionPolicyError::InvalidPolicy(
                "policy epoch is zero",
            ));
        }
        validate_digest("policy assertion digest", &self.policy_assertion_digest)?;
        validate_digest(
            "runtime capabilities digest",
            &self.runtime_capabilities_digest,
        )?;
        validate_digest("model manifest digest", &self.model_manifest_digest)?;
        validate_digest(
            "execution policy trust keyring digest",
            &self.execution_policy_trust_keyring_digest,
        )?;
        if self.valid_from_ms == 0 || self.valid_from_ms >= self.valid_until_ms {
            return Err(GuardianExecutionPolicyError::InvalidPolicy(
                "execution policy validity interval is invalid",
            ));
        }
        if self.rules.len() > MAX_POLICY_RULES
            || self
                .rules
                .windows(2)
                .any(|pair| pair[0].rule_id.as_str() >= pair[1].rule_id.as_str())
        {
            return Err(GuardianExecutionPolicyError::InvalidPolicy(
                "execution rules are not canonical",
            ));
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        for (index, rule) in self.rules.iter().enumerate() {
            if self.rules[index + 1..].iter().any(|other| {
                other.risk_family == rule.risk_family
                    && other.trigger == rule.trigger
                    && other.required_case_status == rule.required_case_status
            }) {
                return Err(GuardianExecutionPolicyError::InvalidPolicy(
                    "execution rules contain an ambiguous transition scope",
                ));
            }
        }
        match self.execution_mode {
            GuardianExecutionMode::ShadowCases
                if self.rules.iter().any(|rule| rule.delivery_class.is_some()) =>
            {
                Err(GuardianExecutionPolicyError::InvalidPolicy(
                    "shadow policy contains a delivery rule",
                ))
            }
            GuardianExecutionMode::CaseTransitions
                if !self.rules.iter().any(|rule| rule.delivery_class.is_some()) =>
            {
                Err(GuardianExecutionPolicyError::InvalidPolicy(
                    "case-transition policy contains no delivery rule",
                ))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn matching_rule(
        &self,
        case: &SafetyCase,
        trigger: GuardianReportTrigger,
        evaluated_at_ms: u64,
    ) -> Option<&GuardianExecutionRule> {
        if self.execution_mode != GuardianExecutionMode::CaseTransitions
            || evaluated_at_ms < self.valid_from_ms
            || evaluated_at_ms >= self.valid_until_ms
        {
            return None;
        }
        self.rules.iter().find(|rule| rule.matches(case, trigger))
    }
}

/// Immutable policy identity retained by a queued Guardian report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianReportExecutionBinding {
    pub authority_lineage_id: String,
    pub policy_epoch: u64,
    pub policy_version: String,
    pub policy_assertion_digest: [u8; 32],
    pub rule_id: String,
    pub rule_digest: [u8; 32],
    pub delivery_class: GuardianDeliveryClass,
    pub runtime_capabilities_digest: [u8; 32],
    pub model_manifest_digest: [u8; 32],
    pub policy_evaluated_at_ms: u64,
}

impl GuardianReportExecutionBinding {
    pub(crate) fn from_policy_rule(
        policy: &GuardianExecutionPolicy,
        rule: &GuardianExecutionRule,
        policy_evaluated_at_ms: u64,
    ) -> Self {
        Self {
            authority_lineage_id: policy.authority_lineage_id.clone(),
            policy_epoch: policy.policy_epoch,
            policy_version: policy.policy_version.clone(),
            policy_assertion_digest: policy.policy_assertion_digest,
            rule_id: rule.rule_id.clone(),
            rule_digest: rule.rule_digest,
            delivery_class: rule
                .delivery_class
                .expect("matching execution rules always carry a delivery class"),
            runtime_capabilities_digest: policy.runtime_capabilities_digest,
            model_manifest_digest: policy.model_manifest_digest,
            policy_evaluated_at_ms,
        }
    }

    pub fn validate(&self) -> Result<(), GuardianExecutionPolicyError> {
        validate_authority_identifier("report authority lineage", &self.authority_lineage_id)?;
        validate_authority_identifier("report policy version", &self.policy_version)?;
        validate_authority_identifier("report rule id", &self.rule_id)?;
        if self.policy_epoch == 0 || self.policy_evaluated_at_ms == 0 {
            return Err(GuardianExecutionPolicyError::InvalidPolicy(
                "report policy binding has a zero monotonic field",
            ));
        }
        validate_digest(
            "report policy assertion digest",
            &self.policy_assertion_digest,
        )?;
        validate_digest("report rule digest", &self.rule_digest)?;
        validate_digest(
            "report runtime capabilities digest",
            &self.runtime_capabilities_digest,
        )?;
        validate_digest("report model manifest digest", &self.model_manifest_digest)
    }
}

/// Rejected signed execution-policy projection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardianExecutionPolicyError {
    #[error("invalid execution policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("invalid execution rule: {0}")]
    InvalidRule(&'static str),
    #[error("{field} is not a canonical authority identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} must be a nonzero SHA-256 digest")]
    InvalidDigest { field: &'static str },
}

fn validate_authority_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), GuardianExecutionPolicyError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(GuardianExecutionPolicyError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_digest(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), GuardianExecutionPolicyError> {
    if digest.iter().all(|byte| *byte == 0) {
        return Err(GuardianExecutionPolicyError::InvalidDigest { field });
    }
    Ok(())
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
    }
}
