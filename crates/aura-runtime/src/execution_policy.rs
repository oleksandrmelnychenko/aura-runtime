//! Account-scoped native execution-policy state and anti-rollback floor.

use aura_agent_policy::safety_case::{GuardianExecutionMode, GuardianExecutionPolicy};
use serde::{Deserialize, Serialize};

/// Signed policy state retained by the native runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeExecutionPolicyState {
    Enabled,
    Disabled,
}

/// Execution mode echoed in an exact native application receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeExecutionMode {
    Off,
    ShadowCases,
    CaseTransitions,
}

/// Fully validated candidate decoded from one canonical signed policy wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExecutionPolicy {
    pub account_key: String,
    pub protected_account_id: [u8; 16],
    pub authority_lineage_id: String,
    pub issuer_key_id: String,
    pub policy_epoch: u64,
    pub revoked_through_policy_epoch: u64,
    pub state: NativeExecutionPolicyState,
    pub execution_mode: NativeExecutionMode,
    pub policy_wire_digest: [u8; 32],
    pub signed_policy_digest: [u8; 32],
    pub runtime_capabilities_digest: [u8; 32],
    pub model_manifest_digest: [u8; 32],
    pub execution_policy_trust_keyring_digest: [u8; 32],
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub maximum_case_observations: usize,
    pub maximum_case_reason_codes: usize,
    pub guardian_policy: Option<GuardianExecutionPolicy>,
    /// Process-local activation bit. Persisted policy state retains the
    /// monotonic floor, but a fresh runtime must re-attest artifacts and apply
    /// the exact signed wire before this policy may authorize new reports.
    #[serde(skip)]
    pub active_for_runtime: bool,
}

impl NativeExecutionPolicy {
    /// Validates persistence invariants independent of protobuf decoding.
    pub fn validate(&self) -> Result<(), NativeExecutionPolicyError> {
        if self.account_key.is_empty()
            || self.account_key.len() > 256
            || self
                .account_key
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(NativeExecutionPolicyError::Malformed("account key"));
        }
        validate_identifier("authority lineage", &self.authority_lineage_id)?;
        validate_identifier("issuer key id", &self.issuer_key_id)?;
        if self.protected_account_id.iter().all(|byte| *byte == 0)
            || self.policy_epoch == 0
            || self.policy_epoch > i64::MAX as u64
            || self.revoked_through_policy_epoch > self.policy_epoch
            || self.valid_from_ms == 0
            || self.valid_from_ms >= self.valid_until_ms
            || self.valid_until_ms > i64::MAX as u64
            || self.maximum_case_observations == 0
            || self.maximum_case_observations > 4_096
            || self.maximum_case_reason_codes == 0
            || self.maximum_case_reason_codes > 64
        {
            return Err(NativeExecutionPolicyError::Malformed(
                "invalid policy identity or validity interval",
            ));
        }
        validate_digest("policy wire digest", &self.policy_wire_digest)?;
        validate_digest("signed policy digest", &self.signed_policy_digest)?;
        validate_digest(
            "runtime capabilities digest",
            &self.runtime_capabilities_digest,
        )?;
        validate_digest("model manifest digest", &self.model_manifest_digest)?;
        validate_digest(
            "execution policy trust keyring digest",
            &self.execution_policy_trust_keyring_digest,
        )?;
        match (self.state, self.execution_mode, &self.guardian_policy) {
            (NativeExecutionPolicyState::Disabled, NativeExecutionMode::Off, None)
                if self.revoked_through_policy_epoch == self.policy_epoch => {}
            (
                NativeExecutionPolicyState::Enabled,
                NativeExecutionMode::ShadowCases,
                Some(policy),
            ) if self.policy_epoch > self.revoked_through_policy_epoch
                && policy.execution_mode == GuardianExecutionMode::ShadowCases =>
            {
                policy.validate().map_err(|_| {
                    NativeExecutionPolicyError::Malformed("invalid shadow reducer policy")
                })?;
            }
            (
                NativeExecutionPolicyState::Enabled,
                NativeExecutionMode::CaseTransitions,
                Some(policy),
            ) if self.policy_epoch > self.revoked_through_policy_epoch
                && policy.execution_mode == GuardianExecutionMode::CaseTransitions =>
            {
                policy.validate().map_err(|_| {
                    NativeExecutionPolicyError::Malformed("invalid transition reducer policy")
                })?;
            }
            _ => {
                return Err(NativeExecutionPolicyError::Malformed(
                    "policy state, execution mode, and reducer projection disagree",
                ));
            }
        }
        if let Some(policy) = &self.guardian_policy {
            if policy.authority_lineage_id != self.authority_lineage_id
                || policy.policy_epoch != self.policy_epoch
                || policy.policy_assertion_digest != self.policy_wire_digest
                || policy.runtime_capabilities_digest != self.runtime_capabilities_digest
                || policy.model_manifest_digest != self.model_manifest_digest
                || policy.execution_policy_trust_keyring_digest
                    != self.execution_policy_trust_keyring_digest
                || policy.valid_from_ms != self.valid_from_ms
                || policy.valid_until_ms != self.valid_until_ms
            {
                return Err(NativeExecutionPolicyError::Malformed(
                    "reducer projection is not bound to the policy head",
                ));
            }
        }
        Ok(())
    }
}

/// Idempotency result of applying an account policy head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeExecutionPolicyApplyDisposition {
    Applied,
    Unchanged,
}

/// Exact account-bound native application receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExecutionPolicyApplicationReceipt {
    pub disposition: NativeExecutionPolicyApplyDisposition,
    pub policy: NativeExecutionPolicy,
}

/// Fail-closed rejection from the native monotonic floor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeExecutionPolicyError {
    #[error("malformed native execution policy: {0}")]
    Malformed(&'static str),
    #[error("execution policy rollback rejected")]
    Rollback,
    #[error("execution policy equivocation rejected")]
    Equivocation,
    #[error("execution policy authority lineage changed")]
    AuthorityLineageChanged,
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), NativeExecutionPolicyError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(NativeExecutionPolicyError::Malformed(field));
    }
    Ok(())
}

fn validate_digest(
    field: &'static str,
    digest: &[u8; 32],
) -> Result<(), NativeExecutionPolicyError> {
    if digest.iter().all(|byte| *byte == 0) {
        return Err(NativeExecutionPolicyError::Malformed(field));
    }
    Ok(())
}
