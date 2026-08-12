use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::DomainModuleId;

/// Current schema of the stable domain-module evidence projection.
pub const DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Domain policy-pack kind used by evidence validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainPolicyPackKind {
    /// Message-level lexical and threshold rules.
    Lexical,
    /// Optional content-free temporal rules.
    Temporal,
}

/// Structural failure in domain release evidence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainModuleEvidenceError {
    /// The projection uses a schema this runtime does not understand.
    #[error("unsupported domain evidence schema {schema_version}")]
    UnsupportedSchema {
        /// Rejected schema version.
        schema_version: u32,
    },
    /// The module version is empty.
    #[error("domain module version is invalid")]
    InvalidModuleVersion,
    /// Stateful ownership and durable state schema disagree.
    #[error("domain state contract is inconsistent")]
    InvalidStateContract,
    /// A policy pack has an empty identity or zero schema version.
    #[error("domain {policy_kind:?} policy identity is invalid")]
    InvalidPolicyIdentity {
        /// Rejected pack kind.
        policy_kind: DomainPolicyPackKind,
    },
    /// A policy pack has an invalid identity, digest, or rule count.
    #[error("domain {policy_kind:?} policy evidence is invalid")]
    InvalidPolicyPack {
        /// Rejected pack kind.
        policy_kind: DomainPolicyPackKind,
    },
}

/// Cryptographic identity and size of one bundled domain policy pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainPolicyPackEvidence {
    /// Stable domain-owned pack identity.
    pub pack_id: String,
    /// Schema version declared inside the pack.
    pub schema_version: u32,
    /// SHA-256 of the exact bundled source bytes.
    pub sha256: String,
    /// Number of executable rules or signal templates in the pack.
    pub rule_count: usize,
}

impl DomainPolicyPackEvidence {
    /// Builds evidence from the exact bytes compiled into a domain module.
    #[must_use]
    pub fn from_source(
        pack_id: impl Into<String>,
        schema_version: u32,
        source: &[u8],
        rule_count: usize,
    ) -> Self {
        let digest = Sha256::digest(source);
        let mut sha256 = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(sha256, "{byte:02x}");
        }
        Self {
            pack_id: pack_id.into(),
            schema_version,
            sha256,
            rule_count,
        }
    }
}

/// Release evidence for an optional domain-owned temporal policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainTemporalPolicyEvidence {
    /// Identity of the exact temporal rule pack.
    pub pack: DomainPolicyPackEvidence,
    /// Whether the ordinary runtime can emit temporal signals.
    pub runtime_enabled: bool,
    /// Whether the pack configures an executable product action.
    pub action_execution_configured: bool,
}

/// Stable release projection of one registered domain module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainModuleEvidence {
    /// Version of this evidence structure.
    pub schema_version: u32,
    /// Registered domain identity.
    pub module_id: DomainModuleId,
    /// Build-time crate version of the implementation.
    pub module_version: String,
    /// Whether confirmed message processing mutates domain-owned memory.
    pub stateful: bool,
    /// Persisted domain-state schema, when the module owns durable state.
    pub state_schema_version: Option<u32>,
    /// Exact lexical rules and policy thresholds compiled into the module.
    pub lexical_policy: DomainPolicyPackEvidence,
    /// Optional temporal policy identity and activation state.
    pub temporal_policy: Option<DomainTemporalPolicyEvidence>,
}

/// Validates the self-contained invariants of domain release evidence.
pub fn validate_domain_module_evidence(
    evidence: &DomainModuleEvidence,
) -> Result<(), DomainModuleEvidenceError> {
    if evidence.schema_version != DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION {
        return Err(DomainModuleEvidenceError::UnsupportedSchema {
            schema_version: evidence.schema_version,
        });
    }
    if evidence.module_version.trim().is_empty() {
        return Err(DomainModuleEvidenceError::InvalidModuleVersion);
    }
    match (evidence.stateful, evidence.state_schema_version) {
        (true, Some(version)) if version > 0 => {}
        (false, None) => {}
        _ => return Err(DomainModuleEvidenceError::InvalidStateContract),
    }
    validate_policy_pack(&evidence.lexical_policy, DomainPolicyPackKind::Lexical)?;
    if let Some(temporal) = evidence.temporal_policy.as_ref() {
        validate_policy_pack(&temporal.pack, DomainPolicyPackKind::Temporal)?;
    }
    Ok(())
}

fn validate_policy_pack(
    policy: &DomainPolicyPackEvidence,
    policy_kind: DomainPolicyPackKind,
) -> Result<(), DomainModuleEvidenceError> {
    if policy.pack_id.trim().is_empty() || policy.schema_version == 0 {
        return Err(DomainModuleEvidenceError::InvalidPolicyIdentity { policy_kind });
    }
    if policy.rule_count == 0 || !is_canonical_sha256(&policy.sha256) {
        return Err(DomainModuleEvidenceError::InvalidPolicyPack { policy_kind });
    }
    Ok(())
}

/// Returns whether a value is a lowercase 64-character SHA-256 digest.
#[must_use]
pub fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{
        validate_domain_module_evidence, DomainModuleEvidence, DomainModuleEvidenceError,
        DomainPolicyPackEvidence,
    };
    use crate::{DomainModuleId, DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION};

    #[test]
    fn policy_pack_digest_binds_exact_source_bytes() {
        let first = DomainPolicyPackEvidence::from_source("test.pack", 1, b"{\"a\":1}", 1);
        let second = DomainPolicyPackEvidence::from_source("test.pack", 1, b"{ \"a\": 1 }", 1);

        assert_ne!(first.sha256, second.sha256);
        assert_eq!(first.sha256.len(), 64);
    }

    #[test]
    fn state_contract_is_validated_once_for_all_consumers() {
        let evidence = DomainModuleEvidence {
            schema_version: DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
            module_id: DomainModuleId::Kids,
            module_version: "0.2.0".to_string(),
            stateful: true,
            state_schema_version: None,
            lexical_policy: DomainPolicyPackEvidence::from_source("kids.test", 1, b"rules", 1),
            temporal_policy: None,
        };

        assert_eq!(
            validate_domain_module_evidence(&evidence),
            Err(DomainModuleEvidenceError::InvalidStateContract)
        );
    }

    #[test]
    fn nested_policy_evidence_rejects_unknown_fields() {
        let raw = r#"{
            "schema_version":1,
            "module_id":"kids",
            "module_version":"0.2.0",
            "stateful":true,
            "state_schema_version":2,
            "lexical_policy":{
                "pack_id":"kids.test",
                "schema_version":1,
                "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "rule_count":1,
                "uncommitted_note":"must not disappear during canonicalization"
            },
            "temporal_policy":null
        }"#;

        let error = serde_json::from_str::<DomainModuleEvidence>(raw)
            .expect_err("unknown nested evidence field must fail");

        assert!(error.to_string().contains("uncommitted_note"));
    }
}
