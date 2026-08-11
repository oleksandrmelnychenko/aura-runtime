use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DomainModuleId;

/// Current schema of the stable domain-module evidence projection.
pub const DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Cryptographic identity and size of one bundled domain policy pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::DomainPolicyPackEvidence;

    #[test]
    fn policy_pack_digest_binds_exact_source_bytes() {
        let first = DomainPolicyPackEvidence::from_source("test.pack", 1, b"{\"a\":1}", 1);
        let second = DomainPolicyPackEvidence::from_source("test.pack", 1, b"{ \"a\": 1 }", 1);

        assert_ne!(first.sha256, second.sha256);
        assert_eq!(first.sha256.len(), 64);
    }
}
