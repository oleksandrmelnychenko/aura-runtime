use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::{
    DomainConfirmedOutput, DomainInput, DomainModule, DomainModuleEvidence, DomainModuleId,
    DomainOutput, DomainPolicyPackEvidence, DomainSignal, DomainTemporalInput,
    DomainTemporalOutput, DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
};

/// Registration failure that prevents an inconsistent module from entering the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainRegistrationError {
    /// A module with the same stable identity is already registered.
    DuplicateModule {
        /// Conflicting stable module identity.
        module_id: DomainModuleId,
    },
    /// The implementation identity differs from its release-evidence identity.
    EvidenceIdentityMismatch {
        /// Identity returned by the executable module.
        module_id: DomainModuleId,
        /// Identity declared by release evidence.
        evidence_module_id: DomainModuleId,
    },
    /// The module uses an unsupported release-evidence schema.
    UnsupportedEvidenceSchema {
        /// Module whose evidence was rejected.
        module_id: DomainModuleId,
        /// Schema version found in the evidence.
        schema_version: u32,
    },
    /// A required module or policy-pack identity field is invalid.
    InvalidIdentity {
        /// Module whose evidence was rejected.
        module_id: DomainModuleId,
        /// Invalid field name.
        field: &'static str,
    },
    /// Stateful ownership and the durable state schema disagree.
    InvalidStateContract {
        /// Module whose state contract was rejected.
        module_id: DomainModuleId,
    },
    /// A policy pack has no executable rules or carries a malformed SHA-256 digest.
    InvalidPolicyPack {
        /// Module whose policy pack was rejected.
        module_id: DomainModuleId,
        /// Whether the lexical or temporal pack failed validation.
        policy_kind: &'static str,
    },
    /// Executable temporal activation differs from the release evidence.
    TemporalActivationMismatch {
        /// Module whose temporal contract was rejected.
        module_id: DomainModuleId,
        /// Value returned by the executable module.
        runtime_enabled: bool,
        /// Value declared in release evidence.
        evidence_enabled: bool,
    },
}

impl fmt::Display for DomainRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateModule { module_id } => {
                write!(formatter, "domain module {module_id:?} is already registered")
            }
            Self::EvidenceIdentityMismatch {
                module_id,
                evidence_module_id,
            } => write!(
                formatter,
                "domain module {module_id:?} declares evidence for {evidence_module_id:?}"
            ),
            Self::UnsupportedEvidenceSchema {
                module_id,
                schema_version,
            } => write!(
                formatter,
                "domain module {module_id:?} uses unsupported evidence schema {schema_version}"
            ),
            Self::InvalidIdentity { module_id, field } => {
                write!(formatter, "domain module {module_id:?} has invalid {field}")
            }
            Self::InvalidStateContract { module_id } => write!(
                formatter,
                "domain module {module_id:?} has an inconsistent state contract"
            ),
            Self::InvalidPolicyPack {
                module_id,
                policy_kind,
            } => write!(
                formatter,
                "domain module {module_id:?} has invalid {policy_kind} policy evidence"
            ),
            Self::TemporalActivationMismatch {
                module_id,
                runtime_enabled,
                evidence_enabled,
            } => write!(
                formatter,
                "domain module {module_id:?} temporal activation mismatch: runtime={runtime_enabled}, evidence={evidence_enabled}"
            ),
        }
    }
}

impl std::error::Error for DomainRegistrationError {}

/// In-process map from stable module identities to thread-safe implementations.
#[derive(Default)]
pub struct DomainRegistry {
    modules: HashMap<DomainModuleId, Arc<dyn DomainModule>>,
}

impl DomainRegistry {
    /// Registers an owned module and fails fast on an invalid or duplicate identity.
    pub fn register<M>(&mut self, module: M)
    where
        M: DomainModule + 'static,
    {
        self.try_register(module)
            .expect("invalid statically registered domain module");
    }

    /// Registers a shared module and fails fast on an invalid or duplicate identity.
    pub fn register_arc<M>(&mut self, module: Arc<M>)
    where
        M: DomainModule + 'static,
    {
        self.try_register_arc(module)
            .expect("invalid statically registered domain module");
    }

    /// Attempts to register an owned module without replacing an existing identity.
    pub fn try_register<M>(&mut self, module: M) -> Result<(), DomainRegistrationError>
    where
        M: DomainModule + 'static,
    {
        self.try_register_arc(Arc::new(module))
    }

    /// Attempts to register a shared module without replacing an existing identity.
    pub fn try_register_arc<M>(&mut self, module: Arc<M>) -> Result<(), DomainRegistrationError>
    where
        M: DomainModule + 'static,
    {
        let module_id = module.id();
        if self.modules.contains_key(&module_id) {
            return Err(DomainRegistrationError::DuplicateModule { module_id });
        }
        validate_module_evidence(module.as_ref())?;
        self.modules.insert(module_id, module);
        Ok(())
    }

    /// Returns whether a module identity is registered.
    #[must_use]
    pub fn contains(&self, module_id: DomainModuleId) -> bool {
        self.modules.contains_key(&module_id)
    }

    /// Returns release evidence for one registered module.
    #[must_use]
    pub fn evidence(&self, module_id: DomainModuleId) -> Option<DomainModuleEvidence> {
        self.modules.get(&module_id).map(|module| module.evidence())
    }

    /// Returns release evidence for every module in stable identity order.
    #[must_use]
    pub fn all_evidence(&self) -> Vec<DomainModuleEvidence> {
        let mut evidence = self
            .modules
            .values()
            .map(|module| module.evidence())
            .collect::<Vec<_>>();
        evidence.sort_by_key(|item| item.module_id);
        evidence
    }

    /// Runs message analysis, or returns `None` when the module is absent.
    #[must_use]
    pub fn run(&self, module_id: DomainModuleId, input: &DomainInput) -> Option<DomainOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.analyze(input))
    }

    /// Runs candidate detection without allowing domain-owned memory mutation.
    #[must_use]
    pub fn run_detection(
        &self,
        module_id: DomainModuleId,
        input: &DomainInput,
    ) -> Option<DomainOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.detect(input))
    }

    /// Commits only signals accepted by the core interpretation boundary.
    #[must_use]
    pub fn commit_confirmed(
        &self,
        module_id: DomainModuleId,
        input: &DomainInput,
        confirmed_signals: &[DomainSignal],
    ) -> Option<DomainConfirmedOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.commit_confirmed(input, confirmed_signals))
    }

    /// Returns whether the registered module has enabled temporal analysis.
    #[must_use]
    pub fn temporal_enabled(&self, module_id: DomainModuleId) -> bool {
        self.modules
            .get(&module_id)
            .is_some_and(|module| module.temporal_enabled())
    }

    /// Runs enabled temporal analysis.
    ///
    /// Returns `None` when the module is absent or its temporal path is disabled.
    #[must_use]
    pub fn run_temporal(
        &self,
        module_id: DomainModuleId,
        input: &DomainTemporalInput,
    ) -> Option<DomainTemporalOutput> {
        let module = self.modules.get(&module_id)?;
        if !module.temporal_enabled() {
            return None;
        }
        Some(module.analyze_temporal(input))
    }
}

fn validate_module_evidence(module: &dyn DomainModule) -> Result<(), DomainRegistrationError> {
    let module_id = module.id();
    let evidence = module.evidence();
    if evidence.module_id != module_id {
        return Err(DomainRegistrationError::EvidenceIdentityMismatch {
            module_id,
            evidence_module_id: evidence.module_id,
        });
    }
    if evidence.schema_version != DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION {
        return Err(DomainRegistrationError::UnsupportedEvidenceSchema {
            module_id,
            schema_version: evidence.schema_version,
        });
    }
    if evidence.module_version.trim().is_empty() {
        return Err(DomainRegistrationError::InvalidIdentity {
            module_id,
            field: "module_version",
        });
    }
    match (evidence.stateful, evidence.state_schema_version) {
        (true, Some(version)) if version > 0 => {}
        (false, None) => {}
        _ => return Err(DomainRegistrationError::InvalidStateContract { module_id }),
    }
    validate_policy_pack(module_id, "lexical", &evidence.lexical_policy)?;
    if let Some(temporal) = evidence.temporal_policy.as_ref() {
        validate_policy_pack(module_id, "temporal", &temporal.pack)?;
    }

    let runtime_enabled = module.temporal_enabled();
    let evidence_enabled = evidence
        .temporal_policy
        .as_ref()
        .is_some_and(|policy| policy.runtime_enabled);
    if runtime_enabled != evidence_enabled {
        return Err(DomainRegistrationError::TemporalActivationMismatch {
            module_id,
            runtime_enabled,
            evidence_enabled,
        });
    }
    Ok(())
}

fn validate_policy_pack(
    module_id: DomainModuleId,
    policy_kind: &'static str,
    policy: &DomainPolicyPackEvidence,
) -> Result<(), DomainRegistrationError> {
    if policy.pack_id.trim().is_empty() || policy.schema_version == 0 {
        return Err(DomainRegistrationError::InvalidIdentity {
            module_id,
            field: if policy_kind == "lexical" {
                "lexical_policy_identity"
            } else {
                "temporal_policy_identity"
            },
        });
    }
    let valid_digest = policy.sha256.len() == 64
        && policy
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if policy.rule_count == 0 || !valid_digest {
        return Err(DomainRegistrationError::InvalidPolicyPack {
            module_id,
            policy_kind,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DomainRegistrationError, DomainRegistry};
    use crate::{
        DomainConversationType, DomainInput, DomainModule, DomainModuleEvidence, DomainModuleId,
        DomainOutput, DomainPolicyPackEvidence, DomainTemporalInput, DomainTemporalPolicyEvidence,
        DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
    };

    struct TestModule {
        module_id: DomainModuleId,
        evidence: DomainModuleEvidence,
        temporal_enabled: bool,
    }

    impl DomainModule for TestModule {
        fn id(&self) -> DomainModuleId {
            self.module_id
        }

        fn evidence(&self) -> DomainModuleEvidence {
            self.evidence.clone()
        }

        fn detect(&self, _input: &DomainInput) -> DomainOutput {
            DomainOutput::default()
        }

        fn analyze(&self, _input: &DomainInput) -> DomainOutput {
            DomainOutput::default()
        }

        fn temporal_enabled(&self) -> bool {
            self.temporal_enabled
        }
    }

    fn test_evidence(module_id: DomainModuleId) -> DomainModuleEvidence {
        DomainModuleEvidence {
            schema_version: DOMAIN_MODULE_EVIDENCE_SCHEMA_VERSION,
            module_id,
            module_version: "test".to_string(),
            stateful: false,
            state_schema_version: None,
            lexical_policy: DomainPolicyPackEvidence::from_source("test.lexical", 1, b"{}", 1),
            temporal_policy: None,
        }
    }

    fn stateless_module() -> TestModule {
        TestModule {
            module_id: DomainModuleId::Military,
            evidence: test_evidence(DomainModuleId::Military),
            temporal_enabled: false,
        }
    }

    #[test]
    fn stateless_module_keeps_temporal_path_disabled() {
        let mut registry = DomainRegistry::default();
        registry.register(stateless_module());

        assert!(!registry.temporal_enabled(DomainModuleId::Military));
        assert_eq!(
            registry
                .evidence(DomainModuleId::Military)
                .expect("registered module evidence")
                .module_version,
            "test"
        );
    }

    #[test]
    fn stateless_module_cannot_run_disabled_temporal_path() {
        let mut registry = DomainRegistry::default();
        registry.register(stateless_module());
        let input = DomainTemporalInput {
            as_of_ms: 0,
            current_actor_id: 0,
            current_content_hash: None,
            conversation_type: DomainConversationType::default(),
            events: Vec::new(),
        };

        let output = registry.run_temporal(DomainModuleId::Military, &input);

        assert!(output.is_none());
    }

    #[test]
    fn duplicate_registration_is_rejected_without_replacement() {
        let mut registry = DomainRegistry::default();
        registry.register(stateless_module());
        let mut replacement = stateless_module();
        replacement.evidence.module_version = "replacement".to_string();

        let error = registry
            .try_register(replacement)
            .expect_err("duplicate module must fail closed");

        assert_eq!(
            error,
            DomainRegistrationError::DuplicateModule {
                module_id: DomainModuleId::Military
            }
        );
        assert_eq!(
            registry
                .evidence(DomainModuleId::Military)
                .expect("original module evidence")
                .module_version,
            "test"
        );
    }

    #[test]
    fn evidence_identity_mismatch_is_rejected() {
        let mut registry = DomainRegistry::default();
        let module = TestModule {
            module_id: DomainModuleId::Military,
            evidence: test_evidence(DomainModuleId::Kids),
            temporal_enabled: false,
        };

        let error = registry
            .try_register(module)
            .expect_err("mismatched evidence identity must fail closed");

        assert_eq!(
            error,
            DomainRegistrationError::EvidenceIdentityMismatch {
                module_id: DomainModuleId::Military,
                evidence_module_id: DomainModuleId::Kids,
            }
        );
        assert!(!registry.contains(DomainModuleId::Military));
    }

    #[test]
    fn temporal_runtime_and_evidence_must_agree() {
        let mut registry = DomainRegistry::default();
        let mut evidence = test_evidence(DomainModuleId::Military);
        evidence.temporal_policy = Some(DomainTemporalPolicyEvidence {
            pack: DomainPolicyPackEvidence::from_source("test.temporal", 1, b"{}", 1),
            runtime_enabled: false,
            action_execution_configured: false,
        });
        let module = TestModule {
            module_id: DomainModuleId::Military,
            evidence,
            temporal_enabled: true,
        };

        let error = registry
            .try_register(module)
            .expect_err("temporal activation mismatch must fail closed");

        assert_eq!(
            error,
            DomainRegistrationError::TemporalActivationMismatch {
                module_id: DomainModuleId::Military,
                runtime_enabled: true,
                evidence_enabled: false,
            }
        );
    }

    #[test]
    fn malformed_policy_or_state_evidence_is_rejected() {
        let mut registry = DomainRegistry::default();
        let mut invalid_state = test_evidence(DomainModuleId::Kids);
        invalid_state.stateful = true;
        let state_error = registry
            .try_register(TestModule {
                module_id: DomainModuleId::Kids,
                evidence: invalid_state,
                temporal_enabled: false,
            })
            .expect_err("missing state schema must fail closed");
        assert_eq!(
            state_error,
            DomainRegistrationError::InvalidStateContract {
                module_id: DomainModuleId::Kids
            }
        );

        let mut invalid_pack = test_evidence(DomainModuleId::Military);
        invalid_pack.lexical_policy.sha256 = "not-a-digest".to_string();
        let pack_error = registry
            .try_register(TestModule {
                module_id: DomainModuleId::Military,
                evidence: invalid_pack,
                temporal_enabled: false,
            })
            .expect_err("malformed policy digest must fail closed");
        assert_eq!(
            pack_error,
            DomainRegistrationError::InvalidPolicyPack {
                module_id: DomainModuleId::Military,
                policy_kind: "lexical",
            }
        );
    }
}
