use aura_proto::messenger::v1 as proto;
use aura_runtime::{
    AccountType, AgentRuntime, Confidence, DomainMode, GuardianDeliveryClass,
    GuardianExecutionMode, GuardianExecutionPolicy, GuardianExecutionRule, GuardianReportTrigger,
    NativeExecutionMode, NativeExecutionPolicy, NativeExecutionPolicyState, ProductRolloutMode,
    RuntimeBackend, RuntimeCapabilities, RuntimeModality, SafetyCaseSeverity, SafetyCaseStatus,
    SafetyReasonCode, ThreatType, SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION,
};
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const POLICY_SCHEMA_VERSION: u32 = 1;
const GUARDIAN_REPORT_SCHEMA_VERSION: u32 = 2;
const DELIVERY_OPERATION_SCHEMA_VERSION: u32 = 3;
const SAFETY_CASE_POLICY_SCHEMA_VERSION: u32 = 2;
const MAX_POLICY_RULES: usize = 64;
const MAX_POLICY_VALIDITY_MS: u64 = 604_800_000;
const MAX_CASE_STATE_TTL_MS: u64 = 7_776_000_000;
const MAX_RULE_COOLDOWN_MS: u64 = 2_592_000_000;
const MAX_POLICY_LANGUAGES: usize = 32;
const MAX_CASE_OBSERVATIONS: u32 = 4_096;
const MAX_CASE_REASON_CODES: u32 = 64;
const MAX_RULE_REASON_CODES: u32 = 16;
const MAX_RULE_EVIDENCE_COMMITMENTS: u32 = 16;
const MAX_TRUST_KEYRING_BYTES: usize = 64 * 1024;
const MAX_TRUSTED_KEYS: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionPolicyTrustKeyring {
    schema_version: u32,
    keyring_version: String,
    authority_lineage_id: String,
    accepted_policy_versions: Vec<String>,
    maximum_policy_validity_ms: u64,
    maximum_case_state_ttl_ms: u64,
    maximum_case_observations: u32,
    maximum_case_reason_codes: u32,
    maximum_rule_count: usize,
    maximum_rule_reason_codes: u32,
    maximum_rule_evidence_commitments: u32,
    maximum_rule_cooldown_ms: u64,
    keys: Vec<ExecutionPolicyTrustedKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionPolicyTrustedKey {
    key_id: String,
    public_key_hex: String,
    minimum_policy_epoch: u64,
    maximum_policy_epoch: u64,
    minimum_safety_profile_authority_epoch: u64,
    maximum_safety_profile_authority_epoch: u64,
    valid_from_ms: u64,
    valid_until_ms: u64,
}

pub fn artifact_attestation(
    runtime: &AgentRuntime,
    request: proto::RuntimeArtifactAttestationRequest,
) -> Result<proto::RuntimeArtifactAttestationResponse, String> {
    let (_, execution_policy_trust_keyring_digest) = embedded_execution_policy_trust_keyring()?;
    if request.nonce.len() != 32 || request.nonce.iter().all(|byte| *byte == 0) {
        return Err("runtime artifact attestation nonce must be 32 nonzero bytes".to_string());
    }
    validate_account_key(&request.account_key)?;
    let capabilities = runtime_capabilities_to_proto(runtime.runtime_capabilities());
    if capabilities.backend == proto::RuntimeBackend::Onnx as i32
        && (capabilities.models.is_empty()
            || capabilities.models.iter().any(|model| {
                model
                    .sha256
                    .as_ref()
                    .is_none_or(|digest| decode_hex_digest(digest).is_none())
            }))
    {
        return Err("active ONNX runtime has an incomplete model identity".to_string());
    }
    let runtime_capabilities_wire = capabilities.encode_to_vec();
    let runtime_capabilities_digest: [u8; 32] = Sha256::digest(&runtime_capabilities_wire).into();
    let model_manifest_digest = runtime.model_manifest_digest();
    if model_manifest_digest.iter().all(|byte| *byte == 0) {
        return Err("active runtime model manifest is not attested".to_string());
    }
    let release_artifact_descriptor_digest = release_artifact_descriptor_digest();
    let release_attested = release_artifact_descriptor_digest
        .iter()
        .any(|byte| *byte != 0);
    Ok(proto::RuntimeArtifactAttestationResponse {
        schema_version: 1,
        account_key: request.account_key,
        nonce: request.nonce,
        runtime_capabilities_wire,
        runtime_capabilities_digest: runtime_capabilities_digest.to_vec(),
        model_manifest_digest: model_manifest_digest.to_vec(),
        release_artifact_descriptor_digest: release_artifact_descriptor_digest.to_vec(),
        release_attested,
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        execution_policy_trust_keyring_digest: execution_policy_trust_keyring_digest.to_vec(),
    })
}

pub fn policy_from_apply_request(
    runtime: &AgentRuntime,
    request: &proto::AuraExecutionPolicyApplyRequest,
) -> Result<NativeExecutionPolicy, String> {
    let (trust_keyring, execution_policy_trust_keyring_digest) =
        embedded_execution_policy_trust_keyring()?;
    validate_account_key(&request.account_key)?;
    if request.policy_wire.is_empty() || request.policy_wire.len() > 65_536 {
        return Err("execution policy wire exceeds the release bound".to_string());
    }
    let policy_wire_digest: [u8; 32] = Sha256::digest(&request.policy_wire).into();
    require_digest(
        "expected policy wire digest",
        &request.expected_policy_wire_digest,
    )?;
    if request.expected_policy_wire_digest.as_slice() != policy_wire_digest {
        return Err("execution policy wire digest mismatch".to_string());
    }
    let capabilities = runtime_capabilities_to_proto(runtime.runtime_capabilities());
    let runtime_capabilities_digest: [u8; 32] = Sha256::digest(capabilities.encode_to_vec()).into();
    let model_manifest_digest = runtime.model_manifest_digest();
    if request.expected_runtime_capabilities_digest.as_slice() != runtime_capabilities_digest
        || request.expected_model_manifest_digest.as_slice() != model_manifest_digest
    {
        return Err("execution policy artifacts do not match the active runtime".to_string());
    }
    require_digest(
        "expected execution policy trust keyring digest",
        &request.expected_execution_policy_trust_keyring_digest,
    )?;
    if request
        .expected_execution_policy_trust_keyring_digest
        .as_slice()
        != execution_policy_trust_keyring_digest
    {
        return Err("execution policy trust keyring digest mismatch".to_string());
    }

    let document = proto::AuraExecutionPolicyDocument::decode(request.policy_wire.as_slice())
        .map_err(|error| format!("invalid execution policy protobuf: {error}"))?;
    if document.encode_to_vec() != request.policy_wire {
        return Err("execution policy protobuf is not canonical".to_string());
    }
    validate_document(
        &document,
        DocumentValidationContext {
            authenticated_server_time_ms: request.authenticated_server_time_unix_ms,
            runtime_capabilities_digest: &runtime_capabilities_digest,
            model_manifest_digest: &model_manifest_digest,
            account_key: &request.account_key,
            runtime_account_type: runtime.account_type(),
            runtime_domain_mode: runtime.effective_domain_mode(),
            runtime_language: runtime.language(),
            trust_keyring: &trust_keyring,
        },
    )?;

    let rules = document
        .rules
        .iter()
        .map(rule_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    let execution_mode = match proto::AuraExecutionMode::try_from(document.execution_mode) {
        Ok(proto::AuraExecutionMode::Off) => NativeExecutionMode::Off,
        Ok(proto::AuraExecutionMode::ShadowCases) => NativeExecutionMode::ShadowCases,
        Ok(proto::AuraExecutionMode::CaseTransitions) => NativeExecutionMode::CaseTransitions,
        _ => return Err("execution policy mode is unsupported".to_string()),
    };
    let state = match proto::AuraExecutionPolicyState::try_from(document.state) {
        Ok(proto::AuraExecutionPolicyState::Enabled) => NativeExecutionPolicyState::Enabled,
        Ok(proto::AuraExecutionPolicyState::Disabled) => NativeExecutionPolicyState::Disabled,
        _ => return Err("execution policy state is unsupported".to_string()),
    };
    let guardian_policy = match (state, execution_mode) {
        (NativeExecutionPolicyState::Disabled, NativeExecutionMode::Off) => None,
        (NativeExecutionPolicyState::Enabled, NativeExecutionMode::ShadowCases) => {
            Some(GuardianExecutionPolicy {
                authority_lineage_id: document.authority_lineage_id.clone(),
                policy_epoch: document.policy_epoch,
                policy_version: document.policy_version.clone(),
                policy_assertion_digest: policy_wire_digest,
                runtime_capabilities_digest,
                model_manifest_digest,
                execution_policy_trust_keyring_digest,
                valid_from_ms: document.valid_from_ms,
                valid_until_ms: document.valid_until_ms,
                execution_mode: GuardianExecutionMode::ShadowCases,
                rules,
            })
        }
        (NativeExecutionPolicyState::Enabled, NativeExecutionMode::CaseTransitions) => {
            Some(GuardianExecutionPolicy {
                authority_lineage_id: document.authority_lineage_id.clone(),
                policy_epoch: document.policy_epoch,
                policy_version: document.policy_version.clone(),
                policy_assertion_digest: policy_wire_digest,
                runtime_capabilities_digest,
                model_manifest_digest,
                execution_policy_trust_keyring_digest,
                valid_from_ms: document.valid_from_ms,
                valid_until_ms: document.valid_until_ms,
                execution_mode: GuardianExecutionMode::CaseTransitions,
                rules,
            })
        }
        _ => return Err("execution policy state and mode disagree".to_string()),
    };

    let protected_account_id: [u8; 16] = document
        .protected_account_id
        .as_slice()
        .try_into()
        .map_err(|_| "protected account id must contain 16 bytes".to_string())?;
    let signed_policy_digest: [u8; 32] = Sha256::digest(signed_document_bytes(&document)).into();
    let policy = NativeExecutionPolicy {
        account_key: request.account_key.clone(),
        protected_account_id,
        authority_lineage_id: document.authority_lineage_id,
        issuer_key_id: document.issuer_key_id,
        policy_epoch: document.policy_epoch,
        revoked_through_policy_epoch: document.revoked_through_policy_epoch,
        state,
        execution_mode,
        policy_wire_digest,
        signed_policy_digest,
        runtime_capabilities_digest,
        model_manifest_digest,
        execution_policy_trust_keyring_digest,
        valid_from_ms: document.valid_from_ms,
        valid_until_ms: document.valid_until_ms,
        maximum_case_observations: usize::try_from(document.max_case_observations)
            .map_err(|_| "maximum case observations exceeds usize".to_string())?,
        maximum_case_reason_codes: usize::try_from(document.max_case_reason_codes)
            .map_err(|_| "maximum case reason codes exceeds usize".to_string())?,
        guardian_policy,
        active_for_runtime: true,
    };
    policy.validate().map_err(|error| error.to_string())?;
    Ok(policy)
}

pub fn application_receipt_to_proto(
    account_key: &str,
    receipt: &aura_runtime::NativeExecutionPolicyApplicationReceipt,
) -> proto::AuraExecutionPolicyApplicationReceipt {
    let policy = &receipt.policy;
    let disposition = match receipt.disposition {
        aura_runtime::NativeExecutionPolicyApplyDisposition::Applied => {
            proto::AuraExecutionPolicyApplyDisposition::Applied
        }
        aura_runtime::NativeExecutionPolicyApplyDisposition::Unchanged => {
            proto::AuraExecutionPolicyApplyDisposition::Unchanged
        }
    };
    let state = match policy.state {
        NativeExecutionPolicyState::Enabled => proto::AuraExecutionPolicyState::Enabled,
        NativeExecutionPolicyState::Disabled => proto::AuraExecutionPolicyState::Disabled,
    };
    let execution_mode = match policy.execution_mode {
        NativeExecutionMode::Off => proto::AuraExecutionMode::Off,
        NativeExecutionMode::ShadowCases => proto::AuraExecutionMode::ShadowCases,
        NativeExecutionMode::CaseTransitions => proto::AuraExecutionMode::CaseTransitions,
    };
    let receipt_digest = application_receipt_digest(account_key, policy, disposition as i32);
    proto::AuraExecutionPolicyApplicationReceipt {
        schema_version: 1,
        disposition: disposition as i32,
        account_key: account_key.to_string(),
        protected_account_id: policy.protected_account_id.to_vec(),
        policy_epoch: policy.policy_epoch,
        policy_wire_digest: policy.policy_wire_digest.to_vec(),
        state: state as i32,
        execution_mode: execution_mode as i32,
        runtime_capabilities_digest: policy.runtime_capabilities_digest.to_vec(),
        model_manifest_digest: policy.model_manifest_digest.to_vec(),
        native_floor_epoch: policy.policy_epoch,
        native_floor_policy_wire_digest: policy.policy_wire_digest.to_vec(),
        signed_policy_digest: policy.signed_policy_digest.to_vec(),
        receipt_digest: receipt_digest.to_vec(),
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        execution_policy_trust_keyring_digest: policy
            .execution_policy_trust_keyring_digest
            .to_vec(),
    }
}

pub(crate) fn runtime_capabilities_to_proto(
    capabilities: RuntimeCapabilities,
) -> proto::RuntimeCapabilities {
    proto::RuntimeCapabilities {
        schema_version: capabilities.schema_version,
        runtime_version: capabilities.runtime_version,
        backend: match capabilities.backend {
            RuntimeBackend::RulesFallback => proto::RuntimeBackend::RulesFallback as i32,
            RuntimeBackend::Onnx => proto::RuntimeBackend::Onnx as i32,
        },
        supported_modalities: capabilities
            .supported_modalities
            .into_iter()
            .map(|modality| match modality {
                RuntimeModality::Text => proto::RuntimeModality::Text as i32,
                RuntimeModality::Url => proto::RuntimeModality::Url as i32,
            })
            .collect(),
        models: capabilities
            .models
            .into_iter()
            .map(|model| proto::RuntimeModelIdentity {
                component: model.component,
                identifier: model.identifier,
                sha256: model.sha256,
            })
            .collect(),
        policy_schema_version: capabilities.policy_schema_version,
        product_schema_version: capabilities.product_schema_version,
        state_schema_version: capabilities.state_schema_version,
        product_rollout_mode: match capabilities.product_rollout_mode {
            ProductRolloutMode::Shadow => proto::ProductRolloutMode::Shadow as i32,
            ProductRolloutMode::StagingPilot => proto::ProductRolloutMode::StagingPilot as i32,
            ProductRolloutMode::GuardianEnabled => {
                proto::ProductRolloutMode::GuardianEnabled as i32
            }
        },
    }
}

struct DocumentValidationContext<'a> {
    authenticated_server_time_ms: i64,
    runtime_capabilities_digest: &'a [u8; 32],
    model_manifest_digest: &'a [u8; 32],
    account_key: &'a str,
    runtime_account_type: AccountType,
    runtime_domain_mode: DomainMode,
    runtime_language: &'a str,
    trust_keyring: &'a ExecutionPolicyTrustKeyring,
}

fn validate_document(
    document: &proto::AuraExecutionPolicyDocument,
    context: DocumentValidationContext<'_>,
) -> Result<(), String> {
    let DocumentValidationContext {
        authenticated_server_time_ms,
        runtime_capabilities_digest,
        model_manifest_digest,
        account_key,
        runtime_account_type,
        runtime_domain_mode,
        runtime_language,
        trust_keyring,
    } = context;
    if document.schema_version != POLICY_SCHEMA_VERSION
        || document.required_guardian_report_schema_version != GUARDIAN_REPORT_SCHEMA_VERSION
        || document.required_delivery_operation_schema_version != DELIVERY_OPERATION_SCHEMA_VERSION
        || document.safety_case_policy_schema_version != SAFETY_CASE_POLICY_SCHEMA_VERSION
        || document.signature_algorithm
            != proto::AuraExecutionPolicySignatureAlgorithm::Ed25519 as i32
    {
        return Err("execution policy requires an unsupported schema".to_string());
    }
    validate_identifier("authority lineage", &document.authority_lineage_id)?;
    validate_identifier("issuer key id", &document.issuer_key_id)?;
    validate_identifier("policy version", &document.policy_version)?;
    validate_identifier("rollout id", &document.rollout_id)?;
    validate_identifier("cohort id", &document.cohort_id)?;
    require_digest("policy body digest", &document.policy_body_digest)?;
    require_digest(
        "safety profile assertion digest",
        &document.safety_profile_assertion_digest,
    )?;
    if document.signature.len() != 64 || document.signature.iter().all(|byte| *byte == 0) {
        return Err("execution policy signature is malformed".to_string());
    }
    if document.runtime_capabilities_digest.as_slice() != runtime_capabilities_digest
        || document.model_manifest_digest.as_slice() != model_manifest_digest
    {
        return Err("execution policy artifact binding is invalid".to_string());
    }
    let expected_profile = match runtime_account_type {
        AccountType::Adult => proto::AuraExecutionAccountProfile::Adult,
        AccountType::Teen => proto::AuraExecutionAccountProfile::Teen,
        AccountType::Child => proto::AuraExecutionAccountProfile::Child,
    };
    if document.account_profile != expected_profile as i32 {
        return Err("execution policy account profile does not match the runtime".to_string());
    }
    let expected_domain = match runtime_domain_mode {
        DomainMode::None => proto::AuraExecutionDomainMode::None,
        DomainMode::Kids => proto::AuraExecutionDomainMode::Kids,
        DomainMode::Military => {
            return Err("execution policies do not support the military runtime domain".to_string())
        }
    };
    if document.domain_mode != expected_domain as i32 {
        return Err("execution policy domain mode does not match the runtime".to_string());
    }
    let state = proto::AuraExecutionPolicyState::try_from(document.state)
        .map_err(|_| "execution policy state is unsupported".to_string())?;
    let execution_mode = proto::AuraExecutionMode::try_from(document.execution_mode)
        .map_err(|_| "execution policy mode is unsupported".to_string())?;
    let policy_shape_is_valid = match state {
        proto::AuraExecutionPolicyState::Enabled => {
            document.policy_epoch > document.revoked_through_policy_epoch
                && matches!(
                    execution_mode,
                    proto::AuraExecutionMode::ShadowCases
                        | proto::AuraExecutionMode::CaseTransitions
                )
        }
        proto::AuraExecutionPolicyState::Disabled => {
            document.policy_epoch == document.revoked_through_policy_epoch
                && execution_mode == proto::AuraExecutionMode::Off
                && document.rules.is_empty()
        }
        proto::AuraExecutionPolicyState::Unspecified => false,
    };
    if !policy_shape_is_valid {
        return Err("execution policy state, mode, revocation, and rules disagree".to_string());
    }
    if document.policy_epoch == 0
        || document.policy_epoch > i64::MAX as u64
        || document.revoked_through_policy_epoch > document.policy_epoch
        || document.safety_profile_authority_epoch == 0
        || document.safety_profile_authority_epoch > i64::MAX as u64
        || document.issued_at_ms == 0
        || document.valid_from_ms == 0
        || document.issued_at_ms > document.valid_from_ms
        || document.valid_from_ms >= document.valid_until_ms
        || document.valid_until_ms > i64::MAX as u64
        || document.policy_updated_at_ms == 0
        || document.policy_updated_at_ms > document.issued_at_ms
        || document.valid_until_ms - document.valid_from_ms > MAX_POLICY_VALIDITY_MS
        || authenticated_server_time_ms <= 0
        || u64::try_from(authenticated_server_time_ms).is_err()
        || u64::try_from(authenticated_server_time_ms).is_ok_and(|now| {
            now < document.valid_from_ms
                || now < document.issued_at_ms
                || now >= document.valid_until_ms
        })
        || document.case_state_ttl_ms == 0
        || document.case_state_ttl_ms > MAX_CASE_STATE_TTL_MS
        || document.max_case_observations == 0
        || document.max_case_observations > MAX_CASE_OBSERVATIONS
        || document.max_case_reason_codes == 0
        || document.max_case_reason_codes > MAX_CASE_REASON_CODES
        || document.rules.len() > MAX_POLICY_RULES
    {
        return Err(
            "execution policy monotonic, validity, or capacity fields are invalid".to_string(),
        );
    }
    let expected_account_key = base64_standard(&document.protected_account_id);
    if document.protected_account_id.len() != 16
        || document.protected_account_id.iter().all(|byte| *byte == 0)
        || expected_account_key != account_key
    {
        return Err("execution policy protected account does not match account key".to_string());
    }
    if document.language_tags.is_empty()
        || document.language_tags.len() > MAX_POLICY_LANGUAGES
        || !is_strictly_ordered(&document.language_tags)
        || document
            .language_tags
            .iter()
            .any(|tag| !is_language_tag(tag))
        || !is_language_tag(runtime_language)
        || document
            .language_tags
            .binary_search_by(|tag| tag.as_str().cmp(runtime_language))
            .is_err()
        || !is_strictly_ordered_by(&document.rules, |rule| rule.rule_id.as_str())
    {
        return Err("execution policy repeated fields are not canonical".to_string());
    }
    for rule in &document.rules {
        if rule.minimum_observation_count == 0
            || rule.minimum_observation_count > document.max_case_observations
            || rule.minimum_peak_risk_bps > 10_000
            || rule.cooldown_ms > document.case_state_ttl_ms
            || rule.cooldown_ms > MAX_RULE_COOLDOWN_MS
            || rule.cooldown_ms > i64::MAX as u64
            || rule.max_report_reason_codes == 0
            || rule.max_report_reason_codes > MAX_RULE_REASON_CODES
            || rule.max_report_reason_codes > document.max_case_reason_codes
            || rule.max_evidence_commitments > MAX_RULE_EVIDENCE_COMMITMENTS
        {
            return Err("execution rule exceeds the signed policy or release bounds".to_string());
        }
        let expected: [u8; 32] = Sha256::digest(rule_bytes(rule)).into();
        if rule.rule_digest.as_slice() != expected {
            return Err("execution rule digest mismatch".to_string());
        }
    }
    match execution_mode {
        proto::AuraExecutionMode::ShadowCases
            if document.rules.iter().any(|rule| {
                rule.delivery_class != proto::AuraExecutionDeliveryClass::None as i32
            }) =>
        {
            return Err("shadow execution policy contains a delivery rule".to_string())
        }
        proto::AuraExecutionMode::CaseTransitions
            if document.rules.is_empty()
                || !document.rules.iter().any(|rule| {
                    matches!(
                        proto::AuraExecutionDeliveryClass::try_from(rule.delivery_class),
                        Ok(proto::AuraExecutionDeliveryClass::NeedsAttention)
                            | Ok(proto::AuraExecutionDeliveryClass::Urgent)
                    )
                }) =>
        {
            return Err("case-transition policy contains no reportable rule".to_string())
        }
        _ => {}
    }
    let expected_body: [u8; 32] = Sha256::digest(policy_body_bytes(document)).into();
    if document.policy_body_digest.as_slice() != expected_body {
        return Err("execution policy body digest mismatch".to_string());
    }
    verify_document_signature(document, trust_keyring)
}

fn rule_from_proto(rule: &proto::AuraExecutionRule) -> Result<GuardianExecutionRule, String> {
    validate_identifier("execution rule id", &rule.rule_id)?;
    let risk_family = match proto::AuraExecutionRiskFamily::try_from(rule.risk_family) {
        Ok(proto::AuraExecutionRiskFamily::Bullying) => ThreatType::Bullying,
        Ok(proto::AuraExecutionRiskFamily::Grooming) => ThreatType::Grooming,
        Ok(proto::AuraExecutionRiskFamily::Explicit) => ThreatType::Explicit,
        Ok(proto::AuraExecutionRiskFamily::Threat) => ThreatType::Threat,
        Ok(proto::AuraExecutionRiskFamily::SelfHarm) => ThreatType::SelfHarm,
        Ok(proto::AuraExecutionRiskFamily::Spam) => ThreatType::Spam,
        Ok(proto::AuraExecutionRiskFamily::Scam) => ThreatType::Scam,
        Ok(proto::AuraExecutionRiskFamily::Phishing) => ThreatType::Phishing,
        Ok(proto::AuraExecutionRiskFamily::Manipulation) => ThreatType::Manipulation,
        Ok(proto::AuraExecutionRiskFamily::Nsfw) => ThreatType::Nsfw,
        Ok(proto::AuraExecutionRiskFamily::HateSpeech) => ThreatType::HateSpeech,
        Ok(proto::AuraExecutionRiskFamily::Doxxing) => ThreatType::Doxxing,
        Ok(proto::AuraExecutionRiskFamily::PiiLeakage) => ThreatType::PiiLeakage,
        Ok(proto::AuraExecutionRiskFamily::Propaganda) => ThreatType::Propaganda,
        Ok(proto::AuraExecutionRiskFamily::OpsecViolation) => ThreatType::OpsecViolation,
        Ok(proto::AuraExecutionRiskFamily::Psyops) => ThreatType::Psyops,
        Ok(proto::AuraExecutionRiskFamily::MilitarySocialEng) => ThreatType::MilitarySocialEng,
        Ok(proto::AuraExecutionRiskFamily::CoordinateLeak) => ThreatType::CoordinateLeak,
        _ => return Err("execution rule risk family is unsupported".to_string()),
    };
    let trigger = match proto::AuraExecutionCaseTrigger::try_from(rule.trigger) {
        Ok(proto::AuraExecutionCaseTrigger::CaseOpened) => GuardianReportTrigger::CaseOpened,
        Ok(proto::AuraExecutionCaseTrigger::CaseEscalated) => GuardianReportTrigger::CaseEscalated,
        Ok(proto::AuraExecutionCaseTrigger::UrgentReview) => GuardianReportTrigger::UrgentReview,
        Ok(proto::AuraExecutionCaseTrigger::CaseResolved) => GuardianReportTrigger::CaseResolved,
        _ => return Err("execution rule trigger is unsupported".to_string()),
    };
    let required_case_status = execution_status(rule.required_case_status)?;
    let minimum_severity = execution_severity(rule.minimum_severity)?;
    let minimum_confidence = execution_confidence(rule.minimum_confidence)?;
    let delivery_class = match proto::AuraExecutionDeliveryClass::try_from(rule.delivery_class) {
        Ok(proto::AuraExecutionDeliveryClass::None) => None,
        Ok(proto::AuraExecutionDeliveryClass::NeedsAttention) => {
            Some(GuardianDeliveryClass::NeedsAttention)
        }
        Ok(proto::AuraExecutionDeliveryClass::Urgent) => Some(GuardianDeliveryClass::Urgent),
        _ => return Err("execution rule delivery class is unsupported".to_string()),
    };
    let allowed_report_reason_codes = rule
        .allowed_report_reason_codes
        .iter()
        .cloned()
        .map(SafetyReasonCode::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let rule_digest: [u8; 32] = rule
        .rule_digest
        .as_slice()
        .try_into()
        .map_err(|_| "execution rule digest must contain 32 bytes".to_string())?;
    let projected = GuardianExecutionRule {
        rule_id: rule.rule_id.clone(),
        risk_family,
        trigger,
        required_case_status,
        minimum_severity,
        minimum_confidence,
        minimum_observation_count: rule.minimum_observation_count,
        minimum_peak_risk_basis_points: u16::try_from(rule.minimum_peak_risk_bps)
            .map_err(|_| "execution rule risk threshold exceeds u16".to_string())?,
        cooldown_ms: rule.cooldown_ms,
        urgent_bypasses_cooldown: rule.urgent_bypasses_cooldown,
        maximum_report_reason_codes: usize::try_from(rule.max_report_reason_codes)
            .map_err(|_| "execution rule reason limit exceeds usize".to_string())?,
        maximum_evidence_commitments: usize::try_from(rule.max_evidence_commitments)
            .map_err(|_| "execution rule evidence limit exceeds usize".to_string())?,
        allowed_report_reason_codes,
        delivery_class,
        rule_digest,
    };
    projected.validate().map_err(|error| error.to_string())?;
    Ok(projected)
}

fn embedded_execution_policy_trust_keyring(
) -> Result<(ExecutionPolicyTrustKeyring, [u8; 32]), String> {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/execution-policy-trust-keyring.json"
    ));
    if bytes.is_empty() || bytes.len() > MAX_TRUST_KEYRING_BYTES {
        return Err("execution policy trust keyring is not embedded".to_string());
    }
    let expected_digest = option_env!("AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256")
        .and_then(decode_hex_digest)
        .ok_or_else(|| "execution policy trust keyring digest is not embedded".to_string())?;
    let actual_digest: [u8; 32] = Sha256::digest(bytes).into();
    if actual_digest != expected_digest {
        return Err("embedded execution policy trust keyring digest mismatch".to_string());
    }
    let keyring: ExecutionPolicyTrustKeyring = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid embedded execution policy trust keyring: {error}"))?;
    validate_execution_policy_trust_keyring(&keyring)?;
    Ok((keyring, actual_digest))
}

fn validate_execution_policy_trust_keyring(
    keyring: &ExecutionPolicyTrustKeyring,
) -> Result<(), String> {
    validate_identifier("execution policy keyring version", &keyring.keyring_version)?;
    validate_identifier(
        "execution policy keyring authority lineage",
        &keyring.authority_lineage_id,
    )?;
    if keyring.schema_version != 1
        || keyring.accepted_policy_versions.is_empty()
        || keyring.accepted_policy_versions.len() > 8
        || !is_strictly_ordered(&keyring.accepted_policy_versions)
        || keyring
            .accepted_policy_versions
            .iter()
            .any(|version| validate_identifier("accepted policy version", version).is_err())
        || keyring.keys.is_empty()
        || keyring.keys.len() > MAX_TRUSTED_KEYS
        || !is_strictly_ordered_by(&keyring.keys, |key| key.key_id.as_str())
        || keyring.maximum_policy_validity_ms == 0
        || keyring.maximum_policy_validity_ms > MAX_POLICY_VALIDITY_MS
        || keyring.maximum_case_state_ttl_ms == 0
        || keyring.maximum_case_state_ttl_ms > MAX_CASE_STATE_TTL_MS
        || keyring.maximum_case_observations == 0
        || keyring.maximum_case_observations > MAX_CASE_OBSERVATIONS
        || keyring.maximum_case_reason_codes == 0
        || keyring.maximum_case_reason_codes > MAX_CASE_REASON_CODES
        || keyring.maximum_rule_count == 0
        || keyring.maximum_rule_count > MAX_POLICY_RULES
        || keyring.maximum_rule_reason_codes == 0
        || keyring.maximum_rule_reason_codes > MAX_RULE_REASON_CODES
        || keyring.maximum_rule_evidence_commitments > MAX_RULE_EVIDENCE_COMMITMENTS
        || keyring.maximum_rule_cooldown_ms == 0
        || keyring.maximum_rule_cooldown_ms > MAX_RULE_COOLDOWN_MS
    {
        return Err(
            "embedded execution policy trust keyring is outside release bounds".to_string(),
        );
    }
    for (index, key) in keyring.keys.iter().enumerate() {
        validate_identifier("trusted execution policy key id", &key.key_id)?;
        let public_key = decode_hex_digest(&key.public_key_hex)
            .ok_or_else(|| "trusted execution policy public key is malformed".to_string())?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| "trusted execution policy public key is invalid".to_string())?;
        if key.minimum_policy_epoch == 0
            || key.minimum_policy_epoch > key.maximum_policy_epoch
            || key.maximum_policy_epoch > i64::MAX as u64
            || key.minimum_safety_profile_authority_epoch == 0
            || key.minimum_safety_profile_authority_epoch
                > key.maximum_safety_profile_authority_epoch
            || key.maximum_safety_profile_authority_epoch > i64::MAX as u64
            || key.valid_from_ms == 0
            || key.valid_from_ms >= key.valid_until_ms
            || key.valid_until_ms > i64::MAX as u64
        {
            return Err("trusted execution policy key range is invalid".to_string());
        }
        if keyring.keys[..index]
            .iter()
            .any(|other| other.public_key_hex == key.public_key_hex)
        {
            return Err("execution policy trust keyring repeats a public key".to_string());
        }
    }
    Ok(())
}

fn verify_document_signature(
    document: &proto::AuraExecutionPolicyDocument,
    keyring: &ExecutionPolicyTrustKeyring,
) -> Result<(), String> {
    if document.authority_lineage_id != keyring.authority_lineage_id
        || keyring
            .accepted_policy_versions
            .binary_search(&document.policy_version)
            .is_err()
        || document.valid_until_ms - document.valid_from_ms > keyring.maximum_policy_validity_ms
        || document.case_state_ttl_ms > keyring.maximum_case_state_ttl_ms
        || document.max_case_observations > keyring.maximum_case_observations
        || document.max_case_reason_codes > keyring.maximum_case_reason_codes
        || document.rules.len() > keyring.maximum_rule_count
        || document.rules.iter().any(|rule| {
            rule.max_report_reason_codes > keyring.maximum_rule_reason_codes
                || rule.max_evidence_commitments > keyring.maximum_rule_evidence_commitments
                || rule.cooldown_ms > keyring.maximum_rule_cooldown_ms
        })
    {
        return Err("execution policy exceeds embedded trust constraints".to_string());
    }
    let key = keyring
        .keys
        .binary_search_by(|key| key.key_id.as_str().cmp(document.issuer_key_id.as_str()))
        .ok()
        .and_then(|index| keyring.keys.get(index))
        .ok_or_else(|| "execution policy issuer key is not trusted".to_string())?;
    if !(key.minimum_policy_epoch..=key.maximum_policy_epoch).contains(&document.policy_epoch)
        || !(key.minimum_safety_profile_authority_epoch
            ..=key.maximum_safety_profile_authority_epoch)
            .contains(&document.safety_profile_authority_epoch)
        || document.issued_at_ms < key.valid_from_ms
        || document.valid_from_ms < key.valid_from_ms
        || document.valid_until_ms > key.valid_until_ms
    {
        return Err("execution policy is outside the trusted issuer range".to_string());
    }
    let public_key = decode_hex_digest(&key.public_key_hex)
        .ok_or_else(|| "trusted execution policy public key is malformed".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "trusted execution policy public key is invalid".to_string())?;
    let signature = Signature::from_slice(&document.signature)
        .map_err(|_| "execution policy signature is malformed".to_string())?;
    verifying_key
        .verify_strict(&signed_document_bytes(document), &signature)
        .map_err(|_| "execution policy Ed25519 signature verification failed".to_string())
}

fn execution_status(value: i32) -> Result<SafetyCaseStatus, String> {
    match proto::AuraExecutionCaseStatus::try_from(value) {
        Ok(proto::AuraExecutionCaseStatus::Observing) => Ok(SafetyCaseStatus::Observing),
        Ok(proto::AuraExecutionCaseStatus::Open) => Ok(SafetyCaseStatus::Open),
        Ok(proto::AuraExecutionCaseStatus::Escalated) => Ok(SafetyCaseStatus::Escalated),
        Ok(proto::AuraExecutionCaseStatus::Urgent) => Ok(SafetyCaseStatus::Urgent),
        Ok(proto::AuraExecutionCaseStatus::Resolved) => Ok(SafetyCaseStatus::Resolved),
        Ok(proto::AuraExecutionCaseStatus::Dismissed) => Ok(SafetyCaseStatus::Dismissed),
        _ => Err("execution case status is unsupported".to_string()),
    }
}

fn execution_severity(value: i32) -> Result<SafetyCaseSeverity, String> {
    match proto::AuraExecutionSeverity::try_from(value) {
        Ok(proto::AuraExecutionSeverity::Informational) => Ok(SafetyCaseSeverity::Informational),
        Ok(proto::AuraExecutionSeverity::Elevated) => Ok(SafetyCaseSeverity::Elevated),
        Ok(proto::AuraExecutionSeverity::High) => Ok(SafetyCaseSeverity::High),
        Ok(proto::AuraExecutionSeverity::Critical) => Ok(SafetyCaseSeverity::Critical),
        _ => Err("execution severity is unsupported".to_string()),
    }
}

fn execution_confidence(value: i32) -> Result<Confidence, String> {
    match proto::AuraExecutionConfidence::try_from(value) {
        Ok(proto::AuraExecutionConfidence::Low) => Ok(Confidence::Low),
        Ok(proto::AuraExecutionConfidence::Medium) => Ok(Confidence::Medium),
        Ok(proto::AuraExecutionConfidence::High) => Ok(Confidence::High),
        _ => Err("execution confidence is unsupported".to_string()),
    }
}

fn rule_bytes(rule: &proto::AuraExecutionRule) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(512);
    append_length_prefixed(b"aura.execution-policy.rule.v1", &mut bytes);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    append_length_prefixed(rule.rule_id.as_bytes(), &mut bytes);
    bytes.push(rule.risk_family as u8);
    bytes.push(rule.trigger as u8);
    bytes.push(rule.required_case_status as u8);
    bytes.push(rule.minimum_severity as u8);
    bytes.push(rule.minimum_confidence as u8);
    bytes.extend_from_slice(&rule.minimum_observation_count.to_be_bytes());
    bytes.extend_from_slice(&rule.minimum_peak_risk_bps.to_be_bytes());
    bytes.extend_from_slice(&rule.cooldown_ms.to_be_bytes());
    bytes.push(u8::from(rule.urgent_bypasses_cooldown));
    bytes.extend_from_slice(&rule.max_report_reason_codes.to_be_bytes());
    bytes.extend_from_slice(&rule.max_evidence_commitments.to_be_bytes());
    bytes.extend_from_slice(&(rule.allowed_report_reason_codes.len() as u16).to_be_bytes());
    for reason in &rule.allowed_report_reason_codes {
        append_length_prefixed(reason.as_bytes(), &mut bytes);
    }
    bytes.push(rule.delivery_class as u8);
    bytes
}

fn policy_body_bytes(document: &proto::AuraExecutionPolicyDocument) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4096);
    append_length_prefixed(b"aura.execution-policy.document.v1", &mut bytes);
    append_document(document, false, &mut bytes);
    bytes
}

fn signed_document_bytes(document: &proto::AuraExecutionPolicyDocument) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4096);
    append_length_prefixed(b"aura.execution-policy.document-signature.v1", &mut bytes);
    append_document(document, true, &mut bytes);
    bytes
}

fn append_document(
    document: &proto::AuraExecutionPolicyDocument,
    include_policy_body_digest: bool,
    bytes: &mut Vec<u8>,
) {
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(document.signature_algorithm as u8);
    append_length_prefixed(document.authority_lineage_id.as_bytes(), bytes);
    append_length_prefixed(document.issuer_key_id.as_bytes(), bytes);
    append_length_prefixed(&document.protected_account_id, bytes);
    bytes.extend_from_slice(&document.policy_epoch.to_be_bytes());
    bytes.extend_from_slice(&document.revoked_through_policy_epoch.to_be_bytes());
    bytes.push(document.state as u8);
    append_length_prefixed(document.policy_version.as_bytes(), bytes);
    if include_policy_body_digest {
        append_length_prefixed(&document.policy_body_digest, bytes);
    }
    bytes.extend_from_slice(&document.safety_profile_authority_epoch.to_be_bytes());
    append_length_prefixed(&document.safety_profile_assertion_digest, bytes);
    bytes.push(document.account_profile as u8);
    bytes.push(document.execution_mode as u8);
    bytes.extend_from_slice(&(document.language_tags.len() as u16).to_be_bytes());
    for tag in &document.language_tags {
        append_length_prefixed(tag.as_bytes(), bytes);
    }
    bytes.push(document.domain_mode as u8);
    append_length_prefixed(&document.runtime_capabilities_digest, bytes);
    append_length_prefixed(&document.model_manifest_digest, bytes);
    bytes.extend_from_slice(&document.safety_case_policy_schema_version.to_be_bytes());
    bytes.extend_from_slice(
        &document
            .required_guardian_report_schema_version
            .to_be_bytes(),
    );
    bytes.extend_from_slice(
        &document
            .required_delivery_operation_schema_version
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&document.case_state_ttl_ms.to_be_bytes());
    bytes.extend_from_slice(&document.max_case_observations.to_be_bytes());
    bytes.extend_from_slice(&document.max_case_reason_codes.to_be_bytes());
    bytes.extend_from_slice(&(document.rules.len() as u16).to_be_bytes());
    for rule in &document.rules {
        append_length_prefixed(&rule_bytes(rule), bytes);
        append_length_prefixed(&rule.rule_digest, bytes);
    }
    append_length_prefixed(document.rollout_id.as_bytes(), bytes);
    append_length_prefixed(document.cohort_id.as_bytes(), bytes);
    bytes.extend_from_slice(&document.issued_at_ms.to_be_bytes());
    bytes.extend_from_slice(&document.valid_from_ms.to_be_bytes());
    bytes.extend_from_slice(&document.valid_until_ms.to_be_bytes());
    bytes.extend_from_slice(&document.policy_updated_at_ms.to_be_bytes());
}

fn application_receipt_digest(
    account_key: &str,
    policy: &NativeExecutionPolicy,
    disposition: i32,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(384);
    append_length_prefixed(
        b"aura.execution-policy.native-application-receipt.v1",
        &mut bytes,
    );
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(disposition as u8);
    append_length_prefixed(account_key.as_bytes(), &mut bytes);
    append_length_prefixed(&policy.protected_account_id, &mut bytes);
    bytes.extend_from_slice(&policy.policy_epoch.to_be_bytes());
    append_length_prefixed(&policy.policy_wire_digest, &mut bytes);
    bytes.push(match policy.state {
        NativeExecutionPolicyState::Enabled => 1,
        NativeExecutionPolicyState::Disabled => 2,
    });
    bytes.push(match policy.execution_mode {
        NativeExecutionMode::Off => 1,
        NativeExecutionMode::ShadowCases => 2,
        NativeExecutionMode::CaseTransitions => 3,
    });
    append_length_prefixed(&policy.runtime_capabilities_digest, &mut bytes);
    append_length_prefixed(&policy.model_manifest_digest, &mut bytes);
    append_length_prefixed(&policy.execution_policy_trust_keyring_digest, &mut bytes);
    append_length_prefixed(&policy.signed_policy_digest, &mut bytes);
    Sha256::digest(bytes).into()
}

fn validate_account_key(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("execution policy account key is malformed".to_string());
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(format!("{field} is not canonical"));
    }
    Ok(())
}

fn require_digest(field: &str, value: &[u8]) -> Result<(), String> {
    if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
        return Err(format!("{field} must be a nonzero SHA-256 digest"));
    }
    Ok(())
}

fn is_strictly_ordered(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_strictly_ordered_by<T, F>(values: &[T], value: F) -> bool
where
    F: Fn(&T) -> &str,
{
    values
        .windows(2)
        .all(|pair| value(&pair[0]) < value(&pair[1]))
}

fn is_language_tag(value: &str) -> bool {
    if value.len() > 35 || value.contains('_') || value.to_ascii_lowercase() != value {
        return false;
    }
    let mut components = value.split('-');
    let Some(language) = components.next() else {
        return false;
    };
    if !(2..=8).contains(&language.len()) || !language.bytes().all(|byte| byte.is_ascii_lowercase())
    {
        return false;
    }
    components.all(|component| {
        (1..=8).contains(&component.len())
            && component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}

fn append_length_prefixed(value: &[u8], bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn release_artifact_descriptor_digest() -> [u8; 32] {
    option_env!("AURA_RELEASE_ARTIFACT_DESCRIPTOR_SHA256")
        .and_then(decode_hex_digest)
        .unwrap_or([0; 32])
}

fn decode_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    digest.iter().any(|byte| *byte != 0).then_some(digest)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}
