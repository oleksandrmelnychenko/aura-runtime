//! C FFI boundary for the AURA analysis engine.
//!
//! Exposes a protobuf-based C API for creating, configuring, and invoking
//! the AURA analyzer from non-Rust host applications.

#![allow(clippy::missing_safety_doc)]

mod execution_policy;

use std::cell::RefCell;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

use aura_agent_core::context::contact::{
    AgeSource as CoreAgeSource, BehavioralSnapshotState as CoreBehavioralSnapshotState,
    ChildSafetyTrajectory as CoreChildSafetyTrajectory,
    ContactProfileState as CoreContactProfileState,
    ContactProfilerWireState as CoreContactProfilerWireState,
};
use aura_agent_core::context::events::{
    ContextEvent as CoreContextEvent, EventContextFrame as CoreEventContextFrame,
    EventKind as CoreEventKind,
};
use aura_agent_core::context::tracker::{
    ConversationTimelineState as CoreConversationTimelineState,
    TrackerWireState as CoreTrackerWireState,
};
use aura_agent_core::AgentRuntime;
use aura_agent_core::{
    config::CulturalContext, AuraConfig, CanonicalSafetyAnalysisOutcome, Confidence,
    ConversationEventKey, ExportedSafetyCaseRuntimeState, GuardianDeliveryClass, GuardianReport,
    GuardianReportKey, GuardianReportObservationVolumeBand, GuardianReportTrigger, MessageInput,
    RelationshipTrustSource, SafetyAccountKey, SafetyCase, SafetyCaseCommand, SafetyCaseDecision,
    SafetyCaseGeneration, SafetyCaseId, SafetyCaseIgnoredReason, SafetyCaseIngestIdentity,
    SafetyCaseIngestOutcome, SafetyCaseRuntimeError, SafetyCaseSeverity, SafetyCaseSourcePreflight,
    SafetyCaseSourceReceipt, SafetyCaseStatus, SafetyCaseSubjectKey,
    SafetyCaseSuccessorActivationDisposition, SafetyCaseSuccessorActivationOutcome,
    SafetyReasonCode, SenderRelationship, SourceEventId, ThreatType,
    SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES, SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION,
};
use aura_patterns::PatternDatabase;
use aura_proto::messenger::v1 as proto;
use prost::Message as ProstMessage;
use sha2::{Digest, Sha256};
use tracing::warn;

const MAX_CONFIG_REQUEST_BYTES: usize = 64 * 1024;
const MAX_IMPORT_CONTEXT_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_CANONICAL_SAFETY_REQUEST_BYTES: usize = 1024 * 1024;
// Matches the host store's release limits for the two native-owned payloads.
// Guardian outbox and envelope overhead have separate host-owned budgets.
const MAX_CANONICAL_CONTEXT_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CANONICAL_COMBINED_STATE_BYTES: usize =
    SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES + MAX_CANONICAL_CONTEXT_STATE_BYTES;
const MAX_SMALL_CONTROL_REQUEST_BYTES: usize = 16 * 1024;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Process-global mirror of the most recent error message.
///
/// `LAST_ERROR` (thread-local, errno-style) is the primary store, but in some
/// static-library / iOS link configurations a thread-local write is not
/// observed by a subsequent read, which surfaced on the Swift side as
/// "unknown error" even though an error message *was* set (e.g. a real
/// `aura_init` failure whose reason was silently dropped). The mirror is a
/// one-shot cross-thread fallback: reading the matching thread-local error, or
/// reading the fallback directly, consumes the global copy so a later
/// successful operation cannot observe a stale failure.
static LAST_ERROR_GLOBAL: Mutex<Option<String>> = Mutex::new(None);

fn set_last_error(msg: impl Into<String>) {
    let msg = msg.into();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg.clone());
    });
    if let Ok(mut guard) = LAST_ERROR_GLOBAL.lock() {
        *guard = Some(msg);
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn ffi_guard<R>(default: R, body: impl FnOnce() -> R) -> R {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            set_last_error(format!("panic in FFI export: {}", panic_message(&*payload)));
            default
        }
    }
}

fn clear_last_error() {
    let previous = LAST_ERROR.with(|error| error.borrow_mut().take());
    let Some(previous) = previous else {
        return;
    };
    if let Ok(mut guard) = LAST_ERROR_GLOBAL.lock() {
        if guard.as_deref() == Some(previous.as_str()) {
            *guard = None;
        }
    }
}

struct AuraInstance {
    analyzer: AgentRuntime,
}

#[derive(Debug)]
struct DecodedConfig {
    aura_config: AuraConfig,
}

#[repr(C)]
/// Opaque byte buffer returned by FFI calls for protobuf-encoded responses.
pub struct AuraBuffer {
    /// Pointer to the allocated byte data.
    pub ptr: *mut u8,
    /// Length of the byte data in bytes.
    pub len: usize,
}

impl AuraBuffer {
    fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

fn build_instance(config: DecodedConfig) -> Result<*mut c_void, String> {
    config
        .aura_config
        .validate()
        .map_err(|e| format!("config validation failed: {e}"))?;

    let pattern_db = load_pattern_db(&config.aura_config);
    let analyzer = AgentRuntime::new(config.aura_config, &pattern_db);
    let instance = Box::new(Mutex::new(AuraInstance { analyzer }));
    Ok(Box::into_raw(instance) as *mut c_void)
}

/// Derives the exact capability and model identities emitted by native
/// attestation for a fully initialized runtime. This is public only so the
/// release identity emitter can share the production protobuf projection.
#[doc(hidden)]
pub fn release_runtime_artifact_digests(runtime: &AgentRuntime) -> ([u8; 32], [u8; 32]) {
    let capabilities =
        execution_policy::runtime_capabilities_to_proto(runtime.runtime_capabilities());
    let runtime_capabilities_digest: [u8; 32] = Sha256::digest(capabilities.encode_to_vec()).into();
    (runtime_capabilities_digest, runtime.model_manifest_digest())
}

fn with_instance<R>(
    handle: *mut c_void,
    f: impl FnOnce(&mut AuraInstance) -> Result<R, String>,
) -> Result<R, String> {
    if handle.is_null() {
        return Err("null handle".to_string());
    }

    let mutex = unsafe { &*(handle as *mut Mutex<AuraInstance>) };
    let mut guard = mutex.lock().map_err(|_| "mutex poisoned".to_string())?;
    f(&mut guard)
}

fn prepare_output(out: *mut AuraBuffer) -> Result<(), String> {
    if out.is_null() {
        return Err("null out pointer".to_string());
    }
    unsafe {
        *out = AuraBuffer::empty();
    }
    Ok(())
}

unsafe fn decode_proto_bounded<M>(
    ptr: *const u8,
    len: usize,
    label: &str,
    max_len: usize,
) -> Result<M, String>
where
    M: ProstMessage + Default,
{
    if ptr.is_null() {
        return Err(format!("null {label} pointer"));
    }
    if len > max_len {
        return Err(format!("{label} exceeds limit of {max_len} bytes"));
    }

    M::decode(std::slice::from_raw_parts(ptr, len))
        .map_err(|e| format!("invalid protobuf in {label}: {e}"))
}

fn write_proto_message<M>(out: *mut AuraBuffer, message: &M) -> Result<(), String>
where
    M: ProstMessage,
{
    let mut bytes = Vec::with_capacity(message.encoded_len());
    message
        .encode(&mut bytes)
        .map_err(|e| format!("failed to encode protobuf response: {e}"))?;

    unsafe {
        *out = bytes_to_buffer(bytes);
    }
    Ok(())
}

fn bytes_to_buffer(bytes: Vec<u8>) -> AuraBuffer {
    let mut bytes = bytes.into_boxed_slice();
    let ptr = bytes.as_mut_ptr();
    let len = bytes.len();
    std::mem::forget(bytes);
    AuraBuffer { ptr, len }
}

fn decode_config_request(
    config_ptr: *const u8,
    config_len: usize,
) -> Result<DecodedConfig, String> {
    let config_proto: proto::AuraConfig = unsafe {
        decode_proto_bounded(config_ptr, config_len, "config", MAX_CONFIG_REQUEST_BYTES)?
    };
    decoded_config_from_proto(config_proto)
}

fn canonical_safety_identity_from_proto(
    identity: proto::CanonicalSafetyEventIdentity,
    input: &MessageInput,
) -> Result<SafetyCaseIngestIdentity, String> {
    let account_key =
        SafetyAccountKey::new(identity.account_key).map_err(|error| error.to_string())?;
    let subject_key =
        SafetyCaseSubjectKey::new(identity.subject_key).map_err(|error| error.to_string())?;
    let conversation_key =
        ConversationEventKey::new(identity.conversation_key).map_err(|error| error.to_string())?;
    if conversation_key.as_str() != input.conversation_id.0.as_str() {
        return Err(
            "canonical conversation key does not match message conversation id".to_string(),
        );
    }
    let event_id = SourceEventId::new(identity.event_id).map_err(|error| error.to_string())?;
    if identity.observed_at_ms < identity.occurred_at_ms {
        return Err("canonical observation timestamp predates source event".to_string());
    }
    Ok(SafetyCaseIngestIdentity::new(
        account_key,
        subject_key,
        conversation_key,
        event_id,
        identity.revision,
        identity.occurred_at_ms,
        identity.observed_at_ms,
    ))
}

unsafe fn decode_safety_account_key(
    ptr: *const u8,
    len: usize,
) -> Result<SafetyAccountKey, String> {
    if ptr.is_null() {
        return Err("null safety account key pointer".to_string());
    }
    if len == 0 || len > 256 {
        return Err("safety account key must contain 1..=256 bytes".to_string());
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let value = std::str::from_utf8(bytes)
        .map_err(|_| "safety account key is not valid UTF-8".to_string())?;
    SafetyAccountKey::new(value.to_string()).map_err(|error| error.to_string())
}

fn canonical_safety_response_to_proto(
    outcome: CanonicalSafetyAnalysisOutcome,
    runtime: &AgentRuntime,
) -> Result<proto::CanonicalSafetyAnalyzeResponse, String> {
    let mut response = proto::CanonicalSafetyAnalyzeResponse {
        disposition: proto::CanonicalSafetyDisposition::Unspecified as i32,
        ignored_reason: None,
        case_id: None,
        case_revision: None,
        case_status: proto::SafetyCaseLifecycleStatus::Unspecified as i32,
        latest_revision: None,
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        case_generation: None,
    };

    match outcome {
        CanonicalSafetyAnalysisOutcome::Processed { safety_case } => match safety_case {
            Ok(SafetyCaseIngestOutcome::Ignored(reason)) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedIgnored as i32;
                response.ignored_reason = Some(safety_case_ignored_reason(reason).to_string());
            }
            Ok(SafetyCaseIngestOutcome::Reduced(decision)) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedReduced as i32;
                response.case_id = Some(decision.case_id().to_string());
                response.case_revision = Some(decision.case_revision());
                response.case_status = proto_safety_case_status(decision.status()) as i32;
                response.case_generation = Some(
                    runtime
                        .safety_cases()
                        .case_generation_by_id(decision.case_id())
                        .ok_or_else(|| {
                            "canonical safety decision is missing its case generation".to_string()
                        })?
                        .value(),
                );
            }
            Ok(_) => {
                return Err(
                    "canonical safety runtime returned an inconsistent processed outcome"
                        .to_string(),
                );
            }
            Err(
                SafetyCaseRuntimeError::AccountStateByteBudgetExceeded { .. }
                | SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded { .. },
            ) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedRejected as i32;
                response.ignored_reason = Some("persistence_byte_budget_exceeded".to_string());
            }
            Err(_) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedRejected as i32;
                response.ignored_reason = Some("projection_rejected".to_string());
            }
        },
        CanonicalSafetyAnalysisOutcome::DuplicateIgnored { receipt } => match receipt {
            SafetyCaseSourceReceipt::Ignored(reason) => {
                response.disposition = proto::CanonicalSafetyDisposition::DuplicateIgnored as i32;
                response.ignored_reason = Some(safety_case_ignored_reason(reason).to_string());
            }
            SafetyCaseSourceReceipt::Applied {
                case_id,
                case_revision,
                status,
            } => {
                response.disposition = proto::CanonicalSafetyDisposition::DuplicateApplied as i32;
                response.case_id = Some(case_id.to_string());
                response.case_revision = Some(case_revision);
                response.case_status = proto_safety_case_status(status) as i32;
                response.case_generation = Some(
                    runtime
                        .safety_cases()
                        .case_generation_by_id(&case_id)
                        .ok_or_else(|| {
                            "canonical safety receipt is missing its case generation".to_string()
                        })?
                        .value(),
                );
            }
            SafetyCaseSourceReceipt::Rejected => {
                response.disposition = proto::CanonicalSafetyDisposition::DuplicateRejected as i32;
            }
            _ => return Err("unsupported canonical safety receipt".to_string()),
        },
        CanonicalSafetyAnalysisOutcome::StaleIgnored { latest_revision } => {
            response.disposition = proto::CanonicalSafetyDisposition::StaleIgnored as i32;
            response.latest_revision = Some(latest_revision);
        }
    }

    Ok(response)
}

fn canonical_persistence_state_lengths(
    runtime: &AgentRuntime,
    account_key: &SafetyAccountKey,
) -> Result<(usize, usize, usize), SafetyCaseRuntimeError> {
    let case_state_len =
        serde_json::to_vec(&runtime.safety_cases().export_account_state(account_key))
            .map_err(|error| SafetyCaseRuntimeError::StateSerialization(error.to_string()))?
            .len();
    let context_state = tracker_state_to_proto(
        &runtime.export_context_state(),
        &runtime.export_kids_memory_state(),
    );
    let context_state_len = proto::ExportContextResponse {
        state: Some(context_state),
    }
    .encoded_len();
    let combined = case_state_len.checked_add(context_state_len).ok_or(
        SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded {
            maximum: MAX_CANONICAL_COMBINED_STATE_BYTES,
            current: usize::MAX,
            required_reserve: 0,
        },
    )?;
    Ok((case_state_len, context_state_len, combined))
}

fn ensure_canonical_persistence_within_budget(
    runtime: &AgentRuntime,
    account_key: &SafetyAccountKey,
) -> Result<(), SafetyCaseRuntimeError> {
    let (case_state_len, context_state_len, combined) =
        canonical_persistence_state_lengths(runtime, account_key)?;
    if case_state_len > SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES {
        return Err(SafetyCaseRuntimeError::AccountStateByteBudgetExceeded {
            maximum: SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES,
            current: case_state_len,
            required_reserve: 0,
        });
    }
    if context_state_len > MAX_CANONICAL_CONTEXT_STATE_BYTES {
        return Err(
            SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded {
                maximum: MAX_CANONICAL_CONTEXT_STATE_BYTES,
                current: context_state_len,
                required_reserve: 0,
            },
        );
    }
    if combined > MAX_CANONICAL_COMBINED_STATE_BYTES {
        return Err(
            SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded {
                maximum: MAX_CANONICAL_COMBINED_STATE_BYTES,
                current: combined,
                required_reserve: 0,
            },
        );
    }
    Ok(())
}

fn safety_case_ignored_reason(reason: SafetyCaseIgnoredReason) -> &'static str {
    match reason {
        SafetyCaseIgnoredReason::NoThreat => "no_threat",
        SafetyCaseIgnoredReason::NonActionable => "non_actionable",
        SafetyCaseIgnoredReason::ZeroRisk => "zero_risk",
        _ => "unknown",
    }
}

fn proto_safety_case_status(status: SafetyCaseStatus) -> proto::SafetyCaseLifecycleStatus {
    match status {
        SafetyCaseStatus::Observing => proto::SafetyCaseLifecycleStatus::Observing,
        SafetyCaseStatus::Open => proto::SafetyCaseLifecycleStatus::Open,
        SafetyCaseStatus::Escalated => proto::SafetyCaseLifecycleStatus::Escalated,
        SafetyCaseStatus::Urgent => proto::SafetyCaseLifecycleStatus::Urgent,
        SafetyCaseStatus::Resolved => proto::SafetyCaseLifecycleStatus::Resolved,
        SafetyCaseStatus::Dismissed => proto::SafetyCaseLifecycleStatus::Dismissed,
        _ => proto::SafetyCaseLifecycleStatus::Unspecified,
    }
}

fn proto_guardian_report_trigger(trigger: GuardianReportTrigger) -> proto::GuardianReportTrigger {
    match trigger {
        GuardianReportTrigger::CaseOpened => proto::GuardianReportTrigger::CaseOpened,
        GuardianReportTrigger::CaseEscalated => proto::GuardianReportTrigger::CaseEscalated,
        GuardianReportTrigger::UrgentReview => proto::GuardianReportTrigger::UrgentReview,
        GuardianReportTrigger::CaseResolved => proto::GuardianReportTrigger::CaseResolved,
        _ => proto::GuardianReportTrigger::Unspecified,
    }
}

fn proto_safety_case_severity(severity: SafetyCaseSeverity) -> proto::SafetyCaseSeverity {
    match severity {
        SafetyCaseSeverity::Informational => proto::SafetyCaseSeverity::Informational,
        SafetyCaseSeverity::Elevated => proto::SafetyCaseSeverity::Elevated,
        SafetyCaseSeverity::High => proto::SafetyCaseSeverity::High,
        SafetyCaseSeverity::Critical => proto::SafetyCaseSeverity::Critical,
        _ => proto::SafetyCaseSeverity::Unspecified,
    }
}

fn proto_threat_type(threat_type: ThreatType) -> proto::ThreatType {
    match threat_type {
        ThreatType::None => proto::ThreatType::None,
        ThreatType::Bullying => proto::ThreatType::Bullying,
        ThreatType::Grooming => proto::ThreatType::Grooming,
        ThreatType::Explicit => proto::ThreatType::Explicit,
        ThreatType::Threat => proto::ThreatType::Threat,
        ThreatType::SelfHarm => proto::ThreatType::SelfHarm,
        ThreatType::Spam => proto::ThreatType::Spam,
        ThreatType::Scam => proto::ThreatType::Scam,
        ThreatType::Phishing => proto::ThreatType::Phishing,
        ThreatType::Manipulation => proto::ThreatType::Manipulation,
        ThreatType::Nsfw => proto::ThreatType::Nsfw,
        ThreatType::HateSpeech => proto::ThreatType::HateSpeech,
        ThreatType::Doxxing => proto::ThreatType::Doxxing,
        ThreatType::PiiLeakage => proto::ThreatType::PiiLeakage,
        ThreatType::Propaganda => proto::ThreatType::Propaganda,
        ThreatType::OpsecViolation => proto::ThreatType::OpsecViolation,
        ThreatType::Psyops => proto::ThreatType::Psyops,
        ThreatType::MilitarySocialEng => proto::ThreatType::MilitarySocialEng,
        ThreatType::CoordinateLeak => proto::ThreatType::CoordinateLeak,
    }
}

fn proto_confidence(confidence: Confidence) -> proto::Confidence {
    match confidence {
        Confidence::Low => proto::Confidence::Low,
        Confidence::Medium => proto::Confidence::Medium,
        Confidence::High => proto::Confidence::High,
    }
}

fn guardian_report_risk_family(threat_type: ThreatType) -> proto::GuardianReportRiskFamily {
    match threat_type {
        ThreatType::Bullying => proto::GuardianReportRiskFamily::Bullying,
        ThreatType::Grooming => proto::GuardianReportRiskFamily::Grooming,
        ThreatType::Explicit => proto::GuardianReportRiskFamily::Explicit,
        ThreatType::Threat => proto::GuardianReportRiskFamily::Threat,
        ThreatType::SelfHarm => proto::GuardianReportRiskFamily::SelfHarm,
        ThreatType::Spam => proto::GuardianReportRiskFamily::Spam,
        ThreatType::Scam => proto::GuardianReportRiskFamily::Scam,
        ThreatType::Phishing => proto::GuardianReportRiskFamily::Phishing,
        ThreatType::Manipulation => proto::GuardianReportRiskFamily::Manipulation,
        ThreatType::Nsfw => proto::GuardianReportRiskFamily::Nsfw,
        ThreatType::HateSpeech => proto::GuardianReportRiskFamily::HateSpeech,
        ThreatType::Doxxing => proto::GuardianReportRiskFamily::Doxxing,
        ThreatType::PiiLeakage => proto::GuardianReportRiskFamily::PiiLeakage,
        ThreatType::Propaganda => proto::GuardianReportRiskFamily::Propaganda,
        ThreatType::OpsecViolation => proto::GuardianReportRiskFamily::OpsecViolation,
        ThreatType::Psyops => proto::GuardianReportRiskFamily::Psyops,
        ThreatType::MilitarySocialEng => proto::GuardianReportRiskFamily::MilitarySocialEng,
        ThreatType::CoordinateLeak => proto::GuardianReportRiskFamily::CoordinateLeak,
        ThreatType::None => proto::GuardianReportRiskFamily::Unspecified,
    }
}

fn guardian_report_delivery_class(
    delivery_class: GuardianDeliveryClass,
) -> proto::GuardianReportDeliveryClass {
    match delivery_class {
        GuardianDeliveryClass::NeedsAttention => proto::GuardianReportDeliveryClass::NeedsAttention,
        GuardianDeliveryClass::Urgent => proto::GuardianReportDeliveryClass::Urgent,
    }
}

fn guardian_report_to_proto(
    report: &GuardianReport,
    generation: SafetyCaseGeneration,
) -> proto::GuardianReport {
    let binding = report.execution_binding();
    proto::GuardianReport {
        schema_version: 2,
        case_id: report.key().case_id().to_string(),
        case_generation: generation.value(),
        transition_revision: report.key().transition_revision(),
        trigger: proto_guardian_report_trigger(report.trigger()) as i32,
        queued_at_ms: report.queued_at_ms(),
        risk_family: guardian_report_risk_family(report.threat_type()) as i32,
        case_status: proto_safety_case_status(report.case_status()) as i32,
        severity: proto_safety_case_severity(report.severity()) as i32,
        confidence_band: proto_confidence(report.confidence()) as i32,
        first_observed_at_ms: report.first_observed_at_ms(),
        last_observed_at_ms: report.last_observed_at_ms(),
        observation_volume_band: match report.observation_volume_band() {
            GuardianReportObservationVolumeBand::Isolated => {
                proto::GuardianReportObservationVolumeBand::Isolated as i32
            }
            GuardianReportObservationVolumeBand::Repeated => {
                proto::GuardianReportObservationVolumeBand::Repeated as i32
            }
            GuardianReportObservationVolumeBand::Sustained => {
                proto::GuardianReportObservationVolumeBand::Sustained as i32
            }
        },
        report_reason_codes: report
            .reason_codes()
            .iter()
            .map(ToString::to_string)
            .collect(),
        evidence_commitments: report
            .evidence_commitments()
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect(),
        execution_policy_authority_lineage_id: binding.authority_lineage_id.clone(),
        execution_policy_epoch: binding.policy_epoch,
        execution_policy_version: binding.policy_version.clone(),
        execution_policy_assertion_digest: binding.policy_assertion_digest.to_vec(),
        execution_rule_id: binding.rule_id.clone(),
        execution_rule_digest: binding.rule_digest.to_vec(),
        delivery_class: guardian_report_delivery_class(binding.delivery_class) as i32,
        runtime_capabilities_digest: binding.runtime_capabilities_digest.to_vec(),
        model_manifest_digest: binding.model_manifest_digest.to_vec(),
        policy_evaluated_at_ms: binding.policy_evaluated_at_ms,
    }
}

fn guardian_report_snapshot_to_proto(
    case: &SafetyCase,
    generation: SafetyCaseGeneration,
) -> proto::GuardianReportSnapshotResponse {
    let mut response = proto::GuardianReportSnapshotResponse {
        disposition: proto::GuardianReportDisposition::NotRequired as i32,
        case_id: case.case_id().to_string(),
        case_generation: generation.value(),
        current_case_revision: case.revision(),
        current_case_status: proto_safety_case_status(case.status()) as i32,
        report: None,
        deferred_trigger: None,
        deferred_eligible_at_ms: None,
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        prepared_at_ms: None,
        canonical_report_bytes: Vec::new(),
        semantic_digest: Vec::new(),
        report_id: String::new(),
    };
    if let Some(report) = case.pending_guardian_report() {
        response.disposition = proto::GuardianReportDisposition::Pending as i32;
        let wire = guardian_report_to_proto(report, generation);
        let canonical_report_bytes = guardian_report_canonical_bytes(&wire);
        let semantic_digest: [u8; 32] = Sha256::digest(&canonical_report_bytes).into();
        response.report_id = format!(
            "aura.guardian.report.v2:{}",
            lowercase_hex(&semantic_digest)
        );
        response.canonical_report_bytes = canonical_report_bytes;
        response.semantic_digest = semantic_digest.to_vec();
        response.report = Some(wire);
        response.prepared_at_ms = case
            .guardian_report_preparation()
            .map(|receipt| receipt.prepared_at_ms());
    } else if let Some(deferred) = case.deferred_guardian_report() {
        response.disposition = proto::GuardianReportDisposition::Deferred as i32;
        response.deferred_trigger = Some(proto_guardian_report_trigger(deferred.trigger()) as i32);
        response.deferred_eligible_at_ms = Some(deferred.eligible_at_ms());
    }
    response
}

fn guardian_report_canonical_bytes(report: &proto::GuardianReport) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1024);
    append_length_prefixed(b"aura.guardian.report.semantic.v2", &mut bytes);
    bytes.extend_from_slice(&2u16.to_be_bytes());
    append_length_prefixed(report.case_id.as_bytes(), &mut bytes);
    bytes.extend_from_slice(&report.case_generation.to_be_bytes());
    bytes.extend_from_slice(&report.transition_revision.to_be_bytes());
    bytes.push(u8::try_from(report.trigger).expect("native trigger fits u8"));
    bytes.extend_from_slice(&report.queued_at_ms.to_be_bytes());
    let risk_family = guardian_report_risk_family_name(report.risk_family);
    append_length_prefixed(risk_family.as_bytes(), &mut bytes);
    bytes.push(u8::try_from(report.case_status).expect("native case status fits u8"));
    let severity = guardian_report_severity_name(report.severity);
    append_length_prefixed(severity.as_bytes(), &mut bytes);
    bytes.push(u8::try_from(report.confidence_band).expect("native confidence fits u8"));
    bytes.extend_from_slice(&report.first_observed_at_ms.to_be_bytes());
    bytes.extend_from_slice(&report.last_observed_at_ms.to_be_bytes());
    bytes.push(
        u8::try_from(report.observation_volume_band)
            .expect("native observation volume band fits u8"),
    );
    bytes.extend_from_slice(
        &u16::try_from(report.report_reason_codes.len())
            .expect("native reason-code count fits u16")
            .to_be_bytes(),
    );
    for reason in &report.report_reason_codes {
        append_length_prefixed(reason.as_bytes(), &mut bytes);
    }
    bytes.extend_from_slice(
        &u16::try_from(report.evidence_commitments.len())
            .expect("native evidence count fits u16")
            .to_be_bytes(),
    );
    for commitment in &report.evidence_commitments {
        append_length_prefixed(commitment, &mut bytes);
    }
    append_length_prefixed(
        report.execution_policy_authority_lineage_id.as_bytes(),
        &mut bytes,
    );
    bytes.extend_from_slice(&report.execution_policy_epoch.to_be_bytes());
    append_length_prefixed(report.execution_policy_version.as_bytes(), &mut bytes);
    append_length_prefixed(&report.execution_policy_assertion_digest, &mut bytes);
    append_length_prefixed(report.execution_rule_id.as_bytes(), &mut bytes);
    append_length_prefixed(&report.execution_rule_digest, &mut bytes);
    bytes.push(u8::try_from(report.delivery_class).expect("native delivery class fits u8"));
    append_length_prefixed(&report.runtime_capabilities_digest, &mut bytes);
    append_length_prefixed(&report.model_manifest_digest, &mut bytes);
    bytes.extend_from_slice(&report.policy_evaluated_at_ms.to_be_bytes());
    bytes
}

fn guardian_report_risk_family_name(value: i32) -> &'static str {
    match proto::GuardianReportRiskFamily::try_from(value)
        .unwrap_or(proto::GuardianReportRiskFamily::Unspecified)
    {
        proto::GuardianReportRiskFamily::Bullying => "bullying",
        proto::GuardianReportRiskFamily::Grooming => "grooming",
        proto::GuardianReportRiskFamily::Explicit => "explicit",
        proto::GuardianReportRiskFamily::Threat => "threat",
        proto::GuardianReportRiskFamily::SelfHarm => "self_harm",
        proto::GuardianReportRiskFamily::Spam => "spam",
        proto::GuardianReportRiskFamily::Scam => "scam",
        proto::GuardianReportRiskFamily::Phishing => "phishing",
        proto::GuardianReportRiskFamily::Manipulation => "manipulation",
        proto::GuardianReportRiskFamily::Nsfw => "nsfw",
        proto::GuardianReportRiskFamily::HateSpeech => "hate_speech",
        proto::GuardianReportRiskFamily::Doxxing => "doxxing",
        proto::GuardianReportRiskFamily::PiiLeakage => "pii_leakage",
        proto::GuardianReportRiskFamily::Propaganda => "propaganda",
        proto::GuardianReportRiskFamily::OpsecViolation => "opsec_violation",
        proto::GuardianReportRiskFamily::Psyops => "psyops",
        proto::GuardianReportRiskFamily::MilitarySocialEng => "military_social_eng",
        proto::GuardianReportRiskFamily::CoordinateLeak => "coordinate_leak",
        proto::GuardianReportRiskFamily::Unspecified => "",
    }
}

fn guardian_report_severity_name(value: i32) -> &'static str {
    match proto::SafetyCaseSeverity::try_from(value)
        .unwrap_or(proto::SafetyCaseSeverity::Unspecified)
    {
        proto::SafetyCaseSeverity::Informational => "informational",
        proto::SafetyCaseSeverity::Elevated => "elevated",
        proto::SafetyCaseSeverity::High => "high",
        proto::SafetyCaseSeverity::Critical => "critical",
        proto::SafetyCaseSeverity::Unspecified => "",
    }
}

fn append_length_prefixed(value: &[u8], output: &mut Vec<u8>) {
    let length = u32::try_from(value.len()).expect("bounded native value fits u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn safety_case_lifecycle_command_from_proto(
    request: proto::SafetyCaseLifecycleCommandRequest,
) -> Result<(SafetyAccountKey, SafetyCaseId, SafetyCaseCommand), String> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    if request.at_ms == 0 {
        return Err("safety case lifecycle timestamp must be non-zero".to_string());
    }
    let reason_code =
        SafetyReasonCode::new(request.reason_code).map_err(|error| error.to_string())?;
    let command_type = proto::SafetyCaseLifecycleCommandType::try_from(request.command_type)
        .map_err(|_| "unsupported safety case lifecycle command type".to_string())?;
    let command = match command_type {
        proto::SafetyCaseLifecycleCommandType::Resolve => SafetyCaseCommand::Resolve {
            at_ms: request.at_ms,
            reason_code,
        },
        proto::SafetyCaseLifecycleCommandType::Dismiss => SafetyCaseCommand::Dismiss {
            at_ms: request.at_ms,
            reason_code,
        },
        proto::SafetyCaseLifecycleCommandType::Unspecified => {
            return Err("safety case lifecycle command type is unspecified".to_string());
        }
    };
    Ok((account_key, case_id, command))
}

fn safety_case_lifecycle_response_to_proto(
    decision: &SafetyCaseDecision,
    case_generation: SafetyCaseGeneration,
) -> proto::SafetyCaseLifecycleCommandResponse {
    proto::SafetyCaseLifecycleCommandResponse {
        case_id: decision.case_id().to_string(),
        case_revision: decision.case_revision(),
        case_status: proto_safety_case_status(decision.status()) as i32,
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        case_generation: Some(case_generation.value()),
    }
}

fn safety_case_successor_activation_from_proto(
    request: proto::SafetyCaseSuccessorActivationRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        u64,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let predecessor_case_id =
        SafetyCaseId::new(request.predecessor_case_id).map_err(|error| error.to_string())?;
    let expected_generation = request
        .expected_case_generation
        .ok_or_else(|| "expected safety case generation is missing".to_string())?;
    if request.expected_case_revision == 0 {
        return Err("expected safety case revision must be non-zero".to_string());
    }
    if request.activated_at_ms == 0 {
        return Err("safety case successor activation timestamp must be non-zero".to_string());
    }
    Ok((
        account_key,
        predecessor_case_id,
        SafetyCaseGeneration::new(expected_generation),
        request.expected_case_revision,
        request.activated_at_ms,
    ))
}

fn safety_case_successor_activation_to_proto(
    outcome: &SafetyCaseSuccessorActivationOutcome,
) -> proto::SafetyCaseSuccessorActivationResponse {
    let disposition = match outcome.disposition() {
        SafetyCaseSuccessorActivationDisposition::Activated => {
            proto::SafetyCaseSuccessorActivationDisposition::Activated
        }
        SafetyCaseSuccessorActivationDisposition::AlreadyActivated => {
            proto::SafetyCaseSuccessorActivationDisposition::AlreadyActivated
        }
    };
    proto::SafetyCaseSuccessorActivationResponse {
        disposition: disposition as i32,
        predecessor_case_id: outcome.predecessor_case_id().to_string(),
        predecessor_case_generation: outcome.predecessor_generation().value(),
        successor_case_id: outcome.successor_case_id().to_string(),
        successor_case_generation: outcome.successor_generation().value(),
        activated_at_ms: outcome.activated_at_ms(),
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
    }
}

fn guardian_report_snapshot_request_from_proto(
    request: proto::GuardianReportSnapshotRequest,
) -> Result<(SafetyAccountKey, SafetyCaseId, SafetyCaseGeneration, u64), String> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report case generation is missing".to_string())?;
    if request.expected_case_revision == 0 {
        return Err("expected guardian report case revision must be non-zero".to_string());
    }
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        request.expected_case_revision,
    ))
}

fn guardian_report_preparation_request_from_proto(
    request: proto::GuardianReportPreparationRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        GuardianReportKey,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report preparation generation is missing".to_string())?;
    if request.report_transition_revision == 0 {
        return Err("guardian report preparation revision must be non-zero".to_string());
    }
    if request.prepared_at_ms == 0 {
        return Err("guardian report preparation timestamp must be non-zero".to_string());
    }
    let report_key = GuardianReportKey::new(case_id.clone(), request.report_transition_revision);
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        report_key,
        request.prepared_at_ms,
    ))
}

fn guardian_report_flush_request_from_proto(
    request: proto::GuardianReportFlushRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        u64,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report flush generation is missing".to_string())?;
    if request.expected_case_revision == 0 {
        return Err("expected guardian report flush revision must be non-zero".to_string());
    }
    if request.evaluated_at_ms == 0 {
        return Err("guardian report flush timestamp must be non-zero".to_string());
    }
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        request.expected_case_revision,
        request.evaluated_at_ms,
    ))
}

fn guardian_report_acknowledgement_request_from_proto(
    request: proto::GuardianReportAcknowledgementRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        GuardianReportKey,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request.expected_case_generation.ok_or_else(|| {
        "expected guardian report acknowledgement generation is missing".to_string()
    })?;
    if request.report_transition_revision == 0 {
        return Err("guardian report transition revision must be non-zero".to_string());
    }
    if request.delivered_at_ms == 0 {
        return Err("guardian report delivery timestamp must be non-zero".to_string());
    }
    let report_key = GuardianReportKey::new(case_id.clone(), request.report_transition_revision);
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        report_key,
        request.delivered_at_ms,
    ))
}

fn guardian_report_suppression_request_from_proto(
    request: proto::GuardianReportSuppressionRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        GuardianReportKey,
        u64,
        SafetyReasonCode,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report suppression generation is missing".to_string())?;
    if request.report_transition_revision == 0 {
        return Err("guardian report suppression revision must be non-zero".to_string());
    }
    if request.suppressed_at_ms == 0 {
        return Err("guardian report suppression timestamp must be non-zero".to_string());
    }
    let report_key = GuardianReportKey::new(case_id.clone(), request.report_transition_revision);
    let reason_code =
        SafetyReasonCode::new(request.reason_code).map_err(|error| error.to_string())?;
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        report_key,
        request.suppressed_at_ms,
        reason_code,
    ))
}

/// Initializes a new AURA instance from a protobuf-encoded configuration.
///
/// Exported as `aura_agent_init` (NOT `aura_init`) to avoid a C-symbol collision
/// with aura-protected-protocol's `aura_init` when both static libs are linked
/// into the same iOS app target — otherwise the linker resolves `aura_init` to
/// whichever archive comes first, silently hijacking the agent runtime's init.
#[export_name = "aura_agent_init"]
pub unsafe extern "C" fn aura_init(config_ptr: *const u8, config_len: usize) -> *mut c_void {
    ffi_guard(std::ptr::null_mut(), move || {
        clear_last_error();

        let config = match decode_config_request(config_ptr, config_len) {
            Ok(config) => config,
            Err(e) => {
                set_last_error(e);
                return std::ptr::null_mut();
            }
        };

        match build_instance(config) {
            Ok(handle) => handle,
            Err(e) => {
                set_last_error(e);
                std::ptr::null_mut()
            }
        }
    })
}

/// Returns a nonce-bound identity for artifacts active in this exact handle.
#[no_mangle]
pub unsafe extern "C" fn aura_attest_runtime_artifacts(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }
        let request: proto::RuntimeArtifactAttestationRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "runtime artifact attestation request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        match with_instance(handle, |instance| {
            let response = execution_policy::artifact_attestation(&instance.analyzer, request)?;
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Verifies and atomically applies one signed execution-policy head against
/// the compile-time trust keyring and account-scoped native monotonic floor.
#[no_mangle]
pub unsafe extern "C" fn aura_apply_execution_policy(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }
        let request: proto::AuraExecutionPolicyApplyRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "execution policy apply request",
            96 * 1024,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        match with_instance(handle, |instance| {
            let account_key = SafetyAccountKey::new(request.account_key.clone())
                .map_err(|error| error.to_string())?;
            let policy = execution_policy::policy_from_apply_request(&instance.analyzer, &request)?;
            let snapshot = instance.analyzer.safety_cases().clone();
            let receipt = instance
                .analyzer
                .safety_cases_mut()
                .apply_execution_policy(&account_key, policy)
                .map_err(|error| error.to_string())?;
            if let Err(error) =
                ensure_canonical_persistence_within_budget(&instance.analyzer, &account_key)
            {
                *instance.analyzer.safety_cases_mut() = snapshot;
                return Err(error.to_string());
            }
            let response =
                execution_policy::application_receipt_to_proto(account_key.as_str(), &receipt);
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Canonically analyzes one source event and reduces it into Safety Case state.
///
/// Exact duplicates and stale revisions are returned without invoking the
/// analyzer, so conversation and Kids context remain exactly-once per revision.
/// First attempts are committed only when compact case JSON plus the exact
/// ExportContextResponse encoding fit the host's shared persistence envelope.
#[no_mangle]
pub unsafe extern "C" fn aura_analyze_canonical_safety(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::CanonicalSafetyAnalyzeRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "canonical safety request",
            MAX_CANONICAL_SAFETY_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let Some(message) = request.message else {
            set_last_error("missing message in canonical safety request");
            return false;
        };
        let Some(identity) = request.identity else {
            set_last_error("missing identity in canonical safety request");
            return false;
        };
        let input = message_input_from_proto(message);
        let identity = match canonical_safety_identity_from_proto(identity, &input) {
            Ok(identity) => identity,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            instance
                .analyzer
                .safety_cases()
                .require_active_execution_policy(identity.account_key(), identity.observed_at_ms())
                .map_err(|error| error.to_string())?;
            if matches!(
                instance
                    .analyzer
                    .safety_cases()
                    .preflight_source(&identity)
                    .map_err(|error| error.to_string())?,
                SafetyCaseSourcePreflight::Ready
            ) {
                ensure_canonical_persistence_within_budget(
                    &instance.analyzer,
                    identity.account_key(),
                )
                .map_err(|error| error.to_string())?;
            }
            let account_key = identity.account_key().clone();
            let outcome = instance
                .analyzer
                .analyze_local_with_canonical_safety_case_guarded(&input, &identity, |runtime| {
                    ensure_canonical_persistence_within_budget(runtime, &account_key)
                })
                .map_err(|error| error.to_string())?;
            let response = canonical_safety_response_to_proto(outcome, &instance.analyzer)?;
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Applies one bounded, account-scoped resolve or dismiss command.
#[no_mangle]
pub unsafe extern "C" fn aura_apply_safety_case_lifecycle(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::SafetyCaseLifecycleCommandRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "safety case lifecycle request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let (account_key, case_id, command) =
            match safety_case_lifecycle_command_from_proto(request) {
                Ok(command) => command,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };

        match with_instance(handle, |instance| {
            let decision = instance
                .analyzer
                .apply_safety_case_lifecycle_guarded(&account_key, &case_id, command, |runtime| {
                    ensure_canonical_persistence_within_budget(runtime, &account_key)
                })
                .map_err(|error| error.to_string())?;
            let generation = instance
                .analyzer
                .safety_cases()
                .case_generation_by_id(&case_id)
                .ok_or_else(|| "safety case lifecycle generation is missing".to_string())?;
            let response = safety_case_lifecycle_response_to_proto(&decision, generation);
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Explicitly activates one successor generation from an active terminal case.
/// No analysis or lifecycle path invokes this operation automatically.
#[no_mangle]
pub unsafe extern "C" fn aura_activate_safety_case_successor(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::SafetyCaseSuccessorActivationRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "safety case successor activation request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let (
            account_key,
            predecessor_case_id,
            expected_generation,
            expected_case_revision,
            activated_at_ms,
        ) = match safety_case_successor_activation_from_proto(request) {
            Ok(values) => values,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let outcome = instance
                .analyzer
                .activate_safety_case_successor_guarded(
                    &account_key,
                    &predecessor_case_id,
                    expected_generation,
                    expected_case_revision,
                    activated_at_ms,
                    |runtime| ensure_canonical_persistence_within_budget(runtime, &account_key),
                )
                .map_err(|error| error.to_string())?;
            write_proto_message(out, &safety_case_successor_activation_to_proto(&outcome))
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Purges one account's Safety Case state and exactly-once receipts from memory.
#[no_mangle]
pub unsafe extern "C" fn aura_remove_safety_case_account(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::SafetyCaseAccountRemovalRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "safety case account removal request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let account_key = match SafetyAccountKey::new(request.account_key) {
            Ok(account_key) => account_key,
            Err(error) => {
                set_last_error(error.to_string());
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let removal = instance
                .analyzer
                .safety_cases_mut()
                .remove_account(&account_key);
            let removed_cases = u64::try_from(removal.removed_cases())
                .map_err(|_| "removed safety case count exceeds u64".to_string())?;
            let removed_source_receipts = u64::try_from(removal.removed_source_receipts())
                .map_err(|_| "removed safety receipt count exceeds u64".to_string())?;
            write_proto_message(
                out,
                &proto::SafetyCaseAccountRemovalResponse {
                    removed_cases,
                    removed_source_receipts,
                    runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION
                        .to_string(),
                },
            )
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Exports the native reducer's current content-free guardian report state.
///
/// The request is account scoped and guarded by the exact case generation and
/// revision observed by the host. This operation never returns message content,
/// analyzer explanations, or a display verdict.
#[no_mangle]
pub unsafe extern "C" fn aura_export_guardian_report_snapshot(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::GuardianReportSnapshotRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "guardian report snapshot request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let (account_key, case_id, expected_generation, expected_case_revision) =
            match guardian_report_snapshot_request_from_proto(request) {
                Ok(values) => values,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };

        match with_instance(handle, |instance| {
            let (case, generation) = instance
                .analyzer
                .safety_cases()
                .account_case_by_id(&account_key, &case_id)
                .ok_or_else(|| "guardian report safety case was not found".to_string())?;
            if generation != expected_generation {
                return Err(format!(
                    "guardian report case generation mismatch: expected {}, actual {}",
                    expected_generation.value(),
                    generation.value()
                ));
            }
            if case.revision() != expected_case_revision {
                return Err(format!(
                    "guardian report case revision mismatch: expected {}, actual {}",
                    expected_case_revision,
                    case.revision()
                ));
            }

            let response = guardian_report_snapshot_to_proto(case, generation);
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Exports every pending or deferred guardian report in one account partition.
#[no_mangle]
pub unsafe extern "C" fn aura_export_guardian_report_account_snapshot(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::GuardianReportAccountSnapshotRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "guardian report account snapshot request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let account_key = match SafetyAccountKey::new(request.account_key) {
            Ok(account_key) => account_key,
            Err(error) => {
                set_last_error(error.to_string());
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let mut snapshots = instance
                .analyzer
                .safety_cases()
                .account_cases(&account_key)
                .filter(|(case, _)| {
                    case.pending_guardian_report().is_some()
                        || case.deferred_guardian_report().is_some()
                })
                .map(|(case, generation)| guardian_report_snapshot_to_proto(case, generation))
                .collect::<Vec<_>>();
            snapshots.sort_by(|left, right| left.case_id.cmp(&right.case_id));
            write_proto_message(
                out,
                &proto::GuardianReportAccountSnapshotResponse {
                    snapshots,
                    runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION
                        .to_string(),
                },
            )
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Flushes one exact deferred guardian report after its native eligibility
/// timestamp and returns the resulting guarded snapshot.
#[no_mangle]
pub unsafe extern "C" fn aura_flush_deferred_guardian_report(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::GuardianReportFlushRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "guardian report flush request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let (account_key, case_id, expected_generation, expected_case_revision, evaluated_at_ms) =
            match guardian_report_flush_request_from_proto(request) {
                Ok(values) => values,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };

        match with_instance(handle, |instance| {
            {
                let (case, generation) = instance
                    .analyzer
                    .safety_cases()
                    .account_case_by_id(&account_key, &case_id)
                    .ok_or_else(|| {
                        "deferred guardian report safety case was not found".to_string()
                    })?;
                if generation != expected_generation {
                    return Err(format!(
                        "guardian report flush generation mismatch: expected {}, actual {}",
                        expected_generation.value(),
                        generation.value()
                    ));
                }
                if case.revision() != expected_case_revision {
                    return Err(format!(
                        "guardian report flush revision mismatch: expected {}, actual {}",
                        expected_case_revision,
                        case.revision()
                    ));
                }
            }

            instance
                .analyzer
                .apply_safety_case_lifecycle_guarded(
                    &account_key,
                    &case_id,
                    SafetyCaseCommand::FlushDeferredGuardianReport {
                        at_ms: evaluated_at_ms,
                    },
                    |runtime| ensure_canonical_persistence_within_budget(runtime, &account_key),
                )
                .map_err(|error| error.to_string())?;
            let (case, generation) = instance
                .analyzer
                .safety_cases()
                .account_case_by_id(&account_key, &case_id)
                .ok_or_else(|| "flushed guardian report safety case was not found".to_string())?;
            let response = guardian_report_snapshot_to_proto(case, generation);
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Locks one exact native report against supersession after the host has
/// atomically persisted its complete encrypted recipient fanout.
#[no_mangle]
pub unsafe extern "C" fn aura_confirm_guardian_report_prepared(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::GuardianReportPreparationRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "guardian report preparation request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let (account_key, case_id, expected_generation, report_key, prepared_at_ms) =
            match guardian_report_preparation_request_from_proto(request) {
                Ok(values) => values,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };

        match with_instance(handle, |instance| {
            let already_prepared = {
                let (case, generation) = instance
                    .analyzer
                    .safety_cases()
                    .account_case_by_id(&account_key, &case_id)
                    .ok_or_else(|| {
                        "guardian report preparation safety case was not found".to_string()
                    })?;
                if generation != expected_generation {
                    return Err(format!(
                        "guardian report preparation generation mismatch: expected {}, actual {}",
                        expected_generation.value(),
                        generation.value()
                    ));
                }
                match case.guardian_report_preparation() {
                    Some(receipt) if receipt.key() == &report_key => {
                        if receipt.prepared_at_ms() != prepared_at_ms {
                            return Err(
                                "guardian report preparation timestamp equivocation".to_string()
                            );
                        }
                        true
                    }
                    Some(_) => {
                        return Err(
                            "guardian report preparation key does not match native state"
                                .to_string(),
                        );
                    }
                    None => false,
                }
            };

            let disposition = if already_prepared {
                proto::GuardianReportPreparationDisposition::AlreadyPrepared
            } else {
                instance
                    .analyzer
                    .apply_safety_case_lifecycle_guarded(
                        &account_key,
                        &case_id,
                        SafetyCaseCommand::ConfirmGuardianReportPrepared {
                            report_key: report_key.clone(),
                            prepared_at_ms,
                        },
                        |runtime| ensure_canonical_persistence_within_budget(runtime, &account_key),
                    )
                    .map_err(|error| error.to_string())?;
                proto::GuardianReportPreparationDisposition::Prepared
            };

            let (case, generation) = instance
                .analyzer
                .safety_cases()
                .account_case_by_id(&account_key, &case_id)
                .ok_or_else(|| "prepared guardian report safety case was not found".to_string())?;
            let preparation = case
                .guardian_report_preparation()
                .ok_or_else(|| "prepared guardian report receipt was not retained".to_string())?;
            if preparation.key() != &report_key || preparation.prepared_at_ms() != prepared_at_ms {
                return Err("prepared guardian report receipt mismatch".to_string());
            }
            write_proto_message(
                out,
                &proto::GuardianReportPreparationResponse {
                    disposition: disposition as i32,
                    case_id: case_id.to_string(),
                    case_generation: generation.value(),
                    case_revision: case.revision(),
                    case_status: proto_safety_case_status(case.status()) as i32,
                    report_transition_revision: report_key.transition_revision(),
                    prepared_at_ms,
                    runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION
                        .to_string(),
                },
            )
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Suppresses one exact unprepared native report after verified host policy
/// selected no safe recipient.
#[no_mangle]
pub unsafe extern "C" fn aura_suppress_guardian_report(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::GuardianReportSuppressionRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "guardian report suppression request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let (account_key, case_id, expected_generation, report_key, suppressed_at_ms, reason_code) =
            match guardian_report_suppression_request_from_proto(request) {
                Ok(values) => values,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };

        match with_instance(handle, |instance| {
            let already_suppressed = {
                let (case, generation) = instance
                    .analyzer
                    .safety_cases()
                    .account_case_by_id(&account_key, &case_id)
                    .ok_or_else(|| {
                        "guardian report suppression safety case was not found".to_string()
                    })?;
                if generation != expected_generation {
                    return Err(format!(
                        "guardian report suppression generation mismatch: expected {}, actual {}",
                        expected_generation.value(),
                        generation.value()
                    ));
                }
                match case.last_guardian_suppression() {
                    Some(receipt) if receipt.key() == &report_key => {
                        if receipt.suppressed_at_ms() != suppressed_at_ms
                            || receipt.reason_code() != &reason_code
                        {
                            return Err(
                                "guardian report suppression receipt equivocation".to_string()
                            );
                        }
                        true
                    }
                    _ => false,
                }
            };

            let disposition = if already_suppressed {
                proto::GuardianReportSuppressionDisposition::AlreadySuppressed
            } else {
                instance
                    .analyzer
                    .apply_safety_case_lifecycle_guarded(
                        &account_key,
                        &case_id,
                        SafetyCaseCommand::SuppressGuardianReport {
                            report_key: report_key.clone(),
                            suppressed_at_ms,
                            reason_code: reason_code.clone(),
                        },
                        |runtime| ensure_canonical_persistence_within_budget(runtime, &account_key),
                    )
                    .map_err(|error| error.to_string())?;
                proto::GuardianReportSuppressionDisposition::Suppressed
            };

            let (case, generation) = instance
                .analyzer
                .safety_cases()
                .account_case_by_id(&account_key, &case_id)
                .ok_or_else(|| {
                    "suppressed guardian report safety case was not found".to_string()
                })?;
            let suppression = case
                .last_guardian_suppression()
                .ok_or_else(|| "suppressed guardian report receipt was not retained".to_string())?;
            if suppression.key() != &report_key
                || suppression.suppressed_at_ms() != suppressed_at_ms
                || suppression.reason_code() != &reason_code
            {
                return Err("suppressed guardian report receipt mismatch".to_string());
            }
            write_proto_message(
                out,
                &proto::GuardianReportSuppressionResponse {
                    disposition: disposition as i32,
                    case_id: case_id.to_string(),
                    case_generation: generation.value(),
                    case_revision: case.revision(),
                    case_status: proto_safety_case_status(case.status()) as i32,
                    report_transition_revision: report_key.transition_revision(),
                    suppressed_at_ms,
                    reason_code: reason_code.to_string(),
                    runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION
                        .to_string(),
                },
            )
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Acknowledges one exact native guardian report after the complete recipient
/// fanout has authenticated durable-enqueue receipts.
#[no_mangle]
pub unsafe extern "C" fn aura_acknowledge_guardian_report(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }

        let request: proto::GuardianReportAcknowledgementRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "guardian report acknowledgement request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
        let (account_key, case_id, expected_generation, report_key, delivered_at_ms) =
            match guardian_report_acknowledgement_request_from_proto(request) {
                Ok(values) => values,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };

        match with_instance(handle, |instance| {
            let already_acknowledged = {
                let (case, generation) = instance
                    .analyzer
                    .safety_cases()
                    .account_case_by_id(&account_key, &case_id)
                    .ok_or_else(|| {
                        "guardian report acknowledgement safety case was not found".to_string()
                    })?;
                if generation != expected_generation {
                    return Err(format!(
                        "guardian report acknowledgement generation mismatch: expected {}, actual {}",
                        expected_generation.value(),
                        generation.value()
                    ));
                }
                match case.last_guardian_delivery() {
                    Some(receipt) if receipt.key() == &report_key => {
                        if receipt.delivered_at_ms() != delivered_at_ms {
                            return Err("guardian report acknowledgement timestamp equivocation"
                                .to_string());
                        }
                        true
                    }
                    _ => false,
                }
            };

            let disposition = if already_acknowledged {
                proto::GuardianReportAcknowledgementDisposition::AlreadyAcknowledged
            } else {
                instance
                    .analyzer
                    .apply_safety_case_lifecycle_guarded(
                        &account_key,
                        &case_id,
                        SafetyCaseCommand::AcknowledgeGuardianReport {
                            report_key: report_key.clone(),
                            delivered_at_ms,
                        },
                        |runtime| ensure_canonical_persistence_within_budget(runtime, &account_key),
                    )
                    .map_err(|error| error.to_string())?;
                proto::GuardianReportAcknowledgementDisposition::Acknowledged
            };

            let (case, generation) = instance
                .analyzer
                .safety_cases()
                .account_case_by_id(&account_key, &case_id)
                .ok_or_else(|| {
                    "acknowledged guardian report safety case was not found".to_string()
                })?;
            write_proto_message(
                out,
                &proto::GuardianReportAcknowledgementResponse {
                    disposition: disposition as i32,
                    case_id: case_id.to_string(),
                    case_generation: generation.value(),
                    case_revision: case.revision(),
                    case_status: proto_safety_case_status(case.status()) as i32,
                    report_transition_revision: report_key.transition_revision(),
                    delivered_at_ms,
                    runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION
                        .to_string(),
                },
            )
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Exports the current conversation context state as a protobuf-encoded buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_export_context(handle: *mut c_void, out: *mut AuraBuffer) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        match with_instance(handle, |instance| {
            let state = tracker_state_to_proto(
                &instance.analyzer.export_context_state(),
                &instance.analyzer.export_kids_memory_state(),
            );
            write_proto_message(out, &proto::ExportContextResponse { state: Some(state) })
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Exports versioned, content-free Safety Case state as UTF-8 JSON.
/// The host must encrypt these bytes per account before persistence.
#[no_mangle]
pub unsafe extern "C" fn aura_export_safety_case_state(
    handle: *mut c_void,
    account_key_ptr: *const u8,
    account_key_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        if let Err(error) = prepare_output(out) {
            set_last_error(error);
            return false;
        }
        let account_key =
            match unsafe { decode_safety_account_key(account_key_ptr, account_key_len) } {
                Ok(account_key) => account_key,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };

        match with_instance(handle, |instance| {
            let state = instance
                .analyzer
                .safety_cases()
                .export_account_state(&account_key);
            let bytes = serde_json::to_vec(&state)
                .map_err(|error| format!("failed to encode safety case state: {error}"))?;
            if bytes.len() > SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES {
                return Err(format!(
                    "safety case state exceeds limit of {SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES} bytes"
                ));
            }
            unsafe {
                *out = bytes_to_buffer(bytes);
            }
            Ok(())
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Imports encrypted-host-restored Safety Case JSON after bounded decoding and
/// deep runtime validation. Existing state is unchanged on failure.
#[no_mangle]
pub unsafe extern "C" fn aura_import_safety_case_state(
    handle: *mut c_void,
    account_key_ptr: *const u8,
    account_key_len: usize,
    state_ptr: *const u8,
    state_len: usize,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();
        let account_key =
            match unsafe { decode_safety_account_key(account_key_ptr, account_key_len) } {
                Ok(account_key) => account_key,
                Err(error) => {
                    set_last_error(error);
                    return false;
                }
            };
        if state_ptr.is_null() {
            set_last_error("null safety case state pointer");
            return false;
        }
        if state_len == 0 {
            set_last_error("safety case state is empty");
            return false;
        }
        if state_len > SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES {
            set_last_error(format!(
                "safety case state exceeds limit of {SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES} bytes"
            ));
            return false;
        }
        let bytes = unsafe { std::slice::from_raw_parts(state_ptr, state_len) };
        let state: ExportedSafetyCaseRuntimeState = match serde_json::from_slice(bytes) {
            Ok(state) => state,
            Err(error) => {
                set_last_error(format!("invalid safety case state JSON: {error}"));
                return false;
            }
        };

        match with_instance(handle, |instance| {
            instance
                .analyzer
                .safety_cases_mut()
                .import_account_state(&account_key, &state)
                .map_err(|error| error.to_string())
        }) {
            Ok(()) => true,
            Err(error) => {
                set_last_error(error);
                false
            }
        }
    })
}

/// Imports a previously exported conversation context state.
#[no_mangle]
pub unsafe extern "C" fn aura_import_context(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        let request: proto::ImportContextRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "import_context request",
            MAX_IMPORT_CONTEXT_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        let Some(state) = request.state else {
            set_last_error("missing state in import_context request");
            return false;
        };

        let state = match tracker_state_from_proto(state) {
            Ok(state) => state,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        let ImportTrackerState {
            core_state,
            kids_state,
        } = state;

        match with_instance(handle, |instance| {
            instance
                .analyzer
                .import_context_state(core_state)
                .map_err(|e| format!("import failed: {e}"))?;
            if let Some(kids_state) = kids_state {
                if !instance.analyzer.import_kids_memory_state(&kids_state) {
                    return Err("kids memory import failed".to_string());
                }
            } else {
                instance.analyzer.clear_kids_memory_state();
            }
            Ok(())
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Frees an AURA instance and all associated resources.
#[no_mangle]
pub unsafe extern "C" fn aura_free(handle: *mut c_void) {
    ffi_guard((), move || {
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut Mutex<AuraInstance>));
        }
    })
}

/// Frees a C string previously returned by the FFI layer.
#[no_mangle]
pub unsafe extern "C" fn aura_free_string(ptr: *mut c_char) {
    ffi_guard((), move || {
        if !ptr.is_null() {
            drop(CString::from_raw(ptr));
        }
    })
}

/// Frees an `AuraBuffer` previously returned by the FFI layer.
///
/// **Every `AuraBuffer` written by an FFI call must be freed exactly
/// once** via this function. Failing to free causes a memory leak;
/// double-freeing is undefined behaviour. The buffer becomes invalid
/// after this call — do not read `ptr` or `len` afterwards.
///
/// # C example
/// ```c
/// AuraBuffer out = {0};
/// if (aura_analyze_canonical_safety(handle, req, req_len, &out)) {
///     process(out.ptr, out.len);
///     aura_free_buffer(out);   // mandatory
/// }
/// ```
///
/// # Swift example
/// ```swift
/// var out = AuraBuffer()
/// if aura_analyze_canonical_safety(handle, req, reqLen, &out) {
///     let data = Data(bytes: out.ptr, count: out.len)
///     aura_free_buffer(out)   // mandatory
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn aura_free_buffer(buf: AuraBuffer) {
    ffi_guard((), move || {
        if !buf.ptr.is_null() && buf.len > 0 {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                buf.ptr, buf.len,
            )));
        }
    })
}

/// Returns a pointer to the null-terminated version string of the AURA library.
///
/// Exported as `aura_agent_version` to avoid colliding with
/// aura-protected-protocol's `aura_version` (both linked into the iOS app).
#[export_name = "aura_agent_version"]
pub extern "C" fn aura_version() -> *const c_char {
    ffi_guard(std::ptr::null(), move || {
        static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
        VERSION.as_ptr() as *const c_char
    })
}

/// Returns the last error message as a C string, or null if no error occurred.
#[no_mangle]
pub extern "C" fn aura_last_error() -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), move || {
        // Prefer the thread-local (correct per-thread semantics); fall back to
        // the process-global mirror when the thread-local read comes back empty
        // (see LAST_ERROR_GLOBAL) so a real error is never reported as null.
        let local_message = LAST_ERROR.with(|error| error.borrow().clone());
        let message = match local_message {
            Some(message) => {
                if let Ok(mut guard) = LAST_ERROR_GLOBAL.lock() {
                    if guard.as_deref() == Some(message.as_str()) {
                        *guard = None;
                    }
                }
                Some(message)
            }
            None => LAST_ERROR_GLOBAL
                .lock()
                .ok()
                .and_then(|mut guard| guard.take()),
        };
        match message {
            Some(msg) => string_to_c(msg),
            None => std::ptr::null_mut(),
        }
    })
}

fn string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn load_pattern_db(config: &AuraConfig) -> PatternDatabase {
    if let Some(ref path) = config.patterns_path {
        match try_load_pattern_db(path) {
            Ok(db) => db,
            Err(error) => {
                warn!(
                    patterns_path = %path,
                    error = %error,
                    "falling back to built-in MVP patterns during init"
                );
                PatternDatabase::default_mvp()
            }
        }
    } else {
        PatternDatabase::default_mvp()
    }
}

fn try_load_pattern_db(path: &str) -> Result<PatternDatabase, String> {
    PatternDatabase::from_file(path).map_err(|error| error.to_string())
}

fn aura_config_from_proto(config: proto::AuraConfig) -> Result<AuraConfig, String> {
    let account_holder_age = match config.account_holder_age {
        Some(age) if age > u16::MAX as u32 => {
            return Err(format!("account_holder_age {age} exceeds u16 range"));
        }
        Some(age) => Some(age as u16),
        None => None,
    };

    if config.language.trim().is_empty() {
        return Err("language must not be empty".to_string());
    }

    let aura_config = AuraConfig {
        protection_level: protection_level_from_proto(config.protection_level)?,
        account_type: account_type_from_proto(config.account_type)?,
        language: config.language,
        cultural_context: cultural_context_from_proto(config.cultural_context)?,
        enabled: config.enabled,
        patterns_path: config.patterns_path,
        models_path: config.models_path,
        account_holder_age,
        ttl_days: config.ttl_days,
        timezone_offset_minutes: config.timezone_offset_minutes,
        protected_account_id: None,
        // Domain mode is the only account-level selector.
        domain_mode: domain_mode_from_proto(config.domain_mode)?,
        product_rollout_mode: product_rollout_mode_from_proto(config.product_rollout_mode)?,
    };
    aura_config.validate().map_err(|error| error.to_string())?;
    Ok(aura_config)
}

fn decoded_config_from_proto(config: proto::AuraConfig) -> Result<DecodedConfig, String> {
    Ok(DecodedConfig {
        aura_config: aura_config_from_proto(config)?,
    })
}

fn message_input_from_proto(message: proto::MessageInput) -> MessageInput {
    MessageInput {
        content_type: content_type_from_proto(message.content_type),
        text: message.text,
        image_data: message.image_data,
        sender_id: aura_agent_core::SenderId::from(non_empty_or(message.sender_id, "unknown")),
        conversation_id: aura_agent_core::ConversationId::from(non_empty_or(
            message.conversation_id,
            "unknown",
        )),
        language: message.language,
        conversation_type: conversation_type_from_proto(message.conversation_type),
        member_count: message.member_count,
        sender_relationship: sender_relationship_from_proto(message.sender_relationship),
        relationship_trust_source: relationship_trust_source_from_proto(
            message.relationship_trust_source,
        ),
    }
}

fn non_empty_or(value: String, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value
    }
}

fn tracker_state_to_proto(
    state: &CoreTrackerWireState,
    kids: &aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState,
) -> proto::TrackerState {
    proto::TrackerState {
        schema_version: state.schema_version,
        timelines: state
            .timelines
            .iter()
            .map(conversation_timeline_state_to_proto)
            .collect(),
        contact_profiler: Some(contact_profiler_state_to_proto(&state.contact_profiler)),
        kids_memory: if kids.conversations.is_empty() && kids.senders.is_empty() {
            None
        } else {
            Some(kids_memory_state_to_proto(kids))
        },
    }
}

struct ImportTrackerState {
    core_state: CoreTrackerWireState,
    kids_state: Option<aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState>,
}

fn tracker_state_from_proto(state: proto::TrackerState) -> Result<ImportTrackerState, String> {
    let kids_state = state
        .kids_memory
        .as_ref()
        .map(kids_memory_state_from_proto)
        .transpose()?;
    Ok(ImportTrackerState {
        core_state: CoreTrackerWireState {
            schema_version: state.schema_version,
            timelines: state
                .timelines
                .into_iter()
                .map(conversation_timeline_state_from_proto)
                .collect::<Result<Vec<_>, _>>()?,
            contact_profiler: match state.contact_profiler {
                Some(state) => contact_profiler_state_from_proto(state)?,
                None => CoreContactProfilerWireState {
                    profiles: Vec::new(),
                },
            },
        },
        kids_state,
    })
}

fn kids_memory_state_to_proto(
    state: &aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState,
) -> proto::KidsMemoryState {
    proto::KidsMemoryState {
        schema_version: state.schema_version,
        conversations: state
            .conversations
            .iter()
            .map(|conv| proto::KidsConversationMemoryState {
                conversation_id: conv.conversation_id.clone(),
                message_index: conv.message_index,
                last_activity_index: Some(conv.last_activity_index),
                last_emitted: conv
                    .last_emitted
                    .iter()
                    .map(|checkpoint| proto::KidsEmissionCheckpoint {
                        reason_code: checkpoint.reason_code.clone(),
                        emitted_at_index: checkpoint.emitted_at_index,
                    })
                    .collect(),
                entries: conv
                    .entries
                    .iter()
                    .map(|snap| proto::KidsMessageRiskSnapshot {
                        sender_id: snap.sender_id.clone(),
                        has_grooming: snap.has_grooming,
                        has_manipulation: snap.has_manipulation,
                        has_bullying: snap.has_bullying,
                        has_self_harm: snap.has_self_harm,
                        has_blackmail_or_sextortion: snap.has_blackmail_or_sextortion,
                        ml_grooming: snap.ml_grooming,
                        ml_bullying: snap.ml_bullying,
                        ml_self_harm: snap.ml_self_harm,
                        ml_manipulation: snap.ml_manipulation,
                    })
                    .collect(),
            })
            .collect(),
        senders: state
            .senders
            .iter()
            .map(|sender| proto::KidsSenderMemoryState {
                sender_id: sender.sender_id.clone(),
                event_index: sender.event_index,
                recent_high_risk_conversations: sender.recent_high_risk_conversations.clone(),
                last_activity_index: Some(sender.last_activity_index),
                last_emitted: sender
                    .last_emitted
                    .iter()
                    .map(|checkpoint| proto::KidsEmissionCheckpoint {
                        reason_code: checkpoint.reason_code.clone(),
                        emitted_at_index: checkpoint.emitted_at_index,
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn kids_memory_state_from_proto(
    state: &proto::KidsMemoryState,
) -> Result<aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState, String> {
    use aura_agent_core::aura_kids::pipeline::{
        ExportedConversationMemory, ExportedEmissionCheckpoint, ExportedKidsMemoryState,
        ExportedMessageSnapshot, ExportedSenderMemory, KIDS_MEMORY_STATE_VERSION,
    };

    if state.schema_version != KIDS_MEMORY_STATE_VERSION {
        return Err(format!(
            "incompatible kids memory state version: found {}, supported {}",
            state.schema_version, KIDS_MEMORY_STATE_VERSION
        ));
    }

    Ok(ExportedKidsMemoryState {
        schema_version: KIDS_MEMORY_STATE_VERSION,
        conversations: state
            .conversations
            .iter()
            .map(|conv| {
                let last_activity_index = conv
                    .last_activity_index
                    .ok_or_else(|| "kids conversation activity index is required".to_string())?;
                Ok(ExportedConversationMemory {
                    conversation_id: conv.conversation_id.clone(),
                    message_index: conv.message_index,
                    last_activity_index,
                    last_emitted: conv
                        .last_emitted
                        .iter()
                        .map(|checkpoint| ExportedEmissionCheckpoint {
                            reason_code: checkpoint.reason_code.clone(),
                            emitted_at_index: checkpoint.emitted_at_index,
                        })
                        .collect(),
                    entries: conv
                        .entries
                        .iter()
                        .map(|snap| ExportedMessageSnapshot {
                            sender_id: snap.sender_id.clone(),
                            has_grooming: snap.has_grooming,
                            has_manipulation: snap.has_manipulation,
                            has_bullying: snap.has_bullying,
                            has_self_harm: snap.has_self_harm,
                            has_blackmail_or_sextortion: snap.has_blackmail_or_sextortion,
                            ml_grooming: snap.ml_grooming,
                            ml_bullying: snap.ml_bullying,
                            ml_self_harm: snap.ml_self_harm,
                            ml_manipulation: snap.ml_manipulation,
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        senders: state
            .senders
            .iter()
            .map(|sender| {
                let last_activity_index = sender
                    .last_activity_index
                    .ok_or_else(|| "kids sender activity index is required".to_string())?;
                Ok(ExportedSenderMemory {
                    sender_id: sender.sender_id.clone(),
                    event_index: sender.event_index,
                    last_activity_index,
                    last_emitted: sender
                        .last_emitted
                        .iter()
                        .map(|checkpoint| ExportedEmissionCheckpoint {
                            reason_code: checkpoint.reason_code.clone(),
                            emitted_at_index: checkpoint.emitted_at_index,
                        })
                        .collect(),
                    recent_high_risk_conversations: sender.recent_high_risk_conversations.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

fn conversation_timeline_state_to_proto(
    state: &CoreConversationTimelineState,
) -> proto::ConversationTimelineState {
    proto::ConversationTimelineState {
        conversation_id: state.conversation_id.to_string(),
        conversation_type: proto_conversation_type(state.conversation_type) as i32,
        events: state.events.iter().map(context_event_to_proto).collect(),
    }
}

fn conversation_timeline_state_from_proto(
    state: proto::ConversationTimelineState,
) -> Result<CoreConversationTimelineState, String> {
    Ok(CoreConversationTimelineState {
        conversation_id: aura_agent_core::ConversationId::from(state.conversation_id),
        conversation_type: conversation_type_from_proto(state.conversation_type),
        events: state
            .events
            .into_iter()
            .map(context_event_from_proto)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn context_event_to_proto(event: &CoreContextEvent) -> proto::ContextEvent {
    proto::ContextEvent {
        event_id: event.event_id,
        timestamp_ms: event.timestamp_ms,
        sender_id: event.sender_id.to_string(),
        conversation_id: event.conversation_id.to_string(),
        kind: proto_event_kind(event.kind.clone()) as i32,
        confidence: event.confidence,
        subtype: event.subtype.clone().unwrap_or_default(),
        content_hash: event.content_hash,
    }
}

fn context_event_from_proto(event: proto::ContextEvent) -> Result<CoreContextEvent, String> {
    Ok(CoreContextEvent {
        event_id: event.event_id,
        timestamp_ms: event.timestamp_ms,
        sender_id: aura_agent_core::SenderId::from(event.sender_id),
        conversation_id: aura_agent_core::ConversationId::from(event.conversation_id),
        kind: event_kind_from_proto(event.kind)?,
        confidence: event.confidence,
        subtype: if event.subtype.is_empty() {
            None
        } else {
            Some(event.subtype)
        },
        content_hash: event.content_hash,
        context: CoreEventContextFrame::default(),
    })
}

fn contact_profiler_state_to_proto(
    state: &CoreContactProfilerWireState,
) -> proto::ContactProfilerState {
    proto::ContactProfilerState {
        profiles: state
            .profiles
            .iter()
            .map(contact_profile_state_to_proto)
            .collect(),
    }
}

fn contact_profiler_state_from_proto(
    state: proto::ContactProfilerState,
) -> Result<CoreContactProfilerWireState, String> {
    Ok(CoreContactProfilerWireState {
        profiles: state
            .profiles
            .into_iter()
            .map(contact_profile_state_from_proto)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn contact_profile_state_to_proto(state: &CoreContactProfileState) -> proto::ContactProfileState {
    let mut narrative_hits = Vec::with_capacity(state.narrative_hits.len());
    for (narrative_id, count) in &state.narrative_hits {
        narrative_hits.push(proto::NarrativeHit {
            narrative_id: u32::from(*narrative_id),
            count: *count,
        });
    }

    let mut hourly_activity = Vec::with_capacity(state.hourly_activity.len());
    for count in state.hourly_activity {
        hourly_activity.push(u32::from(count));
    }

    let mut message_fingerprints = Vec::with_capacity(state.message_fingerprints.len());
    for fingerprint in &state.message_fingerprints {
        message_fingerprints.push(*fingerprint);
    }

    let mut narrative_timeline = Vec::with_capacity(state.narrative_timeline.len());
    for (timestamp_ms, narrative_id) in &state.narrative_timeline {
        narrative_timeline.push(proto::NarrativeTimelineEntry {
            timestamp_ms: *timestamp_ms,
            narrative_id: u32::from(*narrative_id),
        });
    }

    let mut weekly_propaganda_counts = Vec::with_capacity(state.weekly_propaganda_counts.len());
    for (week_start_ms, count) in &state.weekly_propaganda_counts {
        weekly_propaganda_counts.push(proto::WeeklyPropagandaCount {
            week_start_ms: *week_start_ms,
            count: u32::from(*count),
        });
    }

    let mut propaganda_conversations = Vec::with_capacity(state.propaganda_conversations.len());
    for conversation_id in &state.propaganda_conversations {
        propaganda_conversations.push(conversation_id.to_string());
    }

    proto::ContactProfileState {
        sender_id: state.sender_id.to_string(),
        first_seen_ms: state.first_seen_ms,
        last_seen_ms: state.last_seen_ms,
        total_messages: state.total_messages,
        conversation_count: state.conversation_count as u64,
        conversations: state.conversations.iter().map(|c| c.to_string()).collect(),
        grooming_event_count: state.grooming_event_count,
        bullying_event_count: state.bullying_event_count,
        manipulation_event_count: state.manipulation_event_count,
        is_trusted: state.is_trusted,
        severity_sum: state.severity_sum,
        severity_count: state.severity_count,
        inferred_age: state.inferred_age.map(u32::from),
        rating: state.rating,
        trust_level: state.trust_level,
        circle_tier: proto_circle_tier(state.circle_tier) as i32,
        trend: proto_behavioral_trend(state.trend) as i32,
        weekly_snapshots: state
            .weekly_snapshots
            .iter()
            .map(behavioral_snapshot_state_to_proto)
            .collect(),
        current_snapshot: state
            .current_snapshot
            .as_ref()
            .map(behavioral_snapshot_state_to_proto),
        active_days: state.active_days.clone(),
        propaganda_event_count: state.propaganda_event_count,
        propaganda_source_count: state.propaganda_source_count,
        narrative_hits,
        propaganda_score: state.propaganda_score,
        narrative_diversity: u32::from(state.narrative_diversity),
        first_propaganda_ms: state.first_propaganda_ms,
        last_propaganda_ms: state.last_propaganda_ms,
        propaganda_conversations,
        hourly_activity,
        message_fingerprints,
        narrative_timeline,
        weekly_propaganda_counts,
        age_source: proto_age_source(state.age_source) as i32,
        child_safety: Some(child_safety_trajectory_to_proto(&state.child_safety)),
    }
}

fn contact_profile_state_from_proto(
    state: proto::ContactProfileState,
) -> Result<CoreContactProfileState, String> {
    let inferred_age = match state.inferred_age {
        Some(age) if age > u16::MAX as u32 => {
            return Err(format!("inferred_age {age} exceeds u16 range"));
        }
        Some(age) => Some(age as u16),
        None => None,
    };

    let mut narrative_hits = Vec::with_capacity(state.narrative_hits.len());
    for entry in state.narrative_hits {
        if entry.narrative_id > u8::MAX as u32 {
            return Err(format!(
                "narrative_id {} exceeds u8 range",
                entry.narrative_id
            ));
        }
        narrative_hits.push((entry.narrative_id as u8, entry.count));
    }

    if state.narrative_diversity > u8::MAX as u32 {
        return Err(format!(
            "narrative_diversity {} exceeds u8 range",
            state.narrative_diversity
        ));
    }

    let mut hourly_activity = [0u16; 24];
    let hourly_len = state.hourly_activity.len().min(24);
    for (idx, count) in state.hourly_activity.iter().take(hourly_len).enumerate() {
        if *count > u16::MAX as u32 {
            return Err(format!("hourly_activity[{idx}]={count} exceeds u16 range"));
        }
        hourly_activity[idx] = *count as u16;
    }

    let mut narrative_timeline =
        std::collections::VecDeque::with_capacity(state.narrative_timeline.len());
    for entry in state.narrative_timeline {
        if entry.narrative_id > u8::MAX as u32 {
            return Err(format!(
                "narrative_timeline narrative_id {} exceeds u8 range",
                entry.narrative_id
            ));
        }
        narrative_timeline.push_back((entry.timestamp_ms, entry.narrative_id as u8));
    }

    let mut weekly_propaganda_counts =
        std::collections::VecDeque::with_capacity(state.weekly_propaganda_counts.len());
    for entry in state.weekly_propaganda_counts {
        if entry.count > u16::MAX as u32 {
            return Err(format!(
                "weekly_propaganda_counts count {} exceeds u16 range",
                entry.count
            ));
        }
        weekly_propaganda_counts.push_back((entry.week_start_ms, entry.count as u16));
    }

    let mut propaganda_conversations = Vec::with_capacity(state.propaganda_conversations.len());
    for conversation_id in state.propaganda_conversations {
        propaganda_conversations.push(aura_agent_core::ConversationId::from(conversation_id));
    }

    let child_safety = child_safety_trajectory_from_proto(state.child_safety)?;

    Ok(CoreContactProfileState {
        sender_id: aura_agent_core::SenderId::from(state.sender_id),
        first_seen_ms: state.first_seen_ms,
        last_seen_ms: state.last_seen_ms,
        total_messages: state.total_messages,
        conversation_count: state.conversation_count as usize,
        conversations: state
            .conversations
            .into_iter()
            .map(aura_agent_core::ConversationId::from)
            .collect(),
        grooming_event_count: state.grooming_event_count,
        bullying_event_count: state.bullying_event_count,
        manipulation_event_count: state.manipulation_event_count,
        propaganda_event_count: state.propaganda_event_count,
        propaganda_source_count: state.propaganda_source_count,
        narrative_hits,
        propaganda_score: state.propaganda_score,
        narrative_diversity: state.narrative_diversity as u8,
        first_propaganda_ms: state.first_propaganda_ms,
        last_propaganda_ms: state.last_propaganda_ms,
        propaganda_conversations,
        hourly_activity,
        message_fingerprints: std::collections::VecDeque::from(state.message_fingerprints),
        narrative_timeline,
        weekly_propaganda_counts,
        is_trusted: state.is_trusted,
        severity_sum: state.severity_sum,
        severity_count: state.severity_count,
        inferred_age,
        age_source: age_source_from_proto(state.age_source),
        child_safety,
        rating: state.rating,
        trust_level: state.trust_level,
        circle_tier: circle_tier_from_proto(state.circle_tier),
        trend: behavioral_trend_from_proto(state.trend),
        weekly_snapshots: state
            .weekly_snapshots
            .into_iter()
            .map(behavioral_snapshot_state_from_proto)
            .collect(),
        current_snapshot: state
            .current_snapshot
            .map(behavioral_snapshot_state_from_proto),
        active_days: state.active_days,
    })
}

fn child_safety_trajectory_to_proto(
    state: &CoreChildSafetyTrajectory,
) -> proto::ChildSafetyTrajectoryState {
    proto::ChildSafetyTrajectoryState {
        first_grooming_ms: state.first_grooming_ms,
        last_grooming_ms: state.last_grooming_ms,
        grooming_stage_mask: u32::from(state.grooming_stage_mask),
        grooming_event_count: u32::from(state.grooming_event_count),
        high_risk_event_count: u32::from(state.high_risk_event_count),
        rapid_escalation_ms: state.rapid_escalation_ms,
    }
}

fn child_safety_trajectory_from_proto(
    state: Option<proto::ChildSafetyTrajectoryState>,
) -> Result<CoreChildSafetyTrajectory, String> {
    let Some(state) = state else {
        return Ok(CoreChildSafetyTrajectory::default());
    };

    if state.grooming_stage_mask > u8::MAX as u32 {
        return Err(format!(
            "child_safety.grooming_stage_mask {} exceeds u8 range",
            state.grooming_stage_mask
        ));
    }
    if state.grooming_event_count > u16::MAX as u32 {
        return Err(format!(
            "child_safety.grooming_event_count {} exceeds u16 range",
            state.grooming_event_count
        ));
    }
    if state.high_risk_event_count > u16::MAX as u32 {
        return Err(format!(
            "child_safety.high_risk_event_count {} exceeds u16 range",
            state.high_risk_event_count
        ));
    }

    Ok(CoreChildSafetyTrajectory {
        first_grooming_ms: state.first_grooming_ms,
        last_grooming_ms: state.last_grooming_ms,
        grooming_stage_mask: state.grooming_stage_mask as u8,
        grooming_event_count: state.grooming_event_count as u16,
        high_risk_event_count: state.high_risk_event_count as u16,
        rapid_escalation_ms: state.rapid_escalation_ms,
    })
}

fn behavioral_snapshot_state_to_proto(
    state: &CoreBehavioralSnapshotState,
) -> proto::BehavioralSnapshotState {
    proto::BehavioralSnapshotState {
        period_start_ms: state.period_start_ms,
        period_end_ms: state.period_end_ms,
        total_messages: state.total_messages,
        hostile_count: state.hostile_count,
        supportive_count: state.supportive_count,
        neutral_count: state.neutral_count,
        grooming_count: state.grooming_count,
        manipulation_count: state.manipulation_count,
        avg_severity: state.avg_severity,
        propaganda_count: state.propaganda_count,
    }
}

fn behavioral_snapshot_state_from_proto(
    state: proto::BehavioralSnapshotState,
) -> CoreBehavioralSnapshotState {
    CoreBehavioralSnapshotState {
        period_start_ms: state.period_start_ms,
        period_end_ms: state.period_end_ms,
        total_messages: state.total_messages,
        hostile_count: state.hostile_count,
        supportive_count: state.supportive_count,
        neutral_count: state.neutral_count,
        grooming_count: state.grooming_count,
        manipulation_count: state.manipulation_count,
        propaganda_count: state.propaganda_count,
        avg_severity: state.avg_severity,
    }
}

fn protection_level_from_proto(value: i32) -> Result<aura_agent_core::ProtectionLevel, String> {
    match proto::ProtectionLevel::try_from(value) {
        Ok(proto::ProtectionLevel::Off) => Ok(aura_agent_core::ProtectionLevel::Off),
        Ok(proto::ProtectionLevel::Low) => Ok(aura_agent_core::ProtectionLevel::Low),
        Ok(proto::ProtectionLevel::Medium) => Ok(aura_agent_core::ProtectionLevel::Medium),
        Ok(proto::ProtectionLevel::High) => Ok(aura_agent_core::ProtectionLevel::High),
        Ok(proto::ProtectionLevel::Unspecified) => {
            Err("protection_level must be explicit".to_string())
        }
        Err(_) => Err(format!("unsupported protection_level value {value}")),
    }
}

fn account_type_from_proto(value: i32) -> Result<aura_agent_core::AccountType, String> {
    match proto::AccountType::try_from(value) {
        Ok(proto::AccountType::Adult) => Ok(aura_agent_core::AccountType::Adult),
        Ok(proto::AccountType::Teen) => Ok(aura_agent_core::AccountType::Teen),
        Ok(proto::AccountType::Child) => Ok(aura_agent_core::AccountType::Child),
        Ok(proto::AccountType::Unspecified) => Err("account_type must be explicit".to_string()),
        Err(_) => Err(format!("unsupported account_type value {value}")),
    }
}

fn domain_mode_from_proto(value: i32) -> Result<aura_agent_core::DomainMode, String> {
    match proto::DomainMode::try_from(value) {
        Ok(proto::DomainMode::None) => Ok(aura_agent_core::DomainMode::None),
        Ok(proto::DomainMode::Kids) => Ok(aura_agent_core::DomainMode::Kids),
        Ok(proto::DomainMode::Military) => Ok(aura_agent_core::DomainMode::Military),
        Ok(proto::DomainMode::Unspecified) => Err("domain_mode must be explicit".to_string()),
        Err(_) => Err(format!("unsupported domain_mode value {value}")),
    }
}

fn cultural_context_from_proto(
    context: Option<proto::CulturalContext>,
) -> Result<CulturalContext, String> {
    let context = context.ok_or_else(|| "cultural_context must be present".to_string())?;

    match proto::CulturalContextKind::try_from(context.kind) {
        Ok(proto::CulturalContextKind::Ukrainian) => Ok(CulturalContext::Ukrainian),
        Ok(proto::CulturalContextKind::Russian) => Ok(CulturalContext::Russian),
        Ok(proto::CulturalContextKind::English) => Ok(CulturalContext::English),
        Ok(proto::CulturalContextKind::Custom) => {
            let value = context
                .custom_value
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    "custom cultural_context requires a non-empty custom_value".to_string()
                })?;
            Ok(CulturalContext::Custom(value))
        }
        Ok(proto::CulturalContextKind::Unspecified) => {
            Err("cultural_context kind must be explicit".to_string())
        }
        Err(_) => Err(format!(
            "unsupported cultural_context kind value {}",
            context.kind
        )),
    }
}

fn content_type_from_proto(value: i32) -> aura_agent_core::ContentType {
    match proto::ContentType::try_from(value).unwrap_or(proto::ContentType::Text) {
        proto::ContentType::Image => aura_agent_core::ContentType::Image,
        proto::ContentType::Voice => aura_agent_core::ContentType::Voice,
        proto::ContentType::Video => aura_agent_core::ContentType::Video,
        proto::ContentType::Url => aura_agent_core::ContentType::Url,
        _ => aura_agent_core::ContentType::Text,
    }
}

fn conversation_type_from_proto(value: i32) -> aura_agent_core::ConversationType {
    match proto::ConversationType::try_from(value).unwrap_or(proto::ConversationType::Direct) {
        proto::ConversationType::Group => aura_agent_core::ConversationType::Group,
        _ => aura_agent_core::ConversationType::Direct,
    }
}

fn proto_conversation_type(value: aura_agent_core::ConversationType) -> proto::ConversationType {
    match value {
        aura_agent_core::ConversationType::Direct => proto::ConversationType::Direct,
        aura_agent_core::ConversationType::Group => proto::ConversationType::Group,
    }
}

fn sender_relationship_from_proto(value: i32) -> SenderRelationship {
    match proto::SenderRelationship::try_from(value)
        .unwrap_or(proto::SenderRelationship::Unspecified)
    {
        proto::SenderRelationship::Parent => SenderRelationship::Parent,
        proto::SenderRelationship::Guardian => SenderRelationship::Guardian,
        proto::SenderRelationship::Family => SenderRelationship::Family,
        proto::SenderRelationship::Sibling => SenderRelationship::Sibling,
        proto::SenderRelationship::Peer => SenderRelationship::Peer,
        proto::SenderRelationship::Teacher => SenderRelationship::Teacher,
        proto::SenderRelationship::Coach => SenderRelationship::Coach,
        proto::SenderRelationship::Authority => SenderRelationship::Authority,
        proto::SenderRelationship::Service => SenderRelationship::Service,
        proto::SenderRelationship::UnknownAdult => SenderRelationship::UnknownAdult,
        proto::SenderRelationship::UnknownPeer => SenderRelationship::UnknownPeer,
        proto::SenderRelationship::Unspecified | proto::SenderRelationship::Unknown => {
            SenderRelationship::Unknown
        }
    }
}

fn relationship_trust_source_from_proto(value: i32) -> RelationshipTrustSource {
    match proto::RelationshipTrustSource::try_from(value)
        .unwrap_or(proto::RelationshipTrustSource::Unspecified)
    {
        proto::RelationshipTrustSource::UserVerified => RelationshipTrustSource::UserVerified,
        proto::RelationshipTrustSource::GuardianVerified => {
            RelationshipTrustSource::GuardianVerified
        }
        proto::RelationshipTrustSource::PlatformVerified => {
            RelationshipTrustSource::PlatformVerified
        }
        proto::RelationshipTrustSource::AddressBook => RelationshipTrustSource::AddressBook,
        proto::RelationshipTrustSource::SchoolDirectory => RelationshipTrustSource::SchoolDirectory,
        proto::RelationshipTrustSource::ServerReputation => {
            RelationshipTrustSource::ServerReputation
        }
        proto::RelationshipTrustSource::LocalHeuristic => RelationshipTrustSource::LocalHeuristic,
        proto::RelationshipTrustSource::SelfDeclared => RelationshipTrustSource::SelfDeclared,
        proto::RelationshipTrustSource::Unspecified | proto::RelationshipTrustSource::Unknown => {
            RelationshipTrustSource::Unknown
        }
    }
}

fn product_rollout_mode_from_proto(
    value: i32,
) -> Result<aura_agent_core::ProductRolloutMode, String> {
    match proto::ProductRolloutMode::try_from(value) {
        Ok(proto::ProductRolloutMode::Shadow) => Ok(aura_agent_core::ProductRolloutMode::Shadow),
        Ok(proto::ProductRolloutMode::StagingPilot) => {
            Ok(aura_agent_core::ProductRolloutMode::StagingPilot)
        }
        Ok(proto::ProductRolloutMode::GuardianEnabled) => {
            Ok(aura_agent_core::ProductRolloutMode::GuardianEnabled)
        }
        Ok(proto::ProductRolloutMode::Unspecified) => {
            Err("product_rollout_mode must be explicit".to_string())
        }
        Err(_) => Err(format!("unsupported product_rollout_mode value {value}")),
    }
}

fn circle_tier_from_proto(value: i32) -> aura_agent_core::CircleTier {
    match proto::CircleTier::try_from(value).unwrap_or(proto::CircleTier::New) {
        proto::CircleTier::Inner => aura_agent_core::CircleTier::Inner,
        proto::CircleTier::Regular => aura_agent_core::CircleTier::Regular,
        proto::CircleTier::Occasional => aura_agent_core::CircleTier::Occasional,
        _ => aura_agent_core::CircleTier::New,
    }
}

fn proto_circle_tier(value: aura_agent_core::CircleTier) -> proto::CircleTier {
    match value {
        aura_agent_core::CircleTier::Inner => proto::CircleTier::Inner,
        aura_agent_core::CircleTier::Regular => proto::CircleTier::Regular,
        aura_agent_core::CircleTier::Occasional => proto::CircleTier::Occasional,
        aura_agent_core::CircleTier::New => proto::CircleTier::New,
    }
}

fn behavioral_trend_from_proto(value: i32) -> aura_agent_core::BehavioralTrend {
    match proto::BehavioralTrend::try_from(value).unwrap_or(proto::BehavioralTrend::Stable) {
        proto::BehavioralTrend::Improving => aura_agent_core::BehavioralTrend::Improving,
        proto::BehavioralTrend::GradualWorsening => {
            aura_agent_core::BehavioralTrend::GradualWorsening
        }
        proto::BehavioralTrend::RapidWorsening => aura_agent_core::BehavioralTrend::RapidWorsening,
        proto::BehavioralTrend::RoleReversal => aura_agent_core::BehavioralTrend::RoleReversal,
        _ => aura_agent_core::BehavioralTrend::Stable,
    }
}

fn proto_behavioral_trend(value: aura_agent_core::BehavioralTrend) -> proto::BehavioralTrend {
    match value {
        aura_agent_core::BehavioralTrend::Stable => proto::BehavioralTrend::Stable,
        aura_agent_core::BehavioralTrend::Improving => proto::BehavioralTrend::Improving,
        aura_agent_core::BehavioralTrend::GradualWorsening => {
            proto::BehavioralTrend::GradualWorsening
        }
        aura_agent_core::BehavioralTrend::RapidWorsening => proto::BehavioralTrend::RapidWorsening,
        aura_agent_core::BehavioralTrend::RoleReversal => proto::BehavioralTrend::RoleReversal,
    }
}

fn age_source_from_proto(value: i32) -> CoreAgeSource {
    match proto::AgeSource::try_from(value).unwrap_or(proto::AgeSource::UserReported) {
        proto::AgeSource::ParentVerified => CoreAgeSource::ParentVerified,
        proto::AgeSource::MlInferred => CoreAgeSource::MlInferred,
        _ => CoreAgeSource::UserReported,
    }
}

fn proto_age_source(value: CoreAgeSource) -> proto::AgeSource {
    match value {
        CoreAgeSource::ParentVerified => proto::AgeSource::ParentVerified,
        CoreAgeSource::UserReported => proto::AgeSource::UserReported,
        CoreAgeSource::MlInferred => proto::AgeSource::MlInferred,
    }
}

fn event_kind_from_proto(value: i32) -> Result<CoreEventKind, String> {
    let kind = proto::EventKind::try_from(value).unwrap_or(proto::EventKind::Unspecified);
    match kind {
        proto::EventKind::Flattery => Ok(CoreEventKind::Flattery),
        proto::EventKind::GiftOffer => Ok(CoreEventKind::GiftOffer),
        proto::EventKind::SecrecyRequest => Ok(CoreEventKind::SecrecyRequest),
        proto::EventKind::PlatformSwitch => Ok(CoreEventKind::PlatformSwitch),
        proto::EventKind::PersonalInfoRequest => Ok(CoreEventKind::PersonalInfoRequest),
        proto::EventKind::PhotoRequest => Ok(CoreEventKind::PhotoRequest),
        proto::EventKind::VideoCallRequest => Ok(CoreEventKind::VideoCallRequest),
        proto::EventKind::FinancialGrooming => Ok(CoreEventKind::FinancialGrooming),
        proto::EventKind::MeetingRequest => Ok(CoreEventKind::MeetingRequest),
        proto::EventKind::SexualContent => Ok(CoreEventKind::SexualContent),
        proto::EventKind::AgeInappropriate => Ok(CoreEventKind::AgeInappropriate),
        proto::EventKind::Insult => Ok(CoreEventKind::Insult),
        proto::EventKind::Denigration => Ok(CoreEventKind::Denigration),
        proto::EventKind::HarmEncouragement => Ok(CoreEventKind::HarmEncouragement),
        proto::EventKind::PhysicalThreat => Ok(CoreEventKind::PhysicalThreat),
        proto::EventKind::RumorSpreading => Ok(CoreEventKind::RumorSpreading),
        proto::EventKind::Exclusion => Ok(CoreEventKind::Exclusion),
        proto::EventKind::Mockery => Ok(CoreEventKind::Mockery),
        proto::EventKind::GuiltTripping => Ok(CoreEventKind::GuiltTripping),
        proto::EventKind::Gaslighting => Ok(CoreEventKind::Gaslighting),
        proto::EventKind::EmotionalBlackmail => Ok(CoreEventKind::EmotionalBlackmail),
        proto::EventKind::PeerPressure => Ok(CoreEventKind::PeerPressure),
        proto::EventKind::LoveBombing => Ok(CoreEventKind::LoveBombing),
        proto::EventKind::Darvo => Ok(CoreEventKind::Darvo),
        proto::EventKind::Devaluation => Ok(CoreEventKind::Devaluation),
        proto::EventKind::SuicidalIdeation => Ok(CoreEventKind::SuicidalIdeation),
        proto::EventKind::Hopelessness => Ok(CoreEventKind::Hopelessness),
        proto::EventKind::FarewellMessage => Ok(CoreEventKind::FarewellMessage),
        proto::EventKind::DoxxingAttempt => Ok(CoreEventKind::DoxxingAttempt),
        proto::EventKind::ScreenshotThreat => Ok(CoreEventKind::ScreenshotThreat),
        proto::EventKind::HateSpeech => Ok(CoreEventKind::HateSpeech),
        proto::EventKind::LocationRequest => Ok(CoreEventKind::LocationRequest),
        proto::EventKind::MoneyOffer => Ok(CoreEventKind::MoneyOffer),
        proto::EventKind::PiiSelfDisclosure => Ok(CoreEventKind::PiiSelfDisclosure),
        proto::EventKind::CasualMeetingRequest => Ok(CoreEventKind::CasualMeetingRequest),
        proto::EventKind::DareChallenge => Ok(CoreEventKind::DareChallenge),
        proto::EventKind::SuicideCoercion => Ok(CoreEventKind::SuicideCoercion),
        proto::EventKind::FalseConsensus => Ok(CoreEventKind::FalseConsensus),
        proto::EventKind::DebtCreation => Ok(CoreEventKind::DebtCreation),
        proto::EventKind::ReputationThreat => Ok(CoreEventKind::ReputationThreat),
        proto::EventKind::IdentityErosion => Ok(CoreEventKind::IdentityErosion),
        proto::EventKind::NetworkPoisoning => Ok(CoreEventKind::NetworkPoisoning),
        proto::EventKind::FakeVulnerability => Ok(CoreEventKind::FakeVulnerability),
        proto::EventKind::NormalConversation => Ok(CoreEventKind::NormalConversation),
        proto::EventKind::TrustedContact => Ok(CoreEventKind::TrustedContact),
        proto::EventKind::DefenseOfVictim => Ok(CoreEventKind::DefenseOfVictim),
        proto::EventKind::PropagandaNarrative => Ok(CoreEventKind::PropagandaNarrative),
        proto::EventKind::SuspiciousSource => Ok(CoreEventKind::SuspiciousSource),
        proto::EventKind::PositionLeak => Ok(CoreEventKind::PositionLeak),
        proto::EventKind::UnitInfoLeak => Ok(CoreEventKind::UnitInfoLeak),
        proto::EventKind::EquipmentLeak => Ok(CoreEventKind::EquipmentLeak),
        proto::EventKind::CoordinateMention => Ok(CoreEventKind::CoordinateMention),
        proto::EventKind::PsyopsPattern => Ok(CoreEventKind::PsyopsPattern),
        proto::EventKind::IntelGathering => Ok(CoreEventKind::IntelGathering),
        proto::EventKind::MilitaryPhishing => Ok(CoreEventKind::MilitaryPhishing),
        proto::EventKind::MilitaryDisinfo => Ok(CoreEventKind::MilitaryDisinfo),
        proto::EventKind::Unspecified => Err("unspecified event kind in state".to_string()),
    }
}

fn proto_event_kind(value: CoreEventKind) -> proto::EventKind {
    match value {
        CoreEventKind::Flattery => proto::EventKind::Flattery,
        CoreEventKind::GiftOffer => proto::EventKind::GiftOffer,
        CoreEventKind::SecrecyRequest => proto::EventKind::SecrecyRequest,
        CoreEventKind::PlatformSwitch => proto::EventKind::PlatformSwitch,
        CoreEventKind::PersonalInfoRequest => proto::EventKind::PersonalInfoRequest,
        CoreEventKind::PhotoRequest => proto::EventKind::PhotoRequest,
        CoreEventKind::VideoCallRequest => proto::EventKind::VideoCallRequest,
        CoreEventKind::FinancialGrooming => proto::EventKind::FinancialGrooming,
        CoreEventKind::MeetingRequest => proto::EventKind::MeetingRequest,
        CoreEventKind::SexualContent => proto::EventKind::SexualContent,
        CoreEventKind::AgeInappropriate => proto::EventKind::AgeInappropriate,
        CoreEventKind::Insult => proto::EventKind::Insult,
        CoreEventKind::Denigration => proto::EventKind::Denigration,
        CoreEventKind::HarmEncouragement => proto::EventKind::HarmEncouragement,
        CoreEventKind::PhysicalThreat => proto::EventKind::PhysicalThreat,
        CoreEventKind::RumorSpreading => proto::EventKind::RumorSpreading,
        CoreEventKind::Exclusion => proto::EventKind::Exclusion,
        CoreEventKind::Mockery => proto::EventKind::Mockery,
        CoreEventKind::GuiltTripping => proto::EventKind::GuiltTripping,
        CoreEventKind::Gaslighting => proto::EventKind::Gaslighting,
        CoreEventKind::EmotionalBlackmail => proto::EventKind::EmotionalBlackmail,
        CoreEventKind::PeerPressure => proto::EventKind::PeerPressure,
        CoreEventKind::LoveBombing => proto::EventKind::LoveBombing,
        CoreEventKind::Darvo => proto::EventKind::Darvo,
        CoreEventKind::Devaluation => proto::EventKind::Devaluation,
        CoreEventKind::SuicidalIdeation => proto::EventKind::SuicidalIdeation,
        CoreEventKind::Hopelessness => proto::EventKind::Hopelessness,
        CoreEventKind::FarewellMessage => proto::EventKind::FarewellMessage,
        CoreEventKind::DoxxingAttempt => proto::EventKind::DoxxingAttempt,
        CoreEventKind::ScreenshotThreat => proto::EventKind::ScreenshotThreat,
        CoreEventKind::HateSpeech => proto::EventKind::HateSpeech,
        CoreEventKind::LocationRequest => proto::EventKind::LocationRequest,
        CoreEventKind::MoneyOffer => proto::EventKind::MoneyOffer,
        CoreEventKind::PiiSelfDisclosure => proto::EventKind::PiiSelfDisclosure,
        CoreEventKind::CasualMeetingRequest => proto::EventKind::CasualMeetingRequest,
        CoreEventKind::DareChallenge => proto::EventKind::DareChallenge,
        CoreEventKind::SuicideCoercion => proto::EventKind::SuicideCoercion,
        CoreEventKind::FalseConsensus => proto::EventKind::FalseConsensus,
        CoreEventKind::DebtCreation => proto::EventKind::DebtCreation,
        CoreEventKind::ReputationThreat => proto::EventKind::ReputationThreat,
        CoreEventKind::IdentityErosion => proto::EventKind::IdentityErosion,
        CoreEventKind::NetworkPoisoning => proto::EventKind::NetworkPoisoning,
        CoreEventKind::FakeVulnerability => proto::EventKind::FakeVulnerability,
        CoreEventKind::NormalConversation => proto::EventKind::NormalConversation,
        CoreEventKind::TrustedContact => proto::EventKind::TrustedContact,
        CoreEventKind::DefenseOfVictim => proto::EventKind::DefenseOfVictim,
        CoreEventKind::PropagandaNarrative => proto::EventKind::PropagandaNarrative,
        CoreEventKind::SuspiciousSource => proto::EventKind::SuspiciousSource,
        CoreEventKind::PositionLeak => proto::EventKind::PositionLeak,
        CoreEventKind::UnitInfoLeak => proto::EventKind::UnitInfoLeak,
        CoreEventKind::EquipmentLeak => proto::EventKind::EquipmentLeak,
        CoreEventKind::CoordinateMention => proto::EventKind::CoordinateMention,
        CoreEventKind::PsyopsPattern => proto::EventKind::PsyopsPattern,
        CoreEventKind::IntelGathering => proto::EventKind::IntelGathering,
        CoreEventKind::MilitaryPhishing => proto::EventKind::MilitaryPhishing,
        CoreEventKind::MilitaryDisinfo => proto::EventKind::MilitaryDisinfo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as ProstMessage;
    use std::ffi::CStr;

    fn proto_config(account_type: proto::AccountType, enabled: bool) -> proto::AuraConfig {
        proto::AuraConfig {
            protection_level: proto::ProtectionLevel::High as i32,
            account_type: account_type as i32,
            language: "en".to_string(),
            cultural_context: Some(proto::CulturalContext {
                kind: proto::CulturalContextKind::English as i32,
                custom_value: None,
            }),
            enabled,
            patterns_path: None,
            models_path: None,
            account_holder_age: None,
            ttl_days: 30,
            timezone_offset_minutes: 0,
            domain_mode: proto::DomainMode::None as i32,
            product_rollout_mode: proto::ProductRolloutMode::Shadow as i32,
        }
    }

    // Reproduces the EXACT config the iOS app's AuraRuntimeService.makeConfig builds
    // for the local-analysis path: ProtectionLevel::Medium, AccountType::Adult,
    // English language/cultural context, ttl 30, and DomainMode::None.
    #[test]
    fn ios_local_analysis_config_initializes() {
        unsafe {
            let config = proto::AuraConfig {
                protection_level: proto::ProtectionLevel::Medium as i32,
                account_type: proto::AccountType::Adult as i32,
                language: "en".to_string(),
                cultural_context: Some(proto::CulturalContext {
                    kind: proto::CulturalContextKind::English as i32,
                    custom_value: None,
                }),
                enabled: true,
                patterns_path: None,
                models_path: None,
                account_holder_age: None,
                ttl_days: 30,
                timezone_offset_minutes: 120,
                domain_mode: proto::DomainMode::None as i32,
                product_rollout_mode: proto::ProductRolloutMode::Shadow as i32,
            };
            let bytes = encode_proto(&config);
            let handle = aura_init(bytes.as_ptr(), bytes.len());
            if handle.is_null() {
                let err = aura_last_error();
                let msg = if err.is_null() {
                    "<null last_error>".to_string()
                } else {
                    let s = std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned();
                    aura_free_string(err);
                    s
                };
                panic!("ios_local_analysis_config init FAILED: {msg}");
            }
            aura_free(handle);
        }
    }

    // Directly validates the device-symptom fix: when the thread-local LAST_ERROR
    // read comes back empty (the static-lib/iOS behavior that produced
    // "unknown error"), aura_last_error must still surface the message from the
    // sticky process-global mirror.
    #[test]
    fn last_error_global_fallback_survives_threadlocal_clear() {
        unsafe {
            set_last_error("boom-global-fallback-xyz");
            // Simulate the iOS symptom: thread-local does not retain the write.
            LAST_ERROR.with(|e| {
                *e.borrow_mut() = None;
            });
            let err = aura_last_error();
            assert!(!err.is_null(), "global fallback must surface the error");
            let s = std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned();
            aura_free_string(err);
            assert!(s.contains("boom-global-fallback-xyz"), "got: {s}");
        }
    }

    #[test]
    fn domain_mode_defaults_to_none_for_core_only_config() {
        let config = aura_config_from_proto(proto_config(proto::AccountType::Adult, true))
            .expect("config must decode");
        assert_eq!(config.domain_mode, aura_agent_core::DomainMode::None);
    }

    #[test]
    fn military_domain_mode_is_applied() {
        let mut proto = proto_config(proto::AccountType::Adult, true);
        proto.domain_mode = proto::DomainMode::Military as i32;
        let config = aura_config_from_proto(proto).expect("config must decode");
        assert_eq!(config.domain_mode, aura_agent_core::DomainMode::Military);
    }

    #[test]
    fn unspecified_domain_mode_is_rejected() {
        let mut proto = proto_config(proto::AccountType::Adult, true);
        proto.domain_mode = proto::DomainMode::Unspecified as i32;
        let error = aura_config_from_proto(proto).expect_err("domain mode must be explicit");
        assert!(error.contains("domain_mode must be explicit"));
    }

    #[test]
    fn unspecified_product_rollout_is_rejected() {
        let mut proto = proto_config(proto::AccountType::Adult, true);
        proto.product_rollout_mode = proto::ProductRolloutMode::Unspecified as i32;
        let error = aura_config_from_proto(proto).expect_err("rollout must be explicit");
        assert!(error.contains("product_rollout_mode must be explicit"));
    }

    fn proto_message(text: &str, sender_id: &str, conversation_id: &str) -> proto::MessageInput {
        proto::MessageInput {
            content_type: proto::ContentType::Text as i32,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: sender_id.to_string(),
            conversation_id: conversation_id.to_string(),
            language: Some("en".to_string()),
            conversation_type: proto::ConversationType::Direct as i32,
            member_count: None,
            sender_relationship: proto::SenderRelationship::Unspecified as i32,
            relationship_trust_source: proto::RelationshipTrustSource::Unspecified as i32,
        }
    }

    fn encode_proto<M: ProstMessage>(message: &M) -> Vec<u8> {
        message.encode_to_vec()
    }

    unsafe fn decode_buffer<M>(buffer: AuraBuffer) -> M
    where
        M: ProstMessage + Default,
    {
        let bytes = std::slice::from_raw_parts(buffer.ptr, buffer.len);
        let decoded = M::decode(bytes).unwrap();
        aura_free_buffer(buffer);
        decoded
    }

    unsafe fn init_handle(config: proto::AuraConfig) -> *mut c_void {
        let bytes = encode_proto(&config);
        let handle = aura_init(bytes.as_ptr(), bytes.len());
        assert!(
            !handle.is_null(),
            "valid config must initialize the runtime"
        );
        handle
    }

    unsafe fn analyze_canonical(
        handle: *mut c_void,
        message: proto::MessageInput,
        event_id: &str,
        revision: u32,
        timestamp_ms: u64,
    ) -> proto::CanonicalSafetyAnalyzeResponse {
        let conversation_key = message.conversation_id.clone();
        let request = proto::CanonicalSafetyAnalyzeRequest {
            message: Some(message),
            identity: Some(proto::CanonicalSafetyEventIdentity {
                account_key: "account".to_string(),
                subject_key: "subject".to_string(),
                conversation_key,
                event_id: event_id.to_string(),
                revision,
                occurred_at_ms: timestamp_ms,
                observed_at_ms: timestamp_ms,
            }),
        };
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();
        assert!(aura_analyze_canonical_safety(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            &mut out,
        ));
        decode_buffer(out)
    }

    unsafe fn export_context(handle: *mut c_void) -> proto::ExportContextResponse {
        let mut out = AuraBuffer::empty();
        assert!(aura_export_context(handle, &mut out));
        decode_buffer(out)
    }

    unsafe fn import_context_state(handle: *mut c_void, state: proto::TrackerState) {
        let request = proto::ImportContextRequest { state: Some(state) };
        let bytes = encode_proto(&request);
        assert!(aura_import_context(handle, bytes.as_ptr(), bytes.len()));
    }

    fn oversized_request_bytes(limit: usize) -> Vec<u8> {
        vec![0_u8; limit + 1]
    }

    unsafe fn last_error_string() -> String {
        let err = aura_last_error();
        assert!(!err.is_null(), "expected last_error to be set");
        let err_str = CStr::from_ptr(err).to_str().unwrap().to_string();
        aura_free_string(err);
        err_str
    }

    #[test]
    fn kids_memory_proto_conversion_preserves_exact_persistence_fields() {
        use aura_agent_core::aura_kids::pipeline::{
            ExportedConversationMemory, ExportedEmissionCheckpoint, ExportedKidsMemoryState,
            ExportedSenderMemory, KIDS_MEMORY_STATE_VERSION,
        };

        let state = ExportedKidsMemoryState {
            schema_version: KIDS_MEMORY_STATE_VERSION,
            conversations: vec![ExportedConversationMemory {
                conversation_id: "conv_exact".to_string(),
                entries: Vec::new(),
                message_index: 11,
                last_activity_index: 101,
                last_emitted: vec![ExportedEmissionCheckpoint {
                    reason_code: "grooming_progression".to_string(),
                    emitted_at_index: 10,
                }],
            }],
            senders: vec![ExportedSenderMemory {
                sender_id: "sender_exact".to_string(),
                event_index: 13,
                recent_high_risk_conversations: vec!["conv_exact".to_string()],
                last_activity_index: 102,
                last_emitted: vec![ExportedEmissionCheckpoint {
                    reason_code: "cross_conversation_repeat_offender".to_string(),
                    emitted_at_index: 12,
                }],
            }],
        };

        let proto = kids_memory_state_to_proto(&state);
        let restored = kids_memory_state_from_proto(&proto).expect("kids state conversion");

        assert_eq!(
            (
                restored.schema_version,
                restored.conversations[0].last_activity_index,
                restored.conversations[0].last_emitted.clone(),
                restored.senders[0].last_activity_index,
                restored.senders[0].last_emitted.clone(),
            ),
            (
                KIDS_MEMORY_STATE_VERSION,
                101,
                vec![ExportedEmissionCheckpoint {
                    reason_code: "grooming_progression".to_string(),
                    emitted_at_index: 10,
                }],
                102,
                vec![ExportedEmissionCheckpoint {
                    reason_code: "cross_conversation_repeat_offender".to_string(),
                    emitted_at_index: 12,
                }],
            )
        );
    }

    #[test]
    fn kids_memory_rejects_noncurrent_schema_and_missing_activity_indices() {
        let noncurrent = proto::KidsMemoryState {
            conversations: vec![proto::KidsConversationMemoryState {
                conversation_id: "conv".to_string(),
                entries: Vec::new(),
                message_index: 41,
                last_activity_index: None,
                last_emitted: Vec::new(),
            }],
            senders: vec![proto::KidsSenderMemoryState {
                sender_id: "sender".to_string(),
                event_index: 42,
                recent_high_risk_conversations: Vec::new(),
                last_activity_index: None,
                last_emitted: Vec::new(),
            }],
            schema_version: 0,
        };

        assert!(kids_memory_state_from_proto(&noncurrent).is_err());

        let mut missing_conversation_index = noncurrent.clone();
        missing_conversation_index.schema_version = KIDS_MEMORY_STATE_VERSION;
        missing_conversation_index.senders[0].last_activity_index = Some(42);
        assert!(kids_memory_state_from_proto(&missing_conversation_index).is_err());

        let mut missing_sender_index = missing_conversation_index;
        missing_sender_index.conversations[0].last_activity_index = Some(41);
        missing_sender_index.senders[0].last_activity_index = None;
        assert!(kids_memory_state_from_proto(&missing_sender_index).is_err());
    }

    #[test]
    fn version_returns_valid_string() {
        unsafe {
            let version = aura_version();
            let version = CStr::from_ptr(version).to_str().unwrap();
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
        }
    }

    #[test]
    fn last_error_null_by_default() {
        let err = aura_last_error();
        assert!(err.is_null());
    }

    #[test]
    fn last_error_set_on_bad_init() {
        unsafe {
            let bad = [0xFF_u8, 0x01, 0x02];
            let handle = aura_init(bad.as_ptr(), bad.len());
            assert!(handle.is_null());

            let err = aura_last_error();
            assert!(!err.is_null());
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("invalid protobuf"), "Got: {err_str}");
            aura_free_string(err);
        }
    }

    #[test]
    fn oversized_config_is_rejected_during_init() {
        unsafe {
            let request = oversized_request_bytes(MAX_CONFIG_REQUEST_BYTES);
            let handle = aura_init(request.as_ptr(), request.len());
            assert!(handle.is_null());

            let err_str = last_error_string();
            assert!(err_str.contains("config exceeds limit"), "Got: {err_str}");
        }
    }

    #[test]
    fn last_error_cleared_on_success() {
        unsafe {
            let bad = [0xFF_u8, 0x01, 0x02];
            let _ = aura_init(bad.as_ptr(), bad.len());

            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            assert!(!handle.is_null());
            let err = aura_last_error();
            assert!(err.is_null());
            aura_free(handle);
        }
    }

    #[test]
    fn canonical_analysis_is_exactly_once() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let message = proto_message(
                "don't tell your parents, it's our secret",
                "sender",
                "conversation",
            );
            let first = analyze_canonical(handle, message.clone(), "event", 1, 1_000);
            assert_ne!(
                proto::CanonicalSafetyDisposition::try_from(first.disposition).unwrap(),
                proto::CanonicalSafetyDisposition::Unspecified
            );

            let duplicate = analyze_canonical(handle, message, "event", 1, 1_000);
            assert!(matches!(
                proto::CanonicalSafetyDisposition::try_from(duplicate.disposition).unwrap(),
                proto::CanonicalSafetyDisposition::DuplicateIgnored
                    | proto::CanonicalSafetyDisposition::DuplicateApplied
                    | proto::CanonicalSafetyDisposition::DuplicateRejected
            ));
            aura_free(handle);
        }
    }

    #[test]
    fn repeated_import_of_same_state_is_idempotent() {
        unsafe {
            let source = init_handle(proto_config(proto::AccountType::Child, true));
            let replica = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_canonical(
                source,
                proto_message(
                    "don't tell your parents, it's our secret",
                    "sender",
                    "conversation",
                ),
                "event-1",
                1,
                1_000,
            );
            let state = export_context(source)
                .state
                .expect("canonical analysis must export tracker state");

            for _ in 0..25 {
                import_context_state(replica, state.clone());
            }

            assert_eq!(export_context(replica).state, Some(state));
            aura_free(source);
            aura_free(replica);
        }
    }

    #[test]
    fn repeated_export_import_roundtrips_preserve_growth() {
        unsafe {
            let first = init_handle(proto_config(proto::AccountType::Child, true));
            let second = init_handle(proto_config(proto::AccountType::Child, true));
            let mut active = first;
            let mut standby = second;

            for revision in 1..=6 {
                let _ = analyze_canonical(
                    active,
                    proto_message(
                        "don't tell your parents, it's our secret",
                        "sender",
                        "conversation",
                    ),
                    &format!("event-{revision}"),
                    revision,
                    u64::from(revision) * 1_000,
                );
                let state = export_context(active)
                    .state
                    .expect("canonical analysis must export tracker state");
                import_context_state(standby, state);
                std::mem::swap(&mut active, &mut standby);
            }

            assert_eq!(export_context(first).state, export_context(second).state);
            aura_free(first);
            aura_free(second);
        }
    }
}
