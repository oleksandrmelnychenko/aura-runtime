//! C FFI boundary for the AURA analysis engine.
//!
//! Exposes a protobuf-based C API for creating, configuring, and invoking
//! the AURA analyzer from non-Rust host applications.

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
    EventDirectionality as CoreEventDirectionality, EventKind as CoreEventKind,
    EventSpeechAct as CoreEventSpeechAct, EventStance as CoreEventStance,
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

use crate::execution_policy;

const MAX_CONFIG_REQUEST_BYTES: usize = 64 * 1024;
const MAX_IMPORT_CONTEXT_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_CANONICAL_SAFETY_REQUEST_BYTES: usize = 1024 * 1024;
// Matches the host store's release limits for the two native-owned payloads.
// Guardian outbox and envelope overhead have separate host-owned budgets.
const MAX_CANONICAL_CONTEXT_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CANONICAL_COMBINED_STATE_BYTES: usize =
    SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES + MAX_CANONICAL_CONTEXT_STATE_BYTES;
const MAX_SMALL_CONTROL_REQUEST_BYTES: usize = 16 * 1024;

mod errors;

use errors::*;

struct AuraInstance {
    analyzer: AgentRuntime,
}

#[derive(Debug)]
struct DecodedConfig {
    aura_config: AuraConfig,
}

fn build_instance(config: DecodedConfig) -> Result<*mut c_void, String> {
    config
        .aura_config
        .validate()
        .map_err(|e| format!("config validation failed: {e}"))?;

    let pattern_db = load_pattern_db(&config.aura_config)?;
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

mod buffers;

pub use buffers::AuraBuffer;
use buffers::{bytes_to_buffer, decode_proto_bounded, prepare_output, write_proto_message};

mod analysis;

use analysis::*;

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
        let input = match message_input_from_proto(message) {
            Ok(input) => input,
            Err(error) => {
                set_last_error(error);
                return false;
            }
        };
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

/// Returns this thread's last error message as a C string, or null if none occurred.
///
/// The caller must invoke this on the same thread as the failed FFI operation.
#[no_mangle]
pub extern "C" fn aura_last_error() -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), move || {
        let message = LAST_ERROR.with(|error| error.borrow().clone());
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

mod state;

use state::*;

#[cfg(test)]
mod tests;
