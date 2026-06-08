//! C FFI boundary for the AURA analysis engine.
//!
//! Exposes a protobuf-based C API for creating, configuring, and invoking
//! the AURA analyzer from non-Rust host applications.

#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aura_agent_core::aura_contracts::{
    AgentAnalyzeRequest as RelayAnalyzeRequestContract, ClientSafetyTelemetryEvent,
    DetectionLayer as RelayDetectionLayer,
    ProtectedAccountTokenAttestation as ProtectedAccountTokenAttestationContract,
    RelationshipTrustSource, RelayAnalyzeResponse as RelayAnalyzeResponseContract,
    RelayPrivacyMode, RelayRequestAuth as RelayRequestAuthContract,
    RelayResponseAuth as RelayResponseAuthContract, RemoteFinding as RelayRemoteFindingContract,
    RemoteInferenceSummary as RelayRemoteInferenceSummaryContract, RiskHorizon as RelayRiskHorizon,
    SafetyTelemetryAction, SafetyTelemetrySeverity, SafetyTelemetrySurface, SenderRelationship,
    PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG,
};
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
use aura_agent_core::{
    build_product_decision_surface, build_shadow_mode_event, config::CulturalContext, Action,
    AlertPriority, AuraConfig, MessageInput, ProductRolloutMode, ShadowModeBundle,
    ShadowModeEventInput, ShadowModeExpectation, ShadowModeFinding,
};
use aura_agent_core::{AgentRelayPolicy, AgentRuntime, RelayRequestAuthKey, RelayResponseAuthKey};
use aura_patterns::PatternDatabase;
use aura_proto::messenger::v1 as proto;
use prost::Message as ProstMessage;
use tracing::warn;

const MAX_BATCH_SIZE: usize = 1000;
const MAX_RELAY_RECENT_WINDOW_MESSAGES: usize = 50;
const MIN_RELAY_AUTH_SECRET_BYTES: usize = 16;
const MAX_RELAY_AUTH_SECRET_BYTES: usize = 128;
const MAX_RELAY_AUTH_KEYS: usize = 4;
const MAX_CONFIG_REQUEST_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ANALYZE_CONTEXT_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_BATCH_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_SHADOW_BUNDLE_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_IMPORT_CONTEXT_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_SMALL_CONTROL_REQUEST_BYTES: usize = 16 * 1024;
const MAX_QUICK_CHECK_TEXT_BYTES: usize = 64 * 1024;
const MAX_URL_INPUT_BYTES: usize = 4096;
const PATTERN_RELOAD_MIN_INTERVAL_MS: u64 = 1_500;
const PATTERN_RELOAD_MAX_BACKOFF_MS: u64 = 30_000;
const PATTERN_RELOAD_PATH_MAX_BYTES: usize = 1024;
const MANDATORY_KIDS_MEMORY_REASON_CODES: &[&str] = &[
    "kids.memory.grooming_progression",
    "kids.memory.sustained_sextortion",
    "kids.memory.bullying_cascade_selfharm",
    "kids.memory.sender_risk_accumulation",
    "kids.memory.new_sender_fast_escalation",
    "kids.memory.cross_conversation_repeat_offender",
    "kids.memory.victim_vulnerability_targeting",
];

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Process-global mirror of the most recent error message.
///
/// `LAST_ERROR` (thread-local, errno-style) is the primary store, but in some
/// static-library / iOS link configurations a thread-local write is not
/// observed by a subsequent read, which surfaced on the Swift side as
/// "unknown error" even though an error message *was* set (e.g. a real
/// `aura_init` failure whose reason was silently dropped). This sticky global
/// guarantees the last error set by any export remains retrievable as a
/// fallback. It is intentionally NOT reset by `clear_last_error` so a failure's
/// reason cannot be wiped by a concurrent call before the caller reads it.
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
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

struct AuraInstance {
    analyzer: AgentRuntime,
    pattern_db: PatternDatabase,
    last_pattern_reload_attempt: Option<Instant>,
    pattern_reload_failures: u32,
}

#[derive(Debug)]
struct DecodedConfig {
    aura_config: AuraConfig,
    relay_policy: AgentRelayPolicy,
    relay_request_auth_key: Option<RelayRequestAuthKey>,
    relay_response_auth_keys: Vec<RelayResponseAuthKey>,
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
    let mut analyzer =
        AgentRuntime::new(config.aura_config, &pattern_db).with_relay_policy(config.relay_policy);
    apply_relay_request_auth_key(&mut analyzer, config.relay_request_auth_key);
    apply_relay_response_auth_keys(&mut analyzer, config.relay_response_auth_keys);
    let instance = Box::new(Mutex::new(AuraInstance {
        analyzer,
        pattern_db,
        last_pattern_reload_attempt: None,
        pattern_reload_failures: 0,
    }));
    Ok(Box::into_raw(instance) as *mut c_void)
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

fn pattern_reload_backoff(failure_count: u32) -> Duration {
    let shift = failure_count.min(4);
    let multiplier = 1u64 << shift;
    let millis = PATTERN_RELOAD_MIN_INTERVAL_MS
        .saturating_mul(multiplier)
        .min(PATTERN_RELOAD_MAX_BACKOFF_MS);
    Duration::from_millis(millis)
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

fn decode_message_request(
    request_ptr: *const u8,
    request_len: usize,
) -> Result<MessageInput, String> {
    let message: proto::MessageInput = unsafe {
        decode_proto_bounded(
            request_ptr,
            request_len,
            "message",
            MAX_MESSAGE_REQUEST_BYTES,
        )?
    };
    Ok(message_input_from_proto(message))
}

fn validate_batch_items(
    items: Vec<proto::BatchAnalyzeItem>,
) -> Result<Vec<(MessageInput, Option<u64>)>, String> {
    let mut validated = Vec::with_capacity(items.len());
    for item in items {
        let Some(message) = item.message else {
            return Err("missing message in batch item".to_string());
        };
        validated.push((message_input_from_proto(message), item.timestamp_ms));
    }
    Ok(validated)
}

struct ValidatedShadowModeItem {
    request_id: String,
    input: MessageInput,
    timestamp_ms: u64,
    expectation: Option<ShadowModeExpectation>,
}

fn validate_shadow_mode_items(
    items: Vec<proto::ShadowModeAnalyzeItem>,
) -> Result<Vec<ValidatedShadowModeItem>, String> {
    let mut validated = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        let request = item.request.ok_or_else(|| {
            format!(
                "missing analyze_context request in shadow item {}",
                index + 1
            )
        })?;
        let message = request
            .message
            .ok_or_else(|| format!("missing message in shadow item {}", index + 1))?;
        validated.push(ValidatedShadowModeItem {
            request_id: if item.request_id.is_empty() {
                format!("shadow_req_{}", index + 1)
            } else {
                item.request_id
            },
            input: message_input_from_proto(message),
            timestamp_ms: request.timestamp_ms,
            expectation: shadow_mode_expectation_from_proto(item.expectation),
        });
    }
    Ok(validated)
}

fn apply_config_update(instance: &mut AuraInstance, config: DecodedConfig) {
    let next_pattern_db = resolve_pattern_db_for_update(&instance.pattern_db, &config.aura_config);
    instance
        .analyzer
        .update_config(config.aura_config, &next_pattern_db);
    *instance.analyzer.relay_policy_mut() = config.relay_policy;
    apply_relay_request_auth_key(&mut instance.analyzer, config.relay_request_auth_key);
    apply_relay_response_auth_keys(&mut instance.analyzer, config.relay_response_auth_keys);
    instance.pattern_db = next_pattern_db;
}

fn apply_relay_request_auth_key(
    runtime: &mut AgentRuntime,
    relay_request_auth_key: Option<RelayRequestAuthKey>,
) {
    match relay_request_auth_key {
        // Clone out (not partial-move): RelayRequestAuthKey now zeroizes its secret on
        // drop, which disallows moving fields out. The original `key` is zeroized when
        // it drops here; the runtime keeps its own (also zeroize-on-drop) copy.
        Some(key) => runtime.set_relay_request_auth_key(key.key_id.clone(), key.secret.clone()),
        None => runtime.clear_relay_request_auth_key(),
    }
}

fn apply_relay_response_auth_keys(
    runtime: &mut AgentRuntime,
    relay_response_auth_keys: Vec<RelayResponseAuthKey>,
) {
    if relay_response_auth_keys.is_empty() {
        runtime.clear_relay_response_auth_key();
    } else {
        runtime.set_relay_response_auth_keys(relay_response_auth_keys);
    }
}

fn contact_profile_to_proto(
    profile: &aura_agent_core::context::contact::ContactProfile,
    is_new_contact: bool,
) -> proto::ContactProfile {
    proto::ContactProfile {
        sender_id: profile.sender_id.to_string(),
        risk_score: profile.risk_score(),
        rating: profile.rating,
        trust_level: profile.trust_level,
        circle_tier: proto_circle_tier(profile.circle_tier) as i32,
        trend: proto_behavioral_trend(profile.trend) as i32,
        first_seen_ms: profile.first_seen_ms,
        last_seen_ms: profile.last_seen_ms,
        total_messages: profile.total_messages,
        grooming_events: profile.grooming_event_count,
        bullying_events: profile.bullying_event_count,
        manipulation_events: profile.manipulation_event_count,
        is_trusted: profile.is_trusted,
        is_new_contact,
        conversation_count: profile.conversation_count as u64,
        average_severity: profile.average_severity(),
    }
}

fn conversation_summary_to_proto(
    tracker: &aura_agent_core::ConversationTracker,
) -> proto::ConversationSummaryResponse {
    let mut conversations = Vec::new();

    for conv_id in tracker.conversation_ids() {
        if let Some(timeline) = tracker.timeline(conv_id) {
            let events = timeline.all_events();
            let mut unique_senders: Vec<String> = events
                .iter()
                .map(|e| e.sender_id.to_string())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            unique_senders.sort();

            let threat_event_count =
                events.iter().filter(|e| e.kind.severity() >= 0.4).count() as u64;
            let latest_event_ms = events.iter().map(|e| e.timestamp_ms).max().unwrap_or(0);

            conversations.push(proto::ConversationSummaryItem {
                conversation_id: conv_id.to_string(),
                total_events: events.len() as u64,
                unique_senders,
                threat_event_count,
                latest_event_ms,
            });
        }
    }

    conversations.sort_by_key(|conversation| std::cmp::Reverse(conversation.latest_event_ms));

    proto::ConversationSummaryResponse {
        total_conversations: conversations.len() as u64,
        conversations,
    }
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

/// Analyzes a single message and writes the protobuf-encoded result to the output buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_analyze(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let input = match decode_message_request(request_ptr, request_len) {
            Ok(input) => input,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let result = instance.analyzer.analyze_local(&input);
            write_proto_message(
                out,
                &analysis_result_to_proto(
                    &result,
                    Some(input.conversation_id.0.as_str()),
                    Some(input.sender_id.0.as_str()),
                ),
            )
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Analyzes a message with full conversation context and writes the result to the output buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_analyze_context(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let request: proto::AnalyzeContextRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "analyze_context request",
            MAX_ANALYZE_CONTEXT_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        let Some(message) = request.message else {
            set_last_error("missing message in analyze_context request");
            return false;
        };
        let input = message_input_from_proto(message);

        match with_instance(handle, |instance| {
            let result = instance
                .analyzer
                .analyze_local_with_context(&input, request.timestamp_ms);
            write_proto_message(
                out,
                &analysis_result_to_proto(
                    &result,
                    Some(input.conversation_id.0.as_str()),
                    Some(input.sender_id.0.as_str()),
                ),
            )
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Analyzes a message and returns both the local result and optional relay request.
#[no_mangle]
pub unsafe extern "C" fn aura_analyze_for_relay(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let request: proto::AnalyzeContextRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "analyze_for_relay request",
            MAX_ANALYZE_CONTEXT_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        let Some(message) = request.message else {
            set_last_error("missing message in analyze_for_relay request");
            return false;
        };
        let input = message_input_from_proto(message);

        match with_instance(handle, |instance| {
            let envelope = instance
                .analyzer
                .analyze_for_relay(&input, request.timestamp_ms);
            let response = proto::AnalyzeForRelayResponse {
                local_result: Some(analysis_result_to_proto(
                    &envelope.local_result,
                    Some(input.conversation_id.0.as_str()),
                    Some(input.sender_id.0.as_str()),
                )),
                relay_request: envelope.relay_request.as_ref().map(relay_request_to_proto),
            };
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Records a relay response for a sender so future local analysis can apply the server hint.
#[no_mangle]
pub unsafe extern "C" fn aura_record_relay_response(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        let request: proto::RecordRelayResponseRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "record_relay_response request",
            MAX_MESSAGE_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        let sender_id = request.sender_id.trim();
        if sender_id.is_empty() {
            set_last_error("record_relay_response sender_id is empty");
            return false;
        }

        let Some(response) = request.response else {
            set_last_error("missing relay response in record_relay_response request");
            return false;
        };
        let response = relay_response_from_proto(response);

        match with_instance(handle, |instance| {
            let accepted = instance.analyzer.record_relay_response_for_sender(
                &aura_agent_core::SenderId(sender_id.to_string()),
                &response,
                request.received_at_ms,
            );
            accepted
                .then_some(())
                .ok_or_else(|| "relay response rejected".to_string())
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Analyzes a batch of messages and writes the protobuf-encoded results to the output buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_analyze_batch(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let request: proto::BatchAnalyzeRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "batch analyze request",
            MAX_BATCH_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        if request.items.len() > MAX_BATCH_SIZE {
            set_last_error(format!(
                "batch size {} exceeds limit of {MAX_BATCH_SIZE}",
                request.items.len()
            ));
            return false;
        }

        let items = match validate_batch_items(request.items) {
            Ok(items) => items,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let mut results = Vec::with_capacity(items.len());
            for (input, timestamp_ms) in items {
                let result = match timestamp_ms {
                    Some(ts) => instance.analyzer.analyze_local_with_context(&input, ts),
                    None => instance.analyzer.analyze_local(&input),
                };
                results.push(analysis_result_to_proto(
                    &result,
                    Some(input.conversation_id.0.as_str()),
                    Some(input.sender_id.0.as_str()),
                ));
            }

            write_proto_message(out, &proto::BatchAnalyzeResponse { results })
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Builds a protobuf ShadowModeBundle from a sequence of AnalyzeContextRequest items.
#[no_mangle]
pub unsafe extern "C" fn aura_build_shadow_bundle(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let request: proto::BuildShadowModeBundleRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "build_shadow_bundle request",
            MAX_SHADOW_BUNDLE_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        if request.owner_id.is_empty() {
            set_last_error("missing owner_id in build_shadow_bundle request");
            return false;
        }
        if request.items.is_empty() {
            set_last_error("build_shadow_bundle request must include at least one item");
            return false;
        }

        let items = match validate_shadow_mode_items(request.items) {
            Ok(items) => items,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let protection_level = instance.analyzer.protection_level();
            let mut events = Vec::with_capacity(items.len());
            let mut findings = Vec::new();

            for (index, item) in items.into_iter().enumerate() {
                let result = instance
                    .analyzer
                    .analyze_local_with_context(&item.input, item.timestamp_ms);
                let event = build_shadow_mode_event(ShadowModeEventInput {
                    request_id: &item.request_id,
                    sequence: index + 1,
                    timestamp_ms: item.timestamp_ms,
                    sender_id: item.input.sender_id.as_ref(),
                    conversation_id: item.input.conversation_id.as_ref(),
                    language: item.input.language.as_deref().unwrap_or("und"),
                    conversation_type: item.input.conversation_type,
                    member_count: item.input.member_count,
                    expectation: item.expectation.clone(),
                    protection_level,
                    result: &result,
                });
                findings.extend(shadow_mode_findings_for_event(
                    index + 1,
                    &item.request_id,
                    item.timestamp_ms,
                    item.expectation.as_ref(),
                    &result,
                ));
                events.push(event);
            }

            let bundle = ShadowModeBundle::from_events(
                non_empty_or(request.source_kind, "ffi_shadow"),
                non_empty_or(request.source_label, "ffi_shadow_bundle"),
                non_empty_or(request.source_input, "ffi"),
                &request.owner_id,
                protection_level,
                findings,
                events,
            );
            write_proto_message(out, &shadow_mode_bundle_to_proto(&bundle))
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Updates the analyzer configuration on a live instance.
#[no_mangle]
pub unsafe extern "C" fn aura_update_config(
    handle: *mut c_void,
    config_ptr: *const u8,
    config_len: usize,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        let config = match decode_config_request(config_ptr, config_len) {
            Ok(config) => config,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            config
                .aura_config
                .validate()
                .map_err(|e| format!("config validation failed: {e}"))?;
            apply_config_update(instance, config);
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

/// Reloads the pattern database from a protobuf-encoded request.
#[no_mangle]
pub unsafe extern "C" fn aura_reload_patterns(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let request: proto::ReloadPatternsRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "reload_patterns request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let patterns_path = request.patterns_path.trim();
            if patterns_path.is_empty() {
                return Err("patterns_path must not be empty".to_string());
            }
            if patterns_path.len() > PATTERN_RELOAD_PATH_MAX_BYTES {
                return Err(format!(
                    "patterns_path exceeds {} bytes",
                    PATTERN_RELOAD_PATH_MAX_BYTES
                ));
            }
            if !patterns_path.ends_with(".json") {
                return Err("patterns_path must reference a .json file".to_string());
            }

            let now = Instant::now();
            let cooldown = pattern_reload_backoff(instance.pattern_reload_failures);
            if let Some(last_attempt) = instance.last_pattern_reload_attempt {
                let elapsed = now.saturating_duration_since(last_attempt);
                if elapsed < cooldown {
                    let retry_after_ms = (cooldown - elapsed).as_millis();
                    return Err(format!(
                        "pattern reload is rate-limited; retry after {retry_after_ms}ms"
                    ));
                }
            }
            instance.last_pattern_reload_attempt = Some(now);

            let db = match PatternDatabase::from_file(patterns_path) {
                Ok(db) => db,
                Err(e) => {
                    instance.pattern_reload_failures =
                        instance.pattern_reload_failures.saturating_add(1);
                    return Err(format!("pattern load failed: {e}"));
                }
            };

            instance.analyzer.reload_patterns(&db);
            instance.pattern_db = db;
            instance.pattern_reload_failures = 0;
            write_proto_message(
                out,
                &proto::StatusResponse {
                    ok: true,
                    message: None,
                },
            )
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
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
                instance.analyzer.import_kids_memory_state(&kids_state);
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

/// Removes expired conversation timelines and contact profiles.
///
/// **Must be called periodically by the host application.** AURA does not
/// run background timers — the host is responsible for invoking this
/// function to prevent unbounded memory growth from accumulated
/// conversation state.
///
/// Recommended calling patterns:
///
/// - **App lifecycle:** call on every `applicationDidBecomeActive` /
///   `onResume` transition.
/// - **Periodic timer:** every 5–15 minutes while the app is active.
/// - **After heavy sessions:** immediately after processing a large
///   batch of messages (e.g. chat sync on reconnect).
///
/// `now_ms` is the current wall-clock time in milliseconds since the
/// Unix epoch. Events older than `ttl_days` (from config, default 30)
/// are removed.
///
/// # C example
/// ```c
/// #include <time.h>
/// uint64_t now_ms = (uint64_t)time(NULL) * 1000;
/// aura_cleanup_context(handle, now_ms);
/// ```
///
/// # Swift example
/// ```swift
/// let nowMs = UInt64(Date().timeIntervalSince1970 * 1000)
/// aura_cleanup_context(handle, nowMs)
/// ```
#[no_mangle]
pub unsafe extern "C" fn aura_cleanup_context(handle: *mut c_void, now_ms: u64) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        match with_instance(handle, |instance| {
            instance.analyzer.cleanup_context(now_ms);
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

/// Returns all tracked contacts sorted by risk score as a protobuf-encoded buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_get_contacts_by_risk(
    handle: *mut c_void,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        match with_instance(handle, |instance| {
            let profiler = instance.analyzer.context_tracker().contact_profiler();
            let contacts = profiler
                .contacts_by_risk()
                .iter()
                .map(|contact| {
                    contact_profile_to_proto(contact, profiler.is_new_contact(&contact.sender_id))
                })
                .collect();

            write_proto_message(out, &proto::ContactsByRiskResponse { contacts })
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Returns the behavioral profile of a specific contact as a protobuf-encoded buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_get_contact_profile(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let request: proto::ContactProfileRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "contact profile request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let profiler = instance.analyzer.context_tracker().contact_profiler();
            let response = match profiler.profile(&request.sender_id) {
                Some(profile) => proto::ContactProfileResponse {
                    found: true,
                    profile: Some(contact_profile_to_proto(
                        profile,
                        profiler.is_new_contact(&profile.sender_id),
                    )),
                },
                None => proto::ContactProfileResponse {
                    found: false,
                    profile: None,
                },
            };

            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Marks a contact as trusted, suppressing future risk signals for that contact.
#[no_mangle]
pub unsafe extern "C" fn aura_mark_contact_trusted(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        let request: proto::MarkContactTrustedRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "mark_contact_trusted request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        match with_instance(handle, |instance| {
            instance.analyzer.mark_contact_trusted(&request.sender_id);
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

/// Processes guardian feedback to adjust kids memory state.
///
/// Accepts a protobuf-encoded `GuardianFeedbackRequest` and applies the
/// guardian's verdict (Trusted, Block, Monitor, FalsePositive) to the
/// kids conversation and sender memory.
#[no_mangle]
pub unsafe extern "C" fn aura_guardian_feedback(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        let request: proto::GuardianFeedbackRequest = match decode_proto_bounded(
            request_ptr,
            request_len,
            "guardian_feedback request",
            MAX_SMALL_CONTROL_REQUEST_BYTES,
        ) {
            Ok(request) => request,
            Err(e) => {
                set_last_error(e);
                return false;
            }
        };

        let verdict = match proto::GuardianVerdict::try_from(request.verdict) {
            Ok(proto::GuardianVerdict::Trusted) => {
                aura_agent_core::aura_kids::pipeline::GuardianVerdict::Trusted
            }
            Ok(proto::GuardianVerdict::Block) => {
                aura_agent_core::aura_kids::pipeline::GuardianVerdict::Block
            }
            Ok(proto::GuardianVerdict::Monitor) => {
                aura_agent_core::aura_kids::pipeline::GuardianVerdict::Monitor
            }
            Ok(proto::GuardianVerdict::FalsePositive) => {
                aura_agent_core::aura_kids::pipeline::GuardianVerdict::FalsePositive
            }
            Ok(proto::GuardianVerdict::Unspecified) | Err(_) => {
                set_last_error("unspecified or invalid guardian verdict".to_string());
                return false;
            }
        };

        match with_instance(handle, |_instance| {
            aura_agent_core::aura_kids::pipeline::apply_guardian_feedback(
                &request.sender_id,
                &request.conversation_id,
                verdict,
            );
            let response = proto::GuardianFeedbackResponse {
                ok: true,
                message: None,
            };
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Performs a lightweight safety check on raw UTF-8 text for notification filtering.
///
/// Accepts raw text bytes (not protobuf) and returns a protobuf-encoded
/// `StatusResponse`. The `ok` field is `true` when the text is safe to
/// display (action is `Allow` or `Mark`). When the text is unsafe, `ok`
/// is `false` and `message` contains the threat type name (e.g.
/// `"Grooming"`, `"SelfHarm"`).
///
/// This is faster than `aura_analyze` because it skips protobuf
/// decode on the input side and runs a stateless analysis (no context
/// tracking).
#[no_mangle]
pub unsafe extern "C" fn aura_quick_check(
    handle: *mut c_void,
    text_ptr: *const u8,
    text_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        if text_ptr.is_null() {
            set_last_error("null text pointer");
            return false;
        }

        if text_len == 0 || text_len > MAX_QUICK_CHECK_TEXT_BYTES {
            set_last_error(format!(
                "text length {text_len} out of range (1..{MAX_QUICK_CHECK_TEXT_BYTES})"
            ));
            return false;
        }

        let text_bytes = std::slice::from_raw_parts(text_ptr, text_len);
        let text = match std::str::from_utf8(text_bytes) {
            Ok(s) => s.to_string(),
            Err(e) => {
                set_last_error(format!("invalid UTF-8 in text input: {e}"));
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let input = MessageInput {
                content_type: aura_agent_core::ContentType::Text,
                text: Some(text),
                image_data: None,
                sender_id: aura_agent_core::SenderId::from("notification"),
                conversation_id: aura_agent_core::ConversationId::from("notification"),
                language: None,
                conversation_type: aura_agent_core::ConversationType::Direct,
                member_count: None,
                server_sender_risk_hint: None,
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            };
            let result = instance.analyzer.analyze_local(&input);
            let safe = match result.action {
                Action::Allow | Action::Mark => true,
                Action::Blur | Action::Warn | Action::Block => false,
            };
            let message = match safe {
                true => None,
                false => Some(format!("{:?}", result.threat_type)),
            };
            let response = proto::StatusResponse { ok: safe, message };
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Checks a single URL for phishing or malicious patterns.
///
/// Accepts raw UTF-8 URL bytes (not protobuf) and returns a
/// protobuf-encoded `StatusResponse`. The `ok` field is `true` when the
/// URL appears safe. When the URL is suspicious or blocked, `ok` is
/// `false` and `message` contains the threat description.
#[no_mangle]
pub unsafe extern "C" fn aura_detect_suspicious_url(
    handle: *mut c_void,
    url_ptr: *const u8,
    url_len: usize,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        if url_ptr.is_null() {
            set_last_error("null url pointer");
            return false;
        }

        if url_len == 0 || url_len > MAX_URL_INPUT_BYTES {
            set_last_error(format!(
                "url length {url_len} out of range (1..{MAX_URL_INPUT_BYTES})"
            ));
            return false;
        }

        let url_bytes = std::slice::from_raw_parts(url_ptr, url_len);
        let url = match std::str::from_utf8(url_bytes) {
            Ok(s) => s.to_string(),
            Err(e) => {
                set_last_error(format!("invalid UTF-8 in url input: {e}"));
                return false;
            }
        };

        match with_instance(handle, |instance| {
            let checker = aura_patterns::UrlChecker::from_database(&instance.pattern_db);

            let blocked_matches = checker.find_blocked_matches(&url);
            if let Some(hit) = blocked_matches.first() {
                let response = proto::StatusResponse {
                    ok: false,
                    message: Some(format!("{}: {}", hit.threat_type, hit.explanation)),
                };
                return write_proto_message(out, &response);
            }

            let suspicious = checker.find_suspicious_urls(&url);
            if let Some(hit) = suspicious.first() {
                let response = proto::StatusResponse {
                    ok: false,
                    message: Some(hit.explanation.clone()),
                };
                return write_proto_message(out, &response);
            }

            let response = proto::StatusResponse {
                ok: true,
                message: None,
            };
            write_proto_message(out, &response)
        }) {
            Ok(()) => true,
            Err(e) => {
                set_last_error(e);
                false
            }
        }
    })
}

/// Returns a summary of all tracked conversations as a protobuf-encoded buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_get_conversation_summary(
    handle: *mut c_void,
    out: *mut AuraBuffer,
) -> bool {
    ffi_guard(false, move || {
        clear_last_error();

        if let Err(e) = prepare_output(out) {
            set_last_error(e);
            return false;
        }

        match with_instance(handle, |instance| {
            let summary = conversation_summary_to_proto(instance.analyzer.context_tracker());
            write_proto_message(out, &summary)
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
/// if (aura_analyze(handle, req, req_len, &out)) {
///     process(out.ptr, out.len);
///     aura_free_buffer(out);   // mandatory
/// }
/// ```
///
/// # Swift example
/// ```swift
/// var out = AuraBuffer()
/// if aura_analyze(handle, req, reqLen, &out) {
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
        let message = LAST_ERROR
            .with(|e| e.borrow().clone())
            .or_else(|| LAST_ERROR_GLOBAL.lock().ok().and_then(|guard| guard.clone()));
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

fn resolve_pattern_db_for_update(
    current_db: &PatternDatabase,
    config: &AuraConfig,
) -> PatternDatabase {
    match config.patterns_path.as_deref() {
        Some(path) => match try_load_pattern_db(path) {
            Ok(db) => db,
            Err(error) => {
                warn!(
                    patterns_path = %path,
                    error = %error,
                    "keeping existing pattern database during config update"
                );
                current_db.clone()
            }
        },
        None => PatternDatabase::default_mvp(),
    }
}

fn aura_config_from_proto(config: proto::AuraConfig) -> Result<AuraConfig, String> {
    let account_holder_age = match config.account_holder_age {
        Some(age) if age > u16::MAX as u32 => {
            return Err(format!("account_holder_age {age} exceeds u16 range"));
        }
        Some(age) => Some(age as u16),
        None => None,
    };

    Ok(AuraConfig {
        protection_level: protection_level_from_proto(config.protection_level),
        account_type: account_type_from_proto(config.account_type),
        language: if config.language.is_empty() {
            "uk".to_string()
        } else {
            config.language
        },
        cultural_context: cultural_context_from_proto(config.cultural_context),
        enabled: config.enabled,
        patterns_path: config.patterns_path,
        models_path: config.models_path,
        account_holder_age,
        ttl_days: if config.ttl_days == 0 {
            30
        } else {
            config.ttl_days
        },
        timezone_offset_minutes: config.timezone_offset_minutes,
        protected_account_id: None,
        // Domain mode is the only account-level selector.
        domain_mode: domain_mode_from_proto(config.domain_mode),
    })
}

fn decoded_config_from_proto(config: proto::AuraConfig) -> Result<DecodedConfig, String> {
    let relay_policy = relay_policy_from_proto(config.relay_policy.as_ref())?;
    let relay_request_auth_key = relay_request_auth_key_from_proto(
        config
            .relay_policy
            .as_ref()
            .and_then(|policy| policy.request_auth_key.as_ref()),
    )?;
    let relay_response_auth_keys =
        relay_response_auth_keys_from_proto(config.relay_policy.as_ref())?;
    if relay_policy.require_relay_auth
        && (relay_request_auth_key.is_none() || relay_response_auth_keys.is_empty())
    {
        return Err(
            "relay auth is required but request or response auth keys are missing".to_string(),
        );
    }
    validate_required_protected_account_attestation(&relay_policy)?;
    let mut aura_config = aura_config_from_proto(config)?;
    aura_config.protected_account_id = relay_policy.protected_account_id.clone();

    Ok(DecodedConfig {
        aura_config,
        relay_policy,
        relay_request_auth_key,
        relay_response_auth_keys,
    })
}

fn validate_required_protected_account_attestation(
    relay_policy: &AgentRelayPolicy,
) -> Result<(), String> {
    if !relay_policy.require_protected_account_attestation {
        return Ok(());
    }
    let protected_account_id = relay_policy
        .protected_account_id
        .as_deref()
        .ok_or_else(|| {
            "protected account attestation is required but protected_account_id is missing"
                .to_string()
        })?;
    let attestation = relay_policy
        .protected_account_attestation
        .as_ref()
        .ok_or_else(|| {
            "protected account attestation is required but attestation is missing".to_string()
        })?;
    let expected_token = format!(
        "acct_{}",
        aura_agent_core::tokenize_identifier(protected_account_id).token
    );
    if attestation.protected_account_token != expected_token {
        return Err(
            "protected account attestation token does not match protected_account_id".to_string(),
        );
    }
    if attestation.expires_at_ms <= current_unix_ms() {
        return Err(
            "protected account attestation is required but attestation is expired".to_string(),
        );
    }
    Ok(())
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn relay_request_auth_key_from_proto(
    key: Option<&proto::RelayRequestAuthKey>,
) -> Result<Option<RelayRequestAuthKey>, String> {
    let Some(key) = key else {
        return Ok(None);
    };
    validate_relay_auth_key(&key.key_id, &key.secret, "request").map(|key_id| {
        Some(RelayRequestAuthKey {
            key_id,
            secret: key.secret.clone(),
        })
    })
}

fn relay_response_auth_keys_from_proto(
    policy: Option<&proto::AgentRelayPolicy>,
) -> Result<Vec<RelayResponseAuthKey>, String> {
    let Some(policy) = policy else {
        return Ok(Vec::new());
    };

    let mut keys = Vec::new();
    if let Some(key) = policy.response_auth_key.as_ref() {
        keys.push(relay_response_auth_key_from_proto(key)?);
    }
    for key in &policy.accepted_response_auth_keys {
        keys.push(relay_response_auth_key_from_proto(key)?);
    }
    validate_unique_relay_auth_key_ids(&keys, "response")?;
    Ok(keys)
}

fn relay_response_auth_key_from_proto(
    key: &proto::RelayResponseAuthKey,
) -> Result<RelayResponseAuthKey, String> {
    validate_relay_auth_key(&key.key_id, &key.secret, "response").map(|key_id| {
        RelayResponseAuthKey {
            key_id,
            secret: key.secret.clone(),
        }
    })
}

fn validate_unique_relay_auth_key_ids(
    keys: &[RelayResponseAuthKey],
    direction: &str,
) -> Result<(), String> {
    if keys.len() > MAX_RELAY_AUTH_KEYS {
        return Err(format!(
            "relay {direction} auth key set exceeds limit of {MAX_RELAY_AUTH_KEYS}"
        ));
    }
    for (index, key) in keys.iter().enumerate() {
        if keys
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.key_id == key.key_id)
        {
            return Err(format!(
                "relay {direction} auth key_id {} is duplicated",
                key.key_id
            ));
        }
    }
    Ok(())
}

fn validate_relay_auth_key(key_id: &str, secret: &[u8], direction: &str) -> Result<String, String> {
    let key_id = key_id.trim();
    if !relay_auth_key_id_is_valid(key_id) {
        return Err(format!(
            "relay {direction} auth key_id must be 1..64 ASCII [A-Za-z0-9_.-] characters"
        ));
    }
    if secret.len() < MIN_RELAY_AUTH_SECRET_BYTES || secret.len() > MAX_RELAY_AUTH_SECRET_BYTES {
        return Err(format!(
            "relay {direction} auth secret must be {MIN_RELAY_AUTH_SECRET_BYTES}..={MAX_RELAY_AUTH_SECRET_BYTES} bytes"
        ));
    }

    Ok(key_id.to_string())
}

fn relay_auth_key_id_is_valid(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= 64
        && key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn relay_policy_from_proto(
    policy: Option<&proto::AgentRelayPolicy>,
) -> Result<AgentRelayPolicy, String> {
    let Some(policy) = policy else {
        return Ok(AgentRelayPolicy::default());
    };

    let mut relay_policy = AgentRelayPolicy::default();
    if let Some(enabled) = policy.enabled {
        relay_policy.enabled = enabled;
    }
    if let Some(score_threshold) = policy.score_threshold {
        if !(0.0..=1.0).contains(&score_threshold) {
            return Err(format!(
                "relay score_threshold {score_threshold} outside 0.0..=1.0"
            ));
        }
        relay_policy.score_threshold = score_threshold;
    }
    if let Some(send_on_high_uncertainty) = policy.send_on_high_uncertainty {
        relay_policy.send_on_high_uncertainty = send_on_high_uncertainty;
    }
    if let Some(send_on_new_contact) = policy.send_on_new_contact {
        relay_policy.send_on_new_contact = send_on_new_contact;
    }
    if let Some(send_on_repeated_sender) = policy.send_on_repeated_sender {
        relay_policy.send_on_repeated_sender = send_on_repeated_sender;
    }
    relay_policy.privacy_mode = relay_privacy_mode_from_proto(policy.privacy_mode);
    if let Some(max_recent_window_messages) = policy.max_recent_window_messages {
        relay_policy.max_recent_window_messages =
            max_recent_window_messages.min(MAX_RELAY_RECENT_WINDOW_MESSAGES as u32) as usize;
    }
    if let Some(deadline_ms) = policy.deadline_ms {
        relay_policy.deadline_ms = (deadline_ms != 0).then_some(deadline_ms);
    }
    if let Some(emit_local_safety_telemetry) = policy.emit_local_safety_telemetry {
        relay_policy.emit_local_safety_telemetry = emit_local_safety_telemetry;
    }
    if let Some(require_relay_auth) = policy.require_relay_auth {
        relay_policy.require_relay_auth = require_relay_auth;
    }
    if let Some(require_protected_account_attestation) =
        policy.require_protected_account_attestation
    {
        relay_policy.require_protected_account_attestation = require_protected_account_attestation;
    }
    relay_policy.protected_account_id = policy
        .protected_account_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    relay_policy.protected_account_attestation =
        protected_account_attestation_from_proto(policy.protected_account_attestation.as_ref())?;

    Ok(relay_policy)
}

fn protected_account_attestation_from_proto(
    attestation: Option<&proto::ProtectedAccountTokenAttestation>,
) -> Result<Option<ProtectedAccountTokenAttestationContract>, String> {
    let Some(attestation) = attestation else {
        return Ok(None);
    };
    let key_id = attestation.key_id.trim();
    if !relay_auth_key_id_is_valid(key_id) {
        return Err(
            "protected account attestation key_id must be 1..64 ASCII [A-Za-z0-9_.-] characters"
                .to_string(),
        );
    }
    if attestation.alg != PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG {
        return Err(format!(
            "protected account attestation alg must be {PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG}"
        ));
    }
    if attestation.expires_at_ms == 0 {
        return Err("protected account attestation expires_at_ms must be non-zero".to_string());
    }
    let token_check = RelayAnalyzeRequestContract {
        protected_account_token: Some(attestation.protected_account_token.clone()),
        ..RelayAnalyzeRequestContract::default()
    };
    if token_check.privacy_safe_protected_account_token().is_none() {
        return Err(
            "protected account attestation protected_account_token must be privacy-safe acct_ token"
                .to_string(),
        );
    }
    if !hmac_tag_is_hex_32(&attestation.tag) {
        return Err("protected account attestation tag must be 64 hex characters".to_string());
    }

    Ok(Some(ProtectedAccountTokenAttestationContract {
        key_id: key_id.to_string(),
        alg: attestation.alg.clone(),
        protected_account_token: attestation.protected_account_token.clone(),
        expires_at_ms: attestation.expires_at_ms,
        tag: attestation.tag.clone(),
    }))
}

fn hmac_tag_is_hex_32(tag: &str) -> bool {
    tag.len() == 64 && tag.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn relay_privacy_mode_from_proto(mode: i32) -> RelayPrivacyMode {
    match proto::RelayPrivacyMode::try_from(mode).unwrap_or(proto::RelayPrivacyMode::Unspecified) {
        proto::RelayPrivacyMode::MetadataOnly => RelayPrivacyMode::MetadataOnly,
        proto::RelayPrivacyMode::MessageAndWindow => RelayPrivacyMode::MessageAndWindow,
        proto::RelayPrivacyMode::Unspecified | proto::RelayPrivacyMode::MessageOnly => {
            RelayPrivacyMode::MessageOnly
        }
    }
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
        server_sender_risk_hint: message.server_sender_risk_hint,
        sender_relationship: sender_relationship_from_proto(message.sender_relationship),
        relationship_trust_source: relationship_trust_source_from_proto(
            message.relationship_trust_source,
        ),
    }
}

fn shadow_mode_expectation_from_proto(
    expectation: Option<proto::ShadowModeExpectation>,
) -> Option<ShadowModeExpectation> {
    expectation.and_then(|expectation| {
        let expect_threat = match proto::ThreatType::try_from(expectation.expect_threat)
            .unwrap_or(proto::ThreatType::Unspecified)
        {
            proto::ThreatType::Unspecified => None,
            proto::ThreatType::None => Some(aura_agent_core::ThreatType::None),
            proto::ThreatType::Bullying => Some(aura_agent_core::ThreatType::Bullying),
            proto::ThreatType::Grooming => Some(aura_agent_core::ThreatType::Grooming),
            proto::ThreatType::Explicit => Some(aura_agent_core::ThreatType::Explicit),
            proto::ThreatType::Threat => Some(aura_agent_core::ThreatType::Threat),
            proto::ThreatType::SelfHarm => Some(aura_agent_core::ThreatType::SelfHarm),
            proto::ThreatType::Spam => Some(aura_agent_core::ThreatType::Spam),
            proto::ThreatType::Scam => Some(aura_agent_core::ThreatType::Scam),
            proto::ThreatType::Phishing => Some(aura_agent_core::ThreatType::Phishing),
            proto::ThreatType::Manipulation => Some(aura_agent_core::ThreatType::Manipulation),
            proto::ThreatType::Nsfw => Some(aura_agent_core::ThreatType::Nsfw),
            proto::ThreatType::HateSpeech => Some(aura_agent_core::ThreatType::HateSpeech),
            proto::ThreatType::Doxxing => Some(aura_agent_core::ThreatType::Doxxing),
            proto::ThreatType::PiiLeakage => Some(aura_agent_core::ThreatType::PiiLeakage),
            proto::ThreatType::Propaganda => Some(aura_agent_core::ThreatType::Propaganda),
            proto::ThreatType::OpsecViolation => Some(aura_agent_core::ThreatType::OpsecViolation),
            proto::ThreatType::Psyops => Some(aura_agent_core::ThreatType::Psyops),
            proto::ThreatType::MilitarySocialEng => {
                Some(aura_agent_core::ThreatType::MilitarySocialEng)
            }
            proto::ThreatType::CoordinateLeak => Some(aura_agent_core::ThreatType::CoordinateLeak),
        };
        let expect_min_action = match proto::Action::try_from(expectation.expect_min_action)
            .unwrap_or(proto::Action::Unspecified)
        {
            proto::Action::Unspecified => None,
            proto::Action::Allow => Some(Action::Allow),
            proto::Action::Mark => Some(Action::Mark),
            proto::Action::Blur => Some(Action::Blur),
            proto::Action::Warn => Some(Action::Warn),
            proto::Action::Block => Some(Action::Block),
        };
        let expect_min_alert = match proto::AlertPriority::try_from(expectation.expect_min_alert)
            .unwrap_or(proto::AlertPriority::Unspecified)
        {
            proto::AlertPriority::Unspecified => None,
            proto::AlertPriority::None => Some(AlertPriority::None),
            proto::AlertPriority::Low => Some(AlertPriority::Low),
            proto::AlertPriority::Medium => Some(AlertPriority::Medium),
            proto::AlertPriority::High => Some(AlertPriority::High),
            proto::AlertPriority::Urgent => Some(AlertPriority::Urgent),
        };

        if expect_threat.is_none() && expect_min_action.is_none() && expect_min_alert.is_none() {
            None
        } else {
            Some(ShadowModeExpectation {
                expect_threat,
                expect_min_action,
                expect_min_alert,
            })
        }
    })
}

fn non_empty_or(value: String, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value
    }
}

fn shadow_mode_findings_for_event(
    sequence: usize,
    request_id: &str,
    timestamp_ms: u64,
    expectation: Option<&ShadowModeExpectation>,
    result: &aura_agent_core::AnalysisResult,
) -> Vec<ShadowModeFinding> {
    let mut findings = Vec::new();
    let Some(expectation) = expectation else {
        return findings;
    };

    if let Some(expected_threat) = expectation.expect_threat {
        let threat_present = result.threat_type == expected_threat
            || result
                .detected_threats
                .iter()
                .any(|(threat, _)| *threat == expected_threat);
        if !threat_present {
            findings.push(ShadowModeFinding {
                severity: "warning".to_string(),
                event_sequence: sequence,
                request_id: request_id.to_string(),
                timestamp_ms,
                message: format!(
                    "expected threat '{}' but runtime returned '{}'",
                    threat_label(expected_threat),
                    threat_label(result.threat_type)
                ),
            });
        }
    }

    if let Some(expected_action) = expectation.expect_min_action {
        if result.action < expected_action {
            findings.push(ShadowModeFinding {
                severity: "warning".to_string(),
                event_sequence: sequence,
                request_id: request_id.to_string(),
                timestamp_ms,
                message: format!(
                    "expected action >= '{}' but runtime returned '{}'",
                    action_label(expected_action),
                    action_label(result.action)
                ),
            });
        }
    }

    if let Some(expected_alert) = expectation.expect_min_alert {
        let actual_alert = result
            .recommended_action
            .as_ref()
            .map(|recommendation| recommendation.parent_alert)
            .unwrap_or(AlertPriority::None);
        if actual_alert < expected_alert {
            findings.push(ShadowModeFinding {
                severity: "warning".to_string(),
                event_sequence: sequence,
                request_id: request_id.to_string(),
                timestamp_ms,
                message: format!(
                    "expected alert >= '{}' but runtime returned '{}'",
                    alert_label(expected_alert),
                    alert_label(actual_alert)
                ),
            });
        }
    }

    findings
}

fn threat_label(value: aura_agent_core::ThreatType) -> &'static str {
    match value {
        aura_agent_core::ThreatType::None => "none",
        aura_agent_core::ThreatType::Bullying => "bullying",
        aura_agent_core::ThreatType::Grooming => "grooming",
        aura_agent_core::ThreatType::Explicit => "explicit",
        aura_agent_core::ThreatType::Threat => "threat",
        aura_agent_core::ThreatType::SelfHarm => "self_harm",
        aura_agent_core::ThreatType::Spam => "spam",
        aura_agent_core::ThreatType::Scam => "scam",
        aura_agent_core::ThreatType::Phishing => "phishing",
        aura_agent_core::ThreatType::Manipulation => "manipulation",
        aura_agent_core::ThreatType::Nsfw => "nsfw",
        aura_agent_core::ThreatType::HateSpeech => "hate_speech",
        aura_agent_core::ThreatType::Doxxing => "doxxing",
        aura_agent_core::ThreatType::PiiLeakage => "pii_leakage",
        aura_agent_core::ThreatType::Propaganda => "propaganda",
        aura_agent_core::ThreatType::OpsecViolation => "opsec_violation",
        aura_agent_core::ThreatType::Psyops => "psyops",
        aura_agent_core::ThreatType::MilitarySocialEng => "military_social_eng",
        aura_agent_core::ThreatType::CoordinateLeak => "coordinate_leak",
    }
}

fn action_label(value: aura_agent_core::Action) -> &'static str {
    match value {
        aura_agent_core::Action::Allow => "allow",
        aura_agent_core::Action::Mark => "mark",
        aura_agent_core::Action::Blur => "blur",
        aura_agent_core::Action::Warn => "warn",
        aura_agent_core::Action::Block => "block",
    }
}

fn alert_label(value: aura_agent_core::AlertPriority) -> &'static str {
    match value {
        aura_agent_core::AlertPriority::None => "none",
        aura_agent_core::AlertPriority::Low => "low",
        aura_agent_core::AlertPriority::Medium => "medium",
        aura_agent_core::AlertPriority::High => "high",
        aura_agent_core::AlertPriority::Urgent => "urgent",
    }
}

fn normalized_reason_code(reason_code: &str) -> &str {
    reason_code.strip_prefix("domain.").unwrap_or(reason_code)
}

fn kids_memory_reason_codes(reason_codes: &[String]) -> Vec<String> {
    let mut filtered = Vec::new();
    for reason_code in reason_codes {
        let reason_code = normalized_reason_code(reason_code);
        if !reason_code.starts_with("kids.memory.") {
            continue;
        }
        if filtered.iter().any(|existing| existing == reason_code) {
            continue;
        }
        filtered.push(reason_code.to_string());
    }
    filtered
}

fn has_mandatory_kids_memory_reason(reason_codes: &[String]) -> bool {
    for reason_code in reason_codes {
        for mandatory in MANDATORY_KIDS_MEMORY_REASON_CODES {
            if reason_code == mandatory {
                return true;
            }
        }
    }
    false
}

fn kids_memory_explainability_to_proto(
    reason_codes: &[String],
    conversation_id: Option<&str>,
    sender_id: Option<&str>,
) -> Option<proto::KidsMemoryExplainability> {
    let reason_codes = kids_memory_reason_codes(reason_codes);
    if reason_codes.is_empty() {
        return None;
    }
    let conversation_risk_score = conversation_id
        .map(aura_agent_core::aura_kids::pipeline::conversation_risk_score)
        .unwrap_or(0.0);
    let sender_risk_score = sender_id
        .map(aura_agent_core::aura_kids::pipeline::sender_cross_risk_score)
        .unwrap_or(0.0);
    let escalation_message_count = conversation_id
        .map(aura_agent_core::aura_kids::pipeline::conversation_escalation_message_count)
        .unwrap_or(0);
    Some(proto::KidsMemoryExplainability {
        reason_codes: reason_codes.clone(),
        mandatory_guardian_escalation: has_mandatory_kids_memory_reason(&reason_codes),
        conversation_risk_score,
        sender_risk_score,
        escalation_message_count,
    })
}

fn analysis_result_to_proto(
    result: &aura_agent_core::AnalysisResult,
    conversation_id: Option<&str>,
    sender_id: Option<&str>,
) -> proto::AnalysisResult {
    proto::AnalysisResult {
        threat_type: proto_threat_type(result.threat_type) as i32,
        confidence: proto_confidence(result.confidence) as i32,
        action: proto_action(result.action) as i32,
        score: result.score,
        explanation: result.explanation.clone(),
        detected_threats: result
            .detected_threats
            .iter()
            .map(|(threat_type, score)| proto::ThreatScore {
                threat_type: proto_threat_type(*threat_type) as i32,
                score: *score,
            })
            .collect(),
        signals: result
            .signals
            .iter()
            .map(detection_signal_to_proto)
            .collect(),
        recommended_action: result
            .recommended_action
            .as_ref()
            .map(action_recommendation_to_proto),
        risk_breakdown: Some(risk_breakdown_to_proto(&result.risk_breakdown)),
        contact_snapshot: result
            .contact_snapshot
            .as_ref()
            .map(contact_snapshot_to_proto),
        reason_codes: result.reason_codes.clone(),
        analysis_time_us: result.analysis_time_us,
        inference: Some(inference_summary_to_proto(&result.inference)),
        product_surface: Some(product_decision_surface_to_proto(
            &build_product_decision_surface(result, ProductRolloutMode::GuardianEnabled),
        )),
        kids_memory: kids_memory_explainability_to_proto(
            &result.reason_codes,
            conversation_id,
            sender_id,
        ),
    }
}

fn product_decision_surface_to_proto(
    surface: &aura_agent_core::ProductDecisionSurface,
) -> proto::ProductDecisionSurface {
    proto::ProductDecisionSurface {
        schema_version: surface.schema_version.clone(),
        rollout_mode: proto_product_rollout_mode(surface.rollout_mode) as i32,
        threat_type: proto_threat_type(surface.threat_type) as i32,
        action: proto_action(surface.action) as i32,
        score: surface.score,
        child: Some(product_child_surface_to_proto(&surface.child)),
        guardian: Some(product_guardian_surface_to_proto(&surface.guardian)),
        review: Some(product_review_surface_to_proto(&surface.review)),
        uncertainty_disposition: proto_product_uncertainty_disposition(
            surface.uncertainty_disposition,
        ) as i32,
    }
}

fn product_child_surface_to_proto(
    surface: &aura_agent_core::ProductChildSurface,
) -> proto::ProductChildSurface {
    proto::ProductChildSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        visible: surface.visible,
        intervention: proto_product_child_intervention(surface.intervention) as i32,
        ui_actions: surface
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        reason_codes: surface.reason_codes.clone(),
    }
}

fn product_guardian_surface_to_proto(
    surface: &aura_agent_core::ProductGuardianSurface,
) -> proto::ProductGuardianSurface {
    proto::ProductGuardianSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        notify: surface.notify,
        priority: proto_alert_priority(surface.priority) as i32,
        follow_ups: surface
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        reason_codes: surface.reason_codes.clone(),
    }
}

fn product_review_surface_to_proto(
    surface: &aura_agent_core::ProductReviewSurface,
) -> proto::ProductReviewSurface {
    proto::ProductReviewSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        open_review: surface.open_review,
        urgency: proto_product_review_urgency(surface.urgency) as i32,
        reason_codes: surface.reason_codes.clone(),
        latent_states: surface
            .latent_states
            .iter()
            .map(|kind| proto_latent_state_kind(*kind) as i32)
            .collect(),
    }
}

fn detection_signal_to_proto(signal: &aura_agent_core::DetectionSignal) -> proto::DetectionSignal {
    proto::DetectionSignal {
        threat_type: proto_threat_type(signal.threat_type) as i32,
        score: signal.score,
        confidence: proto_confidence(signal.confidence) as i32,
        layer: proto_detection_layer(signal.layer) as i32,
        family: proto_signal_family(signal.family) as i32,
        reason_code: signal.reason_code.clone(),
        explanation: signal.explanation.clone(),
        threat_subtype: signal.threat_subtype.clone(),
    }
}

fn relay_request_to_proto(request: &RelayAnalyzeRequestContract) -> proto::RelayAnalyzeRequest {
    proto::RelayAnalyzeRequest {
        schema_version: request.schema_version.clone(),
        request_id: request.request_id.clone(),
        message_id: request.message_id.clone(),
        sender_token: request.sender_token.clone(),
        protected_account_token: request.protected_account_token.clone(),
        conversation_token: request.conversation_token.clone(),
        account_type: proto_account_type(request.account_type) as i32,
        protection_level: proto_protection_level(request.protection_level) as i32,
        conversation_type: proto_conversation_type(request.conversation_type) as i32,
        language: request.language.clone(),
        text: request.text.clone(),
        local_observations: request
            .local_observations
            .iter()
            .map(relay_observation_to_proto)
            .collect(),
        local_context_summary: Some(relay_local_context_summary_to_proto(
            &request.local_context_summary,
        )),
        local_safety_telemetry: request
            .local_safety_telemetry
            .iter()
            .map(relay_safety_telemetry_to_proto)
            .collect(),
        recent_message_window: request
            .recent_message_window
            .iter()
            .map(|entry| proto::RelayMessageWindowEntry {
                sender_id: entry.sender_id.clone(),
                text: entry.text.clone(),
                timestamp_ms: entry.timestamp_ms,
            })
            .collect(),
        server_sender_risk_hint: request.server_sender_risk_hint,
        sender_relationship: proto_sender_relationship(request.sender_relationship) as i32,
        relationship_trust_source: proto_relationship_trust_source(
            request.relationship_trust_source,
        ) as i32,
        privacy_mode: proto_relay_privacy_mode(request.privacy_mode) as i32,
        capabilities: Some(proto::RelayAgentCapabilities {
            local_context_interpreter: request.capabilities.local_context_interpreter,
            local_tracker: request.capabilities.local_tracker,
            supports_remote_correlation: request.capabilities.supports_remote_correlation,
            relay_timeout_ms: request.capabilities.relay_timeout_ms,
        }),
        deadline_ms: request.deadline_ms,
        protected_account_attestation: request
            .protected_account_attestation
            .as_ref()
            .map(protected_account_attestation_to_proto),
        auth: request.auth.as_ref().map(relay_request_auth_to_proto),
    }
}

fn protected_account_attestation_to_proto(
    attestation: &ProtectedAccountTokenAttestationContract,
) -> proto::ProtectedAccountTokenAttestation {
    proto::ProtectedAccountTokenAttestation {
        key_id: attestation.key_id.clone(),
        alg: attestation.alg.clone(),
        protected_account_token: attestation.protected_account_token.clone(),
        expires_at_ms: attestation.expires_at_ms,
        tag: attestation.tag.clone(),
    }
}

fn relay_request_auth_to_proto(auth: &RelayRequestAuthContract) -> proto::RelayRequestAuth {
    proto::RelayRequestAuth {
        key_id: auth.key_id.clone(),
        alg: auth.alg.clone(),
        tag: auth.tag.clone(),
    }
}

fn relay_local_context_summary_to_proto(
    summary: &aura_agent_core::aura_contracts::LocalContextSummary,
) -> proto::RelayLocalContextSummary {
    proto::RelayLocalContextSummary {
        context_markers: summary.context_markers.clone(),
        recent_observations: summary
            .recent_observations
            .iter()
            .map(relay_observation_to_proto)
            .collect(),
    }
}

fn relay_observation_to_proto(
    observation: &aura_agent_core::aura_contracts::RawObservation,
) -> proto::RelayObservation {
    proto::RelayObservation {
        threat_type: proto_threat_type(observation.threat_type) as i32,
        threat_subtype: observation.threat_subtype.clone(),
        layer: proto_relay_detection_layer(observation.layer) as i32,
        score: observation.score,
        confidence: proto_confidence(observation.confidence) as i32,
        reason_code: observation.reason_code.clone(),
        explanation: observation.explanation.clone(),
    }
}

fn relay_safety_telemetry_to_proto(
    event: &ClientSafetyTelemetryEvent,
) -> proto::RelaySafetyTelemetryEvent {
    proto::RelaySafetyTelemetryEvent {
        event_id: event.event_id.clone(),
        sender_token: event.sender_token.clone(),
        protected_account_token: event.protected_account_token.clone(),
        conversation_token: event.conversation_token.clone(),
        surface: proto_safety_telemetry_surface(event.surface) as i32,
        threat_type: proto_threat_type(event.threat_type) as i32,
        severity: proto_safety_telemetry_severity(event.severity) as i32,
        confidence: proto_confidence(event.confidence) as i32,
        action: proto_safety_telemetry_action(event.action) as i32,
        timestamp_bucket_ms: event.timestamp_bucket_ms,
        reason_family: event.reason_family.clone(),
    }
}

fn relay_response_from_proto(
    response: proto::RelayAnalyzeResponse,
) -> RelayAnalyzeResponseContract {
    RelayAnalyzeResponseContract {
        schema_version: response.schema_version,
        request_id: response.request_id,
        findings: response
            .findings
            .into_iter()
            .map(relay_remote_finding_from_proto)
            .collect(),
        inference: response.inference.map(relay_remote_inference_from_proto),
        reason_codes: response.reason_codes,
        context_markers: response.context_markers,
        confidence: confidence_from_proto(response.confidence),
        expires_at_ms: response.expires_at_ms,
        sender_reputation_hint: response.sender_reputation_hint,
        correlation_findings: response.correlation_findings,
        auth: response.auth.map(relay_response_auth_from_proto),
        ..RelayAnalyzeResponseContract::default()
    }
}

fn relay_response_auth_from_proto(auth: proto::RelayResponseAuth) -> RelayResponseAuthContract {
    RelayResponseAuthContract {
        key_id: auth.key_id,
        alg: auth.alg,
        tag: auth.tag,
    }
}

fn relay_remote_finding_from_proto(
    finding: proto::RelayRemoteFinding,
) -> RelayRemoteFindingContract {
    RelayRemoteFindingContract {
        threat_type: threat_type_from_proto(finding.threat_type),
        score: finding.score,
        confidence: confidence_from_proto(finding.confidence),
        reason_code: finding.reason_code,
        explanation: finding.explanation,
    }
}

fn relay_remote_inference_from_proto(
    inference: proto::RelayRemoteInferenceSummary,
) -> RelayRemoteInferenceSummaryContract {
    RelayRemoteInferenceSummaryContract {
        primary_threat: threat_type_from_proto(inference.primary_threat),
        score: inference.score,
        confidence: confidence_from_proto(inference.confidence),
        risk_horizon: relay_risk_horizon_from_proto(inference.risk_horizon),
    }
}

fn action_recommendation_to_proto(
    recommendation: &aura_agent_core::ActionRecommendation,
) -> proto::ActionRecommendation {
    proto::ActionRecommendation {
        parent_alert: proto_alert_priority(recommendation.parent_alert) as i32,
        follow_ups: recommendation
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        crisis_resources: recommendation.crisis_resources,
        ui_actions: recommendation
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        reason_codes: recommendation.reason_codes.clone(),
    }
}

fn contact_snapshot_to_proto(
    snapshot: &aura_agent_core::ContactSnapshot,
) -> proto::ContactSnapshot {
    proto::ContactSnapshot {
        sender_id: snapshot.sender_id.to_string(),
        rating: snapshot.rating,
        trust_level: snapshot.trust_level,
        circle_tier: proto_circle_tier(snapshot.circle_tier) as i32,
        trend: proto_behavioral_trend(snapshot.trend) as i32,
        is_trusted: snapshot.is_trusted,
        is_new_contact: snapshot.is_new_contact,
        first_seen_ms: snapshot.first_seen_ms,
        last_seen_ms: snapshot.last_seen_ms,
        conversation_count: snapshot.conversation_count as u64,
    }
}

fn risk_breakdown_to_proto(breakdown: &aura_agent_core::RiskBreakdown) -> proto::RiskBreakdown {
    proto::RiskBreakdown {
        content: breakdown.content,
        conversation: breakdown.conversation,
        link: breakdown.link,
        abuse: breakdown.abuse,
    }
}

fn inference_summary_to_proto(
    summary: &aura_agent_core::InferenceSummary,
) -> proto::InferenceSummary {
    proto::InferenceSummary {
        uncertainty: proto_uncertainty_level(summary.uncertainty) as i32,
        risk_horizon: proto_risk_horizon(summary.risk_horizon) as i32,
        escalation_likelihood_24h: summary.escalation_likelihood_24h,
        protective_factor_strength: summary.protective_factor_strength,
        latent_states: summary
            .latent_states
            .iter()
            .map(latent_state_evidence_to_proto)
            .collect(),
    }
}

fn latent_state_evidence_to_proto(
    evidence: &aura_agent_core::LatentStateEvidence,
) -> proto::LatentStateEvidence {
    proto::LatentStateEvidence {
        kind: proto_latent_state_kind(evidence.kind) as i32,
        score: evidence.score,
        reason_codes: evidence.reason_codes.clone(),
    }
}

fn protected_identifier_to_proto(
    identifier: &aura_agent_core::ProtectedIdentifier,
) -> proto::ProtectedIdentifier {
    proto::ProtectedIdentifier {
        token: identifier.token.clone(),
        scheme: identifier.scheme.clone(),
    }
}

fn audit_threat_score_to_proto(
    score: &aura_agent_core::AuditThreatScore,
) -> proto::AuditThreatScore {
    proto::AuditThreatScore {
        threat_type: proto_threat_type(score.threat_type) as i32,
        score: score.score,
    }
}

fn audit_record_to_proto(record: &aura_agent_core::AuditRecord) -> proto::AuditRecord {
    proto::AuditRecord {
        schema_version: record.schema_version.clone(),
        event_timestamp_ms: record.event_timestamp_ms,
        runtime_version: record.runtime_version.clone(),
        wire_package: record.wire_package.clone(),
        state_schema_version: record.state_schema_version,
        protection_level: proto_protection_level(record.protection_level) as i32,
        threat_type: proto_threat_type(record.threat_type) as i32,
        primary_score: record.primary_score,
        top_threat_scores: record
            .top_threat_scores
            .iter()
            .map(audit_threat_score_to_proto)
            .collect(),
        reason_codes: record.reason_codes.clone(),
        ui_actions: record
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        parent_alert: proto_alert_priority(record.parent_alert) as i32,
        follow_ups: record
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        crisis_resources: record.crisis_resources,
        contact_trend: record
            .contact_trend
            .map(|trend| proto_behavioral_trend(trend) as i32)
            .unwrap_or(proto::BehavioralTrend::Unspecified as i32),
        contact_circle_tier: record
            .contact_circle_tier
            .map(|tier| proto_circle_tier(tier) as i32)
            .unwrap_or(proto::CircleTier::Unspecified as i32),
        request_id: record.request_id.clone(),
        sender_token: record
            .sender_token
            .as_ref()
            .map(protected_identifier_to_proto),
        conversation_token: record
            .conversation_token
            .as_ref()
            .map(protected_identifier_to_proto),
        kids_memory: kids_memory_explainability_to_proto(&record.reason_codes, None, None),
    }
}

fn kids_memory_reason_counts_from_events(
    events: &[aura_agent_core::ShadowModeEvent],
) -> std::collections::HashMap<String, u64> {
    let mut counts = std::collections::HashMap::new();
    for event in events {
        let reason_codes = kids_memory_reason_codes(&event.decision.reason_codes);
        for reason_code in reason_codes {
            let entry = counts.entry(reason_code).or_insert(0u64);
            *entry = (*entry).saturating_add(1);
        }
    }
    counts
}

fn shadow_mode_privacy_to_proto(
    privacy: &aura_agent_core::ShadowModePrivacy,
) -> proto::ShadowModePrivacy {
    proto::ShadowModePrivacy {
        identifier_scheme: privacy.identifier_scheme.clone(),
        raw_text_present: privacy.raw_text_present,
        raw_identifier_fields_present: privacy.raw_identifier_fields_present,
    }
}

fn shadow_mode_summary_to_proto(
    summary: &aura_agent_core::ShadowModeSummary,
    kids_memory_reason_counts: std::collections::HashMap<String, u64>,
) -> proto::ShadowModeSummary {
    proto::ShadowModeSummary {
        total_events: summary.total_events as u64,
        threat_events: summary.threat_events as u64,
        blocked_events: summary.blocked_events as u64,
        action_counts: summary
            .action_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value as u64))
            .collect(),
        threat_counts: summary
            .threat_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value as u64))
            .collect(),
        alert_counts: summary
            .alert_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value as u64))
            .collect(),
        finding_count: summary.finding_count as u64,
        kids_memory_reason_counts,
    }
}

fn shadow_mode_expectation_to_proto(
    expectation: &aura_agent_core::ShadowModeExpectation,
) -> proto::ShadowModeExpectation {
    proto::ShadowModeExpectation {
        expect_threat: expectation
            .expect_threat
            .map(|threat| proto_threat_type(threat) as i32)
            .unwrap_or(proto::ThreatType::Unspecified as i32),
        expect_min_action: expectation
            .expect_min_action
            .map(|action| proto_action(action) as i32)
            .unwrap_or(proto::Action::Unspecified as i32),
        expect_min_alert: expectation
            .expect_min_alert
            .map(|alert| proto_alert_priority(alert) as i32)
            .unwrap_or(proto::AlertPriority::Unspecified as i32),
    }
}

fn shadow_mode_mirror_to_proto(
    mirror: &aura_agent_core::ShadowModeMirror,
) -> proto::ShadowModeMirror {
    proto::ShadowModeMirror {
        would_surface_to_child: mirror.would_surface_to_child,
        would_alert_guardian: mirror.would_alert_guardian,
        would_open_review: mirror.would_open_review,
        would_block_message: mirror.would_block_message,
    }
}

fn shadow_mode_contact_summary_to_proto(
    contact: &aura_agent_core::ShadowModeContactSummary,
) -> proto::ShadowModeContactSummary {
    proto::ShadowModeContactSummary {
        sender_token: Some(protected_identifier_to_proto(&contact.sender_token)),
        rating: contact.rating,
        trust_level: contact.trust_level,
        circle_tier: proto_circle_tier(contact.circle_tier) as i32,
        trend: proto_behavioral_trend(contact.trend) as i32,
        is_trusted: contact.is_trusted,
        is_new_contact: contact.is_new_contact,
        conversation_count: contact.conversation_count as u64,
    }
}

fn shadow_mode_decision_to_proto(
    decision: &aura_agent_core::ShadowModeDecision,
) -> proto::ShadowModeDecision {
    proto::ShadowModeDecision {
        threat_type: proto_threat_type(decision.threat_type) as i32,
        confidence: proto_confidence(decision.confidence) as i32,
        action: proto_action(decision.action) as i32,
        score: decision.score,
        reason_codes: decision.reason_codes.clone(),
        top_threat_scores: decision
            .top_threat_scores
            .iter()
            .map(audit_threat_score_to_proto)
            .collect(),
        risk_breakdown: Some(risk_breakdown_to_proto(&decision.risk_breakdown)),
        inference: Some(inference_summary_to_proto(&decision.inference)),
        parent_alert: proto_alert_priority(decision.parent_alert) as i32,
        follow_ups: decision
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        crisis_resources: decision.crisis_resources,
        ui_actions: decision
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        contact: decision
            .contact
            .as_ref()
            .map(shadow_mode_contact_summary_to_proto),
        mirror: Some(shadow_mode_mirror_to_proto(&decision.mirror)),
        product_surface: Some(product_decision_surface_to_proto(&decision.product_surface)),
        kids_memory: kids_memory_explainability_to_proto(&decision.reason_codes, None, None),
    }
}

fn shadow_mode_finding_to_proto(
    finding: &aura_agent_core::ShadowModeFinding,
) -> proto::ShadowModeFinding {
    proto::ShadowModeFinding {
        severity: finding.severity.clone(),
        event_sequence: finding.event_sequence as u64,
        request_id: finding.request_id.clone(),
        timestamp_ms: finding.timestamp_ms,
        message: finding.message.clone(),
    }
}

fn shadow_mode_event_to_proto(event: &aura_agent_core::ShadowModeEvent) -> proto::ShadowModeEvent {
    proto::ShadowModeEvent {
        request_id: event.request_id.clone(),
        sequence: event.sequence as u64,
        timestamp_ms: event.timestamp_ms,
        sender_token: Some(protected_identifier_to_proto(&event.sender_token)),
        conversation_token: Some(protected_identifier_to_proto(&event.conversation_token)),
        language: event.language.clone(),
        conversation_type: proto_conversation_type(event.conversation_type) as i32,
        member_count: event.member_count,
        expectation: event
            .expectation
            .as_ref()
            .map(shadow_mode_expectation_to_proto),
        audit_record: Some(audit_record_to_proto(&event.audit_record)),
        decision: Some(shadow_mode_decision_to_proto(&event.decision)),
    }
}

fn shadow_mode_bundle_to_proto(
    bundle: &aura_agent_core::ShadowModeBundle,
) -> proto::ShadowModeBundle {
    let kids_memory_reason_counts = kids_memory_reason_counts_from_events(&bundle.events);
    proto::ShadowModeBundle {
        schema_version: bundle.schema_version.clone(),
        generated_at_utc: bundle.generated_at_utc.clone(),
        source_kind: bundle.source_kind.clone(),
        source_label: bundle.source_label.clone(),
        source_input: bundle.source_input.clone(),
        owner_token: Some(protected_identifier_to_proto(&bundle.owner_token)),
        runtime_version: bundle.runtime_version.clone(),
        wire_package: bundle.wire_package.clone(),
        state_schema_version: bundle.state_schema_version,
        protection_level: proto_protection_level(bundle.protection_level) as i32,
        privacy: Some(shadow_mode_privacy_to_proto(&bundle.privacy)),
        summary: Some(shadow_mode_summary_to_proto(
            &bundle.summary,
            kids_memory_reason_counts,
        )),
        findings: bundle
            .findings
            .iter()
            .map(shadow_mode_finding_to_proto)
            .collect(),
        events: bundle
            .events
            .iter()
            .map(shadow_mode_event_to_proto)
            .collect(),
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
    let kids_state = state.kids_memory.as_ref().map(kids_memory_state_from_proto);
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
        conversations: state
            .conversations
            .iter()
            .map(|conv| proto::KidsConversationMemoryState {
                conversation_id: conv.conversation_id.clone(),
                message_index: conv.message_index,
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
            })
            .collect(),
    }
}

fn kids_memory_state_from_proto(
    state: &proto::KidsMemoryState,
) -> aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState {
    aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState {
        conversations: state
            .conversations
            .iter()
            .map(
                |conv| aura_agent_core::aura_kids::pipeline::ExportedConversationMemory {
                    conversation_id: conv.conversation_id.clone(),
                    message_index: conv.message_index,
                    last_activity_index: conv.message_index,
                    entries: conv
                        .entries
                        .iter()
                        .map(
                            |snap| aura_agent_core::aura_kids::pipeline::ExportedMessageSnapshot {
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
                            },
                        )
                        .collect(),
                },
            )
            .collect(),
        senders: state
            .senders
            .iter()
            .map(
                |sender| aura_agent_core::aura_kids::pipeline::ExportedSenderMemory {
                    sender_id: sender.sender_id.clone(),
                    event_index: sender.event_index,
                    last_activity_index: sender.event_index,
                    recent_high_risk_conversations: sender.recent_high_risk_conversations.clone(),
                },
            )
            .collect(),
    }
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

fn protection_level_from_proto(value: i32) -> aura_agent_core::ProtectionLevel {
    match proto::ProtectionLevel::try_from(value).unwrap_or(proto::ProtectionLevel::Medium) {
        proto::ProtectionLevel::Off => aura_agent_core::ProtectionLevel::Off,
        proto::ProtectionLevel::Low => aura_agent_core::ProtectionLevel::Low,
        proto::ProtectionLevel::Medium | proto::ProtectionLevel::Unspecified => {
            aura_agent_core::ProtectionLevel::Medium
        }
        proto::ProtectionLevel::High => aura_agent_core::ProtectionLevel::High,
    }
}

fn account_type_from_proto(value: i32) -> aura_agent_core::AccountType {
    match proto::AccountType::try_from(value).unwrap_or(proto::AccountType::Adult) {
        proto::AccountType::Adult | proto::AccountType::Unspecified => {
            aura_agent_core::AccountType::Adult
        }
        proto::AccountType::Teen => aura_agent_core::AccountType::Teen,
        proto::AccountType::Child => aura_agent_core::AccountType::Child,
    }
}

fn proto_protection_level(value: aura_agent_core::ProtectionLevel) -> proto::ProtectionLevel {
    match value {
        aura_agent_core::ProtectionLevel::Off => proto::ProtectionLevel::Off,
        aura_agent_core::ProtectionLevel::Low => proto::ProtectionLevel::Low,
        aura_agent_core::ProtectionLevel::Medium => proto::ProtectionLevel::Medium,
        aura_agent_core::ProtectionLevel::High => proto::ProtectionLevel::High,
    }
}

fn proto_account_type(value: aura_agent_core::AccountType) -> proto::AccountType {
    match value {
        aura_agent_core::AccountType::Adult => proto::AccountType::Adult,
        aura_agent_core::AccountType::Teen => proto::AccountType::Teen,
        aura_agent_core::AccountType::Child => proto::AccountType::Child,
    }
}

fn domain_mode_from_proto(value: i32) -> aura_agent_core::DomainMode {
    match proto::DomainMode::try_from(value).unwrap_or(proto::DomainMode::Unspecified) {
        proto::DomainMode::Unspecified | proto::DomainMode::None => {
            aura_agent_core::DomainMode::None
        }
        proto::DomainMode::Kids => aura_agent_core::DomainMode::Kids,
        proto::DomainMode::Military => aura_agent_core::DomainMode::Military,
    }
}

fn cultural_context_from_proto(context: Option<proto::CulturalContext>) -> CulturalContext {
    let Some(context) = context else {
        return CulturalContext::default();
    };

    match proto::CulturalContextKind::try_from(context.kind)
        .unwrap_or(proto::CulturalContextKind::Ukrainian)
    {
        proto::CulturalContextKind::Unspecified | proto::CulturalContextKind::Ukrainian => {
            CulturalContext::Ukrainian
        }
        proto::CulturalContextKind::Russian => CulturalContext::Russian,
        proto::CulturalContextKind::English => CulturalContext::English,
        proto::CulturalContextKind::Custom => {
            CulturalContext::Custom(context.custom_value.unwrap_or_default())
        }
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

fn proto_sender_relationship(value: SenderRelationship) -> proto::SenderRelationship {
    match value {
        SenderRelationship::Unknown => proto::SenderRelationship::Unknown,
        SenderRelationship::Parent => proto::SenderRelationship::Parent,
        SenderRelationship::Guardian => proto::SenderRelationship::Guardian,
        SenderRelationship::Family => proto::SenderRelationship::Family,
        SenderRelationship::Sibling => proto::SenderRelationship::Sibling,
        SenderRelationship::Peer => proto::SenderRelationship::Peer,
        SenderRelationship::Teacher => proto::SenderRelationship::Teacher,
        SenderRelationship::Coach => proto::SenderRelationship::Coach,
        SenderRelationship::Authority => proto::SenderRelationship::Authority,
        SenderRelationship::Service => proto::SenderRelationship::Service,
        SenderRelationship::UnknownAdult => proto::SenderRelationship::UnknownAdult,
        SenderRelationship::UnknownPeer => proto::SenderRelationship::UnknownPeer,
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

fn proto_relationship_trust_source(
    value: RelationshipTrustSource,
) -> proto::RelationshipTrustSource {
    match value {
        RelationshipTrustSource::Unknown => proto::RelationshipTrustSource::Unknown,
        RelationshipTrustSource::UserVerified => proto::RelationshipTrustSource::UserVerified,
        RelationshipTrustSource::GuardianVerified => {
            proto::RelationshipTrustSource::GuardianVerified
        }
        RelationshipTrustSource::PlatformVerified => {
            proto::RelationshipTrustSource::PlatformVerified
        }
        RelationshipTrustSource::AddressBook => proto::RelationshipTrustSource::AddressBook,
        RelationshipTrustSource::SchoolDirectory => proto::RelationshipTrustSource::SchoolDirectory,
        RelationshipTrustSource::ServerReputation => {
            proto::RelationshipTrustSource::ServerReputation
        }
        RelationshipTrustSource::LocalHeuristic => proto::RelationshipTrustSource::LocalHeuristic,
        RelationshipTrustSource::SelfDeclared => proto::RelationshipTrustSource::SelfDeclared,
    }
}

fn proto_relay_privacy_mode(value: RelayPrivacyMode) -> proto::RelayPrivacyMode {
    match value {
        RelayPrivacyMode::MetadataOnly => proto::RelayPrivacyMode::MetadataOnly,
        RelayPrivacyMode::MessageOnly => proto::RelayPrivacyMode::MessageOnly,
        RelayPrivacyMode::MessageAndWindow => proto::RelayPrivacyMode::MessageAndWindow,
    }
}

fn threat_type_from_proto(value: i32) -> aura_agent_core::ThreatType {
    match proto::ThreatType::try_from(value).unwrap_or(proto::ThreatType::None) {
        proto::ThreatType::Bullying => aura_agent_core::ThreatType::Bullying,
        proto::ThreatType::Grooming => aura_agent_core::ThreatType::Grooming,
        proto::ThreatType::Explicit => aura_agent_core::ThreatType::Explicit,
        proto::ThreatType::Threat => aura_agent_core::ThreatType::Threat,
        proto::ThreatType::SelfHarm => aura_agent_core::ThreatType::SelfHarm,
        proto::ThreatType::Spam => aura_agent_core::ThreatType::Spam,
        proto::ThreatType::Scam => aura_agent_core::ThreatType::Scam,
        proto::ThreatType::Phishing => aura_agent_core::ThreatType::Phishing,
        proto::ThreatType::Manipulation => aura_agent_core::ThreatType::Manipulation,
        proto::ThreatType::Nsfw => aura_agent_core::ThreatType::Nsfw,
        proto::ThreatType::HateSpeech => aura_agent_core::ThreatType::HateSpeech,
        proto::ThreatType::Doxxing => aura_agent_core::ThreatType::Doxxing,
        proto::ThreatType::PiiLeakage => aura_agent_core::ThreatType::PiiLeakage,
        proto::ThreatType::Propaganda => aura_agent_core::ThreatType::Propaganda,
        proto::ThreatType::OpsecViolation => aura_agent_core::ThreatType::OpsecViolation,
        proto::ThreatType::Psyops => aura_agent_core::ThreatType::Psyops,
        proto::ThreatType::MilitarySocialEng => aura_agent_core::ThreatType::MilitarySocialEng,
        proto::ThreatType::CoordinateLeak => aura_agent_core::ThreatType::CoordinateLeak,
        proto::ThreatType::Unspecified | proto::ThreatType::None => {
            aura_agent_core::ThreatType::None
        }
    }
}

fn proto_threat_type(value: aura_agent_core::ThreatType) -> proto::ThreatType {
    match value {
        aura_agent_core::ThreatType::None => proto::ThreatType::None,
        aura_agent_core::ThreatType::Bullying => proto::ThreatType::Bullying,
        aura_agent_core::ThreatType::Grooming => proto::ThreatType::Grooming,
        aura_agent_core::ThreatType::Explicit => proto::ThreatType::Explicit,
        aura_agent_core::ThreatType::Threat => proto::ThreatType::Threat,
        aura_agent_core::ThreatType::SelfHarm => proto::ThreatType::SelfHarm,
        aura_agent_core::ThreatType::Spam => proto::ThreatType::Spam,
        aura_agent_core::ThreatType::Scam => proto::ThreatType::Scam,
        aura_agent_core::ThreatType::Phishing => proto::ThreatType::Phishing,
        aura_agent_core::ThreatType::Manipulation => proto::ThreatType::Manipulation,
        aura_agent_core::ThreatType::Nsfw => proto::ThreatType::Nsfw,
        aura_agent_core::ThreatType::HateSpeech => proto::ThreatType::HateSpeech,
        aura_agent_core::ThreatType::Doxxing => proto::ThreatType::Doxxing,
        aura_agent_core::ThreatType::PiiLeakage => proto::ThreatType::PiiLeakage,
        aura_agent_core::ThreatType::Propaganda => proto::ThreatType::Propaganda,
        aura_agent_core::ThreatType::OpsecViolation => proto::ThreatType::OpsecViolation,
        aura_agent_core::ThreatType::Psyops => proto::ThreatType::Psyops,
        aura_agent_core::ThreatType::MilitarySocialEng => proto::ThreatType::MilitarySocialEng,
        aura_agent_core::ThreatType::CoordinateLeak => proto::ThreatType::CoordinateLeak,
    }
}

fn confidence_from_proto(value: i32) -> aura_agent_core::Confidence {
    match proto::Confidence::try_from(value).unwrap_or(proto::Confidence::Low) {
        proto::Confidence::Medium => aura_agent_core::Confidence::Medium,
        proto::Confidence::High => aura_agent_core::Confidence::High,
        proto::Confidence::Unspecified | proto::Confidence::Low => aura_agent_core::Confidence::Low,
    }
}

fn proto_confidence(value: aura_agent_core::Confidence) -> proto::Confidence {
    match value {
        aura_agent_core::Confidence::Low => proto::Confidence::Low,
        aura_agent_core::Confidence::Medium => proto::Confidence::Medium,
        aura_agent_core::Confidence::High => proto::Confidence::High,
    }
}

fn proto_action(value: aura_agent_core::Action) -> proto::Action {
    match value {
        aura_agent_core::Action::Allow => proto::Action::Allow,
        aura_agent_core::Action::Mark => proto::Action::Mark,
        aura_agent_core::Action::Blur => proto::Action::Blur,
        aura_agent_core::Action::Warn => proto::Action::Warn,
        aura_agent_core::Action::Block => proto::Action::Block,
    }
}

fn proto_detection_layer(value: aura_agent_core::DetectionLayer) -> proto::DetectionLayer {
    match value {
        aura_agent_core::DetectionLayer::PatternMatching => proto::DetectionLayer::PatternMatching,
        aura_agent_core::DetectionLayer::MlClassification => {
            proto::DetectionLayer::MlClassification
        }
        aura_agent_core::DetectionLayer::ContextAnalysis => proto::DetectionLayer::ContextAnalysis,
    }
}

fn proto_relay_detection_layer(value: RelayDetectionLayer) -> proto::DetectionLayer {
    match value {
        RelayDetectionLayer::PatternMatching => proto::DetectionLayer::PatternMatching,
        RelayDetectionLayer::MlClassification => proto::DetectionLayer::MlClassification,
        RelayDetectionLayer::DomainHeuristic => proto::DetectionLayer::DomainHeuristic,
        RelayDetectionLayer::ContextAnalysis => proto::DetectionLayer::ContextAnalysis,
        RelayDetectionLayer::RelayInference => proto::DetectionLayer::RelayInference,
    }
}

fn proto_safety_telemetry_surface(value: SafetyTelemetrySurface) -> proto::SafetyTelemetrySurface {
    match value {
        SafetyTelemetrySurface::Unknown => proto::SafetyTelemetrySurface::Unspecified,
        SafetyTelemetrySurface::DirectMessage => proto::SafetyTelemetrySurface::DirectMessage,
        SafetyTelemetrySurface::GroupChat => proto::SafetyTelemetrySurface::GroupChat,
        SafetyTelemetrySurface::PublicComment => proto::SafetyTelemetrySurface::PublicComment,
        SafetyTelemetrySurface::LivestreamComment => {
            proto::SafetyTelemetrySurface::LivestreamComment
        }
    }
}

fn proto_safety_telemetry_severity(
    value: SafetyTelemetrySeverity,
) -> proto::SafetyTelemetrySeverity {
    match value {
        SafetyTelemetrySeverity::Low => proto::SafetyTelemetrySeverity::Low,
        SafetyTelemetrySeverity::Medium => proto::SafetyTelemetrySeverity::Medium,
        SafetyTelemetrySeverity::High => proto::SafetyTelemetrySeverity::High,
        SafetyTelemetrySeverity::Critical => proto::SafetyTelemetrySeverity::Critical,
    }
}

fn proto_safety_telemetry_action(value: SafetyTelemetryAction) -> proto::SafetyTelemetryAction {
    match value {
        SafetyTelemetryAction::None => proto::SafetyTelemetryAction::None,
        SafetyTelemetryAction::Mark => proto::SafetyTelemetryAction::Mark,
        SafetyTelemetryAction::Blur => proto::SafetyTelemetryAction::Blur,
        SafetyTelemetryAction::Warn => proto::SafetyTelemetryAction::Warn,
        SafetyTelemetryAction::Block => proto::SafetyTelemetryAction::Block,
        SafetyTelemetryAction::GuardianAlert => proto::SafetyTelemetryAction::GuardianAlert,
        SafetyTelemetryAction::ReportQueued => proto::SafetyTelemetryAction::ReportQueued,
        SafetyTelemetryAction::RestrictContact => proto::SafetyTelemetryAction::RestrictContact,
        SafetyTelemetryAction::CrisisSupport => proto::SafetyTelemetryAction::CrisisSupport,
    }
}

fn relay_risk_horizon_from_proto(value: i32) -> RelayRiskHorizon {
    match proto::RiskHorizon::try_from(value).unwrap_or(proto::RiskHorizon::Unknown) {
        proto::RiskHorizon::Immediate => RelayRiskHorizon::Immediate,
        proto::RiskHorizon::ShortTerm => RelayRiskHorizon::NearTerm,
        proto::RiskHorizon::Sustained => RelayRiskHorizon::Sustained,
        proto::RiskHorizon::Unspecified | proto::RiskHorizon::Unknown => RelayRiskHorizon::Unknown,
    }
}

fn proto_signal_family(value: aura_agent_core::SignalFamily) -> proto::SignalFamily {
    match value {
        aura_agent_core::SignalFamily::Content => proto::SignalFamily::Content,
        aura_agent_core::SignalFamily::Conversation => proto::SignalFamily::Conversation,
        aura_agent_core::SignalFamily::Link => proto::SignalFamily::Link,
        aura_agent_core::SignalFamily::Abuse => proto::SignalFamily::Abuse,
    }
}

fn proto_alert_priority(value: aura_agent_core::AlertPriority) -> proto::AlertPriority {
    match value {
        aura_agent_core::AlertPriority::None => proto::AlertPriority::None,
        aura_agent_core::AlertPriority::Low => proto::AlertPriority::Low,
        aura_agent_core::AlertPriority::Medium => proto::AlertPriority::Medium,
        aura_agent_core::AlertPriority::High => proto::AlertPriority::High,
        aura_agent_core::AlertPriority::Urgent => proto::AlertPriority::Urgent,
    }
}

fn proto_follow_up_action(value: aura_agent_core::FollowUpAction) -> proto::FollowUpAction {
    match value {
        aura_agent_core::FollowUpAction::MonitorConversation => {
            proto::FollowUpAction::MonitorConversation
        }
        aura_agent_core::FollowUpAction::BlockSuggested => proto::FollowUpAction::BlockSuggested,
        aura_agent_core::FollowUpAction::ReviewContactProfile => {
            proto::FollowUpAction::ReviewContactProfile
        }
        aura_agent_core::FollowUpAction::ReportToAuthorities => {
            proto::FollowUpAction::ReportToAuthorities
        }
    }
}

fn proto_product_rollout_mode(
    value: aura_agent_core::ProductRolloutMode,
) -> proto::ProductRolloutMode {
    match value {
        aura_agent_core::ProductRolloutMode::Shadow => proto::ProductRolloutMode::Shadow,
        aura_agent_core::ProductRolloutMode::StagingPilot => {
            proto::ProductRolloutMode::StagingPilot
        }
        aura_agent_core::ProductRolloutMode::GuardianEnabled => {
            proto::ProductRolloutMode::GuardianEnabled
        }
    }
}

fn proto_product_delivery_mode(
    value: aura_agent_core::ProductDeliveryMode,
) -> proto::ProductDeliveryMode {
    match value {
        aura_agent_core::ProductDeliveryMode::Suppress => proto::ProductDeliveryMode::Suppress,
        aura_agent_core::ProductDeliveryMode::MirrorOnly => proto::ProductDeliveryMode::MirrorOnly,
        aura_agent_core::ProductDeliveryMode::Apply => proto::ProductDeliveryMode::Apply,
    }
}

fn proto_product_child_intervention(
    value: aura_agent_core::ProductChildIntervention,
) -> proto::ProductChildIntervention {
    match value {
        aura_agent_core::ProductChildIntervention::None => proto::ProductChildIntervention::None,
        aura_agent_core::ProductChildIntervention::Mark => proto::ProductChildIntervention::Mark,
        aura_agent_core::ProductChildIntervention::Blur => proto::ProductChildIntervention::Blur,
        aura_agent_core::ProductChildIntervention::Warn => proto::ProductChildIntervention::Warn,
        aura_agent_core::ProductChildIntervention::Block => proto::ProductChildIntervention::Block,
    }
}

fn proto_product_review_urgency(
    value: aura_agent_core::ProductReviewUrgency,
) -> proto::ProductReviewUrgency {
    match value {
        aura_agent_core::ProductReviewUrgency::None => proto::ProductReviewUrgency::None,
        aura_agent_core::ProductReviewUrgency::Standard => proto::ProductReviewUrgency::Standard,
        aura_agent_core::ProductReviewUrgency::High => proto::ProductReviewUrgency::High,
        aura_agent_core::ProductReviewUrgency::Urgent => proto::ProductReviewUrgency::Urgent,
    }
}

fn proto_product_uncertainty_disposition(
    value: aura_agent_core::ProductUncertaintyDisposition,
) -> proto::ProductUncertaintyDisposition {
    match value {
        aura_agent_core::ProductUncertaintyDisposition::Normal => {
            proto::ProductUncertaintyDisposition::Normal
        }
        aura_agent_core::ProductUncertaintyDisposition::MirrorOnly => {
            proto::ProductUncertaintyDisposition::MirrorOnly
        }
        aura_agent_core::ProductUncertaintyDisposition::RequireReview => {
            proto::ProductUncertaintyDisposition::RequireReview
        }
        aura_agent_core::ProductUncertaintyDisposition::GuardianPriority => {
            proto::ProductUncertaintyDisposition::GuardianPriority
        }
    }
}

fn proto_ui_action(value: aura_agent_core::UiAction) -> proto::UiAction {
    match value {
        aura_agent_core::UiAction::WarnBeforeSend => proto::UiAction::WarnBeforeSend,
        aura_agent_core::UiAction::WarnBeforeDisplay => proto::UiAction::WarnBeforeDisplay,
        aura_agent_core::UiAction::BlurUntilTap => proto::UiAction::BlurUntilTap,
        aura_agent_core::UiAction::ConfirmBeforeOpenLink => proto::UiAction::ConfirmBeforeOpenLink,
        aura_agent_core::UiAction::SuggestBlockContact => proto::UiAction::SuggestBlockContact,
        aura_agent_core::UiAction::SuggestReport => proto::UiAction::SuggestReport,
        aura_agent_core::UiAction::RestrictUnknownContact => {
            proto::UiAction::RestrictUnknownContact
        }
        aura_agent_core::UiAction::SlowDownConversation => proto::UiAction::SlowDownConversation,
        aura_agent_core::UiAction::ShowCrisisSupport => proto::UiAction::ShowCrisisSupport,
        aura_agent_core::UiAction::EscalateToGuardian => proto::UiAction::EscalateToGuardian,
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

fn proto_uncertainty_level(value: aura_agent_core::UncertaintyLevel) -> proto::UncertaintyLevel {
    match value {
        aura_agent_core::UncertaintyLevel::Low => proto::UncertaintyLevel::Low,
        aura_agent_core::UncertaintyLevel::Medium => proto::UncertaintyLevel::Medium,
        aura_agent_core::UncertaintyLevel::High => proto::UncertaintyLevel::High,
    }
}

fn proto_risk_horizon(value: aura_agent_core::RiskHorizon) -> proto::RiskHorizon {
    match value {
        aura_agent_core::RiskHorizon::Unknown => proto::RiskHorizon::Unknown,
        aura_agent_core::RiskHorizon::Immediate => proto::RiskHorizon::Immediate,
        aura_agent_core::RiskHorizon::ShortTerm => proto::RiskHorizon::ShortTerm,
        aura_agent_core::RiskHorizon::Sustained => proto::RiskHorizon::Sustained,
    }
}

fn proto_latent_state_kind(value: aura_agent_core::LatentStateKind) -> proto::LatentStateKind {
    match value {
        aura_agent_core::LatentStateKind::DependencyBuilding => {
            proto::LatentStateKind::DependencyBuilding
        }
        aura_agent_core::LatentStateKind::IsolationPressure => {
            proto::LatentStateKind::IsolationPressure
        }
        aura_agent_core::LatentStateKind::CoerciveControl => {
            proto::LatentStateKind::CoerciveControl
        }
        aura_agent_core::LatentStateKind::Humiliation => proto::LatentStateKind::Humiliation,
        aura_agent_core::LatentStateKind::CrisisVulnerability => {
            proto::LatentStateKind::CrisisVulnerability
        }
        aura_agent_core::LatentStateKind::ProtectiveSupport => {
            proto::LatentStateKind::ProtectiveSupport
        }
        aura_agent_core::LatentStateKind::GroupEscalation => {
            proto::LatentStateKind::GroupEscalation
        }
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
    use chrono::{DateTime, Duration, Utc};
    use prost::Message as ProstMessage;
    use serde::Deserialize;
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
            relay_policy: None,
        }
    }

    // Reproduces the EXACT config the iOS app's AuraRuntimeService.makeConfig builds
    // for the local-analysis path: ProtectionLevel::Medium, AccountType::Adult,
    // language "en", NO cultural_context, ttl 30, DomainMode::None, and a relay
    // policy with enabled=false, MetadataOnly, a base64 protected_account_id, and
    // NO auth keys. On device this aura_init returns null and the Swift side only
    // sees "unknown error"; this test surfaces the real failure on the host.
    #[test]
    fn ios_local_analysis_config_initializes() {
        unsafe {
            let config = proto::AuraConfig {
                protection_level: proto::ProtectionLevel::Medium as i32,
                account_type: proto::AccountType::Adult as i32,
                language: "en".to_string(),
                cultural_context: None,
                enabled: true,
                patterns_path: None,
                models_path: None,
                account_holder_age: None,
                ttl_days: 30,
                timezone_offset_minutes: 120,
                domain_mode: proto::DomainMode::None as i32,
                relay_policy: Some(proto::AgentRelayPolicy {
                    enabled: Some(false),
                    privacy_mode: proto::RelayPrivacyMode::MetadataOnly as i32,
                    protected_account_id: Some("QTNGNUVDRA==".to_string()),
                    ..Default::default()
                }),
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
    fn unspecified_domain_mode_maps_to_none() {
        let mut proto = proto_config(proto::AccountType::Adult, true);
        proto.domain_mode = proto::DomainMode::Unspecified as i32;
        let config = aura_config_from_proto(proto).expect("config must decode");
        assert_eq!(config.domain_mode, aura_agent_core::DomainMode::None);
    }

    #[test]
    fn relay_policy_defaults_when_missing_from_config() {
        let config = decoded_config_from_proto(proto_config(proto::AccountType::Child, true))
            .expect("config must decode");

        assert!(!config.relay_policy.enabled);
        assert_eq!(
            config.relay_policy.privacy_mode,
            RelayPrivacyMode::MessageOnly
        );
        assert!(config.relay_policy.emit_local_safety_telemetry);
        assert!(config.relay_policy.protected_account_id.is_none());
        assert!(config.aura_config.protected_account_id.is_none());
        assert!(!config.relay_policy.require_relay_auth);
        assert!(!config.relay_policy.require_protected_account_attestation);
        assert!(config.relay_request_auth_key.is_none());
        assert!(config.relay_response_auth_keys.is_empty());
    }

    #[test]
    fn relay_policy_maps_metadata_only_safety_telemetry_config() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        config_proto.relay_policy = Some(metadata_only_relay_policy());

        let config = decoded_config_from_proto(config_proto).expect("config must decode");

        assert!(config.relay_policy.enabled);
        assert_eq!(config.relay_policy.score_threshold, 0.42);
        assert!(!config.relay_policy.send_on_high_uncertainty);
        assert!(config.relay_policy.send_on_new_contact);
        assert!(!config.relay_policy.send_on_repeated_sender);
        assert_eq!(
            config.relay_policy.privacy_mode,
            RelayPrivacyMode::MetadataOnly
        );
        assert_eq!(
            config.relay_policy.max_recent_window_messages,
            MAX_RELAY_RECENT_WINDOW_MESSAGES
        );
        assert_eq!(config.relay_policy.deadline_ms, None);
        assert_eq!(
            config.relay_policy.protected_account_id.as_deref(),
            Some("child_local_1")
        );
        assert_eq!(
            config.aura_config.protected_account_id.as_deref(),
            Some("child_local_1")
        );
        assert!(!config.relay_policy.require_relay_auth);
        assert!(!config.relay_policy.require_protected_account_attestation);
        assert!(config.relay_request_auth_key.is_none());
        assert!(config.relay_response_auth_keys.is_empty());
    }

    #[test]
    fn relay_request_auth_key_maps_from_config() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.request_auth_key = Some(relay_request_auth_key_proto());
        config_proto.relay_policy = Some(policy);

        let config = decoded_config_from_proto(config_proto).expect("config must decode");
        let key = config
            .relay_request_auth_key
            .expect("relay request auth key should decode");

        assert_eq!(key.key_id, "relay-req-key-1");
        assert_eq!(key.secret, relay_request_auth_secret());
    }

    #[test]
    fn relay_response_auth_key_maps_from_config() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.response_auth_key = Some(relay_response_auth_key_proto());
        policy
            .accepted_response_auth_keys
            .push(relay_previous_response_auth_key_proto());
        config_proto.relay_policy = Some(policy);

        let config = decoded_config_from_proto(config_proto).expect("config must decode");
        assert_eq!(config.relay_response_auth_keys.len(), 2);
        let key = &config.relay_response_auth_keys[0];

        assert_eq!(key.key_id, "relay-key-1");
        assert_eq!(key.secret, relay_response_auth_secret());
        let previous_key = &config.relay_response_auth_keys[1];
        assert_eq!(previous_key.key_id, "relay-key-previous");
        assert_eq!(previous_key.secret, relay_previous_response_auth_secret());
    }

    #[test]
    fn relay_policy_maps_protected_account_attestation_from_config() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        let token = protected_account_token_for("child_local_1");
        policy.protected_account_attestation = Some(protected_account_attestation_proto(
            &token,
            1_900_000_000_000,
        ));
        config_proto.relay_policy = Some(policy);

        let config = decoded_config_from_proto(config_proto).expect("config must decode");
        let attestation = config
            .relay_policy
            .protected_account_attestation
            .expect("protected account attestation should decode");

        assert_eq!(attestation.key_id, "acct-attest-key-1");
        assert_eq!(attestation.protected_account_token, token);
        assert_eq!(attestation.expires_at_ms, 1_900_000_000_000);
    }

    #[test]
    fn relay_policy_require_protected_account_attestation_accepts_matching_proof() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        let token = protected_account_token_for("child_local_1");
        policy.require_protected_account_attestation = Some(true);
        policy.protected_account_attestation = Some(protected_account_attestation_proto(
            &token,
            future_attestation_expires_at_ms(),
        ));
        config_proto.relay_policy = Some(policy);

        let config = decoded_config_from_proto(config_proto).expect("config must decode");

        assert!(config.relay_policy.require_protected_account_attestation);
    }

    #[test]
    fn relay_policy_require_protected_account_attestation_rejects_missing_or_mismatch() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.require_protected_account_attestation = Some(true);
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("attestation is missing"));

        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        let token = protected_account_token_for("other_child");
        policy.require_protected_account_attestation = Some(true);
        policy.protected_account_attestation = Some(protected_account_attestation_proto(
            &token,
            1_900_000_000_000,
        ));
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("does not match protected_account_id"));

        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        let token = protected_account_token_for("child_local_1");
        policy.require_protected_account_attestation = Some(true);
        policy.protected_account_attestation = Some(protected_account_attestation_proto(&token, 1));
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("attestation is expired"));
    }

    #[test]
    fn relay_policy_rejects_invalid_protected_account_attestation_config() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.protected_account_attestation = Some(proto::ProtectedAccountTokenAttestation {
            key_id: "acct-attest-key-1".to_string(),
            alg: "none".to_string(),
            protected_account_token: "acct_01H0000000000000000000000".to_string(),
            expires_at_ms: 1_900_000_000_000,
            tag: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        });
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("attestation alg"));

        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.protected_account_attestation = Some(proto::ProtectedAccountTokenAttestation {
            key_id: "acct-attest-key-1".to_string(),
            alg: PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG.to_string(),
            protected_account_token: "child@example.test".to_string(),
            expires_at_ms: 1_900_000_000_000,
            tag: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        });
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("privacy-safe acct_ token"));
    }

    #[test]
    fn relay_policy_rejects_invalid_score_threshold() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        config_proto.relay_policy = Some(proto::AgentRelayPolicy {
            score_threshold: Some(1.5),
            ..Default::default()
        });

        let error = decoded_config_from_proto(config_proto).unwrap_err();

        assert!(error.contains("score_threshold"));
    }

    #[test]
    fn relay_policy_require_auth_rejects_missing_keys() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.require_relay_auth = Some(true);
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();

        assert!(error.contains("relay auth is required"));
    }

    #[test]
    fn relay_policy_require_auth_accepts_configured_keys() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.require_relay_auth = Some(true);
        policy.request_auth_key = Some(relay_request_auth_key_proto());
        policy.response_auth_key = Some(relay_response_auth_key_proto());
        config_proto.relay_policy = Some(policy);

        let config = decoded_config_from_proto(config_proto).expect("config must decode");

        assert!(config.relay_policy.require_relay_auth);
        assert!(config.relay_request_auth_key.is_some());
        assert_eq!(config.relay_response_auth_keys.len(), 1);
    }

    #[test]
    fn relay_response_auth_key_rejects_invalid_config() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.response_auth_key = Some(proto::RelayResponseAuthKey {
            key_id: "relay key with spaces".to_string(),
            secret: relay_response_auth_secret(),
        });
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("key_id"));

        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.response_auth_key = Some(proto::RelayResponseAuthKey {
            key_id: "relay-key-1".to_string(),
            secret: b"too short".to_vec(),
        });
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("secret"));

        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.response_auth_key = Some(relay_response_auth_key_proto());
        policy
            .accepted_response_auth_keys
            .push(relay_response_auth_key_proto());
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("duplicated"));
    }

    #[test]
    fn relay_request_auth_key_rejects_invalid_config() {
        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.request_auth_key = Some(proto::RelayRequestAuthKey {
            key_id: "relay request key with spaces".to_string(),
            secret: relay_request_auth_secret(),
        });
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("key_id"));

        let mut config_proto = proto_config(proto::AccountType::Child, true);
        let mut policy = metadata_only_relay_policy();
        policy.request_auth_key = Some(proto::RelayRequestAuthKey {
            key_id: "relay-req-key-1".to_string(),
            secret: b"too short".to_vec(),
        });
        config_proto.relay_policy = Some(policy);

        let error = decoded_config_from_proto(config_proto).unwrap_err();
        assert!(error.contains("secret"));
    }

    #[test]
    fn init_and_update_apply_relay_policy_to_runtime() {
        unsafe {
            let mut config_proto = proto_config(proto::AccountType::Child, true);
            config_proto.relay_policy = Some(metadata_only_relay_policy());

            let handle = init_handle(config_proto);
            assert!(!handle.is_null());
            with_instance(handle, |instance| {
                let policy = instance.analyzer.relay_policy();
                assert!(policy.enabled);
                assert_eq!(policy.privacy_mode, RelayPrivacyMode::MetadataOnly);
                assert_eq!(
                    policy.protected_account_id.as_deref(),
                    Some("child_local_1")
                );
                Ok(())
            })
            .unwrap();

            let mut updated = proto_config(proto::AccountType::Child, true);
            updated.relay_policy = Some(proto::AgentRelayPolicy {
                enabled: Some(false),
                score_threshold: Some(0.9),
                privacy_mode: proto::RelayPrivacyMode::MessageOnly as i32,
                emit_local_safety_telemetry: Some(false),
                protected_account_id: Some(String::new()),
                ..Default::default()
            });
            let bytes = encode_proto(&updated);
            assert!(aura_update_config(handle, bytes.as_ptr(), bytes.len()));

            with_instance(handle, |instance| {
                let policy = instance.analyzer.relay_policy();
                assert!(!policy.enabled);
                assert_eq!(policy.score_threshold, 0.9);
                assert_eq!(policy.privacy_mode, RelayPrivacyMode::MessageOnly);
                assert!(!policy.emit_local_safety_telemetry);
                assert!(policy.protected_account_id.is_none());
                Ok(())
            })
            .unwrap();

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_for_relay_returns_metadata_only_relay_request() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            config.relay_policy = Some(metadata_only_relay_policy());
            let handle = init_handle(config);

            let response = analyze_for_relay_response(
                handle,
                proto_message("i will kill you", "sender_1", "conv_1"),
                1_700_000_123_456,
            );

            assert!(response.local_result.is_some());
            let relay_request = response.relay_request.expect("missing relay request");
            assert!(relay_request.text.is_empty());
            assert!(relay_request.request_id.starts_with("req_"));
            assert!(relay_request.message_id.starts_with("msg_"));
            assert!(relay_request
                .sender_token
                .as_deref()
                .unwrap_or_default()
                .starts_with("snd_"));
            assert!(relay_request
                .protected_account_token
                .as_deref()
                .unwrap_or_default()
                .starts_with("acct_"));
            assert!(relay_request
                .conversation_token
                .as_deref()
                .unwrap_or_default()
                .starts_with("conv_"));
            assert!(!relay_request.request_id.contains("sender_1"));
            assert!(!relay_request.message_id.contains("conv_1"));
            assert_ne!(relay_request.sender_token.as_deref(), Some("sender_1"));
            assert_ne!(
                relay_request.protected_account_token.as_deref(),
                Some("child_local_1")
            );
            assert_ne!(relay_request.conversation_token.as_deref(), Some("conv_1"));
            assert_eq!(
                relay_request.privacy_mode,
                proto::RelayPrivacyMode::MetadataOnly as i32
            );
            assert!(!relay_request.local_observations.is_empty());
            assert!(relay_request
                .local_observations
                .iter()
                .all(|observation| observation.explanation.is_empty()));
            assert_eq!(relay_request.local_safety_telemetry.len(), 1);
            let telemetry = &relay_request.local_safety_telemetry[0];
            assert!(telemetry.event_id.starts_with("evt_"));
            assert!(telemetry.sender_token.starts_with("snd_"));
            assert!(telemetry.protected_account_token.starts_with("acct_"));
            assert!(telemetry
                .conversation_token
                .as_deref()
                .unwrap_or_default()
                .starts_with("conv_"));
            assert!(telemetry.timestamp_bucket_ms > 0);

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_for_relay_preserves_relationship_metadata() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            let mut policy = metadata_only_relay_policy();
            policy.request_auth_key = Some(relay_request_auth_key_proto());
            config.relay_policy = Some(policy);
            let handle = init_handle(config);
            let mut message = proto_message("i will kill you", "sender_1", "conv_1");
            message.sender_relationship = proto::SenderRelationship::UnknownAdult as i32;
            message.relationship_trust_source =
                proto::RelationshipTrustSource::ServerReputation as i32;

            let response = analyze_for_relay_response(handle, message, 1_700_000_123_456);
            let relay_request = response.relay_request.expect("missing relay request");

            assert_eq!(
                relay_request.sender_relationship,
                proto::SenderRelationship::UnknownAdult as i32
            );
            assert_eq!(
                relay_request.relationship_trust_source,
                proto::RelationshipTrustSource::ServerReputation as i32
            );
            let contract = relay_request_contract_from_proto(relay_request);
            assert!(aura_agent_core::aura_contracts::verify_relay_request_auth(
                &contract,
                "relay-req-key-1",
                &relay_request_auth_secret()
            ));

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_for_relay_signs_request_when_auth_key_configured() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            let mut policy = metadata_only_relay_policy();
            policy.request_auth_key = Some(relay_request_auth_key_proto());
            config.relay_policy = Some(policy);
            let handle = init_handle(config);

            let response = analyze_for_relay_response(
                handle,
                proto_message("i will kill you", "sender_1", "conv_1"),
                1_700_000_123_456,
            );

            let relay_request = response.relay_request.expect("missing relay request");
            let auth = relay_request.auth.expect("missing relay request auth");
            assert_eq!(auth.key_id, "relay-req-key-1");
            assert_eq!(auth.alg, "hmac-sha256-v1");
            assert_eq!(auth.tag.len(), 64);

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_for_relay_includes_configured_protected_account_attestation() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            let mut policy = metadata_only_relay_policy();
            let token = protected_account_token_for("child_local_1");
            policy.protected_account_attestation = Some(protected_account_attestation_proto(
                &token,
                1_900_000_000_000,
            ));
            policy.request_auth_key = Some(relay_request_auth_key_proto());
            config.relay_policy = Some(policy);
            let handle = init_handle(config);

            let response = analyze_for_relay_response(
                handle,
                proto_message("i will kill you", "sender_1", "conv_1"),
                1_700_000_123_456,
            );

            let relay_request = response.relay_request.expect("missing relay request");
            let attestation = relay_request
                .protected_account_attestation
                .expect("missing protected account attestation");
            assert_eq!(attestation.key_id, "acct-attest-key-1");
            assert_eq!(attestation.protected_account_token, token);
            assert_eq!(attestation.expires_at_ms, 1_900_000_000_000);
            assert!(relay_request.auth.is_some());

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_for_relay_omits_request_when_required_account_attestation_expired() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            let mut policy = metadata_only_relay_policy();
            let token = protected_account_token_for("child_local_1");
            let expires_at_ms = future_attestation_expires_at_ms();
            policy.require_protected_account_attestation = Some(true);
            policy.protected_account_attestation =
                Some(protected_account_attestation_proto(&token, expires_at_ms));
            config.relay_policy = Some(policy);
            let handle = init_handle(config);

            let response = analyze_for_relay_response(
                handle,
                proto_message("i will kill you", "sender_1", "conv_1"),
                expires_at_ms + 1,
            );

            assert!(response.local_result.is_some());
            assert!(response.relay_request.is_none());

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_for_relay_omits_relay_request_when_policy_disabled() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));

            let response = analyze_for_relay_response(
                handle,
                proto_message("i will kill you", "sender_1", "conv_1"),
                1_700_000_123_456,
            );

            assert!(response.local_result.is_some());
            assert!(response.relay_request.is_none());

            aura_free(handle);
        }
    }

    #[test]
    fn record_relay_response_applies_hint_to_future_context_analysis() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            config.domain_mode = proto::DomainMode::Kids as i32;
            config.relay_policy = Some(metadata_only_relay_policy());
            let handle = init_handle(config);
            let now_ms = 1_778_652_000_000;
            let relay_envelope = analyze_for_relay_response(
                handle,
                proto_message("i will kill you", "server_hint_sender", "conv_pending_hint"),
                now_ms,
            );
            let relay_request = relay_envelope
                .relay_request
                .expect("pending relay request should be emitted");
            let request = proto::RecordRelayResponseRequest {
                sender_id: "server_hint_sender".to_string(),
                response: Some(proto::RelayAnalyzeResponse {
                    schema_version: "aura.relay.v1alpha1".to_string(),
                    request_id: relay_request.request_id,
                    confidence: proto::Confidence::High as i32,
                    expires_at_ms: Some(now_ms + 60_000),
                    sender_reputation_hint: Some(0.9),
                    correlation_findings: vec![
                        "relay.context.cross_conversation_safety_telemetry".to_string()
                    ],
                    ..proto::RelayAnalyzeResponse::default()
                }),
                received_at_ms: now_ms,
            };
            let bytes = encode_proto(&request);

            assert!(aura_record_relay_response(
                handle,
                bytes.as_ptr(),
                bytes.len()
            ));

            let result = analyze_context_result(
                handle,
                proto_message(
                    "our little secret",
                    "server_hint_sender",
                    "conv_server_hint",
                ),
                now_ms + 1,
            );

            assert!(
                result
                    .reason_codes
                    .iter()
                    .any(|code| code == "domain.kids.memory.sender_risk_accumulation"),
                "relay response hint should affect future local analysis, got {:?}",
                result.reason_codes
            );

            aura_free(handle);
        }
    }

    #[test]
    fn record_relay_response_requires_configured_auth_over_ffi() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            config.domain_mode = proto::DomainMode::Kids as i32;
            let mut policy = metadata_only_relay_policy();
            policy.response_auth_key = Some(relay_response_auth_key_proto());
            config.relay_policy = Some(policy);
            let handle = init_handle(config);
            let now_ms = 1_778_652_000_000;
            let relay_envelope = analyze_for_relay_response(
                handle,
                proto_message("i will kill you", "server_hint_sender", "conv_pending_auth"),
                now_ms,
            );
            let relay_request = relay_envelope
                .relay_request
                .expect("pending relay request should be emitted");

            let mut response = proto::RelayAnalyzeResponse {
                schema_version: "aura.relay.v1alpha1".to_string(),
                request_id: relay_request.request_id,
                confidence: proto::Confidence::High as i32,
                expires_at_ms: Some(now_ms + 60_000),
                sender_reputation_hint: Some(0.9),
                correlation_findings: vec![
                    "relay.context.cross_conversation_safety_telemetry".to_string()
                ],
                ..proto::RelayAnalyzeResponse::default()
            };
            let unsigned_request = proto::RecordRelayResponseRequest {
                sender_id: "server_hint_sender".to_string(),
                response: Some(response.clone()),
                received_at_ms: now_ms,
            };
            let unsigned_bytes = encode_proto(&unsigned_request);

            assert!(!aura_record_relay_response(
                handle,
                unsigned_bytes.as_ptr(),
                unsigned_bytes.len()
            ));

            let mut contract_response = relay_response_from_proto(response.clone());
            contract_response.auth = aura_agent_core::aura_contracts::sign_relay_response_auth(
                &contract_response,
                relay_request
                    .sender_token
                    .as_deref()
                    .expect("relay request should carry sender token"),
                "relay-key-1",
                &relay_response_auth_secret(),
            );
            let auth = contract_response.auth.expect("response should sign");
            response.auth = Some(proto::RelayResponseAuth {
                key_id: auth.key_id,
                alg: auth.alg,
                tag: auth.tag,
            });

            let signed_request = proto::RecordRelayResponseRequest {
                sender_id: "server_hint_sender".to_string(),
                response: Some(response),
                received_at_ms: now_ms,
            };
            let signed_bytes = encode_proto(&signed_request);

            assert!(aura_record_relay_response(
                handle,
                signed_bytes.as_ptr(),
                signed_bytes.len()
            ));

            let result = analyze_context_result(
                handle,
                proto_message(
                    "our little secret",
                    "server_hint_sender",
                    "conv_server_hint_auth",
                ),
                now_ms + 1,
            );

            assert!(
                result
                    .reason_codes
                    .iter()
                    .any(|code| code == "domain.kids.memory.sender_risk_accumulation"),
                "signed relay response hint should affect future local analysis, got {:?}",
                result.reason_codes
            );

            aura_free(handle);
        }
    }

    #[test]
    fn strict_ffi_agent_to_relay_config_to_signed_response_e2e() {
        unsafe {
            let request_secret = relay_request_auth_secret();
            let response_secret = relay_response_auth_secret();
            let attestation_secret = "protected account attestation secret";
            let mut config = proto_config(proto::AccountType::Child, true);
            config.domain_mode = proto::DomainMode::Kids as i32;
            let mut policy = metadata_only_relay_policy();
            let protected_account_token = protected_account_token_for("child_local_1");
            let issued_attestation =
                aura_relay_api::ProtectedAccountAttestationIssuer::from_config(
                    aura_relay_api::ProtectedAccountAttestationIssuerConfig {
                        signing_keys: vec![
                            aura_relay_api::RelayProtectedAccountAttestationKeyConfig {
                                key_id: "acct-attest-key-1".to_string(),
                                secret: attestation_secret.to_string(),
                                not_before_ms: Some(1),
                                not_after_ms: Some(current_unix_ms().saturating_add(600_000)),
                                revoked: false,
                            },
                        ],
                        ttl_ms: 60_000,
                        allowed_protected_account_tokens: vec![protected_account_token.clone()],
                    },
                )
                .expect("issuer config should validate")
                .issue(&protected_account_token, None, current_unix_ms())
                .expect("issuer should mint protected account attestation");
            policy.request_auth_key = Some(relay_request_auth_key_proto());
            policy.response_auth_key = Some(relay_response_auth_key_proto());
            policy.require_relay_auth = Some(true);
            policy.require_protected_account_attestation = Some(true);
            policy.protected_account_attestation = Some(
                protected_account_attestation_contract_to_proto(issued_attestation),
            );
            config.relay_policy = Some(policy);
            let handle = init_handle(config);
            let relay =
                aura_relay_api::RelayService::from_auth_config(aura_relay_api::RelayAuthConfig {
                    request_auth_keys: vec![aura_relay_api::RelaySharedSecretKeyConfig {
                        key_id: "relay-req-key-1".to_string(),
                        secret: String::from_utf8(request_secret.clone())
                            .expect("test request secret is utf8"),
                    }],
                    response_auth_key: Some(aura_relay_api::RelaySharedSecretKeyConfig {
                        key_id: "relay-key-1".to_string(),
                        secret: String::from_utf8(response_secret.clone())
                            .expect("test response secret is utf8"),
                    }),
                    protected_account_attestation_keys: vec![
                        aura_relay_api::RelayProtectedAccountAttestationKeyConfig {
                            key_id: "acct-attest-key-1".to_string(),
                            secret: attestation_secret.to_string(),
                            not_before_ms: Some(1),
                            not_after_ms: Some(current_unix_ms().saturating_add(600_000)),
                            revoked: false,
                        },
                    ],
                    protected_account_attestation_max_future_ttl_ms: Some(600_000),
                })
                .expect("strict relay auth config should validate");
            let sender_id = "strict_e2e_sender";
            let base_ms = current_unix_ms();

            for index in 0..3 {
                let timestamp_ms = base_ms.saturating_add(index);
                let relay_envelope = analyze_for_relay_response(
                    handle,
                    proto_message(
                        "dont tell your parents and keep this secret",
                        sender_id,
                        &format!("conv_strict_e2e_{index}"),
                    ),
                    timestamp_ms,
                );
                let relay_request = relay_envelope
                    .relay_request
                    .expect("strict policy should emit relay request");
                assert!(relay_request.auth.is_some());
                assert!(relay_request.protected_account_attestation.is_some());
                assert_eq!(
                    relay_request
                        .protected_account_token
                        .as_deref()
                        .expect("relay request has account token"),
                    protected_account_token
                );

                let relay_response =
                    relay.handle_analyze(relay_request_contract_from_proto(relay_request.clone()));
                assert!(
                    !relay_response
                        .reason_codes
                        .iter()
                        .any(|code| code.starts_with("relay.auth.")),
                    "strict relay rejected FFI request: {:?}",
                    relay_response.reason_codes
                );
                assert!(
                    relay_response.auth.is_some(),
                    "strict relay response should be signed"
                );

                let record_request = proto::RecordRelayResponseRequest {
                    sender_id: sender_id.to_string(),
                    response: Some(relay_response_to_proto(relay_response)),
                    received_at_ms: timestamp_ms,
                };
                let record_bytes = encode_proto(&record_request);
                assert!(aura_record_relay_response(
                    handle,
                    record_bytes.as_ptr(),
                    record_bytes.len()
                ));
            }

            let result = analyze_context_result(
                handle,
                proto_message("our little secret", sender_id, "conv_strict_e2e_final"),
                base_ms.saturating_add(3),
            );

            assert!(
                result
                    .reason_codes
                    .iter()
                    .any(|code| code.starts_with("domain.kids.memory.")),
                "strict relay response loop should preserve kids-memory escalation, got {:?}",
                result.reason_codes
            );

            aura_free(handle);
        }
    }

    fn metadata_only_relay_policy() -> proto::AgentRelayPolicy {
        proto::AgentRelayPolicy {
            enabled: Some(true),
            score_threshold: Some(0.42),
            send_on_high_uncertainty: Some(false),
            send_on_new_contact: Some(true),
            send_on_repeated_sender: Some(false),
            privacy_mode: proto::RelayPrivacyMode::MetadataOnly as i32,
            max_recent_window_messages: Some(999),
            deadline_ms: Some(0),
            emit_local_safety_telemetry: Some(true),
            protected_account_id: Some(" child_local_1 ".to_string()),
            request_auth_key: None,
            response_auth_key: None,
            accepted_response_auth_keys: Vec::new(),
            require_relay_auth: None,
            protected_account_attestation: None,
            require_protected_account_attestation: None,
        }
    }

    fn relay_request_auth_key_proto() -> proto::RelayRequestAuthKey {
        proto::RelayRequestAuthKey {
            key_id: "relay-req-key-1".to_string(),
            secret: relay_request_auth_secret(),
        }
    }

    fn relay_request_auth_secret() -> Vec<u8> {
        b"relay request auth test secret".to_vec()
    }

    fn protected_account_token_for(account_id: &str) -> String {
        format!(
            "acct_{}",
            aura_agent_core::tokenize_identifier(account_id).token
        )
    }

    fn future_attestation_expires_at_ms() -> u64 {
        current_unix_ms().saturating_add(60_000)
    }

    fn protected_account_attestation_proto(
        protected_account_token: &str,
        expires_at_ms: u64,
    ) -> proto::ProtectedAccountTokenAttestation {
        let attestation =
            aura_agent_core::aura_contracts::sign_protected_account_token_attestation(
                protected_account_token,
                expires_at_ms,
                "acct-attest-key-1",
                b"protected account attestation secret",
            )
            .expect("test protected account token should be attestable");
        proto::ProtectedAccountTokenAttestation {
            key_id: attestation.key_id,
            alg: attestation.alg,
            protected_account_token: attestation.protected_account_token,
            expires_at_ms: attestation.expires_at_ms,
            tag: attestation.tag,
        }
    }

    fn protected_account_attestation_contract_to_proto(
        attestation: aura_agent_core::aura_contracts::ProtectedAccountTokenAttestation,
    ) -> proto::ProtectedAccountTokenAttestation {
        proto::ProtectedAccountTokenAttestation {
            key_id: attestation.key_id,
            alg: attestation.alg,
            protected_account_token: attestation.protected_account_token,
            expires_at_ms: attestation.expires_at_ms,
            tag: attestation.tag,
        }
    }

    fn relay_response_auth_key_proto() -> proto::RelayResponseAuthKey {
        proto::RelayResponseAuthKey {
            key_id: "relay-key-1".to_string(),
            secret: relay_response_auth_secret(),
        }
    }

    fn relay_response_auth_secret() -> Vec<u8> {
        b"relay response auth test secret".to_vec()
    }

    fn relay_request_contract_from_proto(
        request: proto::RelayAnalyzeRequest,
    ) -> RelayAnalyzeRequestContract {
        RelayAnalyzeRequestContract {
            schema_version: request.schema_version,
            request_id: request.request_id,
            message_id: request.message_id,
            sender_token: request.sender_token,
            protected_account_token: request.protected_account_token,
            conversation_token: request.conversation_token,
            account_type: account_type_from_proto(request.account_type),
            protection_level: protection_level_from_proto(request.protection_level),
            conversation_type: conversation_type_from_proto(request.conversation_type),
            language: request.language,
            text: request.text,
            local_observations: request
                .local_observations
                .into_iter()
                .map(relay_observation_from_proto_for_test)
                .collect(),
            local_context: None,
            local_context_summary: request
                .local_context_summary
                .map(
                    |summary| aura_agent_core::aura_contracts::LocalContextSummary {
                        context_markers: summary.context_markers,
                        recent_observations: summary
                            .recent_observations
                            .into_iter()
                            .map(relay_observation_from_proto_for_test)
                            .collect(),
                        recent_confirmed_events: Vec::new(),
                    },
                )
                .unwrap_or_default(),
            local_safety_telemetry: request
                .local_safety_telemetry
                .into_iter()
                .map(relay_safety_telemetry_from_proto_for_test)
                .collect(),
            recent_message_window: request
                .recent_message_window
                .into_iter()
                .map(
                    |entry| aura_agent_core::aura_contracts::MessageWindowEntry {
                        sender_id: entry.sender_id,
                        text: entry.text,
                        timestamp_ms: entry.timestamp_ms,
                    },
                )
                .collect(),
            server_sender_risk_hint: request.server_sender_risk_hint,
            sender_relationship: sender_relationship_from_proto(request.sender_relationship),
            relationship_trust_source: relationship_trust_source_from_proto(
                request.relationship_trust_source,
            ),
            privacy_mode: relay_privacy_mode_from_proto(request.privacy_mode),
            capabilities: request
                .capabilities
                .map(
                    |capabilities| aura_agent_core::aura_contracts::AgentCapabilities {
                        local_context_interpreter: capabilities.local_context_interpreter,
                        local_tracker: capabilities.local_tracker,
                        supports_remote_correlation: capabilities.supports_remote_correlation,
                        relay_timeout_ms: capabilities.relay_timeout_ms,
                    },
                )
                .unwrap_or_default(),
            deadline_ms: request.deadline_ms,
            protected_account_attestation: request.protected_account_attestation.map(
                |attestation| ProtectedAccountTokenAttestationContract {
                    key_id: attestation.key_id,
                    alg: attestation.alg,
                    protected_account_token: attestation.protected_account_token,
                    expires_at_ms: attestation.expires_at_ms,
                    tag: attestation.tag,
                },
            ),
            auth: request.auth.map(|auth| RelayRequestAuthContract {
                key_id: auth.key_id,
                alg: auth.alg,
                tag: auth.tag,
            }),
        }
    }

    fn relay_observation_from_proto_for_test(
        observation: proto::RelayObservation,
    ) -> aura_agent_core::aura_contracts::RawObservation {
        aura_agent_core::aura_contracts::RawObservation {
            threat_type: threat_type_from_proto(observation.threat_type),
            threat_subtype: observation.threat_subtype,
            layer: relay_detection_layer_from_proto_for_test(observation.layer),
            score: observation.score,
            confidence: confidence_from_proto(observation.confidence),
            reason_code: observation.reason_code,
            explanation: observation.explanation,
        }
    }

    fn relay_detection_layer_from_proto_for_test(value: i32) -> RelayDetectionLayer {
        match proto::DetectionLayer::try_from(value).unwrap_or(proto::DetectionLayer::Unspecified) {
            proto::DetectionLayer::MlClassification => RelayDetectionLayer::MlClassification,
            proto::DetectionLayer::ContextAnalysis => RelayDetectionLayer::ContextAnalysis,
            proto::DetectionLayer::DomainHeuristic => RelayDetectionLayer::DomainHeuristic,
            proto::DetectionLayer::RelayInference => RelayDetectionLayer::RelayInference,
            proto::DetectionLayer::Unspecified | proto::DetectionLayer::PatternMatching => {
                RelayDetectionLayer::PatternMatching
            }
        }
    }

    fn relay_safety_telemetry_from_proto_for_test(
        event: proto::RelaySafetyTelemetryEvent,
    ) -> ClientSafetyTelemetryEvent {
        ClientSafetyTelemetryEvent {
            event_id: event.event_id,
            sender_token: event.sender_token,
            protected_account_token: event.protected_account_token,
            conversation_token: event.conversation_token,
            surface: safety_telemetry_surface_from_proto_for_test(event.surface),
            threat_type: threat_type_from_proto(event.threat_type),
            severity: safety_telemetry_severity_from_proto_for_test(event.severity),
            confidence: confidence_from_proto(event.confidence),
            action: safety_telemetry_action_from_proto_for_test(event.action),
            timestamp_bucket_ms: event.timestamp_bucket_ms,
            reason_family: event.reason_family,
        }
    }

    fn safety_telemetry_surface_from_proto_for_test(value: i32) -> SafetyTelemetrySurface {
        match proto::SafetyTelemetrySurface::try_from(value)
            .unwrap_or(proto::SafetyTelemetrySurface::Unspecified)
        {
            proto::SafetyTelemetrySurface::GroupChat => SafetyTelemetrySurface::GroupChat,
            proto::SafetyTelemetrySurface::PublicComment => SafetyTelemetrySurface::PublicComment,
            proto::SafetyTelemetrySurface::LivestreamComment => {
                SafetyTelemetrySurface::LivestreamComment
            }
            proto::SafetyTelemetrySurface::Unspecified
            | proto::SafetyTelemetrySurface::DirectMessage => SafetyTelemetrySurface::DirectMessage,
        }
    }

    fn safety_telemetry_severity_from_proto_for_test(value: i32) -> SafetyTelemetrySeverity {
        match proto::SafetyTelemetrySeverity::try_from(value)
            .unwrap_or(proto::SafetyTelemetrySeverity::Unspecified)
        {
            proto::SafetyTelemetrySeverity::Medium => SafetyTelemetrySeverity::Medium,
            proto::SafetyTelemetrySeverity::High => SafetyTelemetrySeverity::High,
            proto::SafetyTelemetrySeverity::Critical => SafetyTelemetrySeverity::Critical,
            proto::SafetyTelemetrySeverity::Unspecified | proto::SafetyTelemetrySeverity::Low => {
                SafetyTelemetrySeverity::Low
            }
        }
    }

    fn safety_telemetry_action_from_proto_for_test(value: i32) -> SafetyTelemetryAction {
        match proto::SafetyTelemetryAction::try_from(value)
            .unwrap_or(proto::SafetyTelemetryAction::Unspecified)
        {
            proto::SafetyTelemetryAction::Mark => SafetyTelemetryAction::Mark,
            proto::SafetyTelemetryAction::Blur => SafetyTelemetryAction::Blur,
            proto::SafetyTelemetryAction::Warn => SafetyTelemetryAction::Warn,
            proto::SafetyTelemetryAction::Block => SafetyTelemetryAction::Block,
            proto::SafetyTelemetryAction::GuardianAlert => SafetyTelemetryAction::GuardianAlert,
            proto::SafetyTelemetryAction::ReportQueued => SafetyTelemetryAction::ReportQueued,
            proto::SafetyTelemetryAction::RestrictContact => SafetyTelemetryAction::RestrictContact,
            proto::SafetyTelemetryAction::CrisisSupport => SafetyTelemetryAction::CrisisSupport,
            proto::SafetyTelemetryAction::Unspecified | proto::SafetyTelemetryAction::None => {
                SafetyTelemetryAction::None
            }
        }
    }

    fn relay_response_to_proto(
        response: RelayAnalyzeResponseContract,
    ) -> proto::RelayAnalyzeResponse {
        proto::RelayAnalyzeResponse {
            schema_version: response.schema_version,
            request_id: response.request_id,
            remote_observations: response
                .remote_observations
                .iter()
                .map(relay_observation_to_proto)
                .collect(),
            findings: response
                .findings
                .into_iter()
                .map(|finding| proto::RelayRemoteFinding {
                    threat_type: proto_threat_type(finding.threat_type) as i32,
                    score: finding.score,
                    confidence: proto_confidence(finding.confidence) as i32,
                    reason_code: finding.reason_code,
                    explanation: finding.explanation,
                })
                .collect(),
            inference: response
                .inference
                .map(|inference| proto::RelayRemoteInferenceSummary {
                    primary_threat: proto_threat_type(inference.primary_threat) as i32,
                    score: inference.score,
                    confidence: proto_confidence(inference.confidence) as i32,
                    risk_horizon: proto_relay_risk_horizon_for_test(inference.risk_horizon) as i32,
                }),
            reason_codes: response.reason_codes,
            context_markers: response.context_markers,
            confidence: proto_confidence(response.confidence) as i32,
            expires_at_ms: response.expires_at_ms,
            sender_reputation_hint: response.sender_reputation_hint,
            correlation_findings: response.correlation_findings,
            auth: response.auth.map(|auth| proto::RelayResponseAuth {
                key_id: auth.key_id,
                alg: auth.alg,
                tag: auth.tag,
            }),
            ..proto::RelayAnalyzeResponse::default()
        }
    }

    fn proto_relay_risk_horizon_for_test(value: RelayRiskHorizon) -> proto::RiskHorizon {
        match value {
            RelayRiskHorizon::Immediate => proto::RiskHorizon::Immediate,
            RelayRiskHorizon::NearTerm => proto::RiskHorizon::ShortTerm,
            RelayRiskHorizon::Sustained => proto::RiskHorizon::Sustained,
            RelayRiskHorizon::Unknown => proto::RiskHorizon::Unknown,
        }
    }

    fn relay_previous_response_auth_key_proto() -> proto::RelayResponseAuthKey {
        proto::RelayResponseAuthKey {
            key_id: "relay-key-previous".to_string(),
            secret: relay_previous_response_auth_secret(),
        }
    }

    fn relay_previous_response_auth_secret() -> Vec<u8> {
        b"relay response previous secret".to_vec()
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
            server_sender_risk_hint: None,
            sender_relationship: proto::SenderRelationship::Unspecified as i32,
            relationship_trust_source: proto::RelationshipTrustSource::Unspecified as i32,
        }
    }

    #[derive(Debug, Deserialize)]
    struct FfiWorldFixture {
        label: String,
        owner: FfiWorldOwner,
        #[serde(default)]
        config: FfiWorldConfig,
        #[serde(default)]
        actors: Vec<FfiWorldActor>,
        #[serde(default)]
        conversations: Vec<FfiWorldConversation>,
        #[serde(default)]
        events: Vec<FfiWorldEvent>,
        #[serde(default)]
        generated_batches: Vec<FfiGeneratedBatch>,
    }

    #[derive(Debug, Deserialize)]
    struct FfiWorldOwner {
        id: String,
        #[serde(default)]
        age: Option<u32>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct FfiWorldConfig {
        #[serde(default)]
        account_type: Option<String>,
        #[serde(default)]
        protection_level: Option<String>,
        #[serde(default)]
        language: Option<String>,
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default)]
        account_holder_age: Option<u32>,
        #[serde(default)]
        ttl_days: Option<u32>,
        #[serde(default)]
        timezone_offset_minutes: Option<i32>,
    }

    #[derive(Debug, Deserialize)]
    struct FfiWorldActor {
        id: String,
        #[serde(default)]
        trusted: bool,
        #[serde(default)]
        sender_relationship: Option<String>,
        #[serde(default)]
        relationship_trust_source: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct FfiWorldConversation {
        id: String,
        #[serde(default)]
        conversation_type: Option<String>,
        #[serde(default)]
        member_count: Option<u32>,
    }

    #[derive(Debug, Deserialize)]
    struct FfiWorldEvent {
        at: String,
        sender_id: String,
        conversation_id: String,
        text: String,
        #[serde(default)]
        language: Option<String>,
        #[serde(default)]
        conversation_type: Option<String>,
        #[serde(default)]
        member_count: Option<u32>,
        #[serde(default)]
        sender_relationship: Option<String>,
        #[serde(default)]
        relationship_trust_source: Option<String>,
        #[serde(default)]
        expect_clean: bool,
        #[serde(default)]
        expect_threat: Option<String>,
        #[serde(default)]
        expect_min_action: Option<String>,
        #[serde(default)]
        expect_min_alert: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct FfiGeneratedBatch {
        label: String,
        start_at: String,
        count: usize,
        interval_minutes: i64,
        #[serde(default = "default_day_repeats_for_ffi_world")]
        day_repeats: usize,
        #[serde(default = "default_day_stride_days_for_ffi_world")]
        day_stride_days: i64,
        sender_ids: Vec<String>,
        conversation_ids: Vec<String>,
        texts: Vec<String>,
        #[serde(default)]
        language: Option<String>,
        #[serde(default)]
        conversation_type: Option<String>,
        #[serde(default)]
        member_count: Option<u32>,
        #[serde(default)]
        sender_relationship: Option<String>,
        #[serde(default)]
        relationship_trust_source: Option<String>,
        #[serde(default)]
        expect_clean: bool,
        #[serde(default)]
        expect_threat: Option<String>,
        #[serde(default)]
        expect_min_action: Option<String>,
        #[serde(default)]
        expect_min_alert: Option<String>,
    }

    fn default_day_repeats_for_ffi_world() -> usize {
        1
    }

    fn default_day_stride_days_for_ffi_world() -> i64 {
        1
    }

    #[derive(Debug, Clone)]
    struct FfiResolvedWorldEvent {
        source_index: usize,
        timestamp_ms: u64,
        sender_id: String,
        conversation_id: String,
        language: String,
        conversation_type: proto::ConversationType,
        member_count: Option<u32>,
        sender_relationship: proto::SenderRelationship,
        relationship_trust_source: proto::RelationshipTrustSource,
        expectation: Option<FfiWorldExpectation>,
        text: String,
        sender_trusted: bool,
    }

    #[derive(Debug, Clone)]
    struct FfiWorldEventSeed {
        timestamp_ms: u64,
        sender_id: String,
        conversation_id: String,
        language: Option<String>,
        conversation_type: Option<String>,
        member_count: Option<u32>,
        sender_relationship: Option<String>,
        relationship_trust_source: Option<String>,
        expectation: Option<FfiWorldExpectation>,
        text: String,
    }

    #[derive(Debug, Clone)]
    struct FfiWorldExpectation {
        expect_clean: bool,
        expect_threat: Option<proto::ThreatType>,
        expect_min_action: Option<proto::Action>,
        expect_min_alert: Option<proto::AlertPriority>,
    }

    #[derive(Debug)]
    struct FfiWorldReplayReport {
        total_events: usize,
        labeled_positive_events: usize,
        labeled_clean_events: usize,
        true_positive_events: usize,
        false_positive_events: usize,
        restore_count: usize,
        findings: Vec<String>,
    }

    impl FfiWorldReplayReport {
        fn positive_recall(&self) -> f64 {
            if self.labeled_positive_events == 0 {
                return 1.0;
            }
            self.true_positive_events as f64 / self.labeled_positive_events as f64
        }

        fn clean_false_positive_rate(&self) -> f64 {
            if self.labeled_clean_events == 0 {
                return 0.0;
            }
            self.false_positive_events as f64 / self.labeled_clean_events as f64
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
        aura_init(bytes.as_ptr(), bytes.len())
    }

    unsafe fn analyze_result(
        handle: *mut c_void,
        message: proto::MessageInput,
    ) -> proto::AnalysisResult {
        let bytes = encode_proto(&message);
        let mut out = AuraBuffer::empty();
        assert!(aura_analyze(handle, bytes.as_ptr(), bytes.len(), &mut out));
        decode_buffer(out)
    }

    unsafe fn analyze_context_result(
        handle: *mut c_void,
        message: proto::MessageInput,
        timestamp_ms: u64,
    ) -> proto::AnalysisResult {
        let request = proto::AnalyzeContextRequest {
            message: Some(message),
            timestamp_ms,
        };
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();
        assert!(aura_analyze_context(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            &mut out
        ));
        decode_buffer(out)
    }

    unsafe fn analyze_for_relay_response(
        handle: *mut c_void,
        message: proto::MessageInput,
        timestamp_ms: u64,
    ) -> proto::AnalyzeForRelayResponse {
        let request = proto::AnalyzeContextRequest {
            message: Some(message),
            timestamp_ms,
        };
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();
        assert!(aura_analyze_for_relay(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            &mut out
        ));
        decode_buffer(out)
    }

    unsafe fn batch_results(
        handle: *mut c_void,
        items: Vec<proto::BatchAnalyzeItem>,
    ) -> proto::BatchAnalyzeResponse {
        let request = proto::BatchAnalyzeRequest { items };
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();
        assert!(aura_analyze_batch(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            &mut out
        ));
        decode_buffer(out)
    }

    unsafe fn build_shadow_bundle(
        handle: *mut c_void,
        request: proto::BuildShadowModeBundleRequest,
    ) -> proto::ShadowModeBundle {
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();
        assert!(aura_build_shadow_bundle(
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

    unsafe fn mark_contact_trusted_for_test(handle: *mut c_void, sender_id: &str) {
        let request = encode_proto(&proto::MarkContactTrustedRequest {
            sender_id: sender_id.to_string(),
        });
        assert!(aura_mark_contact_trusted(
            handle,
            request.as_ptr(),
            request.len()
        ));
    }

    unsafe fn get_contacts_by_risk(handle: *mut c_void) -> proto::ContactsByRiskResponse {
        let mut out = AuraBuffer::empty();
        assert!(aura_get_contacts_by_risk(handle, &mut out));
        decode_buffer(out)
    }

    unsafe fn get_contact_profile(
        handle: *mut c_void,
        sender_id: &str,
    ) -> proto::ContactProfileResponse {
        let request = proto::ContactProfileRequest {
            sender_id: sender_id.to_string(),
        };
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();
        assert!(aura_get_contact_profile(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            &mut out,
        ));
        decode_buffer(out)
    }

    unsafe fn get_conversation_summary(handle: *mut c_void) -> proto::ConversationSummaryResponse {
        let mut out = AuraBuffer::empty();
        assert!(aura_get_conversation_summary(handle, &mut out));
        decode_buffer(out)
    }

    fn temp_fixture_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aura_ffi_{name}_{}_{}.json",
            std::process::id(),
            nonce
        ))
    }

    fn write_temp_patterns_file(name: &str, json: &str) -> PathBuf {
        let path = temp_fixture_path(name);
        fs::write(&path, json)
            .unwrap_or_else(|error| panic!("write temp patterns file {}: {error}", path.display()));
        path
    }

    fn fixture_data_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../aura-core/data")
            .join(relative)
    }

    fn load_ffi_world_fixture(relative: &str) -> FfiWorldFixture {
        let path = fixture_data_path(relative);
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read world fixture {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse world fixture {}: {error}", path.display()))
    }

    fn ffi_config_for_world(world: &FfiWorldFixture) -> proto::AuraConfig {
        let account_type = match world.config.account_type.as_deref() {
            Some("adult") => proto::AccountType::Adult,
            Some("teen") => proto::AccountType::Teen,
            Some("child") | None => proto::AccountType::Child,
            Some(other) => panic!("unsupported fixture account_type: {other}"),
        };
        let mut config = proto_config(account_type, world.config.enabled.unwrap_or(true));
        config.protection_level = match world.config.protection_level.as_deref() {
            Some("off") => proto::ProtectionLevel::Off as i32,
            Some("low") => proto::ProtectionLevel::Low as i32,
            Some("medium") => proto::ProtectionLevel::Medium as i32,
            Some("high") | None => proto::ProtectionLevel::High as i32,
            Some(other) => panic!("unsupported fixture protection_level: {other}"),
        };
        config.language = world
            .config
            .language
            .clone()
            .unwrap_or_else(|| "uk".to_string());
        config.cultural_context = Some(proto::CulturalContext {
            kind: match config.language.as_str() {
                "uk" => proto::CulturalContextKind::Ukrainian as i32,
                "ru" => proto::CulturalContextKind::Russian as i32,
                "en" => proto::CulturalContextKind::English as i32,
                _ => proto::CulturalContextKind::Custom as i32,
            },
            custom_value: (!matches!(config.language.as_str(), "uk" | "ru" | "en"))
                .then(|| config.language.clone()),
        });
        config.account_holder_age = world.config.account_holder_age.or(world.owner.age);
        config.ttl_days = world.config.ttl_days.unwrap_or(30);
        config.timezone_offset_minutes = world.config.timezone_offset_minutes.unwrap_or(120);
        let mut relay_policy = metadata_only_relay_policy();
        relay_policy.enabled = Some(false);
        relay_policy.protected_account_id = Some(world.owner.id.clone());
        config.relay_policy = Some(relay_policy);
        config
    }

    fn resolve_ffi_world_events(world: &FfiWorldFixture) -> Vec<FfiResolvedWorldEvent> {
        let actor_lookup: HashMap<_, _> = world
            .actors
            .iter()
            .map(|actor| (actor.id.as_str(), actor))
            .collect();
        let conversation_lookup: HashMap<_, _> = world
            .conversations
            .iter()
            .map(|conversation| (conversation.id.as_str(), conversation))
            .collect();

        let mut seeds = Vec::new();
        for event in &world.events {
            seeds.push(FfiWorldEventSeed {
                timestamp_ms: timestamp_ms_from_rfc3339(&event.at),
                sender_id: event.sender_id.clone(),
                conversation_id: event.conversation_id.clone(),
                language: event.language.clone(),
                conversation_type: event.conversation_type.clone(),
                member_count: event.member_count,
                sender_relationship: event.sender_relationship.clone(),
                relationship_trust_source: event.relationship_trust_source.clone(),
                expectation: ffi_expectation_from_parts(
                    event.expect_clean,
                    event.expect_threat.as_deref(),
                    event.expect_min_action.as_deref(),
                    event.expect_min_alert.as_deref(),
                ),
                text: event.text.clone(),
            });
        }
        for batch in &world.generated_batches {
            seeds.extend(expand_ffi_generated_batch(batch));
        }

        let mut resolved = seeds
            .into_iter()
            .enumerate()
            .map(|(index, seed)| {
                resolve_ffi_world_event(index, seed, world, &actor_lookup, &conversation_lookup)
            })
            .collect::<Vec<_>>();
        resolved.sort_by_key(|event| (event.timestamp_ms, event.source_index));
        resolved
    }

    fn expand_ffi_generated_batch(batch: &FfiGeneratedBatch) -> Vec<FfiWorldEventSeed> {
        assert!(batch.count > 0, "batch {} has zero count", batch.label);
        assert!(
            batch.interval_minutes > 0,
            "batch {} has non-positive interval",
            batch.label
        );
        assert!(
            batch.day_repeats > 0,
            "batch {} has zero day_repeats",
            batch.label
        );
        assert!(
            batch.day_stride_days > 0,
            "batch {} has non-positive day stride",
            batch.label
        );
        assert!(
            !batch.sender_ids.is_empty()
                && !batch.conversation_ids.is_empty()
                && !batch.texts.is_empty(),
            "batch {} is missing generated dimensions",
            batch.label
        );

        let start = DateTime::parse_from_rfc3339(&batch.start_at)
            .unwrap_or_else(|error| panic!("batch {} timestamp: {error}", batch.label));
        let interval = Duration::minutes(batch.interval_minutes);
        let day_stride = Duration::days(batch.day_stride_days);
        let mut seeds = Vec::with_capacity(batch.count * batch.day_repeats);

        for day_index in 0..batch.day_repeats {
            let day_base = start + day_stride * day_index as i32;
            for event_index in 0..batch.count {
                let absolute_index = day_index * batch.count + event_index;
                let at = day_base + interval * event_index as i32;
                seeds.push(FfiWorldEventSeed {
                    timestamp_ms: at.with_timezone(&Utc).timestamp_millis() as u64,
                    sender_id: batch.sender_ids[absolute_index % batch.sender_ids.len()].clone(),
                    conversation_id: batch.conversation_ids
                        [absolute_index % batch.conversation_ids.len()]
                    .clone(),
                    language: batch.language.clone(),
                    conversation_type: batch.conversation_type.clone(),
                    member_count: batch.member_count,
                    sender_relationship: batch.sender_relationship.clone(),
                    relationship_trust_source: batch.relationship_trust_source.clone(),
                    expectation: ffi_expectation_from_parts(
                        batch.expect_clean,
                        batch.expect_threat.as_deref(),
                        batch.expect_min_action.as_deref(),
                        batch.expect_min_alert.as_deref(),
                    ),
                    text: batch.texts[absolute_index % batch.texts.len()].clone(),
                });
            }
        }
        seeds
    }

    fn resolve_ffi_world_event(
        index: usize,
        seed: FfiWorldEventSeed,
        world: &FfiWorldFixture,
        actor_lookup: &HashMap<&str, &FfiWorldActor>,
        conversation_lookup: &HashMap<&str, &FfiWorldConversation>,
    ) -> FfiResolvedWorldEvent {
        let actor = actor_lookup.get(seed.sender_id.as_str()).copied();
        let conversation = conversation_lookup
            .get(seed.conversation_id.as_str())
            .copied();
        FfiResolvedWorldEvent {
            source_index: index,
            timestamp_ms: seed.timestamp_ms,
            sender_relationship: ffi_sender_relationship(
                seed.sender_relationship
                    .as_deref()
                    .or_else(|| actor.and_then(|actor| actor.sender_relationship.as_deref())),
            ),
            relationship_trust_source: ffi_relationship_trust_source(
                seed.relationship_trust_source
                    .as_deref()
                    .or_else(|| actor.and_then(|actor| actor.relationship_trust_source.as_deref())),
            ),
            conversation_type: ffi_conversation_type(seed.conversation_type.as_deref().or_else(
                || conversation.and_then(|conversation| conversation.conversation_type.as_deref()),
            )),
            member_count: seed
                .member_count
                .or_else(|| conversation.and_then(|conversation| conversation.member_count)),
            language: seed.language.unwrap_or_else(|| {
                world
                    .config
                    .language
                    .clone()
                    .unwrap_or_else(|| "uk".to_string())
            }),
            sender_trusted: actor.is_some_and(|actor| actor.trusted),
            sender_id: seed.sender_id,
            conversation_id: seed.conversation_id,
            expectation: seed.expectation,
            text: seed.text,
        }
    }

    fn timestamp_ms_from_rfc3339(value: &str) -> u64 {
        DateTime::parse_from_rfc3339(value)
            .unwrap_or_else(|error| panic!("invalid fixture timestamp {value}: {error}"))
            .with_timezone(&Utc)
            .timestamp_millis() as u64
    }

    fn ffi_expectation_from_parts(
        expect_clean: bool,
        expect_threat: Option<&str>,
        expect_min_action: Option<&str>,
        expect_min_alert: Option<&str>,
    ) -> Option<FfiWorldExpectation> {
        let expect_threat = expect_threat.map(ffi_threat_type);
        let expect_min_action = expect_min_action.map(ffi_action);
        let expect_min_alert = expect_min_alert.map(ffi_alert_priority);
        (expect_clean
            || expect_threat.is_some()
            || expect_min_action.is_some()
            || expect_min_alert.is_some())
        .then_some(FfiWorldExpectation {
            expect_clean,
            expect_threat,
            expect_min_action,
            expect_min_alert,
        })
    }

    fn ffi_conversation_type(value: Option<&str>) -> proto::ConversationType {
        match value {
            Some("group") => proto::ConversationType::Group,
            Some("direct") | None => proto::ConversationType::Direct,
            Some(other) => panic!("unsupported fixture conversation_type: {other}"),
        }
    }

    fn ffi_sender_relationship(value: Option<&str>) -> proto::SenderRelationship {
        match value {
            Some("parent") => proto::SenderRelationship::Parent,
            Some("guardian") => proto::SenderRelationship::Guardian,
            Some("family") => proto::SenderRelationship::Family,
            Some("sibling") => proto::SenderRelationship::Sibling,
            Some("peer") => proto::SenderRelationship::Peer,
            Some("teacher") => proto::SenderRelationship::Teacher,
            Some("coach") => proto::SenderRelationship::Coach,
            Some("authority") => proto::SenderRelationship::Authority,
            Some("service") => proto::SenderRelationship::Service,
            Some("unknown_adult") => proto::SenderRelationship::UnknownAdult,
            Some("unknown_peer") => proto::SenderRelationship::UnknownPeer,
            Some("unknown") | None => proto::SenderRelationship::Unknown,
            Some(other) => panic!("unsupported fixture sender_relationship: {other}"),
        }
    }

    fn ffi_relationship_trust_source(value: Option<&str>) -> proto::RelationshipTrustSource {
        match value {
            Some("user_verified") => proto::RelationshipTrustSource::UserVerified,
            Some("guardian_verified") => proto::RelationshipTrustSource::GuardianVerified,
            Some("platform_verified") => proto::RelationshipTrustSource::PlatformVerified,
            Some("address_book") => proto::RelationshipTrustSource::AddressBook,
            Some("school_directory") => proto::RelationshipTrustSource::SchoolDirectory,
            Some("server_reputation") => proto::RelationshipTrustSource::ServerReputation,
            Some("local_heuristic") => proto::RelationshipTrustSource::LocalHeuristic,
            Some("self_declared") => proto::RelationshipTrustSource::SelfDeclared,
            Some("unknown") | None => proto::RelationshipTrustSource::Unknown,
            Some(other) => panic!("unsupported fixture relationship_trust_source: {other}"),
        }
    }

    fn ffi_threat_type(value: &str) -> proto::ThreatType {
        match value {
            "bullying" => proto::ThreatType::Bullying,
            "grooming" => proto::ThreatType::Grooming,
            "explicit" => proto::ThreatType::Explicit,
            "threat" => proto::ThreatType::Threat,
            "self_harm" => proto::ThreatType::SelfHarm,
            "spam" => proto::ThreatType::Spam,
            "scam" => proto::ThreatType::Scam,
            "phishing" => proto::ThreatType::Phishing,
            "manipulation" => proto::ThreatType::Manipulation,
            "nsfw" => proto::ThreatType::Nsfw,
            "hate_speech" => proto::ThreatType::HateSpeech,
            "doxxing" => proto::ThreatType::Doxxing,
            "pii_leakage" => proto::ThreatType::PiiLeakage,
            "propaganda" => proto::ThreatType::Propaganda,
            "opsec_violation" => proto::ThreatType::OpsecViolation,
            "psyops" => proto::ThreatType::Psyops,
            "military_social_eng" => proto::ThreatType::MilitarySocialEng,
            "coordinate_leak" => proto::ThreatType::CoordinateLeak,
            other => panic!("unsupported fixture threat_type: {other}"),
        }
    }

    fn ffi_action(value: &str) -> proto::Action {
        match value {
            "allow" => proto::Action::Allow,
            "mark" => proto::Action::Mark,
            "blur" => proto::Action::Blur,
            "warn" => proto::Action::Warn,
            "block" => proto::Action::Block,
            other => panic!("unsupported fixture action: {other}"),
        }
    }

    fn ffi_alert_priority(value: &str) -> proto::AlertPriority {
        match value {
            "none" => proto::AlertPriority::None,
            "low" => proto::AlertPriority::Low,
            "medium" => proto::AlertPriority::Medium,
            "high" => proto::AlertPriority::High,
            "urgent" => proto::AlertPriority::Urgent,
            other => panic!("unsupported fixture alert: {other}"),
        }
    }

    unsafe fn run_ffi_world_replay(relative_fixture_path: &str) -> FfiWorldReplayReport {
        run_ffi_world_replay_with_restore_interval(relative_fixture_path, None)
    }

    unsafe fn run_ffi_world_replay_with_restore_interval(
        relative_fixture_path: &str,
        restore_interval: Option<usize>,
    ) -> FfiWorldReplayReport {
        if let Some(interval) = restore_interval {
            assert!(interval > 0, "restore interval must be positive");
        }

        let world = load_ffi_world_fixture(relative_fixture_path);
        let events = resolve_ffi_world_events(&world);
        let config = ffi_config_for_world(&world);
        let mut handle = init_handle(config.clone());
        assert!(!handle.is_null(), "failed to initialize FFI world replay");

        let mut report = FfiWorldReplayReport {
            total_events: events.len(),
            labeled_positive_events: 0,
            labeled_clean_events: 0,
            true_positive_events: 0,
            false_positive_events: 0,
            restore_count: 0,
            findings: Vec::new(),
        };

        for (sequence, event) in events.iter().enumerate() {
            let mut message = proto_message(&event.text, &event.sender_id, &event.conversation_id);
            message.language = Some(event.language.clone());
            message.conversation_type = event.conversation_type as i32;
            message.member_count = event.member_count;
            message.sender_relationship = event.sender_relationship as i32;
            message.relationship_trust_source = event.relationship_trust_source as i32;

            let result = analyze_context_result(handle, message, event.timestamp_ms);
            if event.sender_trusted {
                mark_contact_trusted_for_test(handle, &event.sender_id);
            }
            evaluate_ffi_world_expectation(&world, event, &result, sequence + 1, &mut report);

            if restore_interval.is_some_and(|interval| {
                (sequence + 1) % interval == 0 && sequence + 1 < events.len()
            }) {
                handle = restart_ffi_world_handle(&config, handle);
                report.restore_count += 1;
            }
        }

        aura_free(handle);
        report
    }

    unsafe fn restart_ffi_world_handle(
        config: &proto::AuraConfig,
        handle: *mut c_void,
    ) -> *mut c_void {
        let state = export_context(handle)
            .state
            .expect("FFI replay restore requires exported context state");
        aura_free(handle);

        let restored = init_handle(config.clone());
        assert!(
            !restored.is_null(),
            "failed to initialize restored FFI handle"
        );
        import_context_state(restored, state);
        restored
    }

    fn evaluate_ffi_world_expectation(
        world: &FfiWorldFixture,
        event: &FfiResolvedWorldEvent,
        result: &proto::AnalysisResult,
        sequence: usize,
        report: &mut FfiWorldReplayReport,
    ) {
        if let Some(expectation) = &event.expectation {
            if expectation.expect_clean {
                report.labeled_clean_events += 1;
                if ffi_clean_expectation_violated(result) {
                    report.false_positive_events += 1;
                    report.findings.push(format!(
                        "{}#{sequence}: expected clean allow, got threat={} action={}",
                        world.label, result.threat_type, result.action
                    ));
                }
            }

            if let Some(expected_threat) = expectation.expect_threat {
                report.labeled_positive_events += 1;
                if ffi_result_contains_threat(result, expected_threat) {
                    report.true_positive_events += 1;
                } else {
                    report.findings.push(format!(
                        "{}#{sequence}: expected threat {:?}, got threat={} detected={:?}",
                        world.label,
                        expected_threat,
                        result.threat_type,
                        result
                            .detected_threats
                            .iter()
                            .map(|threat| threat.threat_type)
                            .collect::<Vec<_>>()
                    ));
                }
            }

            if let Some(expected_action) = expectation.expect_min_action {
                if result.action < expected_action as i32 {
                    report.findings.push(format!(
                        "{}#{sequence}: expected action >= {:?}, got {}",
                        world.label, expected_action, result.action
                    ));
                }
            }

            if let Some(expected_alert) = expectation.expect_min_alert {
                let actual_alert = result
                    .recommended_action
                    .as_ref()
                    .map(|recommendation| recommendation.parent_alert)
                    .unwrap_or(proto::AlertPriority::None as i32);
                if actual_alert < expected_alert as i32 {
                    report.findings.push(format!(
                        "{}#{sequence}: expected alert >= {:?}, got {}",
                        world.label, expected_alert, actual_alert
                    ));
                }
            }
        }

        if event.sender_id == world.owner.id
            && result
                .reason_codes
                .iter()
                .any(|code| code.starts_with("conversation.contact."))
        {
            report.findings.push(format!(
                "{}#{sequence}: owner-authored message triggered contact-risk reason code",
                world.label
            ));
        }
        if event.sender_id == world.owner.id
            && result
                .reason_codes
                .iter()
                .any(|code| code == "conversation.timing.late_night_minor_contact")
        {
            report.findings.push(format!(
                "{}#{sequence}: owner-authored message triggered late-night contact reason code",
                world.label
            ));
        }
    }

    fn ffi_clean_expectation_violated(result: &proto::AnalysisResult) -> bool {
        let threat_type =
            proto::ThreatType::try_from(result.threat_type).unwrap_or(proto::ThreatType::None);
        let action = proto::Action::try_from(result.action).unwrap_or(proto::Action::Allow);
        !matches!(
            threat_type,
            proto::ThreatType::None | proto::ThreatType::Unspecified
        ) || action != proto::Action::Allow
    }

    fn ffi_result_contains_threat(
        result: &proto::AnalysisResult,
        expected: proto::ThreatType,
    ) -> bool {
        result.threat_type == expected as i32
            || result
                .detected_threats
                .iter()
                .any(|threat| threat.threat_type == expected as i32)
    }

    fn empty_ruleset_patterns_json() -> &'static str {
        r#"{"version":"test-empty","updated_at":"2026-03-13","rules":[]}"#
    }

    fn custom_keyword_patterns_json(keyword: &str) -> String {
        format!(
            r#"{{
  "version":"test-custom",
  "updated_at":"2026-03-13",
  "rules":[
    {{
      "id":"custom_threat_rule",
      "threat_type":"threat",
      "kind":{{"type":"keyword","words":["{keyword}"]}},
      "score":0.95,
      "languages":["en"],
      "explanation":"custom threat fixture"
    }}
  ]
}}"#
        )
    }

    fn invalid_regex_patterns_json() -> &'static str {
        r#"{
  "version":"test-invalid-regex",
  "updated_at":"2026-03-15",
  "rules":[
    {
      "id":"broken_regex_rule",
      "threat_type":"threat",
      "kind":{"type":"regex","pattern":"(unclosed"},
      "score":0.95,
      "languages":["en"],
      "explanation":"broken regex fixture"
    }
  ]
}"#
    }

    fn has_pattern_signal(result: &proto::AnalysisResult) -> bool {
        result.signals.iter().any(|signal| {
            signal.layer == proto::DetectionLayer::PatternMatching as i32 && signal.score > 0.0
        })
    }

    fn truncate_proto(bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() > 1, "fixture bytes must be truncatable");
        bytes[..bytes.len() - 1].to_vec()
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
    fn init_and_analyze_clean_message() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            assert!(!handle.is_null());

            let result = analyze_result(
                handle,
                proto_message("Hey, how are you doing?", "user_1", "conv_1"),
            );
            assert_eq!(
                proto::Action::try_from(result.action).unwrap(),
                proto::Action::Allow
            );

            aura_free(handle);
        }
    }

    #[test]
    fn init_and_analyze_threat() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            assert!(!handle.is_null());

            let result =
                analyze_result(handle, proto_message("I will kill you", "user_1", "conv_1"));
            assert_eq!(
                proto::ThreatType::try_from(result.threat_type).unwrap(),
                proto::ThreatType::Threat
            );
            assert_ne!(
                proto::Action::try_from(result.action).unwrap(),
                proto::Action::Allow
            );

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_context_builds_history() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            assert!(!handle.is_null());

            let _ = analyze_context_result(
                handle,
                proto_message(
                    "You're so beautiful and amazing and perfect!",
                    "stranger",
                    "conv_1",
                ),
                1000,
            );

            let result = analyze_context_result(
                handle,
                proto_message(
                    "Don't tell your parents about us, ok?",
                    "stranger",
                    "conv_1",
                ),
                2000,
            );

            assert_eq!(
                proto::ThreatType::try_from(result.threat_type).unwrap(),
                proto::ThreatType::Grooming
            );
            aura_free(handle);
        }
    }

    #[test]
    fn analysis_result_includes_inference_summary_over_ffi() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            assert!(!handle.is_null());

            let _ = analyze_context_result(
                handle,
                proto_message(
                    "I don't want to live anymore. I want to end it all.",
                    "user_1",
                    "conv_sh_1",
                ),
                1000,
            );
            let result = analyze_context_result(
                handle,
                proto_message("Goodbye everyone. This is the end.", "user_1", "conv_sh_1"),
                2000,
            );

            let inference = result.inference.expect("missing inference summary");
            assert!(
                matches!(
                    proto::RiskHorizon::try_from(inference.risk_horizon).unwrap(),
                    proto::RiskHorizon::Immediate
                        | proto::RiskHorizon::ShortTerm
                        | proto::RiskHorizon::Unknown
                ),
                "unexpected risk horizon over FFI: {:?}",
                proto::RiskHorizon::try_from(inference.risk_horizon).unwrap()
            );
            assert!(
                !inference.latent_states.is_empty() || inference.escalation_likelihood_24h >= 0.0,
                "expected inference payload to carry latent states or escalation signal"
            );

            let product_surface = result
                .product_surface
                .expect("missing product decision surface");
            assert_eq!(
                proto::ProductRolloutMode::try_from(product_surface.rollout_mode).unwrap(),
                proto::ProductRolloutMode::GuardianEnabled
            );
            assert_eq!(
                proto::ProductDeliveryMode::try_from(
                    product_surface
                        .child
                        .as_ref()
                        .expect("child surface")
                        .delivery_mode
                )
                .unwrap(),
                proto::ProductDeliveryMode::MirrorOnly
            );
            assert!(
                matches!(
                    proto::ProductUncertaintyDisposition::try_from(
                        product_surface.uncertainty_disposition
                    )
                    .unwrap(),
                    proto::ProductUncertaintyDisposition::GuardianPriority
                        | proto::ProductUncertaintyDisposition::RequireReview
                ),
                "unexpected uncertainty disposition: {:?}",
                proto::ProductUncertaintyDisposition::try_from(
                    product_surface.uncertainty_disposition
                )
                .unwrap()
            );

            aura_free(handle);
        }
    }

    #[test]
    fn build_shadow_bundle_over_ffi_returns_proto_bundle() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            assert!(!handle.is_null());

            let request = proto::BuildShadowModeBundleRequest {
                source_kind: "ios_shadow".to_string(),
                source_label: "pilot-smoke".to_string(),
                source_input: "swift-replay".to_string(),
                owner_id: "owner_olena".to_string(),
                items: vec![
                    proto::ShadowModeAnalyzeItem {
                        request_id: "shadow_req_1".to_string(),
                        request: Some(proto::AnalyzeContextRequest {
                            message: Some(proto_message(
                                "You're so special and beautiful. I can buy you anything.",
                                "stranger_1",
                                "conv_shadow_1",
                            )),
                            timestamp_ms: 1_000,
                        }),
                        expectation: None,
                    },
                    proto::ShadowModeAnalyzeItem {
                        request_id: "shadow_req_2".to_string(),
                        request: Some(proto::AnalyzeContextRequest {
                            message: Some(proto_message(
                                "Don't tell your parents about us. Let's move to Telegram.",
                                "stranger_1",
                                "conv_shadow_1",
                            )),
                            timestamp_ms: 2_000,
                        }),
                        expectation: Some(proto::ShadowModeExpectation {
                            expect_threat: proto::ThreatType::Grooming as i32,
                            expect_min_action: proto::Action::Warn as i32,
                            expect_min_alert: proto::AlertPriority::High as i32,
                        }),
                    },
                ],
            };

            let bundle = build_shadow_bundle(handle, request);
            assert_eq!(bundle.summary.as_ref().expect("summary").total_events, 2);
            assert_eq!(bundle.summary.as_ref().expect("summary").finding_count, 0);
            assert_eq!(bundle.events.len(), 2);
            assert_ne!(
                bundle.owner_token.as_ref().expect("owner token").token,
                "owner_olena"
            );
            assert_eq!(
                proto::ThreatType::try_from(
                    bundle.events[1]
                        .decision
                        .as_ref()
                        .expect("decision")
                        .threat_type
                )
                .unwrap(),
                proto::ThreatType::Grooming
            );
            assert!(
                bundle.events[1]
                    .audit_record
                    .as_ref()
                    .and_then(|record| record.sender_token.as_ref())
                    .is_some(),
                "expected tokenized sender in audit record"
            );
            let product_surface = bundle.events[1]
                .decision
                .as_ref()
                .and_then(|decision| decision.product_surface.as_ref())
                .expect("missing shadow product surface");
            assert_eq!(
                proto::ProductRolloutMode::try_from(product_surface.rollout_mode).unwrap(),
                proto::ProductRolloutMode::Shadow
            );
            assert_eq!(
                proto::ProductDeliveryMode::try_from(
                    product_surface
                        .child
                        .as_ref()
                        .expect("child surface")
                        .delivery_mode
                )
                .unwrap(),
                proto::ProductDeliveryMode::MirrorOnly
            );

            aura_free(handle);
        }
    }

    #[test]
    fn context_export_import_via_ffi() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message(
                    "our little secret. don't tell your parents.",
                    "stranger",
                    "conv_1",
                ),
                1000,
            );

            let exported = export_context(handle);
            let state = exported.state.expect("missing state");
            assert!(
                state.kids_memory.is_some(),
                "expected exported protobuf state to include instance-owned kids memory"
            );
            assert!(
                state
                    .timelines
                    .iter()
                    .any(|timeline| timeline.conversation_id == "conv_1"),
                "expected exported protobuf state to include conv_1"
            );
            let exported_profile = state
                .contact_profiler
                .as_ref()
                .and_then(|profiler| {
                    profiler
                        .profiles
                        .iter()
                        .find(|profile| profile.sender_id == "stranger")
                })
                .expect("missing exported stranger profile");
            let exported_child_safety = exported_profile
                .child_safety
                .as_ref()
                .expect("missing exported child safety trajectory");
            let exported_grooming_count = exported_child_safety.grooming_event_count;
            assert!(
                exported_grooming_count > 0,
                "expected exported child safety trajectory to preserve grooming memory"
            );

            let handle2 = init_handle(proto_config(proto::AccountType::Child, true));
            let request = proto::ImportContextRequest { state: Some(state) };
            let request = encode_proto(&request);
            assert!(aura_import_context(
                handle2,
                request.as_ptr(),
                request.len()
            ));

            let imported = get_contact_profile(handle2, "stranger");
            assert!(imported.found);
            let post_import = analyze_context_result(
                handle2,
                proto_message(
                    "you can only trust me. do it now or i post everything.",
                    "stranger",
                    "conv_1",
                ),
                1001,
            );
            assert!(
                post_import
                    .reason_codes
                    .iter()
                    .any(|code| code == "domain.kids.memory.grooming_progression"),
                "expected imported kids memory to affect FFI analysis, got {:?}",
                post_import.reason_codes
            );
            let reexported = export_context(handle2)
                .state
                .expect("missing reexported state");
            let reexported_child_safety = reexported
                .contact_profiler
                .as_ref()
                .and_then(|profiler| {
                    profiler
                        .profiles
                        .iter()
                        .find(|profile| profile.sender_id == "stranger")
                })
                .and_then(|profile| profile.child_safety.as_ref())
                .expect("missing reexported child safety trajectory");
            assert!(
                reexported_child_safety.grooming_event_count >= exported_grooming_count,
                "reexported grooming count should preserve imported state and may grow after follow-up analysis"
            );

            aura_free(handle);
            aura_free(handle2);
        }
    }

    #[test]
    fn repeated_import_of_same_state_is_idempotent() {
        unsafe {
            let source = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                source,
                proto_message("don't tell your parents", "stranger", "conv_1"),
                1000,
            );
            let exported = export_context(source)
                .state
                .expect("missing exported state");

            let replica = init_handle(proto_config(proto::AccountType::Child, true));
            for _ in 0..25 {
                import_context_state(replica, exported.clone());
            }

            let summary = get_conversation_summary(replica);
            assert_eq!(summary.total_conversations, 1);
            assert_eq!(summary.conversations.len(), 1);
            assert_eq!(summary.conversations[0].conversation_id, "conv_1");
            assert!(
                summary.conversations[0].total_events >= 2,
                "expected at least 2 events, got {}",
                summary.conversations[0].total_events,
            );

            let expected_events = summary.conversations[0].total_events;
            let profile = get_contact_profile(replica, "stranger");
            assert!(profile.found);
            let profile = profile.profile.expect("missing contact profile");
            assert_eq!(profile.total_messages, expected_events);

            aura_free(source);
            aura_free(replica);
        }
    }

    #[test]
    fn repeated_export_import_roundtrips_preserve_growth() {
        unsafe {
            let handle_a = init_handle(proto_config(proto::AccountType::Child, true));
            let handle_b = init_handle(proto_config(proto::AccountType::Child, true));

            let timeline = [
                ("Hey, you seem really cool", 1000_u64),
                ("don't tell your parents about us", 2000),
                ("you're beautiful and amazing", 3000),
                ("send me a pic, just for me", 4000),
                ("why are you ignoring me, answer now", 5000),
                ("keep this secret between us", 6000),
            ];

            for (index, (text, timestamp_ms)) in timeline.iter().enumerate() {
                let active = if index % 2 == 0 { handle_a } else { handle_b };
                let standby = if index % 2 == 0 { handle_b } else { handle_a };

                let _ = analyze_context_result(
                    active,
                    proto_message(text, "stranger", "conv_sync"),
                    *timestamp_ms,
                );
                let state = export_context(active)
                    .state
                    .expect("missing exported state");
                import_context_state(standby, state);
            }

            let final_state = export_context(handle_a).state.expect("missing final state");
            import_context_state(handle_b, final_state);

            let summary_a = get_conversation_summary(handle_a);
            let summary_b = get_conversation_summary(handle_b);
            assert_eq!(summary_a.total_conversations, 1);
            assert_eq!(summary_b.total_conversations, 1);
            assert_eq!(summary_a.conversations[0].conversation_id, "conv_sync");
            assert_eq!(summary_b.conversations[0].conversation_id, "conv_sync");
            assert!(summary_a.conversations[0].total_events >= timeline.len() as u64);
            assert!(summary_b.conversations[0].total_events >= timeline.len() as u64);
            let event_delta = summary_a.conversations[0]
                .total_events
                .abs_diff(summary_b.conversations[0].total_events);
            assert!(
                event_delta <= 1,
                "replicas diverged too much: {event_delta}"
            );
            assert_eq!(summary_a.conversations[0].latest_event_ms, 6000);
            assert_eq!(summary_b.conversations[0].latest_event_ms, 6000);

            let profile_a = get_contact_profile(handle_a, "stranger");
            let profile_b = get_contact_profile(handle_b, "stranger");
            assert!(profile_a.found);
            assert!(profile_b.found);
            let profile_a_messages = profile_a
                .profile
                .as_ref()
                .expect("profile a")
                .total_messages;
            let profile_b_messages = profile_b
                .profile
                .as_ref()
                .expect("profile b")
                .total_messages;
            assert!(profile_a_messages >= timeline.len() as u64);
            assert!(profile_b_messages >= timeline.len() as u64);
            assert!(
                profile_a_messages.abs_diff(profile_b_messages) <= 1,
                "profile replicas diverged too much: {profile_a_messages} vs {profile_b_messages}"
            );

            aura_free(handle_a);
            aura_free(handle_b);
        }
    }

    #[test]
    #[ignore = "long fixture replay; run via ci/ffi_world_replay_gate.sh"]
    fn ffi_replays_six_month_world_fixture() {
        unsafe {
            let report = run_ffi_world_replay("world_sim_13yo_6mo.json");
            assert!(
                report.total_events >= 400,
                "six-month FFI replay unexpectedly small: {:?}",
                report
            );
            assert!(
                report.positive_recall() >= 0.95,
                "six-month FFI replay recall below gate: {:?}",
                report
            );
            assert!(
                report.clean_false_positive_rate() <= 0.01,
                "six-month FFI replay clean FP above gate: {:?}",
                report
            );
            assert!(
                report.findings.is_empty(),
                "six-month FFI replay findings: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    #[ignore = "long fixture replay; run via ci/ffi_world_replay_gate.sh"]
    fn ffi_replays_dense_two_year_world_fixture() {
        unsafe {
            let report = run_ffi_world_replay("world_lifecycle_suite/sofia_13_to_15_dense_2y.json");
            assert!(
                report.total_events >= 6000,
                "dense two-year FFI replay unexpectedly small: {:?}",
                report
            );
            assert!(
                report.positive_recall() >= 0.95,
                "dense two-year FFI replay recall below gate: {:?}",
                report
            );
            assert!(
                report.clean_false_positive_rate() <= 0.01,
                "dense two-year FFI replay clean FP above gate: {:?}",
                report
            );
            assert!(
                report.findings.is_empty(),
                "dense two-year FFI replay findings: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    #[ignore = "long client-boundary fixture replay; run via ci/client_boundary_replay_gate.sh"]
    fn ffi_replays_six_month_world_across_periodic_state_restore() {
        unsafe {
            let report =
                run_ffi_world_replay_with_restore_interval("world_sim_13yo_6mo.json", Some(50));
            assert!(
                report.total_events >= 400,
                "six-month client-boundary replay unexpectedly small: {:?}",
                report
            );
            assert!(
                report.restore_count >= 8,
                "six-month client-boundary replay did not restore often enough: {:?}",
                report
            );
            assert!(
                report.positive_recall() >= 0.95,
                "six-month client-boundary replay recall below gate: {:?}",
                report
            );
            assert!(
                report.clean_false_positive_rate() <= 0.01,
                "six-month client-boundary replay clean FP above gate: {:?}",
                report
            );
            assert!(
                report.findings.is_empty(),
                "six-month client-boundary replay findings: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    #[ignore = "long client-boundary fixture replay; run via ci/client_boundary_replay_gate.sh"]
    fn ffi_replays_dense_two_year_world_across_periodic_state_restore() {
        unsafe {
            let report = run_ffi_world_replay_with_restore_interval(
                "world_lifecycle_suite/sofia_13_to_15_dense_2y.json",
                Some(500),
            );
            assert!(
                report.total_events >= 6000,
                "dense two-year client-boundary replay unexpectedly small: {:?}",
                report
            );
            assert!(
                report.restore_count >= 13,
                "dense two-year client-boundary replay did not restore often enough: {:?}",
                report
            );
            assert!(
                report.positive_recall() >= 0.95,
                "dense two-year client-boundary replay recall below gate: {:?}",
                report
            );
            assert!(
                report.clean_false_positive_rate() <= 0.01,
                "dense two-year client-boundary replay clean FP above gate: {:?}",
                report
            );
            assert!(
                report.findings.is_empty(),
                "dense two-year client-boundary replay findings: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    fn contacts_and_profile_are_available_over_proto() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));

            let _ = analyze_context_result(
                handle,
                proto_message(
                    "You're so beautiful and amazing, truly special",
                    "stranger_1",
                    "conv_1",
                ),
                1000,
            );
            let _ = analyze_context_result(
                handle,
                proto_message("Hey, want to play Minecraft?", "friend_1", "conv_2"),
                2000,
            );

            let contacts = get_contacts_by_risk(handle);
            assert_eq!(contacts.contacts.len(), 2);
            assert!(contacts
                .contacts
                .iter()
                .any(|c| c.sender_id == "stranger_1"));

            let profile = get_contact_profile(handle, "stranger_1");
            assert!(profile.found);
            let profile = profile.profile.unwrap();
            assert!(profile.rating > 0.0);
            assert!(profile.trust_level >= 0.0);

            aura_free(handle);
        }
    }

    #[test]
    fn update_config_disables_aura() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            assert!(!handle.is_null());

            let updated = encode_proto(&proto_config(proto::AccountType::Adult, false));
            assert!(aura_update_config(handle, updated.as_ptr(), updated.len()));

            let result =
                analyze_result(handle, proto_message("I will kill you", "user_1", "conv_1"));
            assert_eq!(
                proto::Action::try_from(result.action).unwrap(),
                proto::Action::Allow
            );

            aura_free(handle);
        }
    }

    #[test]
    fn null_handle_sets_last_error() {
        unsafe {
            let message = encode_proto(&proto_message("test", "u1", "c1"));
            let mut out = AuraBuffer::empty();
            assert!(!aura_analyze(
                std::ptr::null_mut(),
                message.as_ptr(),
                message.len(),
                &mut out,
            ));

            let err = aura_last_error();
            assert!(!err.is_null());
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("null handle"), "Got: {err_str}");
            aura_free_string(err);
        }
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
    fn cleanup_context_works() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ =
                analyze_context_result(handle, proto_message("hello", "friend", "conv_1"), 1000);
            assert!(aura_cleanup_context(handle, u64::MAX));
            aura_free(handle);
        }
    }

    #[test]
    fn batch_analysis_multiple_messages() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let results = batch_results(
                handle,
                vec![
                    proto::BatchAnalyzeItem {
                        message: Some(proto_message("Hello friend!", "u1", "c1")),
                        timestamp_ms: Some(1000),
                    },
                    proto::BatchAnalyzeItem {
                        message: Some(proto_message("I will kill you", "u2", "c1")),
                        timestamp_ms: Some(2000),
                    },
                    proto::BatchAnalyzeItem {
                        message: Some(proto_message("Nice weather today", "u3", "c2")),
                        timestamp_ms: Some(3000),
                    },
                ],
            );

            assert_eq!(results.results.len(), 3);
            assert_eq!(
                proto::Action::try_from(results.results[0].action).unwrap(),
                proto::Action::Allow
            );
            assert_ne!(
                proto::Action::try_from(results.results[1].action).unwrap(),
                proto::Action::Allow
            );

            aura_free(handle);
        }
    }

    #[test]
    fn batch_size_limit_enforced() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            let request = proto::BatchAnalyzeRequest {
                items: (0..1001)
                    .map(|i| proto::BatchAnalyzeItem {
                        message: Some(proto_message("hello", "user", &format!("conv_{i}"))),
                        timestamp_ms: None,
                    })
                    .collect(),
            };
            let request = encode_proto(&request);
            let mut out = AuraBuffer::empty();
            assert!(!aura_analyze_batch(
                handle,
                request.as_ptr(),
                request.len(),
                &mut out,
            ));

            let err = aura_last_error();
            assert!(!err.is_null());
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("exceeds limit"), "Got: {err_str}");
            aura_free_string(err);

            aura_free(handle);
        }
    }

    #[test]
    fn analyze_context_missing_message_sets_last_error_and_preserves_state() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message("don't tell your parents", "stranger", "conv_1"),
                1000,
            );

            let request = proto::AnalyzeContextRequest {
                message: None,
                timestamp_ms: 2000,
            };
            let bytes = encode_proto(&request);
            let mut out = AuraBuffer::empty();
            assert!(!aura_analyze_context(
                handle,
                bytes.as_ptr(),
                bytes.len(),
                &mut out,
            ));
            assert!(out.ptr.is_null());

            let err_str = last_error_string();
            assert!(
                err_str.contains("missing message in analyze_context request"),
                "Got: {err_str}"
            );

            let profile = get_contact_profile(handle, "stranger");
            assert!(profile.found, "existing context should remain intact");

            aura_free(handle);
        }
    }

    #[test]
    fn batch_missing_message_is_atomic_and_preserves_state() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let request = proto::BatchAnalyzeRequest {
                items: vec![
                    proto::BatchAnalyzeItem {
                        message: Some(proto_message(
                            "don't tell your parents",
                            "stranger",
                            "conv_1",
                        )),
                        timestamp_ms: Some(1000),
                    },
                    proto::BatchAnalyzeItem {
                        message: None,
                        timestamp_ms: Some(2000),
                    },
                ],
            };
            let bytes = encode_proto(&request);
            let mut out = AuraBuffer::empty();
            assert!(!aura_analyze_batch(
                handle,
                bytes.as_ptr(),
                bytes.len(),
                &mut out,
            ));
            assert!(out.ptr.is_null());

            let err_str = last_error_string();
            assert!(
                err_str.contains("missing message in batch item"),
                "Got: {err_str}"
            );

            let profile = get_contact_profile(handle, "stranger");
            assert!(
                !profile.found,
                "failed batch should not partially mutate context"
            );

            let summary = get_conversation_summary(handle);
            assert_eq!(summary.total_conversations, 0);

            aura_free(handle);
        }
    }

    #[test]
    fn oversized_batch_request_is_rejected_before_decode() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let request = oversized_request_bytes(MAX_BATCH_REQUEST_BYTES);
            let mut out = AuraBuffer::empty();

            assert!(!aura_analyze_batch(
                handle,
                request.as_ptr(),
                request.len(),
                &mut out,
            ));
            assert!(out.ptr.is_null());

            let err_str = last_error_string();
            assert!(
                err_str.contains("batch analyze request exceeds limit"),
                "Got: {err_str}"
            );

            aura_free(handle);
        }
    }

    #[test]
    fn recommended_action_in_output() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let result = analyze_context_result(
                handle,
                proto_message("don't tell your parents about us", "stranger", "conv_1"),
                1000,
            );

            let recommendation = result.recommended_action.expect("missing recommendation");
            assert!(!recommendation.ui_actions.is_empty());
            assert!(result.risk_breakdown.is_some());
            assert!(result.contact_snapshot.is_some());
            assert!(!result.reason_codes.is_empty());

            aura_free(handle);
        }
    }

    #[test]
    fn conversation_summary_tracks_conversations() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message("don't tell your parents", "stranger", "conv_A"),
                1000,
            );
            let _ = analyze_context_result(
                handle,
                proto_message("hey want to play minecraft?", "friend", "conv_B"),
                2000,
            );

            let summary = get_conversation_summary(handle);
            assert_eq!(summary.total_conversations, 2);
            assert_eq!(summary.conversations.len(), 2);
            assert!(summary
                .conversations
                .iter()
                .any(|conv| conv.conversation_id == "conv_A"));

            aura_free(handle);
        }
    }

    #[test]
    fn reload_patterns_missing_file_returns_error() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            let request = encode_proto(&proto::ReloadPatternsRequest {
                patterns_path: "/definitely/missing/patterns.json".to_string(),
            });
            let mut out = AuraBuffer::empty();
            assert!(!aura_reload_patterns(
                handle,
                request.as_ptr(),
                request.len(),
                &mut out,
            ));

            let err = aura_last_error();
            assert!(!err.is_null());
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("pattern load failed"), "Got: {err_str}");
            aura_free_string(err);

            aura_free(handle);
        }
    }

    #[test]
    fn reload_patterns_invalid_regex_returns_error() {
        unsafe {
            let invalid_path =
                write_temp_patterns_file("invalid_regex_reload", invalid_regex_patterns_json());
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            let request = encode_proto(&proto::ReloadPatternsRequest {
                patterns_path: invalid_path.to_string_lossy().into_owned(),
            });
            let mut out = AuraBuffer::empty();
            assert!(!aura_reload_patterns(
                handle,
                request.as_ptr(),
                request.len(),
                &mut out,
            ));

            let err = aura_last_error();
            assert!(!err.is_null());
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("pattern load failed"), "Got: {err_str}");
            assert!(err_str.contains("broken_regex_rule"), "Got: {err_str}");
            aura_free_string(err);

            aura_free(handle);
            let _ = fs::remove_file(invalid_path);
        }
    }

    #[test]
    fn reload_patterns_is_rate_limited() {
        unsafe {
            let valid_path = write_temp_patterns_file(
                "valid_reload_rate_limit",
                &custom_keyword_patterns_json("signal_rate_limit"),
            );
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            let request = encode_proto(&proto::ReloadPatternsRequest {
                patterns_path: valid_path.to_string_lossy().into_owned(),
            });

            let mut out = AuraBuffer::empty();
            assert!(aura_reload_patterns(
                handle,
                request.as_ptr(),
                request.len(),
                &mut out,
            ));
            aura_free_buffer(out);

            let mut out2 = AuraBuffer::empty();
            assert!(!aura_reload_patterns(
                handle,
                request.as_ptr(),
                request.len(),
                &mut out2,
            ));
            let err = last_error_string();
            assert!(err.contains("rate-limited"), "Got: {err}");

            aura_free(handle);
            let _ = fs::remove_file(valid_path);
        }
    }

    #[test]
    fn mark_contact_trusted_is_applied() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ =
                analyze_context_result(handle, proto_message("hello", "friend", "conv_1"), 1000);

            let request = encode_proto(&proto::MarkContactTrustedRequest {
                sender_id: "friend".to_string(),
            });
            assert!(aura_mark_contact_trusted(
                handle,
                request.as_ptr(),
                request.len(),
            ));

            let profile = get_contact_profile(handle, "friend").profile.unwrap();
            assert!(profile.is_trusted);

            aura_free(handle);
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
    fn init_with_missing_patterns_path_falls_back_to_builtin_patterns() {
        unsafe {
            let mut config = proto_config(proto::AccountType::Child, true);
            config.patterns_path = Some("/definitely/missing/patterns.json".to_string());
            let handle = init_handle(config);
            assert!(!handle.is_null());

            let result = analyze_result(
                handle,
                proto_message(
                    "don't tell your parents about our chats",
                    "stranger",
                    "conv_1",
                ),
            );
            assert!(has_pattern_signal(&result));

            aura_free(handle);
        }
    }

    #[test]
    fn init_with_empty_ruleset_falls_back_to_builtin_patterns() {
        unsafe {
            let path =
                write_temp_patterns_file("empty_ruleset_init", empty_ruleset_patterns_json());
            let mut config = proto_config(proto::AccountType::Child, true);
            config.patterns_path = Some(path.to_string_lossy().into_owned());
            let handle = init_handle(config);
            assert!(!handle.is_null());

            let result = analyze_result(
                handle,
                proto_message(
                    "don't tell your parents about our chats",
                    "stranger",
                    "conv_1",
                ),
            );
            assert!(has_pattern_signal(&result));

            aura_free(handle);
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn invalid_proto_request_sets_last_error() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            let bad = [0xFF_u8, 0x01, 0x02];
            let mut out = AuraBuffer::empty();
            assert!(!aura_analyze(handle, bad.as_ptr(), bad.len(), &mut out));
            assert!(out.ptr.is_null());

            let err = aura_last_error();
            assert!(!err.is_null());
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("invalid protobuf"), "Got: {err_str}");
            aura_free_string(err);

            aura_free(handle);
        }
    }

    #[test]
    fn update_config_with_empty_ruleset_preserves_existing_pattern_db() {
        unsafe {
            let custom_keyword = "moonlit_badger_alarm_phrase";
            let custom_path = write_temp_patterns_file(
                "custom_rule_update",
                &custom_keyword_patterns_json(custom_keyword),
            );
            let empty_path =
                write_temp_patterns_file("empty_ruleset_update", empty_ruleset_patterns_json());

            let mut config = proto_config(proto::AccountType::Adult, true);
            config.patterns_path = Some(custom_path.to_string_lossy().into_owned());
            let handle = init_handle(config);
            assert!(!handle.is_null());

            let baseline = analyze_result(
                handle,
                proto_message(custom_keyword, "user_1", "conv_custom"),
            );
            assert!(has_pattern_signal(&baseline));

            let mut update = proto_config(proto::AccountType::Adult, true);
            update.patterns_path = Some(empty_path.to_string_lossy().into_owned());
            let update_bytes = encode_proto(&update);
            assert!(aura_update_config(
                handle,
                update_bytes.as_ptr(),
                update_bytes.len()
            ));

            let after_update = analyze_result(
                handle,
                proto_message(custom_keyword, "user_1", "conv_custom"),
            );
            assert!(
                has_pattern_signal(&after_update),
                "expected existing pattern database to remain active"
            );

            aura_free(handle);
            let _ = fs::remove_file(custom_path);
            let _ = fs::remove_file(empty_path);
        }
    }

    #[test]
    fn update_config_without_patterns_path_resets_to_builtin_patterns() {
        unsafe {
            let custom_keyword = "obsidian_badger_alarm_phrase";
            let custom_path = write_temp_patterns_file(
                "custom_rule_reset",
                &custom_keyword_patterns_json(custom_keyword),
            );

            let mut config = proto_config(proto::AccountType::Child, true);
            config.patterns_path = Some(custom_path.to_string_lossy().into_owned());
            let handle = init_handle(config);
            assert!(!handle.is_null());

            let custom_result = analyze_result(
                handle,
                proto_message(custom_keyword, "user_1", "conv_custom"),
            );
            assert!(has_pattern_signal(&custom_result));

            let reset_update = encode_proto(&proto_config(proto::AccountType::Child, true));
            assert!(aura_update_config(
                handle,
                reset_update.as_ptr(),
                reset_update.len()
            ));

            let after_reset = analyze_result(
                handle,
                proto_message(custom_keyword, "user_1", "conv_custom"),
            );
            assert!(
                !has_pattern_signal(&after_reset),
                "expected custom-only pattern database to be removed"
            );

            let builtin_result = analyze_result(
                handle,
                proto_message(
                    "don't tell your parents about our chats",
                    "stranger",
                    "conv_builtin",
                ),
            );
            assert!(
                has_pattern_signal(&builtin_result),
                "expected built-in pattern database to become active again"
            );

            aura_free(handle);
            let _ = fs::remove_file(custom_path);
        }
    }

    #[test]
    fn null_out_pointer_sets_last_error() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            let message = encode_proto(&proto_message("test", "u1", "c1"));

            assert!(!aura_analyze(
                handle,
                message.as_ptr(),
                message.len(),
                std::ptr::null_mut(),
            ));

            let err_str = last_error_string();
            assert!(err_str.contains("null out pointer"), "Got: {err_str}");

            aura_free(handle);
        }
    }

    #[test]
    fn oversized_message_request_is_rejected_before_decode() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Adult, true));
            let request = oversized_request_bytes(MAX_MESSAGE_REQUEST_BYTES);
            let mut out = AuraBuffer::empty();

            assert!(!aura_analyze(
                handle,
                request.as_ptr(),
                request.len(),
                &mut out,
            ));
            assert!(out.ptr.is_null());

            let err_str = last_error_string();
            assert!(err_str.contains("message exceeds limit"), "Got: {err_str}");

            aura_free(handle);
        }
    }

    #[test]
    fn truncated_analyze_context_request_sets_last_error() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let request = proto::AnalyzeContextRequest {
                message: Some(proto_message(
                    "don't tell your parents",
                    "stranger",
                    "conv_1",
                )),
                timestamp_ms: 1000,
            };
            let bytes = encode_proto(&request);
            let truncated = truncate_proto(&bytes);
            let mut out = AuraBuffer::empty();

            assert!(!aura_analyze_context(
                handle,
                truncated.as_ptr(),
                truncated.len(),
                &mut out,
            ));
            assert!(out.ptr.is_null());

            let err_str = last_error_string();
            assert!(err_str.contains("invalid protobuf"), "Got: {err_str}");

            aura_free(handle);
        }
    }

    #[test]
    fn truncated_import_context_request_preserves_existing_state() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message("don't tell your parents", "stranger", "conv_1"),
                1000,
            );

            let exported = export_context(handle);
            let request = proto::ImportContextRequest {
                state: exported.state,
            };
            let bytes = encode_proto(&request);
            let truncated = truncate_proto(&bytes);

            assert!(!aura_import_context(
                handle,
                truncated.as_ptr(),
                truncated.len(),
            ));

            let err_str = last_error_string();
            assert!(err_str.contains("invalid protobuf"), "Got: {err_str}");

            let profile = get_contact_profile(handle, "stranger");
            assert!(profile.found, "existing state should remain intact");

            aura_free(handle);
        }
    }

    #[test]
    fn future_schema_import_via_ffi_preserves_existing_state() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message("don't tell your parents", "stranger", "conv_1"),
                1000,
            );

            let mut state = export_context(handle).state.expect("missing state");
            state.schema_version = aura_agent_core::context::tracker::TRACKER_STATE_VERSION + 1;
            let request = proto::ImportContextRequest { state: Some(state) };
            let bytes = encode_proto(&request);

            assert!(!aura_import_context(handle, bytes.as_ptr(), bytes.len()));

            let err_str = last_error_string();
            assert!(
                err_str.contains("incompatible state version"),
                "Got: {err_str}"
            );

            let profile = get_contact_profile(handle, "stranger");
            assert!(profile.found, "existing state should remain intact");

            aura_free(handle);
        }
    }

    #[test]
    fn missing_state_import_via_ffi_preserves_existing_state() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message("don't tell your parents", "stranger", "conv_1"),
                1000,
            );

            let request = proto::ImportContextRequest { state: None };
            let bytes = encode_proto(&request);

            assert!(!aura_import_context(handle, bytes.as_ptr(), bytes.len()));

            let err_str = last_error_string();
            assert!(
                err_str.contains("missing state in import_context request"),
                "Got: {err_str}"
            );

            let profile = get_contact_profile(handle, "stranger");
            assert!(profile.found, "existing state should remain intact");

            aura_free(handle);
        }
    }

    #[test]
    fn oversized_import_context_request_preserves_existing_state() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message("don't tell your parents", "stranger", "conv_1"),
                1000,
            );

            let request = oversized_request_bytes(MAX_IMPORT_CONTEXT_REQUEST_BYTES);
            assert!(!aura_import_context(
                handle,
                request.as_ptr(),
                request.len()
            ));

            let err_str = last_error_string();
            assert!(
                err_str.contains("import_context request exceeds limit"),
                "Got: {err_str}"
            );

            let profile = get_contact_profile(handle, "stranger");
            assert!(profile.found, "existing state should remain intact");

            aura_free(handle);
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
    fn stress_rapid_init_analyze_free_cycle() {
        for _ in 0..20 {
            unsafe {
                let handle = init_handle(proto_config(proto::AccountType::Child, true));
                let mut out = AuraBuffer::empty();
                let msg = proto_message("hello world", "user_x", "conv_x");
                let request = encode_proto(&msg);
                assert!(aura_analyze(
                    handle,
                    request.as_ptr(),
                    request.len(),
                    &mut out,
                ));
                aura_free_buffer(out);
                aura_free(handle);
            }
        }
    }

    #[test]
    fn stress_buffer_lifecycle_no_leak() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            for i in 0..100 {
                let mut out = AuraBuffer::empty();
                let text = format!("message number {i} with some content");
                let msg = proto_message(&text, "sender", "conv");
                let request = encode_proto(&msg);
                assert!(aura_analyze(
                    handle,
                    request.as_ptr(),
                    request.len(),
                    &mut out,
                ));
                assert!(!out.ptr.is_null());
                assert!(out.len > 0);
                aura_free_buffer(out);
            }
            aura_free(handle);
        }
    }

    #[test]
    fn stress_export_import_roundtrip_stability() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));

            for i in 0..10 {
                let msg = proto_message(
                    "don't tell your parents, it's our secret",
                    &format!("sender_{i}"),
                    "conv_1",
                );
                let _ = analyze_context_result(handle, msg, 1000 + i * 1000);
            }

            let mut export_buf = AuraBuffer::empty();
            assert!(aura_export_context(handle, &mut export_buf));
            let exported = std::slice::from_raw_parts(export_buf.ptr, export_buf.len).to_vec();

            for _ in 0..5 {
                assert!(aura_import_context(
                    handle,
                    exported.as_ptr(),
                    exported.len(),
                ));
            }

            let mut export_buf2 = AuraBuffer::empty();
            assert!(aura_export_context(handle, &mut export_buf2));
            assert!(export_buf2.len > 0);

            aura_free_buffer(export_buf);
            aura_free_buffer(export_buf2);
            aura_free(handle);
        }
    }

    #[test]
    fn quick_check_safe_text_returns_ok_true() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let text = b"Hey, how are you doing today?";
            let mut out = AuraBuffer::empty();
            assert!(aura_quick_check(
                handle,
                text.as_ptr(),
                text.len(),
                &mut out,
            ));
            let response: proto::StatusResponse = decode_buffer(out);
            assert!(response.ok);
            assert!(response.message.is_none());
            aura_free(handle);
        }
    }

    #[test]
    fn quick_check_null_text_fails() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let mut out = AuraBuffer::empty();
            assert!(!aura_quick_check(handle, std::ptr::null(), 10, &mut out,));
            let err = aura_last_error();
            assert!(!err.is_null());
            let msg = CStr::from_ptr(err).to_string_lossy().to_string();
            assert!(msg.contains("null text pointer"));
            aura_free_string(err);
            aura_free(handle);
        }
    }

    #[test]
    fn quick_check_empty_text_fails() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let text = b"x";
            let mut out = AuraBuffer::empty();
            assert!(!aura_quick_check(handle, text.as_ptr(), 0, &mut out,));
            let err = aura_last_error();
            assert!(!err.is_null());
            let msg = CStr::from_ptr(err).to_string_lossy().to_string();
            assert!(msg.contains("out of range"));
            aura_free_string(err);
            aura_free(handle);
        }
    }

    #[test]
    fn quick_check_null_handle_fails() {
        unsafe {
            let text = b"hello";
            let mut out = AuraBuffer::empty();
            assert!(!aura_quick_check(
                std::ptr::null_mut(),
                text.as_ptr(),
                text.len(),
                &mut out,
            ));
        }
    }

    #[test]
    fn quick_check_null_out_fails() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let text = b"hello";
            assert!(!aura_quick_check(
                handle,
                text.as_ptr(),
                text.len(),
                std::ptr::null_mut(),
            ));
            aura_free(handle);
        }
    }

    #[test]
    fn detect_suspicious_url_safe_url_returns_ok() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let url = b"https://www.google.com";
            let mut out = AuraBuffer::empty();
            assert!(aura_detect_suspicious_url(
                handle,
                url.as_ptr(),
                url.len(),
                &mut out,
            ));
            let response: proto::StatusResponse = decode_buffer(out);
            assert!(response.ok);
            aura_free(handle);
        }
    }

    #[test]
    fn detect_suspicious_url_null_pointer_fails() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let mut out = AuraBuffer::empty();
            assert!(!aura_detect_suspicious_url(
                handle,
                std::ptr::null(),
                10,
                &mut out,
            ));
            let err = aura_last_error();
            assert!(!err.is_null());
            let msg = CStr::from_ptr(err).to_string_lossy().to_string();
            assert!(msg.contains("null url pointer"));
            aura_free_string(err);
            aura_free(handle);
        }
    }

    #[test]
    fn detect_suspicious_url_empty_url_fails() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let url = b"x";
            let mut out = AuraBuffer::empty();
            assert!(!aura_detect_suspicious_url(
                handle,
                url.as_ptr(),
                0,
                &mut out,
            ));
            let err = aura_last_error();
            assert!(!err.is_null());
            let msg = CStr::from_ptr(err).to_string_lossy().to_string();
            assert!(msg.contains("out of range"));
            aura_free_string(err);
            aura_free(handle);
        }
    }

    #[test]
    fn detect_suspicious_url_null_handle_fails() {
        unsafe {
            let url = b"https://example.com";
            let mut out = AuraBuffer::empty();
            assert!(!aura_detect_suspicious_url(
                std::ptr::null_mut(),
                url.as_ptr(),
                url.len(),
                &mut out,
            ));
        }
    }

    #[test]
    fn detect_suspicious_url_null_out_fails() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Teen, true));
            let url = b"https://example.com";
            assert!(!aura_detect_suspicious_url(
                handle,
                url.as_ptr(),
                url.len(),
                std::ptr::null_mut(),
            ));
            aura_free(handle);
        }
    }
}
