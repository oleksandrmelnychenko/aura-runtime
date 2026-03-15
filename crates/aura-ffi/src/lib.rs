#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

use aura_core::context::contact::{
    BehavioralSnapshotState as CoreBehavioralSnapshotState,
    ContactProfileState as CoreContactProfileState,
    ContactProfilerWireState as CoreContactProfilerWireState,
};
use aura_core::context::events::{ContextEvent as CoreContextEvent, EventKind as CoreEventKind};
use aura_core::context::tracker::{
    ConversationTimelineState as CoreConversationTimelineState,
    TrackerWireState as CoreTrackerWireState,
};
use aura_core::{config::CulturalContext, Analyzer, AuraConfig, MessageInput};
use aura_patterns::PatternDatabase;
use aura_proto::messenger::v1 as proto;
use prost::Message as ProstMessage;
use tracing::warn;

const MAX_BATCH_SIZE: usize = 1000;
const MAX_CONFIG_REQUEST_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ANALYZE_CONTEXT_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_BATCH_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_IMPORT_CONTEXT_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_SMALL_CONTROL_REQUEST_BYTES: usize = 16 * 1024;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg.into());
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

struct AuraInstance {
    analyzer: Analyzer,
    pattern_db: PatternDatabase,
}

#[repr(C)]
pub struct AuraBuffer {
    pub ptr: *mut u8,
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

fn build_instance(config: AuraConfig) -> Result<*mut c_void, String> {
    config
        .validate()
        .map_err(|e| format!("config validation failed: {e}"))?;

    let pattern_db = load_pattern_db(&config);
    let analyzer = Analyzer::new(config, &pattern_db);
    let instance = Box::new(Mutex::new(AuraInstance {
        analyzer,
        pattern_db,
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

fn decode_config_request(config_ptr: *const u8, config_len: usize) -> Result<AuraConfig, String> {
    let config_proto: proto::AuraConfig = unsafe {
        decode_proto_bounded(config_ptr, config_len, "config", MAX_CONFIG_REQUEST_BYTES)?
    };
    aura_config_from_proto(config_proto)
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

fn apply_config_update(instance: &mut AuraInstance, config: AuraConfig) {
    let next_pattern_db = resolve_pattern_db_for_update(&instance.pattern_db, &config);
    instance.analyzer.update_config(config, &next_pattern_db);
    instance.pattern_db = next_pattern_db;
}

fn contact_profile_to_proto(
    profile: &aura_core::context::contact::ContactProfile,
    is_new_contact: bool,
) -> proto::ContactProfile {
    proto::ContactProfile {
        sender_id: profile.sender_id.clone(),
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
    tracker: &aura_core::ConversationTracker,
) -> proto::ConversationSummaryResponse {
    let mut conversations = Vec::new();

    for conv_id in tracker.conversation_ids() {
        if let Some(timeline) = tracker.timeline(&conv_id) {
            let events = timeline.all_events();
            let mut unique_senders: Vec<String> = events
                .iter()
                .map(|e| e.sender_id.clone())
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

    conversations.sort_by(|a, b| b.latest_event_ms.cmp(&a.latest_event_ms));

    proto::ConversationSummaryResponse {
        total_conversations: conversations.len() as u64,
        conversations,
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_init(config_ptr: *const u8, config_len: usize) -> *mut c_void {
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_analyze(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
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
        let result = instance.analyzer.analyze(&input);
        write_proto_message(out, &analysis_result_to_proto(&result))
    }) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e);
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_analyze_context(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
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
            .analyze_with_context(&input, request.timestamp_ms);
        write_proto_message(out, &analysis_result_to_proto(&result))
    }) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e);
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_analyze_batch(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
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
                Some(ts) => instance.analyzer.analyze_with_context(&input, ts),
                None => instance.analyzer.analyze(&input),
            };
            results.push(analysis_result_to_proto(&result));
        }

        write_proto_message(out, &proto::BatchAnalyzeResponse { results })
    }) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e);
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_update_config(
    handle: *mut c_void,
    config_ptr: *const u8,
    config_len: usize,
) -> bool {
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_reload_patterns(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
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

    let db = match PatternDatabase::from_file(&request.patterns_path) {
        Ok(db) => db,
        Err(e) => {
            set_last_error(format!("pattern load failed: {e}"));
            return false;
        }
    };

    match with_instance(handle, |instance| {
        instance.analyzer.reload_patterns(&db);
        instance.pattern_db = db;
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_export_context(handle: *mut c_void, out: *mut AuraBuffer) -> bool {
    clear_last_error();

    if let Err(e) = prepare_output(out) {
        set_last_error(e);
        return false;
    }

    match with_instance(handle, |instance| {
        let state = tracker_state_to_proto(&instance.analyzer.export_context_state());
        write_proto_message(out, &proto::ExportContextResponse { state: Some(state) })
    }) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e);
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_import_context(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
) -> bool {
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

    match with_instance(handle, |instance| {
        instance
            .analyzer
            .import_context_state(state)
            .map_err(|e| format!("import failed: {e}"))
    }) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e);
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_cleanup_context(handle: *mut c_void, now_ms: u64) -> bool {
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_get_contacts_by_risk(
    handle: *mut c_void,
    out: *mut AuraBuffer,
) -> bool {
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_get_contact_profile(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out: *mut AuraBuffer,
) -> bool {
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_mark_contact_trusted(
    handle: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
) -> bool {
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_get_conversation_summary(
    handle: *mut c_void,
    out: *mut AuraBuffer,
) -> bool {
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
}

#[no_mangle]
pub unsafe extern "C" fn aura_free(handle: *mut c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut Mutex<AuraInstance>));
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_free_buffer(buf: AuraBuffer) {
    if !buf.ptr.is_null() && buf.len > 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            buf.ptr, buf.len,
        )));
    }
}

#[no_mangle]
pub extern "C" fn aura_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn aura_last_error() -> *mut c_char {
    LAST_ERROR.with(|e| {
        let borrow = e.borrow();
        match borrow.as_ref() {
            Some(msg) => string_to_c(msg.clone()),
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
    })
}

fn message_input_from_proto(message: proto::MessageInput) -> MessageInput {
    MessageInput {
        content_type: content_type_from_proto(message.content_type),
        text: message.text,
        image_data: message.image_data,
        sender_id: non_empty_or(message.sender_id, "unknown"),
        conversation_id: non_empty_or(message.conversation_id, "unknown"),
        language: message.language,
        conversation_type: conversation_type_from_proto(message.conversation_type),
        member_count: message.member_count,
    }
}

fn non_empty_or(value: String, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value
    }
}

fn analysis_result_to_proto(result: &aura_core::AnalysisResult) -> proto::AnalysisResult {
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
        risk_breakdown: Some(proto::RiskBreakdown {
            content: result.risk_breakdown.content,
            conversation: result.risk_breakdown.conversation,
            link: result.risk_breakdown.link,
            abuse: result.risk_breakdown.abuse,
        }),
        contact_snapshot: result
            .contact_snapshot
            .as_ref()
            .map(contact_snapshot_to_proto),
        reason_codes: result.reason_codes.clone(),
        analysis_time_us: result.analysis_time_us,
    }
}

fn detection_signal_to_proto(signal: &aura_core::DetectionSignal) -> proto::DetectionSignal {
    proto::DetectionSignal {
        threat_type: proto_threat_type(signal.threat_type) as i32,
        score: signal.score,
        confidence: proto_confidence(signal.confidence) as i32,
        layer: proto_detection_layer(signal.layer) as i32,
        family: proto_signal_family(signal.family) as i32,
        reason_code: signal.reason_code.clone(),
        explanation: signal.explanation.clone(),
    }
}

fn action_recommendation_to_proto(
    recommendation: &aura_core::ActionRecommendation,
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

fn contact_snapshot_to_proto(snapshot: &aura_core::ContactSnapshot) -> proto::ContactSnapshot {
    proto::ContactSnapshot {
        sender_id: snapshot.sender_id.clone(),
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

fn tracker_state_to_proto(state: &CoreTrackerWireState) -> proto::TrackerState {
    proto::TrackerState {
        schema_version: state.schema_version,
        timelines: state
            .timelines
            .iter()
            .map(conversation_timeline_state_to_proto)
            .collect(),
        contact_profiler: Some(contact_profiler_state_to_proto(&state.contact_profiler)),
    }
}

fn tracker_state_from_proto(state: proto::TrackerState) -> Result<CoreTrackerWireState, String> {
    Ok(CoreTrackerWireState {
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
    })
}

fn conversation_timeline_state_to_proto(
    state: &CoreConversationTimelineState,
) -> proto::ConversationTimelineState {
    proto::ConversationTimelineState {
        conversation_id: state.conversation_id.clone(),
        conversation_type: proto_conversation_type(state.conversation_type) as i32,
        events: state.events.iter().map(context_event_to_proto).collect(),
    }
}

fn conversation_timeline_state_from_proto(
    state: proto::ConversationTimelineState,
) -> Result<CoreConversationTimelineState, String> {
    Ok(CoreConversationTimelineState {
        conversation_id: state.conversation_id,
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
        sender_id: event.sender_id.clone(),
        conversation_id: event.conversation_id.clone(),
        kind: proto_event_kind(event.kind.clone()) as i32,
        confidence: event.confidence,
    }
}

fn context_event_from_proto(event: proto::ContextEvent) -> Result<CoreContextEvent, String> {
    Ok(CoreContextEvent {
        event_id: event.event_id,
        timestamp_ms: event.timestamp_ms,
        sender_id: event.sender_id,
        conversation_id: event.conversation_id,
        kind: event_kind_from_proto(event.kind)?,
        confidence: event.confidence,
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
    proto::ContactProfileState {
        sender_id: state.sender_id.clone(),
        first_seen_ms: state.first_seen_ms,
        last_seen_ms: state.last_seen_ms,
        total_messages: state.total_messages,
        conversation_count: state.conversation_count as u64,
        conversations: state.conversations.clone(),
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

    Ok(CoreContactProfileState {
        sender_id: state.sender_id,
        first_seen_ms: state.first_seen_ms,
        last_seen_ms: state.last_seen_ms,
        total_messages: state.total_messages,
        conversation_count: state.conversation_count as usize,
        conversations: state.conversations,
        grooming_event_count: state.grooming_event_count,
        bullying_event_count: state.bullying_event_count,
        manipulation_event_count: state.manipulation_event_count,
        is_trusted: state.is_trusted,
        severity_sum: state.severity_sum,
        severity_count: state.severity_count,
        inferred_age,
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
        avg_severity: state.avg_severity,
    }
}

fn protection_level_from_proto(value: i32) -> aura_core::ProtectionLevel {
    match proto::ProtectionLevel::try_from(value).unwrap_or(proto::ProtectionLevel::Medium) {
        proto::ProtectionLevel::Off => aura_core::ProtectionLevel::Off,
        proto::ProtectionLevel::Low => aura_core::ProtectionLevel::Low,
        proto::ProtectionLevel::Medium | proto::ProtectionLevel::Unspecified => {
            aura_core::ProtectionLevel::Medium
        }
        proto::ProtectionLevel::High => aura_core::ProtectionLevel::High,
    }
}

fn account_type_from_proto(value: i32) -> aura_core::AccountType {
    match proto::AccountType::try_from(value).unwrap_or(proto::AccountType::Adult) {
        proto::AccountType::Adult | proto::AccountType::Unspecified => {
            aura_core::AccountType::Adult
        }
        proto::AccountType::Teen => aura_core::AccountType::Teen,
        proto::AccountType::Child => aura_core::AccountType::Child,
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

fn content_type_from_proto(value: i32) -> aura_core::ContentType {
    match proto::ContentType::try_from(value).unwrap_or(proto::ContentType::Text) {
        proto::ContentType::Image => aura_core::ContentType::Image,
        proto::ContentType::Voice => aura_core::ContentType::Voice,
        proto::ContentType::Video => aura_core::ContentType::Video,
        proto::ContentType::Url => aura_core::ContentType::Url,
        _ => aura_core::ContentType::Text,
    }
}

fn conversation_type_from_proto(value: i32) -> aura_core::ConversationType {
    match proto::ConversationType::try_from(value).unwrap_or(proto::ConversationType::Direct) {
        proto::ConversationType::GroupChat => aura_core::ConversationType::GroupChat,
        proto::ConversationType::Group => aura_core::ConversationType::Group,
        _ => aura_core::ConversationType::Direct,
    }
}

fn proto_conversation_type(value: aura_core::ConversationType) -> proto::ConversationType {
    match value {
        aura_core::ConversationType::Direct => proto::ConversationType::Direct,
        aura_core::ConversationType::GroupChat => proto::ConversationType::GroupChat,
        aura_core::ConversationType::Group => proto::ConversationType::Group,
    }
}

fn proto_threat_type(value: aura_core::ThreatType) -> proto::ThreatType {
    match value {
        aura_core::ThreatType::None => proto::ThreatType::None,
        aura_core::ThreatType::Bullying => proto::ThreatType::Bullying,
        aura_core::ThreatType::Grooming => proto::ThreatType::Grooming,
        aura_core::ThreatType::Explicit => proto::ThreatType::Explicit,
        aura_core::ThreatType::Threat => proto::ThreatType::Threat,
        aura_core::ThreatType::SelfHarm => proto::ThreatType::SelfHarm,
        aura_core::ThreatType::Spam => proto::ThreatType::Spam,
        aura_core::ThreatType::Scam => proto::ThreatType::Scam,
        aura_core::ThreatType::Phishing => proto::ThreatType::Phishing,
        aura_core::ThreatType::Manipulation => proto::ThreatType::Manipulation,
        aura_core::ThreatType::Nsfw => proto::ThreatType::Nsfw,
        aura_core::ThreatType::HateSpeech => proto::ThreatType::HateSpeech,
        aura_core::ThreatType::Doxxing => proto::ThreatType::Doxxing,
        aura_core::ThreatType::PiiLeakage => proto::ThreatType::PiiLeakage,
    }
}

fn proto_confidence(value: aura_core::Confidence) -> proto::Confidence {
    match value {
        aura_core::Confidence::Low => proto::Confidence::Low,
        aura_core::Confidence::Medium => proto::Confidence::Medium,
        aura_core::Confidence::High => proto::Confidence::High,
    }
}

fn proto_action(value: aura_core::Action) -> proto::Action {
    match value {
        aura_core::Action::Allow => proto::Action::Allow,
        aura_core::Action::Mark => proto::Action::Mark,
        aura_core::Action::Blur => proto::Action::Blur,
        aura_core::Action::Warn => proto::Action::Warn,
        aura_core::Action::Block => proto::Action::Block,
    }
}

fn proto_detection_layer(value: aura_core::DetectionLayer) -> proto::DetectionLayer {
    match value {
        aura_core::DetectionLayer::PatternMatching => proto::DetectionLayer::PatternMatching,
        aura_core::DetectionLayer::MlClassification => proto::DetectionLayer::MlClassification,
        aura_core::DetectionLayer::ContextAnalysis => proto::DetectionLayer::ContextAnalysis,
    }
}

fn proto_signal_family(value: aura_core::SignalFamily) -> proto::SignalFamily {
    match value {
        aura_core::SignalFamily::Content => proto::SignalFamily::Content,
        aura_core::SignalFamily::Conversation => proto::SignalFamily::Conversation,
        aura_core::SignalFamily::Link => proto::SignalFamily::Link,
        aura_core::SignalFamily::Abuse => proto::SignalFamily::Abuse,
    }
}

fn proto_alert_priority(value: aura_core::AlertPriority) -> proto::AlertPriority {
    match value {
        aura_core::AlertPriority::None => proto::AlertPriority::None,
        aura_core::AlertPriority::Low => proto::AlertPriority::Low,
        aura_core::AlertPriority::Medium => proto::AlertPriority::Medium,
        aura_core::AlertPriority::High => proto::AlertPriority::High,
        aura_core::AlertPriority::Urgent => proto::AlertPriority::Urgent,
    }
}

fn proto_follow_up_action(value: aura_core::FollowUpAction) -> proto::FollowUpAction {
    match value {
        aura_core::FollowUpAction::MonitorConversation => {
            proto::FollowUpAction::MonitorConversation
        }
        aura_core::FollowUpAction::BlockSuggested => proto::FollowUpAction::BlockSuggested,
        aura_core::FollowUpAction::ReviewContactProfile => {
            proto::FollowUpAction::ReviewContactProfile
        }
        aura_core::FollowUpAction::ReportToAuthorities => {
            proto::FollowUpAction::ReportToAuthorities
        }
    }
}

fn proto_ui_action(value: aura_core::UiAction) -> proto::UiAction {
    match value {
        aura_core::UiAction::WarnBeforeSend => proto::UiAction::WarnBeforeSend,
        aura_core::UiAction::WarnBeforeDisplay => proto::UiAction::WarnBeforeDisplay,
        aura_core::UiAction::BlurUntilTap => proto::UiAction::BlurUntilTap,
        aura_core::UiAction::ConfirmBeforeOpenLink => proto::UiAction::ConfirmBeforeOpenLink,
        aura_core::UiAction::SuggestBlockContact => proto::UiAction::SuggestBlockContact,
        aura_core::UiAction::SuggestReport => proto::UiAction::SuggestReport,
        aura_core::UiAction::RestrictUnknownContact => proto::UiAction::RestrictUnknownContact,
        aura_core::UiAction::SlowDownConversation => proto::UiAction::SlowDownConversation,
        aura_core::UiAction::ShowCrisisSupport => proto::UiAction::ShowCrisisSupport,
        aura_core::UiAction::EscalateToGuardian => proto::UiAction::EscalateToGuardian,
    }
}

fn circle_tier_from_proto(value: i32) -> aura_core::CircleTier {
    match proto::CircleTier::try_from(value).unwrap_or(proto::CircleTier::New) {
        proto::CircleTier::Inner => aura_core::CircleTier::Inner,
        proto::CircleTier::Regular => aura_core::CircleTier::Regular,
        proto::CircleTier::Occasional => aura_core::CircleTier::Occasional,
        _ => aura_core::CircleTier::New,
    }
}

fn proto_circle_tier(value: aura_core::CircleTier) -> proto::CircleTier {
    match value {
        aura_core::CircleTier::Inner => proto::CircleTier::Inner,
        aura_core::CircleTier::Regular => proto::CircleTier::Regular,
        aura_core::CircleTier::Occasional => proto::CircleTier::Occasional,
        aura_core::CircleTier::New => proto::CircleTier::New,
    }
}

fn behavioral_trend_from_proto(value: i32) -> aura_core::BehavioralTrend {
    match proto::BehavioralTrend::try_from(value).unwrap_or(proto::BehavioralTrend::Stable) {
        proto::BehavioralTrend::Improving => aura_core::BehavioralTrend::Improving,
        proto::BehavioralTrend::GradualWorsening => aura_core::BehavioralTrend::GradualWorsening,
        proto::BehavioralTrend::RapidWorsening => aura_core::BehavioralTrend::RapidWorsening,
        proto::BehavioralTrend::RoleReversal => aura_core::BehavioralTrend::RoleReversal,
        _ => aura_core::BehavioralTrend::Stable,
    }
}

fn proto_behavioral_trend(value: aura_core::BehavioralTrend) -> proto::BehavioralTrend {
    match value {
        aura_core::BehavioralTrend::Stable => proto::BehavioralTrend::Stable,
        aura_core::BehavioralTrend::Improving => proto::BehavioralTrend::Improving,
        aura_core::BehavioralTrend::GradualWorsening => proto::BehavioralTrend::GradualWorsening,
        aura_core::BehavioralTrend::RapidWorsening => proto::BehavioralTrend::RapidWorsening,
        aura_core::BehavioralTrend::RoleReversal => proto::BehavioralTrend::RoleReversal,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as ProstMessage;
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
        }
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
    fn context_export_import_via_ffi() {
        unsafe {
            let handle = init_handle(proto_config(proto::AccountType::Child, true));
            let _ = analyze_context_result(
                handle,
                proto_message("don't tell your parents", "stranger", "conv_1"),
                1000,
            );

            let exported = export_context(handle);
            let state = exported.state.expect("missing state");
            assert!(
                state
                    .timelines
                    .iter()
                    .any(|timeline| timeline.conversation_id == "conv_1"),
                "expected exported protobuf state to include conv_1"
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
            assert_eq!(summary.conversations[0].total_events, 1);

            let profile = get_contact_profile(replica, "stranger");
            assert!(profile.found);
            let profile = profile.profile.expect("missing contact profile");
            assert_eq!(profile.total_messages, 1);

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
            assert_eq!(
                summary_a.conversations[0].total_events,
                timeline.len() as u64
            );
            assert_eq!(
                summary_b.conversations[0].total_events,
                timeline.len() as u64
            );
            assert_eq!(summary_a.conversations[0].latest_event_ms, 6000);
            assert_eq!(summary_b.conversations[0].latest_event_ms, 6000);

            let profile_a = get_contact_profile(handle_a, "stranger");
            let profile_b = get_contact_profile(handle_b, "stranger");
            assert!(profile_a.found);
            assert!(profile_b.found);
            assert_eq!(
                profile_a
                    .profile
                    .as_ref()
                    .expect("profile a")
                    .total_messages,
                timeline.len() as u64
            );
            assert_eq!(
                profile_b
                    .profile
                    .as_ref()
                    .expect("profile b")
                    .total_messages,
                timeline.len() as u64
            );

            aura_free(handle_a);
            aura_free(handle_b);
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
            state.schema_version = aura_core::context::tracker::TRACKER_STATE_VERSION + 1;
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
}
