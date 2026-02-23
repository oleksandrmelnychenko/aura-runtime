#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

use aura_core::{Analyzer, AuraConfig, ContentType, ConversationType, MessageInput};
use aura_patterns::PatternDatabase;

const MAX_BATCH_SIZE: usize = 1000;

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

#[no_mangle]
pub unsafe extern "C" fn aura_init(config_json: *const c_char) -> *mut c_void {
    clear_last_error();

    if config_json.is_null() {
        set_last_error("null config_json pointer");
        return std::ptr::null_mut();
    }

    let config_str = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("invalid UTF-8 in config_json");
            return std::ptr::null_mut();
        }
    };

    let config: AuraConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("invalid config JSON: {e}"));
            return std::ptr::null_mut();
        }
    };

    if let Err(e) = config.validate() {
        set_last_error(format!("config validation failed: {e}"));
        return std::ptr::null_mut();
    }

    let pattern_db = load_pattern_db(&config);
    let analyzer = Analyzer::new(config, &pattern_db);

    let instance = Box::new(Mutex::new(AuraInstance {
        analyzer,
        pattern_db,
    }));

    Box::into_raw(instance) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn aura_analyze(
    handle: *mut c_void,
    text: *const c_char,
    sender_id: *const c_char,
    conversation_id: *const c_char,
) -> *mut c_char {
    if handle.is_null() || text.is_null() {
        return error_json("null handle or text pointer");
    }

    let text_str = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8 in text"),
    };

    let sender = c_str_or(sender_id, "unknown");
    let conversation = c_str_or(conversation_id, "unknown");

    let input = MessageInput {
        content_type: ContentType::Text,
        text: Some(text_str.to_string()),
        image_data: None,
        sender_id: sender,
        conversation_id: conversation,
        language: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
    };

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    let result = guard.analyzer.analyze(&input);
    result_to_json(&result)
}

#[no_mangle]
pub unsafe extern "C" fn aura_analyze_json(
    handle: *mut c_void,
    message_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() || message_json.is_null() {
        return error_json("null handle or message pointer");
    }

    let msg_str = match CStr::from_ptr(message_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8 in message"),
    };

    let ffi_input: FfiMessageInput = match serde_json::from_str(msg_str) {
        Ok(m) => m,
        Err(e) => return error_json(&format!("invalid message JSON: {e}")),
    };

    let input = MessageInput {
        content_type: ContentType::Text,
        text: ffi_input.text,
        image_data: None,
        sender_id: ffi_input.sender_id.unwrap_or_else(|| "unknown".into()),
        conversation_id: ffi_input
            .conversation_id
            .unwrap_or_else(|| "unknown".into()),
        language: ffi_input.language,
        conversation_type: parse_conversation_type(ffi_input.conversation_type.as_deref()),
        member_count: ffi_input.member_count,
    };

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    let result = guard.analyzer.analyze(&input);
    result_to_json(&result)
}

#[no_mangle]
pub unsafe extern "C" fn aura_analyze_context(
    handle: *mut c_void,
    message_json: *const c_char,
    timestamp_ms: u64,
) -> *mut c_char {
    if handle.is_null() || message_json.is_null() {
        return error_json("null handle or message pointer");
    }

    let msg_str = match CStr::from_ptr(message_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8 in message"),
    };

    let ffi_input: FfiMessageInput = match serde_json::from_str(msg_str) {
        Ok(m) => m,
        Err(e) => return error_json(&format!("invalid message JSON: {e}")),
    };

    let input = MessageInput {
        content_type: ContentType::Text,
        text: ffi_input.text,
        image_data: None,
        sender_id: ffi_input.sender_id.unwrap_or_else(|| "unknown".into()),
        conversation_id: ffi_input
            .conversation_id
            .unwrap_or_else(|| "unknown".into()),
        language: ffi_input.language,
        conversation_type: parse_conversation_type(ffi_input.conversation_type.as_deref()),
        member_count: ffi_input.member_count,
    };

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    let result = guard.analyzer.analyze_with_context(&input, timestamp_ms);
    result_to_json(&result)
}

#[no_mangle]
pub unsafe extern "C" fn aura_analyze_batch(
    handle: *mut c_void,
    messages_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() || messages_json.is_null() {
        return error_json("null handle or messages pointer");
    }

    let msg_str = match CStr::from_ptr(messages_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8 in messages"),
    };

    let batch_items: Vec<FfiBatchItem> = match serde_json::from_str(msg_str) {
        Ok(items) => items,
        Err(e) => return error_json(&format!("invalid JSON in batch: {e}")),
    };

    if batch_items.len() > MAX_BATCH_SIZE {
        return error_json(&format!(
            "batch size {} exceeds limit of {MAX_BATCH_SIZE}",
            batch_items.len()
        ));
    }

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    let mut results = Vec::with_capacity(batch_items.len());
    for item in &batch_items {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: item.text.clone(),
            image_data: None,
            sender_id: item.sender_id.clone().unwrap_or_else(|| "unknown".into()),
            conversation_id: item
                .conversation_id
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            language: item.language.clone(),
            conversation_type: parse_conversation_type(item.conversation_type.as_deref()),
            member_count: item.member_count,
        };
        let result = if let Some(ts) = item.timestamp_ms {
            guard.analyzer.analyze_with_context(&input, ts)
        } else {
            guard.analyzer.analyze(&input)
        };
        results.push(result);
    }

    match serde_json::to_string(&results) {
        Ok(json) => string_to_c(json),
        Err(_) => error_json("failed to serialize batch results"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_update_config(
    handle: *mut c_void,
    config_json: *const c_char,
) -> bool {
    clear_last_error();

    if handle.is_null() || config_json.is_null() {
        set_last_error("null handle or config_json pointer");
        return false;
    }

    let config_str = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("invalid UTF-8 in config_json");
            return false;
        }
    };

    let config: AuraConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("invalid config JSON: {e}"));
            return false;
        }
    };

    if let Err(e) = config.validate() {
        set_last_error(format!("config validation failed: {e}"));
        return false;
    }

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("mutex poisoned");
            return false;
        }
    };

    if let Some(ref path) = config.patterns_path {
        if let Ok(json) = std::fs::read_to_string(path) {
            if let Ok(db) = PatternDatabase::from_json(&json) {
                guard.pattern_db = db;
            }
        }
    }

    let db_ptr = &guard.pattern_db as *const PatternDatabase;

    guard.analyzer.update_config(config, &*db_ptr);
    true
}

#[no_mangle]
pub unsafe extern "C" fn aura_reload_patterns(
    handle: *mut c_void,
    patterns_path: *const c_char,
) -> *mut c_char {
    if handle.is_null() || patterns_path.is_null() {
        return error_json("null handle or patterns_path");
    }

    let path_str = match CStr::from_ptr(patterns_path).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8 in patterns_path"),
    };

    let db = match PatternDatabase::from_file(path_str) {
        Ok(db) => db,
        Err(e) => return error_json(&format!("pattern load failed: {e}")),
    };

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    guard.analyzer.reload_patterns(&db);
    guard.pattern_db = db;

    string_to_c(r#"{"ok":true}"#.to_string())
}

#[no_mangle]
pub unsafe extern "C" fn aura_export_context(handle: *mut c_void) -> *mut c_char {
    if handle.is_null() {
        return error_json("null handle");
    }

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    match guard.analyzer.export_context() {
        Ok(json) => string_to_c(json),
        Err(e) => error_json(&format!("export failed: {e}")),
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_import_context(
    handle: *mut c_void,
    state_json: *const c_char,
) -> bool {
    clear_last_error();

    if handle.is_null() || state_json.is_null() {
        set_last_error("null handle or state_json pointer");
        return false;
    }

    let state_str = match CStr::from_ptr(state_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("invalid UTF-8 in state_json");
            return false;
        }
    };

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("mutex poisoned");
            return false;
        }
    };

    match guard.analyzer.import_context(state_str) {
        Ok(_) => true,
        Err(e) => {
            set_last_error(format!("import failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_cleanup_context(handle: *mut c_void, now_ms: u64) -> bool {
    clear_last_error();

    if handle.is_null() {
        set_last_error("null handle");
        return false;
    }

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("mutex poisoned");
            return false;
        }
    };

    guard.analyzer.cleanup_context(now_ms);
    true
}

#[no_mangle]
pub unsafe extern "C" fn aura_get_contacts_by_risk(handle: *mut c_void) -> *mut c_char {
    if handle.is_null() {
        return error_json("null handle");
    }

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    let profiler = guard.analyzer.context_tracker().contact_profiler();
    let contacts = profiler.contacts_by_risk();

    let ffi_contacts: Vec<FfiContactProfile> = contacts
        .iter()
        .map(|c| FfiContactProfile {
            sender_id: c.sender_id.clone(),
            risk_score: c.risk_score(),
            first_seen_ms: c.first_seen_ms,
            last_seen_ms: c.last_seen_ms,
            total_messages: c.total_messages,
            grooming_events: c.grooming_event_count,
            bullying_events: c.bullying_event_count,
            manipulation_events: c.manipulation_event_count,
            is_trusted: c.is_trusted,
            is_new_contact: profiler.is_new_contact(&c.sender_id),
            conversation_count: c.conversation_count,
            average_severity: c.average_severity(),
        })
        .collect();

    match serde_json::to_string(&ffi_contacts) {
        Ok(json) => string_to_c(json),
        Err(_) => error_json("failed to serialize contacts"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_get_contact_profile(
    handle: *mut c_void,
    sender_id: *const c_char,
) -> *mut c_char {
    if handle.is_null() || sender_id.is_null() {
        return error_json("null handle or sender_id");
    }

    let sender_str = match CStr::from_ptr(sender_id).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8 in sender_id"),
    };

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    let profiler = guard.analyzer.context_tracker().contact_profiler();

    match profiler.profile(sender_str) {
        Some(c) => {
            let ffi_profile = FfiContactProfile {
                sender_id: c.sender_id.clone(),
                risk_score: c.risk_score(),
                first_seen_ms: c.first_seen_ms,
                last_seen_ms: c.last_seen_ms,
                total_messages: c.total_messages,
                grooming_events: c.grooming_event_count,
                bullying_events: c.bullying_event_count,
                manipulation_events: c.manipulation_event_count,
                is_trusted: c.is_trusted,
                is_new_contact: profiler.is_new_contact(&c.sender_id),
                conversation_count: c.conversation_count,
                average_severity: c.average_severity(),
            };
            match serde_json::to_string(&ffi_profile) {
                Ok(json) => string_to_c(json),
                Err(_) => error_json("failed to serialize profile"),
            }
        }
        None => string_to_c(r#"{"error":false,"message":"contact not found"}"#.to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_mark_contact_trusted(
    handle: *mut c_void,
    sender_id: *const c_char,
) -> bool {
    clear_last_error();

    if handle.is_null() || sender_id.is_null() {
        set_last_error("null handle or sender_id pointer");
        return false;
    }

    let sender_str = match CStr::from_ptr(sender_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("invalid UTF-8 in sender_id");
            return false;
        }
    };

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let mut guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("mutex poisoned");
            return false;
        }
    };

    guard.analyzer.mark_contact_trusted(sender_str);
    true
}

#[no_mangle]
pub unsafe extern "C" fn aura_get_conversation_summary(handle: *mut c_void) -> *mut c_char {
    if handle.is_null() {
        return error_json("null handle");
    }

    let instance = &*(handle as *mut Mutex<AuraInstance>);
    let guard = match instance.lock() {
        Ok(g) => g,
        Err(_) => return error_json("mutex poisoned"),
    };

    let tracker = guard.analyzer.context_tracker();
    let conv_ids = tracker.conversation_ids();
    let mut conversations = Vec::new();

    for conv_id in &conv_ids {
        if let Some(timeline) = tracker.timeline(conv_id) {
            let events = timeline.all_events();
            let mut unique_senders: Vec<String> = events
                .iter()
                .map(|e| e.sender_id.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            unique_senders.sort();

            let threat_event_count = events.iter().filter(|e| e.kind.severity() >= 0.4).count();

            let latest_event_ms = events.iter().map(|e| e.timestamp_ms).max().unwrap_or(0);

            conversations.push(FfiConversationSummary {
                conversation_id: conv_id.to_string(),
                total_events: events.len(),
                unique_senders,
                threat_event_count,
                latest_event_ms,
            });
        }
    }

    conversations.sort_by(|a, b| b.latest_event_ms.cmp(&a.latest_event_ms));

    let summary = FfiConversationOverview {
        total_conversations: conversations.len(),
        conversations,
    };

    match serde_json::to_string(&summary) {
        Ok(json) => string_to_c(json),
        Err(_) => error_json("failed to serialize conversation summary"),
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
pub extern "C" fn aura_version() -> *const c_char {
    static VERSION: &[u8] = b"0.3.0\0";
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

#[derive(serde::Deserialize)]
struct FfiMessageInput {
    text: Option<String>,
    sender_id: Option<String>,
    conversation_id: Option<String>,
    language: Option<String>,
    conversation_type: Option<String>,
    member_count: Option<u32>,
}

#[derive(serde::Deserialize)]
struct FfiBatchItem {
    text: Option<String>,
    sender_id: Option<String>,
    conversation_id: Option<String>,
    language: Option<String>,
    timestamp_ms: Option<u64>,
    conversation_type: Option<String>,
    member_count: Option<u32>,
}

fn parse_conversation_type(s: Option<&str>) -> ConversationType {
    match s {
        Some("group_chat") => ConversationType::GroupChat,
        Some("group") => ConversationType::Group,
        _ => ConversationType::Direct,
    }
}

#[derive(serde::Serialize)]
struct FfiConversationSummary {
    conversation_id: String,
    total_events: usize,
    unique_senders: Vec<String>,
    threat_event_count: usize,
    latest_event_ms: u64,
}

#[derive(serde::Serialize)]
struct FfiConversationOverview {
    total_conversations: usize,
    conversations: Vec<FfiConversationSummary>,
}

#[derive(serde::Serialize)]
struct FfiContactProfile {
    sender_id: String,
    risk_score: f32,
    first_seen_ms: u64,
    last_seen_ms: u64,
    total_messages: u64,
    grooming_events: u64,
    bullying_events: u64,
    manipulation_events: u64,
    is_trusted: bool,
    is_new_contact: bool,
    conversation_count: usize,
    average_severity: f32,
}

fn load_pattern_db(config: &AuraConfig) -> PatternDatabase {
    if let Some(ref path) = config.patterns_path {
        match std::fs::read_to_string(path) {
            Ok(json) => {
                PatternDatabase::from_json(&json).unwrap_or_else(|_| PatternDatabase::default_mvp())
            }
            Err(_) => PatternDatabase::default_mvp(),
        }
    } else {
        PatternDatabase::default_mvp()
    }
}

unsafe fn c_str_or(ptr: *const c_char, default: &str) -> String {
    if ptr.is_null() {
        default.to_string()
    } else {
        CStr::from_ptr(ptr).to_str().unwrap_or(default).to_string()
    }
}

fn result_to_json(result: &aura_core::AnalysisResult) -> *mut c_char {
    match serde_json::to_string(result) {
        Ok(json) => string_to_c(json),
        Err(_) => error_json("failed to serialize result"),
    }
}

fn string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

const ERR_NULL_POINTER: u32 = 1000;
const ERR_INVALID_UTF8: u32 = 1001;
const ERR_INVALID_JSON: u32 = 1002;
const ERR_MUTEX_POISONED: u32 = 1003;
const ERR_SERIALIZATION: u32 = 1004;
const ERR_INVALID_CONFIG: u32 = 1005;
const ERR_MODEL_NOT_FOUND: u32 = 1006;
const ERR_INCOMPATIBLE_STATE: u32 = 1007;

fn error_json_code(code: u32, msg: &str) -> *mut c_char {
    let json = format!(
        r#"{{"error":true,"code":{code},"message":"{}","action":"allow","score":0.0}}"#,
        msg.replace('"', "\\\"")
    );
    string_to_c(json)
}

fn error_json(msg: &str) -> *mut c_char {
    let code = if msg.contains("null") {
        ERR_NULL_POINTER
    } else if msg.contains("UTF-8") {
        ERR_INVALID_UTF8
    } else if msg.contains("JSON") || msg.contains("json") {
        ERR_INVALID_JSON
    } else if msg.contains("mutex") || msg.contains("poisoned") {
        ERR_MUTEX_POISONED
    } else if msg.contains("serialize") {
        ERR_SERIALIZATION
    } else {
        ERR_NULL_POINTER
    };
    error_json_code(code, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    const EN_CONFIG: &str = r#"{"protection_level":"medium","account_type":"adult","language":"en","cultural_context":"english","enabled":true}"#;
    const CHILD_CONFIG: &str = r#"{"protection_level":"high","account_type":"child","language":"en","cultural_context":"english","enabled":true}"#;

    #[test]
    fn init_and_analyze_clean_message() {
        unsafe {
            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(!handle.is_null());

            let text = CString::new("Hey, how are you doing?").unwrap();
            let sender = CString::new("user_1").unwrap();
            let conv = CString::new("conv_1").unwrap();
            let result_ptr = aura_analyze(handle, text.as_ptr(), sender.as_ptr(), conv.as_ptr());
            assert!(!result_ptr.is_null());

            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            assert!(result_str.contains("\"action\":\"allow\""));

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn init_and_analyze_threat() {
        unsafe {
            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(!handle.is_null());

            let text = CString::new("I will kill you").unwrap();
            let sender = CString::new("user_1").unwrap();
            let conv = CString::new("conv_1").unwrap();
            let result_ptr = aura_analyze(handle, text.as_ptr(), sender.as_ptr(), conv.as_ptr());
            assert!(!result_ptr.is_null());

            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            assert!(result_str.contains("\"threat\""));
            assert!(!result_str.contains("\"action\":\"allow\""));

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn analyze_json_input() {
        unsafe {
            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(!handle.is_null());

            let msg = CString::new(r#"{"text":"don't tell your parents","sender_id":"user_1","conversation_id":"conv_1"}"#).unwrap();
            let result_ptr = aura_analyze_json(handle, msg.as_ptr());
            assert!(!result_ptr.is_null());

            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            assert!(result_str.contains("grooming"));

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn analyze_context_builds_history() {
        unsafe {
            let config = CString::new(CHILD_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(!handle.is_null());

            let msg1 = CString::new(
                r#"{"text":"You're so beautiful and amazing and perfect!","sender_id":"stranger","conversation_id":"conv_1"}"#,
            ).unwrap();
            let r1 = aura_analyze_context(handle, msg1.as_ptr(), 1000);
            aura_free_string(r1);

            let msg2 = CString::new(
                r#"{"text":"Don't tell your parents about us, ok?","sender_id":"stranger","conversation_id":"conv_1"}"#,
            ).unwrap();
            let r2 = aura_analyze_context(handle, msg2.as_ptr(), 2000);
            let r2_str = CStr::from_ptr(r2).to_str().unwrap();
            assert!(
                r2_str.contains("grooming"),
                "Should detect grooming: {r2_str}"
            );
            aura_free_string(r2);

            aura_free(handle);
        }
    }

    #[test]
    fn context_export_import_via_ffi() {
        unsafe {
            let config = CString::new(CHILD_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let msg = CString::new(
                r#"{"text":"don't tell your parents","sender_id":"stranger","conversation_id":"conv_1"}"#,
            ).unwrap();
            let r = aura_analyze_context(handle, msg.as_ptr(), 1000);
            aura_free_string(r);

            let state_ptr = aura_export_context(handle);
            assert!(!state_ptr.is_null());
            let state_str = CStr::from_ptr(state_ptr).to_str().unwrap();
            assert!(
                state_str.contains("conv_1"),
                "State should contain conversation"
            );

            let handle2 = aura_init(config.as_ptr());
            assert!(aura_import_context(handle2, state_ptr));

            aura_free_string(state_ptr);
            aura_free(handle);
            aura_free(handle2);
        }
    }

    #[test]
    fn parent_dashboard_contacts() {
        unsafe {
            let config = CString::new(CHILD_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let msg1 = CString::new(
                r#"{"text":"You're so beautiful and amazing, truly special","sender_id":"stranger_1","conversation_id":"conv_1"}"#,
            ).unwrap();
            let r1 = aura_analyze_context(handle, msg1.as_ptr(), 1000);
            aura_free_string(r1);

            let msg2 = CString::new(
                r#"{"text":"Hey, want to play Minecraft?","sender_id":"friend_1","conversation_id":"conv_2"}"#,
            ).unwrap();
            let r2 = aura_analyze_context(handle, msg2.as_ptr(), 2000);
            aura_free_string(r2);

            let contacts_ptr = aura_get_contacts_by_risk(handle);
            assert!(!contacts_ptr.is_null());
            let contacts_str = CStr::from_ptr(contacts_ptr).to_str().unwrap();
            assert!(contacts_str.contains("stranger_1"));
            assert!(contacts_str.contains("friend_1"));
            aura_free_string(contacts_ptr);

            let sender = CString::new("stranger_1").unwrap();
            let profile_ptr = aura_get_contact_profile(handle, sender.as_ptr());
            assert!(!profile_ptr.is_null());
            let profile_str = CStr::from_ptr(profile_ptr).to_str().unwrap();
            assert!(profile_str.contains("stranger_1"));
            assert!(profile_str.contains("risk_score"));
            aura_free_string(profile_ptr);

            assert!(aura_mark_contact_trusted(handle, sender.as_ptr()));

            aura_free(handle);
        }
    }

    #[test]
    fn update_config_disables_aura() {
        unsafe {
            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(!handle.is_null());

            let new_config = CString::new(r#"{"protection_level":"medium","account_type":"adult","language":"en","cultural_context":"english","enabled":false}"#).unwrap();
            assert!(aura_update_config(handle, new_config.as_ptr()));

            let text = CString::new("I will kill you").unwrap();
            let sender = CString::new("user_1").unwrap();
            let conv = CString::new("conv_1").unwrap();
            let result_ptr = aura_analyze(handle, text.as_ptr(), sender.as_ptr(), conv.as_ptr());
            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            assert!(result_str.contains("\"action\":\"allow\""));

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn null_handle_returns_error() {
        unsafe {
            let text = CString::new("test").unwrap();
            let result_ptr = aura_analyze(
                std::ptr::null_mut(),
                text.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert!(!result_ptr.is_null());

            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            assert!(result_str.contains("error"));

            aura_free_string(result_ptr);
        }
    }

    #[test]
    fn version_returns_valid_string() {
        let version = aura_version();
        unsafe {
            let v = CStr::from_ptr(version).to_str().unwrap();
            assert_eq!(v, "0.3.0");
        }
    }

    #[test]
    fn cleanup_context_works() {
        unsafe {
            let config = CString::new(CHILD_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let msg =
                CString::new(r#"{"text":"hello","sender_id":"friend","conversation_id":"conv_1"}"#)
                    .unwrap();
            let r = aura_analyze_context(handle, msg.as_ptr(), 1000);
            aura_free_string(r);

            assert!(aura_cleanup_context(handle, u64::MAX));

            aura_free(handle);
        }
    }

    #[test]
    fn batch_analysis_multiple_messages() {
        unsafe {
            let config = CString::new(CHILD_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(!handle.is_null());

            let batch = CString::new(r#"[
                {"text":"Hello friend!","sender_id":"u1","conversation_id":"c1","timestamp_ms":1000},
                {"text":"I will kill you","sender_id":"u2","conversation_id":"c1","timestamp_ms":2000},
                {"text":"Nice weather today","sender_id":"u3","conversation_id":"c2","timestamp_ms":3000}
            ]"#).unwrap();

            let result_ptr = aura_analyze_batch(handle, batch.as_ptr());
            assert!(!result_ptr.is_null());

            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();

            let results: Vec<serde_json::Value> = serde_json::from_str(result_str).unwrap();
            assert_eq!(results.len(), 3, "Batch should return 3 results");

            assert_eq!(results[0]["action"], "allow");
            assert_ne!(
                results[1]["action"], "allow",
                "Threat should not be allowed"
            );
            assert_eq!(results[2]["action"], "allow");

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn batch_analysis_empty_array() {
        unsafe {
            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let batch = CString::new("[]").unwrap();
            let result_ptr = aura_analyze_batch(handle, batch.as_ptr());
            assert!(!result_ptr.is_null());

            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            let results: Vec<serde_json::Value> = serde_json::from_str(result_str).unwrap();
            assert_eq!(results.len(), 0, "Empty batch should return empty array");

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn structured_error_codes_in_responses() {
        unsafe {
            let text = CString::new("test").unwrap();
            let result_ptr = aura_analyze(
                std::ptr::null_mut(),
                text.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            );
            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            let v: serde_json::Value = serde_json::from_str(result_str).unwrap();
            assert_eq!(v["error"], true);
            assert_eq!(v["code"], 1000, "Null pointer should produce code 1000");
            aura_free_string(result_ptr);

            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            let bad_json = CString::new("{invalid json!!!}").unwrap();
            let result_ptr = aura_analyze_json(handle, bad_json.as_ptr());
            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            let v: serde_json::Value = serde_json::from_str(result_str).unwrap();
            assert_eq!(v["error"], true);
            assert_eq!(v["code"], 1002, "Invalid JSON should produce code 1002");
            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn recommended_action_in_output() {
        unsafe {
            let config = CString::new(CHILD_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let msg = CString::new(
                r#"{"text":"don't tell your parents about us","sender_id":"stranger","conversation_id":"conv_1"}"#,
            ).unwrap();
            let result_ptr = aura_analyze_context(handle, msg.as_ptr(), 1000);
            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            assert!(
                result_str.contains("recommended_action"),
                "Output should include recommended_action field: {result_str}"
            );
            assert!(
                result_str.contains("parent_alert"),
                "recommended_action should include parent_alert: {result_str}"
            );

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn conversation_summary_tracks_conversations() {
        unsafe {
            let config = CString::new(CHILD_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let msg1 = CString::new(
                r#"{"text":"don't tell your parents","sender_id":"stranger","conversation_id":"conv_A"}"#,
            ).unwrap();
            let r1 = aura_analyze_context(handle, msg1.as_ptr(), 1000);
            aura_free_string(r1);

            let msg2 = CString::new(
                r#"{"text":"hey want to play minecraft?","sender_id":"friend","conversation_id":"conv_B"}"#,
            ).unwrap();
            let r2 = aura_analyze_context(handle, msg2.as_ptr(), 2000);
            aura_free_string(r2);

            let summary_ptr = aura_get_conversation_summary(handle);
            assert!(!summary_ptr.is_null());
            let summary_str = CStr::from_ptr(summary_ptr).to_str().unwrap();

            let v: serde_json::Value = serde_json::from_str(summary_str).unwrap();
            assert_eq!(v["total_conversations"], 2, "Should track 2 conversations");
            let convs = v["conversations"].as_array().unwrap();
            assert_eq!(convs.len(), 2);

            let conv_ids: Vec<&str> = convs
                .iter()
                .map(|c| c["conversation_id"].as_str().unwrap())
                .collect();
            assert!(conv_ids.contains(&"conv_A"));
            assert!(conv_ids.contains(&"conv_B"));

            aura_free_string(summary_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn conversation_summary_empty_state() {
        unsafe {
            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let summary_ptr = aura_get_conversation_summary(handle);
            assert!(!summary_ptr.is_null());
            let summary_str = CStr::from_ptr(summary_ptr).to_str().unwrap();

            let v: serde_json::Value = serde_json::from_str(summary_str).unwrap();
            assert_eq!(v["total_conversations"], 0, "No conversations initially");
            assert_eq!(v["conversations"].as_array().unwrap().len(), 0);

            aura_free_string(summary_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn last_error_null_by_default() {
        let err = aura_last_error();
        assert!(err.is_null(), "No error initially");
    }

    #[test]
    fn last_error_set_on_bad_init() {
        unsafe {
            let bad = CString::new("{invalid!!!}").unwrap();
            let handle = aura_init(bad.as_ptr());
            assert!(handle.is_null(), "Bad JSON should return null handle");

            let err = aura_last_error();
            assert!(!err.is_null(), "last_error should be set");
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("invalid config JSON"), "Got: {err_str}");
            aura_free_string(err);
        }
    }

    #[test]
    fn last_error_set_on_validation_failure() {
        unsafe {
            let config = CString::new(r#"{"protection_level":"medium","account_type":"adult","language":"en","cultural_context":"english","enabled":true,"ttl_days":0}"#).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(handle.is_null(), "Invalid ttl_days should return null");

            let err = aura_last_error();
            assert!(!err.is_null());
            let err_str = CStr::from_ptr(err).to_str().unwrap();
            assert!(err_str.contains("ttl_days"), "Got: {err_str}");
            aura_free_string(err);
        }
    }

    #[test]
    fn batch_size_limit_enforced() {
        unsafe {
            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());

            let mut items = String::from("[");
            for i in 0..1001 {
                if i > 0 { items.push(','); }
                items.push_str(&format!(r#"{{"text":"msg {}","sender_id":"u","conversation_id":"c"}}"#, i));
            }
            items.push(']');
            let batch = CString::new(items).unwrap();
            let result_ptr = aura_analyze_batch(handle, batch.as_ptr());
            let result_str = CStr::from_ptr(result_ptr).to_str().unwrap();
            assert!(result_str.contains("error"), "Should reject oversized batch");
            assert!(result_str.contains("1000"), "Should mention the limit");

            aura_free_string(result_ptr);
            aura_free(handle);
        }
    }

    #[test]
    fn last_error_cleared_on_success() {
        unsafe {
            let bad = CString::new("{invalid!!!}").unwrap();
            let _ = aura_init(bad.as_ptr());

            let config = CString::new(EN_CONFIG).unwrap();
            let handle = aura_init(config.as_ptr());
            assert!(!handle.is_null());

            let err = aura_last_error();
            assert!(err.is_null(), "Error should be cleared after success");

            aura_free(handle);
        }
    }
}
