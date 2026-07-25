use super::*;
use aura_agent_core::{
    GuardianExecutionMode, GuardianExecutionPolicy, NativeExecutionMode, NativeExecutionPolicy,
    NativeExecutionPolicyState,
};
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

fn test_execution_policy() -> NativeExecutionPolicy {
    let policy_wire_digest = [1; 32];
    let runtime_capabilities_digest = [2; 32];
    let model_manifest_digest = [3; 32];
    let execution_policy_trust_keyring_digest = [4; 32];
    NativeExecutionPolicy {
        account_key: "account".to_string(),
        protected_account_id: [5; 16],
        authority_lineage_id: "test-authority".to_string(),
        issuer_key_id: "test-issuer".to_string(),
        policy_epoch: 1,
        revoked_through_policy_epoch: 0,
        state: NativeExecutionPolicyState::Enabled,
        execution_mode: NativeExecutionMode::ShadowCases,
        policy_wire_digest,
        signed_policy_digest: [6; 32],
        runtime_capabilities_digest,
        model_manifest_digest,
        execution_policy_trust_keyring_digest,
        valid_from_ms: 1,
        valid_until_ms: 1_000_000,
        maximum_case_observations: 128,
        maximum_case_reason_codes: 16,
        guardian_policy: Some(GuardianExecutionPolicy {
            authority_lineage_id: "test-authority".to_string(),
            policy_epoch: 1,
            policy_version: "test-v1".to_string(),
            policy_assertion_digest: policy_wire_digest,
            runtime_capabilities_digest,
            model_manifest_digest,
            execution_policy_trust_keyring_digest,
            valid_from_ms: 1,
            valid_until_ms: 1_000_000,
            execution_mode: GuardianExecutionMode::ShadowCases,
            rules: Vec::new(),
        }),
        active_for_runtime: false,
    }
}

unsafe fn apply_test_execution_policy(handle: *mut c_void) {
    let account_key = SafetyAccountKey::new("account").expect("test account key must be valid");
    with_instance(handle, |instance| {
        instance
            .analyzer
            .safety_cases_mut()
            .apply_execution_policy(&account_key, test_execution_policy())
            .map(|_| ())
            .map_err(|error| error.to_string())
    })
    .expect("test execution policy must apply");
}

unsafe fn init_canonical_handle(config: proto::AuraConfig) -> *mut c_void {
    let handle = init_handle(config);
    apply_test_execution_policy(handle);
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
    let succeeded = aura_analyze_canonical_safety(handle, bytes.as_ptr(), bytes.len(), &mut out);
    assert!(
        succeeded,
        "canonical safety analysis failed: {}",
        last_error_string()
    );
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
    // Imported policy heads are intentionally inactive until this process
    // freshly applies the exact policy wire again.
    apply_test_execution_policy(handle);
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
    missing_conversation_index.schema_version =
        aura_agent_core::aura_kids::pipeline::KIDS_MEMORY_STATE_VERSION;
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
fn last_error_thread_local_is_empty_by_default() {
    let thread_local_error = LAST_ERROR.with(|error| error.borrow().clone());
    assert!(thread_local_error.is_none());
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
fn null_config_pointer_is_rejected_without_dereference() {
    unsafe {
        let handle = aura_init(std::ptr::null(), 1);
        assert!(handle.is_null());

        let err_str = last_error_string();
        assert!(err_str.contains("null config pointer"), "Got: {err_str}");
    }
}

#[test]
fn truncated_config_is_rejected_without_partial_decode() {
    unsafe {
        let mut request = encode_proto(&proto_config(proto::AccountType::Adult, true));
        assert!(request.len() > 1, "encoded config must be non-empty");
        request.pop();

        let handle = aura_init(request.as_ptr(), request.len());
        assert!(handle.is_null());

        let err_str = last_error_string();
        assert!(err_str.contains("invalid protobuf"), "Got: {err_str}");
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
fn output_pointer_and_owned_buffer_paths_are_explicit() {
    unsafe {
        let handle = init_handle(proto_config(proto::AccountType::Adult, true));

        assert!(!aura_export_context(handle, std::ptr::null_mut()));
        let err_str = last_error_string();
        assert!(err_str.contains("null out pointer"), "Got: {err_str}");

        let mut out = AuraBuffer::empty();
        assert!(aura_export_context(handle, &mut out));
        assert!(!out.ptr.is_null());
        assert!(out.len > 0);
        let owned_bytes = std::slice::from_raw_parts(out.ptr, out.len).to_vec();
        let _ = proto::ExportContextResponse::decode(owned_bytes.as_slice())
            .expect("owned FFI bytes must remain valid until freed");
        aura_free_buffer(out);

        aura_free_buffer(AuraBuffer::empty());
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
        let thread_local_error = LAST_ERROR.with(|error| error.borrow().clone());
        assert!(
            thread_local_error.is_none(),
            "successful init must clear the calling thread's error, got: {thread_local_error:?}"
        );
        aura_free(handle);
    }
}

#[test]
fn canonical_analysis_is_exactly_once() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
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
        let source = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let replica = init_canonical_handle(proto_config(proto::AccountType::Child, true));
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
        let first = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let second = init_canonical_handle(proto_config(proto::AccountType::Child, true));
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
