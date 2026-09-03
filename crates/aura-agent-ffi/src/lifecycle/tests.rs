use super::*;
use aura_runtime::{
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

#[test]
fn configured_missing_pattern_pack_blocks_initialization() {
    unsafe {
        let mut config = proto_config(proto::AccountType::Adult, true);
        let missing_path = std::env::temp_dir().join(format!(
            "aura-missing-pattern-pack-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time must follow UNIX epoch")
                .as_nanos()
        ));
        config.patterns_path = Some(missing_path.to_string_lossy().into_owned());

        let bytes = encode_proto(&config);
        let handle = aura_init(bytes.as_ptr(), bytes.len());

        assert!(handle.is_null(), "missing pattern pack must fail closed");
        let error = last_error_string();
        assert!(error.starts_with(PATTERN_PACK_LOAD_FAILED));
        assert!(error.contains("failed to load configured pattern pack"));
        assert!(error.contains("failed to read pattern file"));
    }
}

#[test]
fn configured_invalid_pattern_pack_blocks_initialization() {
    unsafe {
        let pattern_file = tempfile::NamedTempFile::new().expect("temporary pattern file");
        std::fs::write(pattern_file.path(), b"{not-json").expect("write invalid pattern pack");
        let mut config = proto_config(proto::AccountType::Adult, true);
        config.patterns_path = Some(pattern_file.path().to_string_lossy().into_owned());

        let bytes = encode_proto(&config);
        let handle = aura_init(bytes.as_ptr(), bytes.len());

        assert!(handle.is_null(), "invalid pattern pack must fail closed");
        let error = last_error_string();
        assert!(error.starts_with(PATTERN_PACK_LOAD_FAILED));
        assert!(error.contains("failed to load configured pattern pack"));
        assert!(error.contains("failed to parse pattern JSON"));
    }
}

#[test]
fn configured_valid_pattern_pack_initializes() {
    unsafe {
        let pattern_file = tempfile::NamedTempFile::new().expect("temporary pattern file");
        let pattern_json = br#"{
            "version": "rel003-custom",
            "updated_at": "2026-08-01",
            "rules": [{
                "id": "rel003_sentinel",
                "threat_type": "phishing",
                "kind": { "type": "keyword", "words": ["rel003sentinel"] },
                "score": 0.9,
                "languages": ["en"],
                "explanation": "REL-003 test rule"
            }]
        }"#;
        std::fs::write(pattern_file.path(), pattern_json).expect("write valid pattern pack");
        let mut config = proto_config(proto::AccountType::Adult, true);
        config.patterns_path = Some(pattern_file.path().to_string_lossy().into_owned());

        let decoded = aura_config_from_proto(config.clone()).expect("decode config");
        let loaded = load_pattern_db(&decoded).expect("load configured pattern pack");
        assert_eq!(loaded.version, "rel003-custom");
        assert_eq!(loaded.rules.len(), 1);

        let bytes = encode_proto(&config);
        let handle = aura_init(bytes.as_ptr(), bytes.len());

        assert!(!handle.is_null(), "valid configured pattern pack must load");
        aura_free(handle);
    }
}

#[test]
fn last_error_does_not_leak_to_another_thread() {
    let synchronized = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release_writer = std::sync::Arc::new(std::sync::Barrier::new(2));

    let writer_synchronized = synchronized.clone();
    let writer_release = release_writer.clone();
    let writer = std::thread::spawn(move || {
        set_last_error("writer-thread-error");
        writer_synchronized.wait();
        writer_release.wait();
        unsafe { last_error_string() }
    });

    let observer = std::thread::spawn(move || {
        synchronized.wait();
        let observed = unsafe {
            let error = aura_last_error();
            if error.is_null() {
                None
            } else {
                let message = CStr::from_ptr(error).to_string_lossy().into_owned();
                aura_free_string(error);
                Some(message)
            }
        };
        release_writer.wait();
        observed
    });

    assert_eq!(observer.join().expect("observer thread"), None);
    assert_eq!(writer.join().expect("writer thread"), "writer-thread-error");
}

#[test]
fn domain_mode_defaults_to_none_for_core_only_config() {
    let config = aura_config_from_proto(proto_config(proto::AccountType::Adult, true))
        .expect("config must decode");
    assert_eq!(config.domain_mode, aura_runtime::DomainMode::None);
}

#[test]
fn military_domain_mode_is_applied() {
    let mut proto = proto_config(proto::AccountType::Adult, true);
    proto.domain_mode = proto::DomainMode::Military as i32;
    let config = aura_config_from_proto(proto).expect("config must decode");
    assert_eq!(config.domain_mode, aura_runtime::DomainMode::Military);
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

#[test]
fn minor_disabled_config_is_rejected_at_ffi_boundary() {
    unsafe {
        for account_type in [proto::AccountType::Child, proto::AccountType::Teen] {
            let config = proto_config(account_type, false);
            let bytes = encode_proto(&config);
            let handle = aura_init(bytes.as_ptr(), bytes.len());
            if !handle.is_null() {
                aura_free(handle);
                panic!("disabled {account_type:?} config must be rejected");
            }
            assert!(last_error_string().contains("minor protection cannot be disabled"));
        }
    }
}

#[test]
fn minor_military_domain_is_rejected_at_ffi_boundary() {
    unsafe {
        for account_type in [proto::AccountType::Child, proto::AccountType::Teen] {
            let mut config = proto_config(account_type, true);
            config.domain_mode = proto::DomainMode::Military as i32;
            let bytes = encode_proto(&config);
            let handle = aura_init(bytes.as_ptr(), bytes.len());
            if !handle.is_null() {
                aura_free(handle);
                panic!("Military domain must not replace Kids for {account_type:?}");
            }
            assert!(last_error_string().contains("minor accounts require the Kids domain"));
        }
    }
}

#[test]
fn adult_disabled_config_still_initializes() {
    unsafe {
        let config = proto_config(proto::AccountType::Adult, false);
        let bytes = encode_proto(&config);
        let handle = aura_init(bytes.as_ptr(), bytes.len());
        assert!(!handle.is_null(), "adult accounts may disable protection");
        aura_free(handle);
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
        language_evidence: None,
        conversation_type: proto::ConversationType::Direct as i32,
        member_count: None,
        sender_relationship: proto::SenderRelationship::Unspecified as i32,
        relationship_trust_source: proto::RelationshipTrustSource::Unspecified as i32,
    }
}

#[test]
fn message_input_rejects_empty_whitespace_and_oversized_ids() {
    let empty_sender = message_input_from_proto(proto_message("hello", "", "conversation"))
        .expect_err("empty sender id must fail");
    let empty_conversation = message_input_from_proto(proto_message("hello", "sender", ""))
        .expect_err("empty conversation id must fail");
    let whitespace_sender =
        message_input_from_proto(proto_message("hello", "sender with spaces", "conversation"))
            .expect_err("whitespace sender id must fail");
    let oversized_sender = "s".repeat(MAX_FFI_IDENTIFIER_BYTES + 1);
    let oversized =
        message_input_from_proto(proto_message("hello", &oversized_sender, "conversation"))
            .expect_err("oversized sender id must fail");

    assert!(empty_sender.contains("message sender id must not be empty"));
    assert!(empty_conversation.contains("message conversation id must not be empty"));
    assert!(whitespace_sender.contains("whitespace or control"));
    assert!(oversized.contains("exceeds 256 bytes"));
}

#[test]
fn message_input_rejects_text_beyond_analyzed_prefix() {
    let exact_text = "a".repeat(aura_runtime::MAX_DOMAIN_TEXT_BYTES);
    let oversized_text = "a".repeat(aura_runtime::MAX_DOMAIN_TEXT_BYTES + 1);

    assert!(message_input_from_proto(proto_message(&exact_text, "sender", "conversation")).is_ok());

    let error = message_input_from_proto(proto_message(&oversized_text, "sender", "conversation"))
        .expect_err("text outside the analysis bound must fail closed");

    assert!(error.contains("message text exceeds 10000 UTF-8 bytes"));
}

fn language_candidate(
    language_tag: &str,
    confidence: f32,
    source: proto::LanguageEvidenceSource,
) -> proto::LanguageCandidateV1 {
    proto::LanguageCandidateV1 {
        language_tag: language_tag.to_string(),
        confidence,
        source: source as i32,
    }
}

fn typed_language_evidence(
    candidates: Vec<proto::LanguageCandidateV1>,
    spans: Vec<proto::LanguageSpanV1>,
) -> proto::LanguageEvidenceV1 {
    proto::LanguageEvidenceV1 {
        schema_version: 1,
        candidates,
        spans,
    }
}

#[test]
fn message_input_accepts_legacy_language_without_typed_evidence() {
    let input = message_input_from_proto(proto_message("hello", "sender", "conversation"))
        .expect("legacy message must remain accepted");

    assert!(input.language_evidence.is_none());
}

#[test]
fn message_input_accepts_bounded_classifier_evidence() {
    let text = "hello привіт";
    let mut message = proto_message(text, "sender", "conversation");
    message.language_evidence = Some(typed_language_evidence(
        vec![
            language_candidate("en", 1.0, proto::LanguageEvidenceSource::ClientDeclared),
            language_candidate(
                "uk",
                0.91,
                proto::LanguageEvidenceSource::OnDeviceClassifier,
            ),
        ],
        vec![proto::LanguageSpanV1 {
            language_tag: "uk".to_string(),
            script: proto::LanguageScript::Cyrillic as i32,
            confidence: 0.91,
            source: proto::LanguageEvidenceSource::OnDeviceClassifier as i32,
            start_utf8: 6,
            end_utf8: text.len() as u32,
        }],
    ));

    let input = message_input_from_proto(message).expect("typed evidence must be accepted");
    let evidence = input.language_evidence.expect("typed evidence");

    assert_eq!(evidence.candidates().len(), 2);
    assert_eq!(evidence.spans().len(), 1);
}

#[test]
fn message_input_rejects_noncanonical_typed_language_tag() {
    let mut message = proto_message("hello", "sender", "conversation");
    message.language_evidence = Some(typed_language_evidence(
        vec![language_candidate(
            "EN",
            1.0,
            proto::LanguageEvidenceSource::ClientDeclared,
        )],
        Vec::new(),
    ));

    let error = message_input_from_proto(message).expect_err("uppercase tag must fail");

    assert!(error.contains("canonical lowercase"));
}

#[test]
fn message_input_rejects_nonfinite_classifier_confidence() {
    let mut message = proto_message("hello", "sender", "conversation");
    message.language_evidence = Some(typed_language_evidence(
        vec![language_candidate(
            "en",
            f32::NAN,
            proto::LanguageEvidenceSource::OnDeviceClassifier,
        )],
        Vec::new(),
    ));

    let error = message_input_from_proto(message).expect_err("NaN must fail");

    assert!(error.contains("confidence must be finite"));
}

#[test]
fn message_input_rejects_unknown_language_source() {
    let mut message = proto_message("hello", "sender", "conversation");
    let mut candidate =
        language_candidate("en", 0.9, proto::LanguageEvidenceSource::OnDeviceClassifier);
    candidate.source = 999;
    message.language_evidence = Some(typed_language_evidence(vec![candidate], Vec::new()));

    let error = message_input_from_proto(message).expect_err("unknown enum must fail");

    assert!(error.contains("unknown language evidence source 999"));
}

#[test]
fn message_input_rejects_excessive_language_candidates() {
    let mut message = proto_message("hello", "sender", "conversation");
    let candidate =
        language_candidate("en", 0.9, proto::LanguageEvidenceSource::OnDeviceClassifier);
    message.language_evidence = Some(typed_language_evidence(
        vec![candidate; MAX_LANGUAGE_CANDIDATES + 1],
        Vec::new(),
    ));

    let error = message_input_from_proto(message).expect_err("candidate overflow must fail");

    assert!(error.contains("exceeds 4 candidates"));
}

#[test]
fn message_input_rejects_excessive_language_spans_before_mapping() {
    let mut message = proto_message("hello", "sender", "conversation");
    let span = proto::LanguageSpanV1 {
        language_tag: "en".to_string(),
        script: proto::LanguageScript::Latin as i32,
        confidence: 0.9,
        source: proto::LanguageEvidenceSource::OnDeviceClassifier as i32,
        start_utf8: 0,
        end_utf8: 5,
    };
    message.language_evidence = Some(typed_language_evidence(
        vec![language_candidate(
            "en",
            0.9,
            proto::LanguageEvidenceSource::OnDeviceClassifier,
        )],
        vec![span; MAX_LANGUAGE_SPANS + 1],
    ));

    let error = message_input_from_proto(message).expect_err("span overflow must fail");

    assert!(error.contains("exceeds 32 spans"));
}

#[test]
fn message_input_rejects_unknown_language_evidence_schema() {
    let mut message = proto_message("hello", "sender", "conversation");
    let mut evidence = typed_language_evidence(
        vec![language_candidate(
            "en",
            1.0,
            proto::LanguageEvidenceSource::ClientDeclared,
        )],
        Vec::new(),
    );
    evidence.schema_version = 2;
    message.language_evidence = Some(evidence);

    let error = message_input_from_proto(message).expect_err("unknown schema must fail");

    assert!(error.contains("schema_version must be 1"));
}

#[test]
fn message_input_rejects_legacy_typed_language_conflict() {
    let mut message = proto_message("bonjour", "sender", "conversation");
    message.language_evidence = Some(typed_language_evidence(
        vec![language_candidate(
            "fr",
            1.0,
            proto::LanguageEvidenceSource::ClientDeclared,
        )],
        Vec::new(),
    ));

    let error = message_input_from_proto(message).expect_err("conflict must fail closed");

    assert!(error.contains("legacy language conflicts"));
}

#[test]
fn message_input_rejects_span_at_non_utf8_boundary() {
    let mut message = proto_message("é", "sender", "conversation");
    message.language_evidence = Some(typed_language_evidence(
        vec![language_candidate(
            "fr",
            0.9,
            proto::LanguageEvidenceSource::OnDeviceClassifier,
        )],
        vec![proto::LanguageSpanV1 {
            language_tag: "fr".to_string(),
            script: proto::LanguageScript::Latin as i32,
            confidence: 0.9,
            source: proto::LanguageEvidenceSource::OnDeviceClassifier as i32,
            start_utf8: 1,
            end_utf8: 2,
        }],
    ));

    let error = message_input_from_proto(message).expect_err("invalid UTF-8 boundary must fail");

    assert!(error.contains("invalid UTF-8 boundaries"));
}

#[test]
fn message_input_rejects_span_with_false_script_claim() {
    let mut message = proto_message("hello", "sender", "conversation");
    message.language_evidence = Some(typed_language_evidence(
        vec![language_candidate(
            "en",
            0.9,
            proto::LanguageEvidenceSource::OnDeviceClassifier,
        )],
        vec![proto::LanguageSpanV1 {
            language_tag: "en".to_string(),
            script: proto::LanguageScript::Cyrillic as i32,
            confidence: 0.9,
            source: proto::LanguageEvidenceSource::OnDeviceClassifier as i32,
            start_utf8: 0,
            end_utf8: 5,
        }],
    ));

    let error = message_input_from_proto(message).expect_err("false script must fail");

    assert!(error.contains("script does not match"));
}

#[test]
fn message_input_rejects_overlapping_language_spans() {
    let text = "hello world";
    let mut message = proto_message(text, "sender", "conversation");
    let span = |start_utf8, end_utf8| proto::LanguageSpanV1 {
        language_tag: "en".to_string(),
        script: proto::LanguageScript::Latin as i32,
        confidence: 0.9,
        source: proto::LanguageEvidenceSource::OnDeviceClassifier as i32,
        start_utf8,
        end_utf8,
    };
    message.language_evidence = Some(typed_language_evidence(
        vec![language_candidate(
            "en",
            0.9,
            proto::LanguageEvidenceSource::OnDeviceClassifier,
        )],
        vec![span(0, 5), span(4, 11)],
    ));

    let error = message_input_from_proto(message).expect_err("overlap must fail");

    assert!(error.contains("sorted and non-overlapping"));
}

#[test]
fn classifier_candidate_routes_same_script_language_pack_through_ffi() {
    // SAFETY: the test creates one valid FFI handle, keeps all encoded input
    // buffers alive for each call, and frees the handle exactly once below.
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let mut message = proto_message(
            "никому не рассказывай, это наш секрет",
            "sender",
            "language-routing-conversation",
        );
        message.language = Some("uk".to_string());
        message.language_evidence = Some(typed_language_evidence(
            vec![language_candidate(
                "ru",
                0.96,
                proto::LanguageEvidenceSource::OnDeviceClassifier,
            )],
            Vec::new(),
        ));

        let response = analyze_local_decision(handle, message, "language-routing-event", 1, 1_000);
        let decision = response.decision.expect("first attempt decision");

        assert!(decision
            .reason_codes
            .iter()
            .any(|code| code == "pattern.grooming_secrecy_ru"));
        aura_free(handle);
    }
}

#[test]
fn declared_language_cannot_suppress_governed_release_pack_through_ffi() {
    // SAFETY: the test creates one valid FFI handle, keeps all encoded input
    // buffers alive for each call, and frees the handle exactly once below.
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let mut message = proto_message(
            "никому не рассказывай, это наш секрет",
            "sender",
            "language-declaration-safety-conversation",
        );
        message.language = Some("uk".to_string());
        message.language_evidence = Some(typed_language_evidence(
            vec![language_candidate(
                "uk",
                1.0,
                proto::LanguageEvidenceSource::ClientDeclared,
            )],
            Vec::new(),
        ));

        let response = analyze_local_decision(
            handle,
            message,
            "language-declaration-safety-event",
            1,
            1_000,
        );
        let decision = response.decision.expect("first attempt decision");

        assert!(decision
            .reason_codes
            .iter()
            .any(|code| code == "pattern.grooming_secrecy_ru"));
        aura_free(handle);
    }
}

#[test]
fn canonical_ffi_rejects_empty_message_id_before_analysis() {
    unsafe {
        let handle = init_handle(proto_config(proto::AccountType::Adult, true));
        let request = proto::CanonicalSafetyAnalyzeRequest {
            message: Some(proto_message("hello", "", "conversation")),
            identity: Some(proto::CanonicalSafetyEventIdentity {
                account_key: "account".to_string(),
                subject_key: "subject".to_string(),
                conversation_key: "conversation".to_string(),
                event_id: "event".to_string(),
                revision: 1,
                occurred_at_ms: 1,
                observed_at_ms: 1,
            }),
        };
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();

        assert!(!aura_analyze_canonical_safety(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            &mut out,
        ));
        assert!(out.ptr.is_null());
        assert!(last_error_string().contains("message sender id must not be empty"));
        aura_free(handle);
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
        valid_until_ms: i64::MAX as u64,
        maximum_case_observations: 4_096,
        maximum_case_reason_codes: 64,
        guardian_policy: Some(GuardianExecutionPolicy {
            authority_lineage_id: "test-authority".to_string(),
            policy_epoch: 1,
            policy_version: "test-v1".to_string(),
            policy_assertion_digest: policy_wire_digest,
            runtime_capabilities_digest,
            model_manifest_digest,
            execution_policy_trust_keyring_digest,
            valid_from_ms: 1,
            valid_until_ms: i64::MAX as u64,
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
            .bind_protected_account_id(account_key.as_str().to_string())
            .map_err(|error| error.to_string())?;
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

unsafe fn analyze_local_decision(
    handle: *mut c_void,
    message: proto::MessageInput,
    event_id: &str,
    revision: u32,
    timestamp_ms: u64,
) -> proto::LocalDecisionAnalyzeResponse {
    analyze_local_decision_at(
        handle,
        message,
        event_id,
        revision,
        timestamp_ms,
        timestamp_ms,
    )
}

unsafe fn analyze_local_decision_at(
    handle: *mut c_void,
    message: proto::MessageInput,
    event_id: &str,
    revision: u32,
    occurred_at_ms: u64,
    observed_at_ms: u64,
) -> proto::LocalDecisionAnalyzeResponse {
    let conversation_key = message.conversation_id.clone();
    let request = proto::LocalDecisionAnalyzeRequest {
        message: Some(message),
        identity: Some(proto::CanonicalSafetyEventIdentity {
            account_key: "account".to_string(),
            subject_key: "subject".to_string(),
            conversation_key,
            event_id: event_id.to_string(),
            revision,
            occurred_at_ms,
            observed_at_ms,
        }),
    };
    let bytes = encode_proto(&request);
    let mut out = AuraBuffer::empty();
    let succeeded = aura_analyze_local_decision(handle, bytes.as_ptr(), bytes.len(), &mut out);
    assert!(
        succeeded,
        "local decision analysis failed: {}",
        last_error_string()
    );
    decode_buffer(out)
}

unsafe fn acknowledge_source_checkpoint(
    handle: *mut c_void,
    conversation_key: &str,
    event_id: &str,
    revision: u32,
    timestamp_ms: u64,
) {
    let identity = proto::CanonicalSafetyEventIdentity {
        account_key: "account".to_string(),
        subject_key: "subject".to_string(),
        conversation_key: conversation_key.to_string(),
        event_id: event_id.to_string(),
        revision,
        occurred_at_ms: timestamp_ms,
        observed_at_ms: timestamp_ms,
    };
    let bytes = encode_proto(&identity);
    assert!(
        aura_acknowledge_source_checkpoint(handle, bytes.as_ptr(), bytes.len()),
        "source checkpoint failed: {}",
        last_error_string()
    );
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

unsafe fn export_safety_case_state(handle: *mut c_void) -> Vec<u8> {
    let account_key = b"account";
    let mut out = AuraBuffer::empty();
    assert!(aura_export_safety_case_state(
        handle,
        account_key.as_ptr(),
        account_key.len(),
        &mut out,
    ));
    let bytes = std::slice::from_raw_parts(out.ptr, out.len).to_vec();
    aura_free_buffer(out);
    bytes
}

unsafe fn import_safety_case_state(handle: *mut c_void, state: &[u8]) {
    let account_key = b"account";
    assert!(aura_import_safety_case_state(
        handle,
        account_key.as_ptr(),
        account_key.len(),
        state.as_ptr(),
        state.len(),
    ));
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
    use aura_runtime::aura_kids::pipeline::{
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
            guardian_blocked: true,
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
            restored.senders[0].guardian_blocked,
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
            true,
        )
    );
}

#[test]
fn legacy_kids_guardian_block_state_migrates_through_proto_boundary() {
    let legacy = proto::KidsMemoryState {
        conversations: Vec::new(),
        senders: vec![proto::KidsSenderMemoryState {
            sender_id: "legacy_blocked".to_string(),
            event_index: 5,
            recent_high_risk_conversations: vec![
                "real_conversation".to_string(),
                "guardian_block_legacy_blocked_0".to_string(),
                "guardian_block_legacy_blocked_1".to_string(),
                "guardian_block_legacy_blocked_2".to_string(),
                "guardian_block_legacy_blocked_3".to_string(),
                "guardian_block_legacy_blocked_4".to_string(),
            ],
            last_activity_index: Some(9),
            last_emitted: Vec::new(),
            guardian_blocked: false,
        }],
        schema_version: 1,
    };

    let converted = kids_memory_state_from_proto(&legacy).expect("legacy kids state conversion");
    let module = aura_runtime::aura_kids::KidsModule::new();
    assert!(module.import_memory(&converted));
    let migrated = module.export_memory();

    assert_eq!(
        migrated.schema_version,
        aura_runtime::aura_kids::pipeline::KIDS_MEMORY_STATE_VERSION
    );
    assert!(migrated.senders[0].guardian_blocked);
    assert_eq!(
        migrated.senders[0].recent_high_risk_conversations,
        vec!["real_conversation".to_string()]
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
            guardian_blocked: false,
            last_activity_index: None,
            last_emitted: Vec::new(),
        }],
        schema_version: 0,
    };

    assert!(kids_memory_state_from_proto(&noncurrent).is_err());

    let mut missing_conversation_index = noncurrent.clone();
    missing_conversation_index.schema_version =
        aura_runtime::aura_kids::pipeline::KIDS_MEMORY_STATE_VERSION;
    missing_conversation_index.senders[0].last_activity_index = Some(42);
    assert!(kids_memory_state_from_proto(&missing_conversation_index).is_err());

    let mut missing_sender_index = missing_conversation_index;
    missing_sender_index.conversations[0].last_activity_index = Some(41);
    missing_sender_index.senders[0].last_activity_index = None;
    assert!(kids_memory_state_from_proto(&missing_sender_index).is_err());
}

#[test]
fn persisted_context_rejects_invalid_nested_sender_and_conversation_ids() {
    let invalid_timeline = proto::TrackerState {
        schema_version: 3,
        timelines: vec![proto::ConversationTimelineState {
            conversation_id: String::new(),
            conversation_type: proto::ConversationType::Direct as i32,
            events: Vec::new(),
        }],
        contact_profiler: None,
        kids_memory: None,
    };
    let timeline_error = tracker_state_from_proto(invalid_timeline)
        .err()
        .expect("empty timeline conversation id must fail");

    let invalid_event = proto::ContextEvent {
        sender_id: String::new(),
        conversation_id: "conversation".to_string(),
        kind: proto::EventKind::NormalConversation as i32,
        ..proto::ContextEvent::default()
    };
    let event_error =
        context_event_from_proto(invalid_event).expect_err("empty context sender id must fail");

    let invalid_contact = proto::ContactProfilerState {
        profiles: vec![proto::ContactProfileState::default()],
    };
    let contact_error = contact_profiler_state_from_proto(invalid_contact)
        .expect_err("empty contact sender id must fail");

    assert!(timeline_error.contains("timeline conversation id must not be empty"));
    assert!(event_error.contains("context event sender id must not be empty"));
    assert!(contact_error.contains("contact profile sender id must not be empty"));
}

#[test]
fn v2_tracker_golden_fixture_imports_and_reexports_as_v3() {
    const TRACKER_STATE_V2_GOLDEN: &[u8] =
        include_bytes!("../../../aura-proto/tests/fixtures/tracker_state.pb");

    unsafe {
        let legacy = proto::TrackerState::decode(TRACKER_STATE_V2_GOLDEN)
            .expect("decode v2 tracker golden fixture");
        assert_eq!(legacy.schema_version, 2);
        assert_eq!(legacy.timelines.len(), 1);
        assert_eq!(legacy.contact_profiler.as_ref().unwrap().profiles.len(), 1);

        let handle = init_handle(proto_config(proto::AccountType::Adult, true));
        let request = proto::ImportContextRequest {
            state: Some(legacy),
        };
        let bytes = encode_proto(&request);
        let imported = aura_import_context(handle, bytes.as_ptr(), bytes.len());

        assert!(
            imported,
            "v2 golden fixture must migrate: {}",
            if imported {
                String::new()
            } else {
                last_error_string()
            }
        );
        let migrated = export_context(handle)
            .state
            .expect("migrated tracker state");
        assert_eq!(migrated.schema_version, 3);
        assert_eq!(migrated.timelines.len(), 1);
        assert_eq!(migrated.timelines[0].conversation_id, "conv_fixture_1");
        assert_eq!(migrated.timelines[0].events.len(), 2);
        assert!(migrated.timelines[0]
            .events
            .iter()
            .all(|event| event.context.as_ref() == Some(&proto::EventContextFrame::default())));
        let profile = &migrated.contact_profiler.unwrap().profiles[0];
        assert_eq!(profile.sender_id, "mentor_42");
        assert_eq!(profile.total_messages, 5);
        assert_eq!(profile.grooming_event_count, 3);
        aura_free(handle);
    }
}

#[test]
fn v3_tracker_context_golden_fixture_roundtrips_without_semantic_loss() {
    const TRACKER_STATE_V3_GOLDEN: &[u8] =
        include_bytes!("../../../aura-proto/tests/fixtures/tracker_state_v3.pb");

    unsafe {
        let expected = proto::TrackerState::decode(TRACKER_STATE_V3_GOLDEN)
            .expect("decode v3 tracker golden fixture");
        assert_eq!(expected.schema_version, 3);
        assert!(expected.timelines[0]
            .events
            .iter()
            .all(|event| event.context.is_some()));

        let handle = init_handle(proto_config(proto::AccountType::Adult, true));
        let request = proto::ImportContextRequest {
            state: Some(expected.clone()),
        };
        let bytes = encode_proto(&request);
        assert!(aura_import_context(handle, bytes.as_ptr(), bytes.len()));

        let restored = export_context(handle).state.expect("restored v3 state");
        assert_eq!(restored.schema_version, 3);
        assert_eq!(restored.timelines, expected.timelines);
        aura_free(handle);
    }
}

#[test]
fn rejected_context_imports_do_not_mutate_existing_ffi_state() {
    const TRACKER_STATE_V3_GOLDEN: &[u8] =
        include_bytes!("../../../aura-proto/tests/fixtures/tracker_state_v3.pb");

    unsafe {
        let initial = proto::TrackerState::decode(TRACKER_STATE_V3_GOLDEN)
            .expect("decode v3 tracker golden fixture");
        let handle = init_handle(proto_config(proto::AccountType::Adult, true));
        let initial_request = proto::ImportContextRequest {
            state: Some(initial),
        };
        let initial_bytes = encode_proto(&initial_request);
        assert!(aura_import_context(
            handle,
            initial_bytes.as_ptr(),
            initial_bytes.len(),
        ));
        let before = export_context(handle).state.expect("initial state");

        let corrupt = [0x0a, 0x05, 0x08];
        assert!(!aura_import_context(
            handle,
            corrupt.as_ptr(),
            corrupt.len(),
        ));
        assert!(last_error_string().contains("invalid protobuf in import_context request"));
        assert_eq!(export_context(handle).state.as_ref(), Some(&before));

        let mut future = before.clone();
        future.schema_version = 999;
        let future_request = proto::ImportContextRequest {
            state: Some(future),
        };
        let future_bytes = encode_proto(&future_request);
        assert!(!aura_import_context(
            handle,
            future_bytes.as_ptr(),
            future_bytes.len(),
        ));
        assert!(last_error_string().contains("incompatible state version"));
        assert_eq!(export_context(handle).state.as_ref(), Some(&before));
        aura_free(handle);
    }
}

#[test]
fn event_context_rejects_unknown_enums_and_nonfinite_confidence() {
    let unknown_speech_act = proto::EventContextFrame {
        speech_act: i32::MAX,
        ..proto::EventContextFrame::default()
    };
    let invalid_confidence = proto::EventContextFrame {
        confidence: f32::NAN,
        ..proto::EventContextFrame::default()
    };

    assert!(event_context_frame_from_proto(unknown_speech_act)
        .expect_err("unknown speech act must fail")
        .contains("unknown speech_act"));
    assert!(event_context_frame_from_proto(invalid_confidence)
        .expect_err("NaN confidence must fail")
        .contains("finite and within 0..=1"));
}

#[test]
fn persisted_kids_memory_rejects_invalid_nested_ids() {
    let valid_conversation = proto::KidsConversationMemoryState {
        conversation_id: "conversation".to_string(),
        entries: vec![proto::KidsMessageRiskSnapshot {
            sender_id: Some("sender".to_string()),
            ..proto::KidsMessageRiskSnapshot::default()
        }],
        message_index: 1,
        last_activity_index: Some(1),
        last_emitted: Vec::new(),
    };
    let valid_sender = proto::KidsSenderMemoryState {
        sender_id: "sender".to_string(),
        event_index: 1,
        recent_high_risk_conversations: vec!["conversation".to_string()],
        last_activity_index: Some(1),
        last_emitted: Vec::new(),
        guardian_blocked: false,
    };
    let valid_state = proto::KidsMemoryState {
        conversations: vec![valid_conversation],
        senders: vec![valid_sender],
        schema_version: aura_runtime::aura_kids::pipeline::KIDS_MEMORY_STATE_VERSION,
    };

    let mut empty_conversation = valid_state.clone();
    empty_conversation.conversations[0].conversation_id.clear();
    let conversation_error = kids_memory_state_from_proto(&empty_conversation)
        .expect_err("empty kids conversation id must fail");

    let mut empty_snapshot_sender = valid_state.clone();
    empty_snapshot_sender.conversations[0].entries[0].sender_id = Some(String::new());
    let snapshot_error = kids_memory_state_from_proto(&empty_snapshot_sender)
        .expect_err("empty kids snapshot sender id must fail");

    let mut oversized_recent_conversation = valid_state;
    oversized_recent_conversation.senders[0].recent_high_risk_conversations[0] =
        "c".repeat(MAX_FFI_IDENTIFIER_BYTES + 1);
    let recent_error = kids_memory_state_from_proto(&oversized_recent_conversation)
        .expect_err("oversized recent conversation id must fail");

    assert!(conversation_error.contains("kids conversation id must not be empty"));
    assert!(snapshot_error.contains("kids message sender id must not be empty"));
    assert!(recent_error.contains("kids recent conversation id exceeds 256 bytes"));
}

#[test]
fn persisted_kids_memory_rejects_non_finite_ml_scores() {
    let state = proto::KidsMemoryState {
        conversations: vec![proto::KidsConversationMemoryState {
            conversation_id: "conversation".to_string(),
            entries: vec![proto::KidsMessageRiskSnapshot {
                sender_id: Some("sender".to_string()),
                ml_grooming: f32::NAN,
                ..proto::KidsMessageRiskSnapshot::default()
            }],
            message_index: 1,
            last_activity_index: Some(1),
            last_emitted: Vec::new(),
        }],
        senders: Vec::new(),
        schema_version: aura_runtime::aura_kids::pipeline::KIDS_MEMORY_STATE_VERSION,
    };

    let error = kids_memory_state_from_proto(&state)
        .expect_err("non-finite kids memory ML score must fail closed");
    assert!(error.contains("finite and within 0..=1"), "{error}");
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
fn local_decision_returns_typed_product_projection_exactly_once() {
    unsafe {
        let mut config = proto_config(proto::AccountType::Child, true);
        config.product_rollout_mode = proto::ProductRolloutMode::GuardianEnabled as i32;
        let handle = init_canonical_handle(config);
        let message = proto_message(
            "don't tell your parents, it's our secret",
            "sender",
            "conversation",
        );

        let first = analyze_local_decision(handle, message.clone(), "local-event", 1, 1_000);
        assert!(matches!(
            proto::CanonicalSafetyDisposition::try_from(first.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::ProcessedIgnored
                | proto::CanonicalSafetyDisposition::ProcessedReduced
        ));
        let decision = first
            .decision
            .expect("successful first attempt must return a typed decision");
        assert!(decision.product_surface.is_some());
        assert!(decision.recommended_action.is_some());
        assert!(decision.inference.is_some());
        assert!(!decision.reason_codes.is_empty());
        assert_eq!(
            proto::RuntimeBackend::try_from(decision.runtime_backend).unwrap(),
            proto::RuntimeBackend::RulesFallback
        );
        assert!(decision.degraded);
        let temporal = decision
            .temporal_context
            .expect("first decision must carry temporal context");
        assert_eq!(temporal.schema_version, 1);
        assert_eq!(temporal.occurred_at_ms, 1_000);
        assert_eq!(temporal.observed_at_ms, 1_000);
        assert_eq!(temporal.observation_delay_ms, 0);
        assert_eq!(temporal.case_generation, first.case_generation);
        assert_eq!(temporal.case_revision, first.case_revision);
        assert_eq!(temporal.status_after, first.case_status);

        let context_after_first = export_context(handle);
        let duplicate = analyze_local_decision(handle, message, "local-event", 1, 1_000);
        assert!(matches!(
            proto::CanonicalSafetyDisposition::try_from(duplicate.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::DuplicateIgnored
                | proto::CanonicalSafetyDisposition::DuplicateApplied
                | proto::CanonicalSafetyDisposition::DuplicateRejected
        ));
        assert!(duplicate.decision.is_none());
        assert_eq!(export_context(handle), context_after_first);

        aura_free(handle);
    }
}

#[test]
fn local_decision_temporal_context_distinguishes_event_and_observation_time() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let response = analyze_local_decision_at(
            handle,
            proto_message(
                "don't tell your parents, it's our secret",
                "sender",
                "temporal-conversation",
            ),
            "temporal-event",
            1,
            1_000,
            9_000,
        );
        assert_eq!(
            proto::CanonicalSafetyDisposition::try_from(response.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::ProcessedReduced
        );
        let temporal = response
            .decision
            .expect("first attempt decision")
            .temporal_context
            .expect("temporal context");
        assert_eq!(temporal.occurred_at_ms, 1_000);
        assert_eq!(temporal.observed_at_ms, 9_000);
        assert_eq!(temporal.observation_delay_ms, 8_000);
        assert!(temporal.contributed_to_case);
        assert_eq!(temporal.case_generation, response.case_generation);
        assert_eq!(temporal.case_revision, response.case_revision);
        assert_eq!(temporal.status_after, response.case_status);
        assert_eq!(temporal.retained_observation_count, 1);
        assert!(temporal.peak_risk_basis_points > 0);
        assert_eq!(temporal.case_first_event_at_ms, Some(1_000));
        assert_eq!(temporal.case_last_event_at_ms, Some(1_000));

        aura_free(handle);
    }
}

#[test]
fn local_decision_temporal_context_retains_bounds_for_out_of_order_arrival() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let first = analyze_local_decision_at(
            handle,
            proto_message(
                "don't tell your parents, it's our secret",
                "sender",
                "out-of-order-conversation",
            ),
            "later-source-event",
            1,
            3_000,
            4_000,
        );
        assert_eq!(
            proto::CanonicalSafetyDisposition::try_from(first.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::ProcessedReduced
        );

        let backfill = analyze_local_decision_at(
            handle,
            proto_message(
                "don't tell your parents, it's our secret",
                "sender",
                "out-of-order-conversation",
            ),
            "earlier-source-event",
            1,
            1_000,
            9_000,
        );
        assert_eq!(
            proto::CanonicalSafetyDisposition::try_from(backfill.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::ProcessedReduced
        );
        assert_eq!(backfill.case_id, first.case_id);
        let temporal = backfill
            .decision
            .expect("backfilled first attempt decision")
            .temporal_context
            .expect("backfilled temporal context");
        assert_eq!(temporal.occurred_at_ms, 1_000);
        assert_eq!(temporal.observed_at_ms, 9_000);
        assert_eq!(temporal.observation_delay_ms, 8_000);
        assert_eq!(temporal.retained_observation_count, 2);
        assert_eq!(temporal.case_first_event_at_ms, Some(1_000));
        assert_eq!(temporal.case_last_event_at_ms, Some(3_000));

        aura_free(handle);
    }
}

#[test]
fn ignored_local_decision_has_content_free_temporal_context_without_case_projection() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let response = analyze_local_decision_at(
            handle,
            proto_message(
                "ordinary clean message",
                "sender",
                "clean-temporal-conversation",
            ),
            "clean-temporal-event",
            1,
            2_000,
            3_500,
        );
        assert_eq!(
            proto::CanonicalSafetyDisposition::try_from(response.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::ProcessedIgnored
        );
        let temporal = response
            .decision
            .expect("first attempt decision")
            .temporal_context
            .expect("temporal context");
        assert_eq!(temporal.observation_delay_ms, 1_500);
        assert!(!temporal.contributed_to_case);
        assert!(temporal.case_generation.is_none());
        assert!(temporal.case_revision.is_none());
        assert_eq!(
            proto::SafetyCaseLifecycleStatus::try_from(temporal.status_before).unwrap(),
            proto::SafetyCaseLifecycleStatus::Unspecified
        );
        assert_eq!(
            proto::SafetyCaseLifecycleStatus::try_from(temporal.status_after).unwrap(),
            proto::SafetyCaseLifecycleStatus::Unspecified
        );
        assert!(!temporal.status_changed);
        assert_eq!(temporal.retained_observation_count, 0);
        assert_eq!(temporal.peak_risk_basis_points, 0);
        assert!(temporal.case_first_event_at_ms.is_none());
        assert!(temporal.case_last_event_at_ms.is_none());

        aura_free(handle);
    }
}

#[test]
fn local_decision_restart_replays_receipt_without_double_analysis() {
    unsafe {
        let config = proto_config(proto::AccountType::Child, true);
        let source = init_canonical_handle(config.clone());
        let message = proto_message(
            "don't tell your parents, it's our secret",
            "sender",
            "conversation",
        );
        let first = analyze_local_decision(source, message.clone(), "restart-event", 1, 1_000);
        let durable_response = first.encode_to_vec();
        assert!(first.decision.is_some());
        let context = export_context(source)
            .state
            .expect("local decision must export context");
        let safety_state = export_safety_case_state(source);

        let restored = init_handle(config);
        import_safety_case_state(restored, &safety_state);
        import_context_state(restored, context.clone());

        // Timestamps are not exactly-once identity fields. Even if a relaunched
        // host supplies drifted values, native state must not analyze twice;
        // the host reconciles the response with its encrypted original receipt.
        let duplicate =
            analyze_local_decision_at(restored, message, "restart-event", 1, 900, 1_500);
        assert!(matches!(
            proto::CanonicalSafetyDisposition::try_from(duplicate.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::DuplicateIgnored
                | proto::CanonicalSafetyDisposition::DuplicateApplied
                | proto::CanonicalSafetyDisposition::DuplicateRejected
        ));
        assert!(duplicate.decision.is_none());
        assert_eq!(export_context(restored).state, Some(context));
        assert!(
            proto::LocalDecisionAnalyzeResponse::decode(durable_response.as_slice())
                .expect("durable response must remain decodable")
                .decision
                .is_some()
        );

        aura_free(source);
        aura_free(restored);
    }
}

#[test]
fn local_decision_and_canonical_api_share_source_ledger() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let message = proto_message(
            "don't tell your parents, it's our secret",
            "sender",
            "conversation",
        );
        let first = analyze_local_decision(handle, message.clone(), "shared-event", 2, 2_000);
        assert!(first.decision.is_some());
        let context_after_first = export_context(handle);

        let canonical_duplicate =
            analyze_canonical(handle, message.clone(), "shared-event", 2, 2_000);
        assert!(matches!(
            proto::CanonicalSafetyDisposition::try_from(canonical_duplicate.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::DuplicateIgnored
                | proto::CanonicalSafetyDisposition::DuplicateApplied
                | proto::CanonicalSafetyDisposition::DuplicateRejected
        ));
        assert_eq!(export_context(handle), context_after_first);

        let stale = analyze_local_decision(handle, message, "shared-event", 1, 2_000);
        assert_eq!(
            proto::CanonicalSafetyDisposition::try_from(stale.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::StaleIgnored
        );
        assert_eq!(stale.latest_revision, Some(2));
        assert!(stale.decision.is_none());
        assert_eq!(export_context(handle), context_after_first);

        aura_free(handle);
    }
}

#[test]
fn local_decision_preserves_supportive_self_harm_boundary() {
    unsafe {
        let mut config = proto_config(proto::AccountType::Child, true);
        config.product_rollout_mode = proto::ProductRolloutMode::GuardianEnabled as i32;
        let handle = init_canonical_handle(config);
        let response = analyze_local_decision(
            handle,
            proto_message(
                "My friend said there is no reason to live. I'm here with you, let's tell your parents together and get help tonight.",
                "supportive-peer",
                "supportive-conversation",
            ),
            "supportive-event",
            1,
            1_000,
        );
        let decision = response.decision.expect("safe first attempt decision");
        let decision_debug = format!("{decision:?}");
        let product = decision.product_surface.expect("product surface");
        assert_eq!(
            proto::ThreatType::try_from(product.threat_type).unwrap(),
            proto::ThreatType::None,
            "{decision_debug}"
        );
        assert_eq!(
            proto::Action::try_from(product.action).unwrap(),
            proto::Action::Allow,
            "{decision_debug}"
        );
        let child = product.child.expect("child surface");
        assert!(!child.visible);
        assert_eq!(
            proto::ProductChildIntervention::try_from(child.intervention).unwrap(),
            proto::ProductChildIntervention::None
        );
        assert!(!product.guardian.expect("guardian surface").notify);

        aura_free(handle);
    }
}

#[test]
fn execution_policy_account_binding_excludes_owner_messages_from_contact_risk() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        for event in 1..=150 {
            let response = analyze_local_decision(
                handle,
                proto_message(
                    "Normal update from the protected account",
                    "account",
                    "owner-conversation",
                ),
                &format!("owner-event-{event}"),
                1,
                event * 60_000,
            );
            let decision = response
                .decision
                .expect("owner event must return a local decision");
            assert!(
                !decision
                    .reason_codes
                    .iter()
                    .any(|code| code.starts_with("conversation.contact.")),
                "owner event {event} was profiled as an external contact: {:?}",
                decision.reason_codes
            );
        }
        aura_free(handle);
    }
}

#[test]
fn terminal_host_checkpoint_compacts_non_observation_receipts_idempotently() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let message = proto_message(
            "ordinary clean message",
            "sender",
            "checkpoint-conversation",
        );
        let first = analyze_local_decision(handle, message.clone(), "checkpoint-event", 1, 1_000);
        assert!(first.decision.is_some());
        assert_eq!(
            with_instance(handle, |instance| Ok(instance
                .analyzer
                .safety_cases()
                .source_receipt_count()))
            .expect("receipt count"),
            1
        );

        acknowledge_source_checkpoint(
            handle,
            "checkpoint-conversation",
            "checkpoint-event",
            1,
            1_000,
        );
        acknowledge_source_checkpoint(
            handle,
            "checkpoint-conversation",
            "checkpoint-event",
            1,
            1_000,
        );
        assert_eq!(
            with_instance(handle, |instance| Ok(instance
                .analyzer
                .safety_cases()
                .source_receipt_count()))
            .expect("receipt count"),
            0
        );

        let transferred = analyze_local_decision(handle, message, "checkpoint-event", 1, 1_000);
        assert!(
            transferred.decision.is_some(),
            "after a terminal host checkpoint, native replay responsibility is intentionally released"
        );
        aura_free(handle);
    }
}

#[test]
fn terminal_host_checkpoint_retains_receipts_that_cover_case_observations() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let message = proto_message(
            "don't tell your parents, it's our secret",
            "sender",
            "observed-conversation",
        );
        let first = analyze_local_decision(handle, message.clone(), "observed-event", 1, 1_000);
        assert!(first.case_id.is_some(), "fixture must reduce into a case");

        acknowledge_source_checkpoint(handle, "observed-conversation", "observed-event", 1, 1_000);
        assert_eq!(
            with_instance(handle, |instance| Ok(instance
                .analyzer
                .safety_cases()
                .source_receipt_count()))
            .expect("receipt count"),
            1
        );
        let duplicate = analyze_local_decision(handle, message, "observed-event", 1, 1_000);
        assert!(duplicate.decision.is_none());
        assert!(matches!(
            proto::CanonicalSafetyDisposition::try_from(duplicate.disposition).unwrap(),
            proto::CanonicalSafetyDisposition::DuplicateApplied
        ));
        aura_free(handle);
    }
}

#[test]
fn source_checkpoint_rejects_a_different_account_without_mutation() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let first = analyze_local_decision(
            handle,
            proto_message(
                "ordinary clean message",
                "sender",
                "account-bound-conversation",
            ),
            "account-bound-event",
            1,
            1_000,
        );
        assert!(first.decision.is_some());

        let request = proto::CanonicalSafetyEventIdentity {
            account_key: "different-account".to_string(),
            subject_key: "subject".to_string(),
            conversation_key: "account-bound-conversation".to_string(),
            event_id: "account-bound-event".to_string(),
            revision: 1,
            occurred_at_ms: 1_000,
            observed_at_ms: 1_000,
        };
        let bytes = encode_proto(&request);
        assert!(!aura_acknowledge_source_checkpoint(
            handle,
            bytes.as_ptr(),
            bytes.len()
        ));
        let error = last_error_string();
        assert!(error.contains("execution policy"), "{error}");
        assert_eq!(
            with_instance(handle, |instance| Ok(instance
                .analyzer
                .safety_cases()
                .source_receipt_count()))
            .expect("receipt count"),
            1
        );
        aura_free(handle);
    }
}

#[test]
fn malformed_source_checkpoint_is_rejected_without_mutation() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let request = proto::CanonicalSafetyEventIdentity {
            account_key: "account".to_string(),
            subject_key: "subject".to_string(),
            conversation_key: "conversation".to_string(),
            event_id: "event".to_string(),
            revision: 1,
            occurred_at_ms: 0,
            observed_at_ms: 0,
        };
        let bytes = encode_proto(&request);
        assert!(!aura_acknowledge_source_checkpoint(
            handle,
            bytes.as_ptr(),
            bytes.len()
        ));
        assert!(last_error_string().contains("timestamps must be nonzero"));
        assert_eq!(
            with_instance(handle, |instance| Ok(instance
                .analyzer
                .safety_cases()
                .source_receipt_count()))
            .expect("receipt count"),
            0
        );
        aura_free(handle);
    }
}

#[test]
fn invalid_local_decision_request_does_not_mutate_context() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let before = export_context(handle);
        let request = proto::LocalDecisionAnalyzeRequest {
            message: Some(proto_message("hello", "sender", "conversation")),
            identity: Some(proto::CanonicalSafetyEventIdentity {
                account_key: "account".to_string(),
                subject_key: "subject".to_string(),
                conversation_key: "different-conversation".to_string(),
                event_id: "invalid-event".to_string(),
                revision: 1,
                occurred_at_ms: 1_000,
                observed_at_ms: 1_000,
            }),
        };
        let bytes = encode_proto(&request);
        let mut out = AuraBuffer::empty();

        assert!(!aura_analyze_local_decision(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            &mut out,
        ));
        assert!(out.ptr.is_null());
        assert!(last_error_string()
            .contains("canonical conversation key does not match message conversation id"));
        assert_eq!(export_context(handle), before);

        aura_free(handle);
    }
}

#[test]
fn oversized_local_decision_request_is_rejected_before_mutation() {
    unsafe {
        let handle = init_canonical_handle(proto_config(proto::AccountType::Child, true));
        let before = export_context(handle);
        let request = oversized_request_bytes(MAX_LOCAL_DECISION_REQUEST_BYTES);
        let mut out = AuraBuffer::empty();

        assert!(!aura_analyze_local_decision(
            handle,
            request.as_ptr(),
            request.len(),
            &mut out,
        ));
        assert!(out.ptr.is_null());
        assert!(last_error_string().contains("local decision request exceeds"));
        assert_eq!(export_context(handle), before);

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

        let first_state = export_context(first)
            .state
            .expect("first runtime must export tracker state");
        let second_state = export_context(second)
            .state
            .expect("second runtime must export tracker state");
        assert_eq!(first_state.timelines, second_state.timelines);
        assert_eq!(first_state.contact_profiler, second_state.contact_profiler);
        assert_eq!(first_state.kids_memory, second_state.kids_memory);
        aura_free(first);
        aura_free(second);
    }
}

mod world_replay;
