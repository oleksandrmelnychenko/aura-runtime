use aura_proto::compat_fixtures::analysis_result_fixture;
use aura_proto::messenger::v1 as proto;
use prost::Message;

#[test]
fn analysis_result_round_trip() {
    let original = analysis_result_fixture();
    let bytes = original.encode_to_vec();
    let decoded = proto::AnalysisResult::decode(bytes.as_slice()).expect("decode round-trip");
    assert_eq!(decoded, original);
    assert_eq!(decoded.threat_type, proto::ThreatType::Grooming as i32);
    assert_eq!(decoded.confidence, proto::Confidence::High as i32);
    assert_eq!(decoded.action, proto::Action::Block as i32);
    assert!((decoded.score - 0.91).abs() < f32::EPSILON);
    assert_eq!(decoded.detected_threats.len(), 2);
    assert_eq!(decoded.signals.len(), 1);
    assert!(decoded.recommended_action.is_some());
    assert!(decoded.risk_breakdown.is_some());
    assert!(decoded.contact_snapshot.is_some());
    assert_eq!(decoded.reason_codes.len(), 2);
    assert!(decoded.inference.is_some());
    assert!(decoded.product_surface.is_some());
}

#[test]
fn analysis_result_unknown_fields_forward_compat() {
    let original = analysis_result_fixture();
    let mut bytes = original.encode_to_vec();

    // Append an unknown field (field 200, varint type, value 42).
    // Wire type 0 (varint), field number 200 -> tag = (200 << 3) | 0 = 1600.
    // 1600 in varint encoding: 0xC0 0x0C
    bytes.push(0xC0);
    bytes.push(0x0C);
    bytes.push(42);

    let decoded =
        proto::AnalysisResult::decode(bytes.as_slice()).expect("decode with unknown fields");
    assert_eq!(decoded.threat_type, original.threat_type);
    assert_eq!(decoded.action, original.action);
    assert!((decoded.score - original.score).abs() < f32::EPSILON);
    assert_eq!(decoded.explanation, original.explanation);
    assert_eq!(
        decoded.detected_threats.len(),
        original.detected_threats.len()
    );
}

#[test]
fn analysis_result_default_values() {
    let empty_bytes: &[u8] = &[];
    let decoded = proto::AnalysisResult::decode(empty_bytes).expect("decode empty message");
    assert_eq!(decoded.threat_type, 0);
    assert_eq!(decoded.confidence, 0);
    assert_eq!(decoded.action, 0);
    assert!((decoded.score - 0.0).abs() < f32::EPSILON);
    assert_eq!(decoded.explanation, "");
    assert!(decoded.detected_threats.is_empty());
    assert!(decoded.signals.is_empty());
    assert!(decoded.recommended_action.is_none());
    assert!(decoded.risk_breakdown.is_none());
    assert!(decoded.contact_snapshot.is_none());
    assert!(decoded.reason_codes.is_empty());
    assert_eq!(decoded.analysis_time_us, 0);
    assert!(decoded.inference.is_none());
    assert!(decoded.product_surface.is_none());
    assert!(decoded.kids_memory.is_none());
}

#[test]
fn kids_memory_explainability_round_trip() {
    let original = proto::KidsMemoryExplainability {
        reason_codes: vec![
            "grooming.stage_sequence".to_string(),
            "kids.memory.sender_risk".to_string(),
        ],
        mandatory_guardian_escalation: true,
        conversation_risk_score: 0.87,
        sender_risk_score: 0.72,
        escalation_message_count: 5,
    };

    let bytes = original.encode_to_vec();
    let decoded =
        proto::KidsMemoryExplainability::decode(bytes.as_slice()).expect("decode kids memory");
    assert_eq!(decoded, original);
    assert_eq!(decoded.reason_codes.len(), 2);
    assert_eq!(decoded.reason_codes[0], "grooming.stage_sequence");
    assert_eq!(decoded.reason_codes[1], "kids.memory.sender_risk");
    assert!(decoded.mandatory_guardian_escalation);
    assert!((decoded.conversation_risk_score - 0.87).abs() < f32::EPSILON);
    assert!((decoded.sender_risk_score - 0.72).abs() < f32::EPSILON);
    assert_eq!(decoded.escalation_message_count, 5);
}

#[test]
fn kids_memory_explainability_defaults() {
    let empty_bytes: &[u8] = &[];
    let decoded =
        proto::KidsMemoryExplainability::decode(empty_bytes).expect("decode empty kids memory");
    assert!(decoded.reason_codes.is_empty());
    assert!(!decoded.mandatory_guardian_escalation);
    assert!((decoded.conversation_risk_score - 0.0).abs() < f32::EPSILON);
    assert!((decoded.sender_risk_score - 0.0).abs() < f32::EPSILON);
    assert_eq!(decoded.escalation_message_count, 0);
}

#[test]
fn analysis_result_with_kids_memory_round_trip() {
    let mut result = analysis_result_fixture();
    result.kids_memory = Some(proto::KidsMemoryExplainability {
        reason_codes: vec!["grooming.secrecy_request".to_string()],
        mandatory_guardian_escalation: true,
        conversation_risk_score: 0.91,
        sender_risk_score: 0.65,
        escalation_message_count: 3,
    });

    let bytes = result.encode_to_vec();
    let decoded = proto::AnalysisResult::decode(bytes.as_slice()).expect("decode with kids memory");
    assert!(decoded.kids_memory.is_some());
    let km = decoded.kids_memory.unwrap();
    assert_eq!(km.reason_codes, vec!["grooming.secrecy_request"]);
    assert!(km.mandatory_guardian_escalation);
    assert!((km.conversation_risk_score - 0.91).abs() < f32::EPSILON);
    assert!((km.sender_risk_score - 0.65).abs() < f32::EPSILON);
    assert_eq!(km.escalation_message_count, 3);
}

#[test]
fn guardian_feedback_request_trusted_round_trip() {
    let original = proto::GuardianFeedbackRequest {
        sender_id: "sender_abc".to_string(),
        conversation_id: "conv_xyz".to_string(),
        verdict: proto::GuardianVerdict::Trusted as i32,
    };
    let bytes = original.encode_to_vec();
    let decoded =
        proto::GuardianFeedbackRequest::decode(bytes.as_slice()).expect("decode guardian trusted");
    assert_eq!(decoded, original);
    assert_eq!(decoded.verdict, proto::GuardianVerdict::Trusted as i32);
}

#[test]
fn guardian_feedback_request_block_round_trip() {
    let original = proto::GuardianFeedbackRequest {
        sender_id: "sender_abc".to_string(),
        conversation_id: "conv_xyz".to_string(),
        verdict: proto::GuardianVerdict::Block as i32,
    };
    let bytes = original.encode_to_vec();
    let decoded =
        proto::GuardianFeedbackRequest::decode(bytes.as_slice()).expect("decode guardian block");
    assert_eq!(decoded, original);
    assert_eq!(decoded.verdict, proto::GuardianVerdict::Block as i32);
}

#[test]
fn guardian_feedback_request_monitor_round_trip() {
    let original = proto::GuardianFeedbackRequest {
        sender_id: "s1".to_string(),
        conversation_id: "c1".to_string(),
        verdict: proto::GuardianVerdict::Monitor as i32,
    };
    let bytes = original.encode_to_vec();
    let decoded =
        proto::GuardianFeedbackRequest::decode(bytes.as_slice()).expect("decode guardian monitor");
    assert_eq!(decoded, original);
    assert_eq!(decoded.verdict, proto::GuardianVerdict::Monitor as i32);
}

#[test]
fn guardian_feedback_request_false_positive_round_trip() {
    let original = proto::GuardianFeedbackRequest {
        sender_id: "s1".to_string(),
        conversation_id: "c1".to_string(),
        verdict: proto::GuardianVerdict::FalsePositive as i32,
    };
    let bytes = original.encode_to_vec();
    let decoded = proto::GuardianFeedbackRequest::decode(bytes.as_slice())
        .expect("decode guardian false positive");
    assert_eq!(decoded, original);
    assert_eq!(
        decoded.verdict,
        proto::GuardianVerdict::FalsePositive as i32
    );
}

#[test]
fn guardian_feedback_request_unspecified_round_trip() {
    let original = proto::GuardianFeedbackRequest {
        sender_id: "s1".to_string(),
        conversation_id: "c1".to_string(),
        verdict: proto::GuardianVerdict::Unspecified as i32,
    };
    let bytes = original.encode_to_vec();
    let decoded = proto::GuardianFeedbackRequest::decode(bytes.as_slice())
        .expect("decode guardian unspecified");
    assert_eq!(decoded, original);
}

#[test]
fn guardian_feedback_response_round_trip() {
    let original = proto::GuardianFeedbackResponse {
        ok: true,
        message: Some("action applied".to_string()),
    };
    let bytes = original.encode_to_vec();
    let decoded = proto::GuardianFeedbackResponse::decode(bytes.as_slice())
        .expect("decode guardian feedback response");
    assert_eq!(decoded, original);
    assert!(decoded.ok);
    assert_eq!(decoded.message.as_deref(), Some("action applied"));
}

#[test]
fn guardian_feedback_response_no_message_round_trip() {
    let original = proto::GuardianFeedbackResponse {
        ok: false,
        message: None,
    };
    let bytes = original.encode_to_vec();
    let decoded = proto::GuardianFeedbackResponse::decode(bytes.as_slice())
        .expect("decode guardian feedback response no msg");
    assert_eq!(decoded, original);
    assert!(!decoded.ok);
    assert!(decoded.message.is_none());
}

#[test]
fn tracker_state_with_kids_memory_round_trip() {
    let kids_memory = proto::KidsMemoryState {
        conversations: vec![proto::KidsConversationMemoryState {
            conversation_id: "conv_kids_1".to_string(),
            entries: vec![
                proto::KidsMessageRiskSnapshot {
                    sender_id: Some("sender_a".to_string()),
                    has_grooming: true,
                    has_manipulation: false,
                    has_bullying: false,
                    has_self_harm: false,
                    has_blackmail_or_sextortion: false,
                    ml_grooming: 0.85,
                    ml_bullying: 0.0,
                    ml_self_harm: 0.0,
                    ml_manipulation: 0.1,
                },
                proto::KidsMessageRiskSnapshot {
                    sender_id: Some("sender_a".to_string()),
                    has_grooming: true,
                    has_manipulation: true,
                    has_bullying: false,
                    has_self_harm: false,
                    has_blackmail_or_sextortion: true,
                    ml_grooming: 0.92,
                    ml_bullying: 0.0,
                    ml_self_harm: 0.05,
                    ml_manipulation: 0.78,
                },
            ],
            message_index: 2,
        }],
        senders: vec![proto::KidsSenderMemoryState {
            sender_id: "sender_a".to_string(),
            event_index: 4,
            recent_high_risk_conversations: vec![
                "conv_kids_1".to_string(),
                "conv_kids_2".to_string(),
            ],
        }],
    };

    let original = proto::TrackerState {
        schema_version: 2,
        timelines: vec![proto::ConversationTimelineState {
            conversation_id: "conv_kids_1".to_string(),
            conversation_type: proto::ConversationType::Direct as i32,
            events: vec![proto::ContextEvent {
                event_id: 1,
                timestamp_ms: 1_710_000_100_000,
                sender_id: "sender_a".to_string(),
                conversation_id: "conv_kids_1".to_string(),
                kind: proto::EventKind::Flattery as i32,
                confidence: 0.87,
                subtype: String::new(),
                content_hash: None,
            }],
        }],
        contact_profiler: Some(proto::ContactProfilerState {
            profiles: vec![proto::ContactProfileState {
                sender_id: "sender_a".to_string(),
                first_seen_ms: 1_710_000_000_000,
                last_seen_ms: 1_710_000_200_000,
                total_messages: 3,
                conversation_count: 1,
                conversations: vec!["conv_kids_1".to_string()],
                grooming_event_count: 2,
                bullying_event_count: 0,
                manipulation_event_count: 1,
                is_trusted: false,
                severity_sum: 1.8,
                severity_count: 2,
                inferred_age: Some(28),
                rating: 0.15,
                trust_level: 0.1,
                circle_tier: proto::CircleTier::New as i32,
                trend: proto::BehavioralTrend::GradualWorsening as i32,
                weekly_snapshots: Vec::new(),
                current_snapshot: None,
                active_days: vec![1],
                propaganda_event_count: 0,
                propaganda_source_count: 0,
                narrative_hits: Vec::new(),
                propaganda_score: 0.0,
                narrative_diversity: 0,
                first_propaganda_ms: 0,
                last_propaganda_ms: 0,
                propaganda_conversations: Vec::new(),
                hourly_activity: vec![0; 24],
                message_fingerprints: Vec::new(),
                narrative_timeline: Vec::new(),
                weekly_propaganda_counts: Vec::new(),
                age_source: proto::AgeSource::UserReported as i32,
            }],
        }),
        kids_memory: Some(kids_memory),
    };

    let bytes = original.encode_to_vec();
    let decoded =
        proto::TrackerState::decode(bytes.as_slice()).expect("decode tracker state with kids");
    assert_eq!(decoded, original);

    let km = decoded.kids_memory.unwrap();
    assert_eq!(km.conversations.len(), 1);
    assert_eq!(km.conversations[0].conversation_id, "conv_kids_1");
    assert_eq!(km.conversations[0].entries.len(), 2);
    assert_eq!(km.conversations[0].message_index, 2);
    assert!(km.conversations[0].entries[0].has_grooming);
    assert!(!km.conversations[0].entries[0].has_manipulation);
    assert!(km.conversations[0].entries[1].has_blackmail_or_sextortion);
    assert!((km.conversations[0].entries[1].ml_grooming - 0.92).abs() < f32::EPSILON);

    assert_eq!(km.senders.len(), 1);
    assert_eq!(km.senders[0].sender_id, "sender_a");
    assert_eq!(km.senders[0].event_index, 4);
    assert_eq!(km.senders[0].recent_high_risk_conversations.len(), 2);
}

#[test]
fn tracker_state_empty_kids_memory_round_trip() {
    let original = proto::TrackerState {
        schema_version: 2,
        timelines: Vec::new(),
        contact_profiler: None,
        kids_memory: Some(proto::KidsMemoryState {
            conversations: Vec::new(),
            senders: Vec::new(),
        }),
    };
    let bytes = original.encode_to_vec();
    let decoded = proto::TrackerState::decode(bytes.as_slice()).expect("decode empty kids memory");
    assert_eq!(decoded, original);
    let km = decoded.kids_memory.unwrap();
    assert!(km.conversations.is_empty());
    assert!(km.senders.is_empty());
}

#[test]
fn kids_message_risk_snapshot_defaults() {
    let empty_bytes: &[u8] = &[];
    let decoded =
        proto::KidsMessageRiskSnapshot::decode(empty_bytes).expect("decode empty kids snapshot");
    assert!(decoded.sender_id.is_none());
    assert!(!decoded.has_grooming);
    assert!(!decoded.has_manipulation);
    assert!(!decoded.has_bullying);
    assert!(!decoded.has_self_harm);
    assert!(!decoded.has_blackmail_or_sextortion);
    assert!((decoded.ml_grooming - 0.0).abs() < f32::EPSILON);
}
