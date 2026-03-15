use crate::messenger::v1 as proto;

pub fn analysis_result_fixture() -> proto::AnalysisResult {
    proto::AnalysisResult {
        threat_type: proto::ThreatType::Grooming as i32,
        confidence: proto::Confidence::High as i32,
        action: proto::Action::Block as i32,
        score: 0.91,
        explanation: "adult asks for secrecy after repeated flattery".to_string(),
        detected_threats: vec![
            proto::ThreatScore {
                threat_type: proto::ThreatType::Grooming as i32,
                score: 0.91,
            },
            proto::ThreatScore {
                threat_type: proto::ThreatType::Manipulation as i32,
                score: 0.42,
            },
        ],
        signals: vec![proto::DetectionSignal {
            threat_type: proto::ThreatType::Grooming as i32,
            score: 0.95,
            confidence: proto::Confidence::High as i32,
            layer: proto::DetectionLayer::ContextAnalysis as i32,
            family: proto::SignalFamily::Conversation as i32,
            reason_code: "grooming.secrecy_request".to_string(),
            explanation: "secrecy request after trust-building".to_string(),
        }],
        recommended_action: Some(proto::ActionRecommendation {
            parent_alert: proto::AlertPriority::High as i32,
            follow_ups: vec![
                proto::FollowUpAction::BlockSuggested as i32,
                proto::FollowUpAction::ReviewContactProfile as i32,
            ],
            crisis_resources: false,
            ui_actions: vec![
                proto::UiAction::WarnBeforeDisplay as i32,
                proto::UiAction::SuggestBlockContact as i32,
                proto::UiAction::SuggestReport as i32,
            ],
            reason_codes: vec![
                "grooming.secrecy_request".to_string(),
                "contact.trust_low".to_string(),
            ],
        }),
        risk_breakdown: Some(proto::RiskBreakdown {
            content: 0.22,
            conversation: 0.91,
            link: 0.0,
            abuse: 0.78,
        }),
        contact_snapshot: Some(proto::ContactSnapshot {
            sender_id: "mentor_42".to_string(),
            rating: 0.11,
            trust_level: 0.08,
            circle_tier: proto::CircleTier::New as i32,
            trend: proto::BehavioralTrend::RapidWorsening as i32,
            is_trusted: false,
            is_new_contact: true,
            first_seen_ms: 1_710_000_000_000,
            last_seen_ms: 1_710_003_600_000,
            conversation_count: 3,
        }),
        reason_codes: vec![
            "grooming.secrecy_request".to_string(),
            "conversation.escalation".to_string(),
        ],
        analysis_time_us: 1_842,
    }
}

pub fn tracker_state_fixture() -> proto::TrackerState {
    let weekly_snapshot = proto::BehavioralSnapshotState {
        period_start_ms: 1_710_000_000_000,
        period_end_ms: 1_710_086_400_000,
        total_messages: 12,
        hostile_count: 0,
        supportive_count: 1,
        neutral_count: 4,
        grooming_count: 5,
        manipulation_count: 2,
        avg_severity: 0.88,
    };
    let current_snapshot = proto::BehavioralSnapshotState {
        period_start_ms: 1_710_003_600_000,
        period_end_ms: 1_710_007_200_000,
        total_messages: 5,
        hostile_count: 0,
        supportive_count: 0,
        neutral_count: 1,
        grooming_count: 3,
        manipulation_count: 1,
        avg_severity: 0.91,
    };

    proto::TrackerState {
        schema_version: 2,
        timelines: vec![proto::ConversationTimelineState {
            conversation_id: "conv_fixture_1".to_string(),
            conversation_type: proto::ConversationType::Direct as i32,
            events: vec![
                proto::ContextEvent {
                    event_id: 1,
                    timestamp_ms: 1_710_000_100_000,
                    sender_id: "mentor_42".to_string(),
                    conversation_id: "conv_fixture_1".to_string(),
                    kind: proto::EventKind::Flattery as i32,
                    confidence: 0.87,
                },
                proto::ContextEvent {
                    event_id: 2,
                    timestamp_ms: 1_710_000_200_000,
                    sender_id: "mentor_42".to_string(),
                    conversation_id: "conv_fixture_1".to_string(),
                    kind: proto::EventKind::SecrecyRequest as i32,
                    confidence: 0.96,
                },
            ],
        }],
        contact_profiler: Some(proto::ContactProfilerState {
            profiles: vec![proto::ContactProfileState {
                sender_id: "mentor_42".to_string(),
                first_seen_ms: 1_710_000_000_000,
                last_seen_ms: 1_710_000_200_000,
                total_messages: 5,
                conversation_count: 1,
                conversations: vec!["conv_fixture_1".to_string()],
                grooming_event_count: 3,
                bullying_event_count: 0,
                manipulation_event_count: 1,
                is_trusted: false,
                severity_sum: 2.65,
                severity_count: 3,
                inferred_age: Some(35),
                rating: 0.11,
                trust_level: 0.08,
                circle_tier: proto::CircleTier::New as i32,
                trend: proto::BehavioralTrend::RapidWorsening as i32,
                weekly_snapshots: vec![weekly_snapshot.clone()],
                current_snapshot: Some(current_snapshot),
                active_days: vec![1, 2, 4],
            }],
        }),
    }
}

pub fn batch_analyze_response_fixture() -> proto::BatchAnalyzeResponse {
    proto::BatchAnalyzeResponse {
        results: vec![
            proto::AnalysisResult {
                threat_type: proto::ThreatType::None as i32,
                confidence: proto::Confidence::Low as i32,
                action: proto::Action::Allow as i32,
                score: 0.02,
                explanation: "benign coordination".to_string(),
                detected_threats: Vec::new(),
                signals: Vec::new(),
                recommended_action: Some(proto::ActionRecommendation {
                    parent_alert: proto::AlertPriority::None as i32,
                    follow_ups: Vec::new(),
                    crisis_resources: false,
                    ui_actions: Vec::new(),
                    reason_codes: vec!["policy.allow".to_string()],
                }),
                risk_breakdown: Some(proto::RiskBreakdown {
                    content: 0.01,
                    conversation: 0.02,
                    link: 0.0,
                    abuse: 0.0,
                }),
                contact_snapshot: None,
                reason_codes: vec!["policy.allow".to_string()],
                analysis_time_us: 512,
            },
            analysis_result_fixture(),
        ],
    }
}
