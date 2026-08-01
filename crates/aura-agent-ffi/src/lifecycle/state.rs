use super::*;

pub(super) fn load_pattern_db(config: &AuraConfig) -> PatternDatabase {
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

pub(super) fn try_load_pattern_db(path: &str) -> Result<PatternDatabase, String> {
    PatternDatabase::from_file(path).map_err(|error| error.to_string())
}

pub(super) fn aura_config_from_proto(config: proto::AuraConfig) -> Result<AuraConfig, String> {
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

pub(super) fn decoded_config_from_proto(
    config: proto::AuraConfig,
) -> Result<DecodedConfig, String> {
    Ok(DecodedConfig {
        aura_config: aura_config_from_proto(config)?,
    })
}

pub(super) fn message_input_from_proto(message: proto::MessageInput) -> MessageInput {
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

pub(super) fn non_empty_or(value: String, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value
    }
}

pub(super) fn tracker_state_to_proto(
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

pub(super) struct ImportTrackerState {
    pub(super) core_state: CoreTrackerWireState,
    pub(super) kids_state: Option<aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState>,
}

pub(super) fn tracker_state_from_proto(
    state: proto::TrackerState,
) -> Result<ImportTrackerState, String> {
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

pub(super) fn kids_memory_state_to_proto(
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
                guardian_blocked: sender.guardian_blocked,
            })
            .collect(),
    }
}

pub(super) fn kids_memory_state_from_proto(
    state: &proto::KidsMemoryState,
) -> Result<aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState, String> {
    use aura_agent_core::aura_kids::pipeline::{
        is_supported_kids_memory_state_version, ExportedConversationMemory,
        ExportedEmissionCheckpoint, ExportedKidsMemoryState, ExportedMessageSnapshot,
        ExportedSenderMemory, KIDS_MEMORY_STATE_VERSION,
    };

    if !is_supported_kids_memory_state_version(state.schema_version) {
        return Err(format!(
            "incompatible kids memory state version: found {}, supported {}",
            state.schema_version, KIDS_MEMORY_STATE_VERSION
        ));
    }

    Ok(ExportedKidsMemoryState {
        // Preserve the source version so the kids runtime can apply its
        // version-specific migration before normalizing on the next export.
        schema_version: state.schema_version,
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
                    guardian_blocked: sender.guardian_blocked,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

pub(super) fn conversation_timeline_state_to_proto(
    state: &CoreConversationTimelineState,
) -> proto::ConversationTimelineState {
    proto::ConversationTimelineState {
        conversation_id: state.conversation_id.to_string(),
        conversation_type: proto_conversation_type(state.conversation_type) as i32,
        events: state.events.iter().map(context_event_to_proto).collect(),
    }
}

pub(super) fn conversation_timeline_state_from_proto(
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

pub(super) fn context_event_to_proto(event: &CoreContextEvent) -> proto::ContextEvent {
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

pub(super) fn context_event_from_proto(
    event: proto::ContextEvent,
) -> Result<CoreContextEvent, String> {
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

pub(super) fn contact_profiler_state_to_proto(
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

pub(super) fn contact_profiler_state_from_proto(
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

pub(super) fn contact_profile_state_to_proto(
    state: &CoreContactProfileState,
) -> proto::ContactProfileState {
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

pub(super) fn contact_profile_state_from_proto(
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

pub(super) fn child_safety_trajectory_to_proto(
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

pub(super) fn child_safety_trajectory_from_proto(
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

pub(super) fn behavioral_snapshot_state_to_proto(
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

pub(super) fn behavioral_snapshot_state_from_proto(
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

pub(super) fn protection_level_from_proto(
    value: i32,
) -> Result<aura_agent_core::ProtectionLevel, String> {
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

pub(super) fn account_type_from_proto(value: i32) -> Result<aura_agent_core::AccountType, String> {
    match proto::AccountType::try_from(value) {
        Ok(proto::AccountType::Adult) => Ok(aura_agent_core::AccountType::Adult),
        Ok(proto::AccountType::Teen) => Ok(aura_agent_core::AccountType::Teen),
        Ok(proto::AccountType::Child) => Ok(aura_agent_core::AccountType::Child),
        Ok(proto::AccountType::Unspecified) => Err("account_type must be explicit".to_string()),
        Err(_) => Err(format!("unsupported account_type value {value}")),
    }
}

pub(super) fn domain_mode_from_proto(value: i32) -> Result<aura_agent_core::DomainMode, String> {
    match proto::DomainMode::try_from(value) {
        Ok(proto::DomainMode::None) => Ok(aura_agent_core::DomainMode::None),
        Ok(proto::DomainMode::Kids) => Ok(aura_agent_core::DomainMode::Kids),
        Ok(proto::DomainMode::Military) => Ok(aura_agent_core::DomainMode::Military),
        Ok(proto::DomainMode::Unspecified) => Err("domain_mode must be explicit".to_string()),
        Err(_) => Err(format!("unsupported domain_mode value {value}")),
    }
}

pub(super) fn cultural_context_from_proto(
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

pub(super) fn content_type_from_proto(value: i32) -> aura_agent_core::ContentType {
    match proto::ContentType::try_from(value).unwrap_or(proto::ContentType::Text) {
        proto::ContentType::Image => aura_agent_core::ContentType::Image,
        proto::ContentType::Voice => aura_agent_core::ContentType::Voice,
        proto::ContentType::Video => aura_agent_core::ContentType::Video,
        proto::ContentType::Url => aura_agent_core::ContentType::Url,
        _ => aura_agent_core::ContentType::Text,
    }
}

pub(super) fn conversation_type_from_proto(value: i32) -> aura_agent_core::ConversationType {
    match proto::ConversationType::try_from(value).unwrap_or(proto::ConversationType::Direct) {
        proto::ConversationType::Group => aura_agent_core::ConversationType::Group,
        _ => aura_agent_core::ConversationType::Direct,
    }
}

pub(super) fn proto_conversation_type(
    value: aura_agent_core::ConversationType,
) -> proto::ConversationType {
    match value {
        aura_agent_core::ConversationType::Direct => proto::ConversationType::Direct,
        aura_agent_core::ConversationType::Group => proto::ConversationType::Group,
    }
}

pub(super) fn sender_relationship_from_proto(value: i32) -> SenderRelationship {
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

pub(super) fn relationship_trust_source_from_proto(value: i32) -> RelationshipTrustSource {
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

pub(super) fn product_rollout_mode_from_proto(
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

pub(super) fn circle_tier_from_proto(value: i32) -> aura_agent_core::CircleTier {
    match proto::CircleTier::try_from(value).unwrap_or(proto::CircleTier::New) {
        proto::CircleTier::Inner => aura_agent_core::CircleTier::Inner,
        proto::CircleTier::Regular => aura_agent_core::CircleTier::Regular,
        proto::CircleTier::Occasional => aura_agent_core::CircleTier::Occasional,
        _ => aura_agent_core::CircleTier::New,
    }
}

pub(super) fn proto_circle_tier(value: aura_agent_core::CircleTier) -> proto::CircleTier {
    match value {
        aura_agent_core::CircleTier::Inner => proto::CircleTier::Inner,
        aura_agent_core::CircleTier::Regular => proto::CircleTier::Regular,
        aura_agent_core::CircleTier::Occasional => proto::CircleTier::Occasional,
        aura_agent_core::CircleTier::New => proto::CircleTier::New,
    }
}

pub(super) fn behavioral_trend_from_proto(value: i32) -> aura_agent_core::BehavioralTrend {
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

pub(super) fn proto_behavioral_trend(
    value: aura_agent_core::BehavioralTrend,
) -> proto::BehavioralTrend {
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

pub(super) fn age_source_from_proto(value: i32) -> CoreAgeSource {
    match proto::AgeSource::try_from(value).unwrap_or(proto::AgeSource::UserReported) {
        proto::AgeSource::ParentVerified => CoreAgeSource::ParentVerified,
        proto::AgeSource::MlInferred => CoreAgeSource::MlInferred,
        _ => CoreAgeSource::UserReported,
    }
}

pub(super) fn proto_age_source(value: CoreAgeSource) -> proto::AgeSource {
    match value {
        CoreAgeSource::ParentVerified => proto::AgeSource::ParentVerified,
        CoreAgeSource::UserReported => proto::AgeSource::UserReported,
        CoreAgeSource::MlInferred => proto::AgeSource::MlInferred,
    }
}

pub(super) fn event_kind_from_proto(value: i32) -> Result<CoreEventKind, String> {
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

pub(super) fn proto_event_kind(value: CoreEventKind) -> proto::EventKind {
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
