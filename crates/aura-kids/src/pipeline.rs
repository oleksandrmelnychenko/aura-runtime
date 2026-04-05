use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use aura_domain::{
    promote_action_to_warn, DomainAction, DomainConversationType, DomainInput, DomainOutput,
    DomainRiskProfile, DomainSignal,
};

use crate::detectors::{bullying, grooming, manipulation, selfharm};
use crate::lexicon;
use crate::policy::{guardian, intervention};

pub fn run_kids_pipeline(input: &DomainInput) -> DomainOutput {
    let mut signals: Vec<DomainSignal> = Vec::new();

    signals.extend(grooming::detect_all(input));
    signals.extend(bullying::detect_all(input));
    signals.extend(selfharm::detect_all(input));
    signals.extend(manipulation::detect_all(input));

    apply_kids_risk_amplifiers(&mut signals);
    apply_kids_conversation_memory_amplifiers(input, &mut signals);
    signals.sort_by(|left, right| {
        let left_priority = left.priority.unwrap_or(0);
        let right_priority = right.priority.unwrap_or(0);
        right_priority.cmp(&left_priority)
    });

    let guardian_escalation = guardian::needs_guardian_escalation_with_priority(
        &signals,
        lexicon::guardian_escalation_priority(),
    );
    let mut action = intervention::decide_with_thresholds(&signals, lexicon::policy_thresholds());
    for signal in &signals {
        let Some(signal_action) = signal.action else {
            continue;
        };
        action = match (action, signal_action) {
            (Some(current), incoming) if action_rank(incoming) > action_rank(current) => {
                Some(incoming)
            }
            (Some(current), _) => Some(current),
            (None, incoming) => Some(incoming),
        };
    }
    if guardian_escalation {
        action = promote_action_to_warn(action);
    }

    DomainOutput { signals, action }
}

#[derive(Clone, Copy, Default)]
struct MessageRiskSnapshot {
    has_grooming: bool,
    has_manipulation: bool,
    has_bullying: bool,
    has_self_harm: bool,
    has_blackmail_or_sextortion: bool,
    /// ML safety scores for this message (0.0 if ML was not available).
    ml_grooming: f32,
    ml_bullying: f32,
    ml_self_harm: f32,
    ml_manipulation: f32,
}

#[derive(Default)]
struct ConversationRiskMemory {
    entries: VecDeque<(Option<String>, MessageRiskSnapshot)>,
    message_index: u64,
    last_emitted: HashMap<&'static str, u64>,
    /// Monotonic counter updated on every message — used for LRU eviction.
    last_activity_index: u64,
}

struct KidsProfileSettings {
    memory_window_messages: usize,
    cooldown_messages: u64,
    grooming_progression_min: usize,
    sustained_sextortion_min: usize,
    bullying_cascade_min: usize,
    sender_risk_min: f32,
    new_sender_message_max: usize,
    sender_risk_new_sender_delta: f32,
    sender_risk_known_sender_delta: f32,
    cross_conversation_repeat_min: usize,
    victim_targeting_sender_risk_min: f32,
}

const MAX_TRACKED_CONVERSATIONS: usize = 2000;
const MAX_TRACKED_SENDERS: usize = 4000;
const SENDER_RISK_CONVERSATION_WINDOW: usize = 12;

/// Global monotonic counter for LRU eviction ordering across all conversations/senders.
static GLOBAL_ACTIVITY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_global_activity() -> u64 {
    GLOBAL_ACTIVITY_COUNTER.fetch_add(1, Ordering::Relaxed) + 1
}

static KIDS_CONVERSATION_MEMORY: OnceLock<Mutex<HashMap<String, ConversationRiskMemory>>> =
    OnceLock::new();
static KIDS_SENDER_MEMORY: OnceLock<Mutex<HashMap<String, SenderRiskMemory>>> = OnceLock::new();

fn conversation_memory() -> &'static Mutex<HashMap<String, ConversationRiskMemory>> {
    KIDS_CONVERSATION_MEMORY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Default)]
struct SenderRiskMemory {
    event_index: u64,
    recent_high_risk_conversations: VecDeque<String>,
    /// Monotonic counter updated on every event — used for LRU eviction.
    last_activity_index: u64,
    last_emitted: HashMap<&'static str, u64>,
}

fn sender_memory() -> &'static Mutex<HashMap<String, SenderRiskMemory>> {
    KIDS_SENDER_MEMORY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn apply_kids_risk_amplifiers(signals: &mut Vec<DomainSignal>) {
    let has_grooming = has_threat_type(signals, "grooming");
    let has_bullying = has_threat_type(signals, "bullying");
    let has_self_harm = has_threat_type(signals, "self_harm");
    let has_manipulation = has_threat_type(signals, "manipulation");
    let has_suicide_coercion = has_reason_fragment(signals, "suicide_coercion");
    let has_blackmail =
        has_reason_fragment(signals, "blackmail") || has_reason_fragment(signals, "sextortion");

    if has_self_harm && has_manipulation && has_suicide_coercion {
        signals.push(DomainSignal {
            threat_key: "kids_compound_selfharm_coercion".to_string(),
            reason_code: "kids.selfharm.coercion_compound".to_string(),
            score: 0.98,
            threat_type: Some("self_harm".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(aura_domain::DomainAction::Warn),
        });
    }

    if has_grooming && has_manipulation {
        signals.push(DomainSignal {
            threat_key: "kids_compound_grooming_control".to_string(),
            reason_code: "kids.grooming.controlled_secrecy_compound".to_string(),
            score: 0.93,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }

    if has_grooming && has_blackmail {
        signals.push(DomainSignal {
            threat_key: "kids_compound_grooming_blackmail".to_string(),
            reason_code: "kids.grooming.blackmail_compound".to_string(),
            score: 0.97,
            threat_type: Some("grooming".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(aura_domain::DomainAction::Warn),
        });
    }

    if has_bullying && has_self_harm {
        signals.push(DomainSignal {
            threat_key: "kids_compound_bullying_selfharm".to_string(),
            reason_code: "kids.bullying.selfharm_compound".to_string(),
            score: 0.96,
            threat_type: Some("self_harm".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(99),
            action: Some(aura_domain::DomainAction::Warn),
        });
    }
}

fn apply_kids_conversation_memory_amplifiers(input: &DomainInput, signals: &mut Vec<DomainSignal>) {
    let Some(conversation_id) = input.conversation_id.as_deref() else {
        return;
    };

    let ml_hint = input.ml_safety_hint.unwrap_or_default();
    // ML scores above this threshold count as a detection for memory tracking,
    // even when no lexicon rule fired. This closes the evasion gap where
    // paraphrased/novel threats bypass the lexicon but the ML model catches them.
    const ML_MEMORY_THRESHOLD: f32 = 0.3;

    let current = MessageRiskSnapshot {
        has_grooming: has_threat_type(signals, "grooming")
            || ml_hint.grooming >= ML_MEMORY_THRESHOLD,
        has_manipulation: has_threat_type(signals, "manipulation")
            || ml_hint.manipulation >= ML_MEMORY_THRESHOLD,
        has_bullying: has_threat_type(signals, "bullying")
            || ml_hint.bullying >= ML_MEMORY_THRESHOLD,
        has_self_harm: has_threat_type(signals, "self_harm")
            || ml_hint.self_harm >= ML_MEMORY_THRESHOLD,
        has_blackmail_or_sextortion: has_reason_fragment(signals, "blackmail")
            || has_reason_fragment(signals, "sextortion"),
        ml_grooming: ml_hint.grooming,
        ml_bullying: ml_hint.bullying,
        ml_self_harm: ml_hint.self_harm,
        ml_manipulation: ml_hint.manipulation,
    };
    let sender = input.sender_id.clone();
    let sender_present = sender.is_some();
    let settings = profile_settings(input.risk_profile, input.conversation_type);

    let mut repeated_sender_grooming = 0usize;
    let mut repeated_sender_blackmail = 0usize;
    let mut sender_message_count = 0usize;
    let mut sender_risk_score = 0.0f32;
    let mut repeated_conversation_bullying = 0usize;
    let mut conversation_has_self_harm = false;
    let mut conversation_has_grooming = false;

    let Ok(mut guard) = conversation_memory().lock() else {
        return;
    };
    trim_conversation_memory_if_needed(&mut guard, conversation_id);
    let memory = guard
        .entry(conversation_id.to_string())
        .or_insert_with(ConversationRiskMemory::default);
    memory.message_index = memory.message_index.saturating_add(1);
    memory.last_activity_index = next_global_activity();
    let now_index = memory.message_index;
    memory.entries.push_back((sender.clone(), current));
    while memory.entries.len() > settings.memory_window_messages {
        memory.entries.pop_front();
    }

    for (entry_sender, snapshot) in &memory.entries {
        if sender_present && *entry_sender == sender {
            sender_message_count += 1;
            if snapshot.has_grooming {
                repeated_sender_grooming += 1;
                sender_risk_score += 1.0;
            }
            if snapshot.has_blackmail_or_sextortion {
                repeated_sender_blackmail += 1;
                sender_risk_score += 1.5;
            }
            if snapshot.has_manipulation {
                sender_risk_score += 0.8;
            }
            // ML sub-threshold contributions: accumulate risk from messages
            // where the ML model detected a signal above the memory threshold
            // but no lexicon rule fired. Prevents gradual escalation by
            // paraphrasing predators from flying under the radar.
            if snapshot.ml_grooming >= ML_MEMORY_THRESHOLD {
                sender_risk_score += snapshot.ml_grooming * 0.5;
            }
            if snapshot.ml_manipulation >= ML_MEMORY_THRESHOLD {
                sender_risk_score += snapshot.ml_manipulation * 0.3;
            }
        }
        if snapshot.has_bullying {
            repeated_conversation_bullying += 1;
        }
        if snapshot.has_self_harm {
            conversation_has_self_harm = true;
        }
        if snapshot.has_grooming {
            conversation_has_grooming = true;
        }
    }
    // Server reputation hint boosts sender risk score.
    if let Some(server_hint) = input.server_sender_risk_hint {
        sender_risk_score += server_hint * 2.0;
    }
    let sender_is_new = sender_present && sender_message_count <= settings.new_sender_message_max;
    let sender_risk_min = if sender_is_new {
        settings.sender_risk_min - settings.sender_risk_new_sender_delta
    } else {
        settings.sender_risk_min + settings.sender_risk_known_sender_delta
    };
    if sender_present
        && repeated_sender_grooming >= settings.grooming_progression_min
        && current.has_manipulation
        && should_emit_memory_signal(
            memory,
            "grooming_progression",
            now_index,
            settings.cooldown_messages,
        )
    {
        mark_memory_signal_emitted(memory, "grooming_progression", now_index);
        signals.push(DomainSignal {
            threat_key: "kids_memory_grooming_progression".to_string(),
            reason_code: "kids.memory.grooming_progression".to_string(),
            score: 0.96,
            threat_type: Some("grooming".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(DomainAction::Warn),
        });
    }

    if sender_present
        && repeated_sender_blackmail >= settings.sustained_sextortion_min
        && conversation_has_grooming
        && should_emit_memory_signal(
            memory,
            "sustained_sextortion",
            now_index,
            settings.cooldown_messages,
        )
    {
        mark_memory_signal_emitted(memory, "sustained_sextortion", now_index);
        signals.push(DomainSignal {
            threat_key: "kids_memory_sustained_sextortion".to_string(),
            reason_code: "kids.memory.sustained_sextortion".to_string(),
            score: 0.97,
            threat_type: Some("manipulation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(DomainAction::Warn),
        });
    }

    if repeated_conversation_bullying >= settings.bullying_cascade_min
        && conversation_has_self_harm
        && should_emit_memory_signal(
            memory,
            "bullying_cascade_selfharm",
            now_index,
            settings.cooldown_messages,
        )
    {
        mark_memory_signal_emitted(memory, "bullying_cascade_selfharm", now_index);
        signals.push(DomainSignal {
            threat_key: "kids_memory_bullying_cascade_selfharm".to_string(),
            reason_code: "kids.memory.bullying_cascade_selfharm".to_string(),
            score: 0.98,
            threat_type: Some("self_harm".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(DomainAction::Warn),
        });
    }

    if sender_present
        && sender_risk_score >= sender_risk_min
        && (current.has_grooming || current.has_manipulation || current.has_blackmail_or_sextortion)
        && should_emit_memory_signal(
            memory,
            "sender_risk_accumulation",
            now_index,
            settings.cooldown_messages,
        )
    {
        mark_memory_signal_emitted(memory, "sender_risk_accumulation", now_index);
        signals.push(DomainSignal {
            threat_key: "kids_memory_sender_risk_accumulation".to_string(),
            reason_code: "kids.memory.sender_risk_accumulation".to_string(),
            score: 0.95,
            threat_type: Some("manipulation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(99),
            action: Some(DomainAction::Warn),
        });
    }

    if sender_is_new
        && current.has_grooming
        && current.has_blackmail_or_sextortion
        && should_emit_memory_signal(
            memory,
            "new_sender_fast_escalation",
            now_index,
            settings.cooldown_messages,
        )
    {
        mark_memory_signal_emitted(memory, "new_sender_fast_escalation", now_index);
        signals.push(DomainSignal {
            threat_key: "kids_memory_new_sender_fast_escalation".to_string(),
            reason_code: "kids.memory.new_sender_fast_escalation".to_string(),
            score: 0.97,
            threat_type: Some("manipulation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(DomainAction::Warn),
        });
    }

    if sender_present
        && conversation_has_self_harm
        && (current.has_grooming || current.has_manipulation || current.has_blackmail_or_sextortion)
        && sender_risk_score >= settings.victim_targeting_sender_risk_min
        && should_emit_memory_signal(
            memory,
            "victim_vulnerability_targeting",
            now_index,
            settings.cooldown_messages,
        )
    {
        mark_memory_signal_emitted(memory, "victim_vulnerability_targeting", now_index);
        signals.push(DomainSignal {
            threat_key: "kids_memory_victim_vulnerability_targeting".to_string(),
            reason_code: "kids.memory.victim_vulnerability_targeting".to_string(),
            score: 0.98,
            threat_type: Some("self_harm".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(DomainAction::Warn),
        });
    }
    drop(guard);
    apply_cross_conversation_sender_amplifier(input, &settings, &current, signals);
}

fn clear_kids_memory_internal() {
    let Ok(mut guard) = conversation_memory().lock() else {
        return;
    };
    guard.clear();
    let Ok(mut guard) = sender_memory().lock() else {
        return;
    };
    guard.clear();
}

pub fn clear_kids_memory() {
    clear_kids_memory_internal();
}

#[cfg(test)]
fn clear_conversation_memory_for_tests() {
    clear_kids_memory_internal();
}

fn apply_cross_conversation_sender_amplifier(
    input: &DomainInput,
    settings: &KidsProfileSettings,
    current: &MessageRiskSnapshot,
    signals: &mut Vec<DomainSignal>,
) {
    let Some(sender_id) = input.sender_id.as_deref() else {
        return;
    };
    let Some(conversation_id) = input.conversation_id.as_deref() else {
        return;
    };

    let sender_has_high_risk = current.has_grooming
        || current.has_manipulation
        || current.has_blackmail_or_sextortion
        || (current.has_bullying && current.has_self_harm);
    if !sender_has_high_risk {
        return;
    }

    let Ok(mut guard) = sender_memory().lock() else {
        return;
    };
    trim_sender_memory_if_needed(&mut guard, sender_id);
    let memory = guard
        .entry(sender_id.to_string())
        .or_insert_with(SenderRiskMemory::default);
    memory.event_index = memory.event_index.saturating_add(1);
    memory.last_activity_index = next_global_activity();
    let now_index = memory.event_index;

    let mut existing_idx = None;
    for (idx, conv) in memory.recent_high_risk_conversations.iter().enumerate() {
        if conv == conversation_id {
            existing_idx = Some(idx);
            break;
        }
    }
    if let Some(idx) = existing_idx {
        memory.recent_high_risk_conversations.remove(idx);
    }
    memory
        .recent_high_risk_conversations
        .push_back(conversation_id.to_string());
    while memory.recent_high_risk_conversations.len() > SENDER_RISK_CONVERSATION_WINDOW {
        memory.recent_high_risk_conversations.pop_front();
    }

    let conversation_count = memory.recent_high_risk_conversations.len();
    if conversation_count >= settings.cross_conversation_repeat_min
        && should_emit_sender_memory_signal(
            memory,
            "cross_conversation_repeat_offender",
            now_index,
            settings.cooldown_messages,
        )
    {
        mark_sender_memory_signal_emitted(memory, "cross_conversation_repeat_offender", now_index);
        signals.push(DomainSignal {
            threat_key: "kids_memory_cross_conversation_repeat_offender".to_string(),
            reason_code: "kids.memory.cross_conversation_repeat_offender".to_string(),
            score: 0.96,
            threat_type: Some("manipulation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(DomainAction::Warn),
        });
    }
}

/// Evict the least-recently-active conversation (by `last_activity_index`),
/// excluding the current conversation. This ensures an in-progress grooming
/// conversation is never silently discarded.
fn trim_conversation_memory_if_needed(
    memory: &mut HashMap<String, ConversationRiskMemory>,
    current_conversation_id: &str,
) {
    while memory.len() >= MAX_TRACKED_CONVERSATIONS {
        let mut oldest_key: Option<String> = None;
        let mut oldest_activity = u64::MAX;
        for (key, mem) in memory.iter() {
            if key.as_str() == current_conversation_id {
                continue;
            }
            if mem.last_activity_index < oldest_activity {
                oldest_activity = mem.last_activity_index;
                oldest_key = Some(key.clone());
            }
        }
        let Some(candidate) = oldest_key else {
            break;
        };
        memory.remove(&candidate);
    }
}

/// Evict the least-recently-active sender (by `last_activity_index`),
/// excluding the current sender.
fn trim_sender_memory_if_needed(
    memory: &mut HashMap<String, SenderRiskMemory>,
    current_sender_id: &str,
) {
    while memory.len() >= MAX_TRACKED_SENDERS {
        let mut oldest_key: Option<String> = None;
        let mut oldest_activity = u64::MAX;
        for (key, mem) in memory.iter() {
            if key.as_str() == current_sender_id {
                continue;
            }
            if mem.last_activity_index < oldest_activity {
                oldest_activity = mem.last_activity_index;
                oldest_key = Some(key.clone());
            }
        }
        let Some(candidate) = oldest_key else {
            break;
        };
        memory.remove(&candidate);
    }
}

fn should_emit_memory_signal(
    memory: &ConversationRiskMemory,
    key: &'static str,
    now_index: u64,
    cooldown_messages: u64,
) -> bool {
    let Some(previous) = memory.last_emitted.get(key) else {
        return true;
    };
    now_index.saturating_sub(*previous) >= cooldown_messages
}

fn mark_memory_signal_emitted(
    memory: &mut ConversationRiskMemory,
    key: &'static str,
    now_index: u64,
) {
    memory.last_emitted.insert(key, now_index);
}

fn should_emit_sender_memory_signal(
    memory: &SenderRiskMemory,
    key: &'static str,
    now_index: u64,
    cooldown_messages: u64,
) -> bool {
    let Some(previous) = memory.last_emitted.get(key) else {
        return true;
    };
    now_index.saturating_sub(*previous) >= cooldown_messages
}

fn mark_sender_memory_signal_emitted(
    memory: &mut SenderRiskMemory,
    key: &'static str,
    now_index: u64,
) {
    memory.last_emitted.insert(key, now_index);
}

fn profile_settings(
    profile: DomainRiskProfile,
    conversation_type: DomainConversationType,
) -> KidsProfileSettings {
    match (profile, conversation_type) {
        (DomainRiskProfile::Strict, DomainConversationType::Direct) => KidsProfileSettings {
            memory_window_messages: 16,
            cooldown_messages: 2,
            grooming_progression_min: 1,
            sustained_sextortion_min: 2,
            bullying_cascade_min: 2,
            sender_risk_min: 2.8,
            new_sender_message_max: 2,
            sender_risk_new_sender_delta: 0.2,
            sender_risk_known_sender_delta: 0.2,
            cross_conversation_repeat_min: 2,
            victim_targeting_sender_risk_min: 1.5,
        },
        (DomainRiskProfile::Strict, DomainConversationType::Group) => KidsProfileSettings {
            memory_window_messages: 18,
            cooldown_messages: 2,
            grooming_progression_min: 2,
            sustained_sextortion_min: 2,
            bullying_cascade_min: 2,
            sender_risk_min: 2.6,
            new_sender_message_max: 2,
            sender_risk_new_sender_delta: 0.2,
            sender_risk_known_sender_delta: 0.2,
            cross_conversation_repeat_min: 2,
            victim_targeting_sender_risk_min: 1.2,
        },
        (DomainRiskProfile::Normal, DomainConversationType::Direct) => KidsProfileSettings {
            memory_window_messages: 12,
            cooldown_messages: 3,
            grooming_progression_min: 2,
            sustained_sextortion_min: 2,
            bullying_cascade_min: 3,
            sender_risk_min: 3.5,
            new_sender_message_max: 2,
            sender_risk_new_sender_delta: 0.2,
            sender_risk_known_sender_delta: 0.2,
            cross_conversation_repeat_min: 3,
            victim_targeting_sender_risk_min: 2.0,
        },
        (DomainRiskProfile::Normal, DomainConversationType::Group) => KidsProfileSettings {
            memory_window_messages: 14,
            cooldown_messages: 2,
            grooming_progression_min: 3,
            sustained_sextortion_min: 2,
            bullying_cascade_min: 2,
            sender_risk_min: 3.2,
            new_sender_message_max: 2,
            sender_risk_new_sender_delta: 0.2,
            sender_risk_known_sender_delta: 0.2,
            cross_conversation_repeat_min: 2,
            victim_targeting_sender_risk_min: 1.7,
        },
    }
}

fn has_threat_type(signals: &[DomainSignal], threat_type: &str) -> bool {
    for signal in signals {
        let Some(signal_threat_type) = signal.threat_type.as_deref() else {
            continue;
        };
        if signal_threat_type == threat_type {
            return true;
        }
    }
    false
}

fn has_reason_fragment(signals: &[DomainSignal], fragment: &str) -> bool {
    for signal in signals {
        if signal.reason_code.contains(fragment) {
            return true;
        }
    }
    false
}

fn action_rank(action: DomainAction) -> u8 {
    match action {
        DomainAction::Allow => 0,
        DomainAction::Mark => 1,
        DomainAction::Warn => 2,
        DomainAction::Block => 3,
    }
}

// ── Export / Import ────────────────────────────────────────────────────

/// Exported conversation memory entry for serialization.
#[derive(Debug, Clone)]
pub struct ExportedMessageSnapshot {
    pub sender_id: Option<String>,
    pub has_grooming: bool,
    pub has_manipulation: bool,
    pub has_bullying: bool,
    pub has_self_harm: bool,
    pub has_blackmail_or_sextortion: bool,
    pub ml_grooming: f32,
    pub ml_bullying: f32,
    pub ml_self_harm: f32,
    pub ml_manipulation: f32,
}

/// Exported per-conversation memory.
#[derive(Debug, Clone)]
pub struct ExportedConversationMemory {
    pub conversation_id: String,
    pub entries: Vec<ExportedMessageSnapshot>,
    pub message_index: u64,
    pub last_activity_index: u64,
}

/// Exported per-sender memory.
#[derive(Debug, Clone)]
pub struct ExportedSenderMemory {
    pub sender_id: String,
    pub event_index: u64,
    pub recent_high_risk_conversations: Vec<String>,
    pub last_activity_index: u64,
}

/// Full kids memory state for export.
#[derive(Debug, Clone, Default)]
pub struct ExportedKidsMemoryState {
    pub conversations: Vec<ExportedConversationMemory>,
    pub senders: Vec<ExportedSenderMemory>,
}

/// Export the current kids memory state for persistence/transfer.
pub fn export_kids_memory() -> ExportedKidsMemoryState {
    let mut state = ExportedKidsMemoryState::default();

    if let Ok(guard) = conversation_memory().lock() {
        for (conv_id, memory) in guard.iter() {
            let mut entries = Vec::with_capacity(memory.entries.len());
            for (sender, snap) in &memory.entries {
                entries.push(ExportedMessageSnapshot {
                    sender_id: sender.clone(),
                    has_grooming: snap.has_grooming,
                    has_manipulation: snap.has_manipulation,
                    has_bullying: snap.has_bullying,
                    has_self_harm: snap.has_self_harm,
                    has_blackmail_or_sextortion: snap.has_blackmail_or_sextortion,
                    ml_grooming: snap.ml_grooming,
                    ml_bullying: snap.ml_bullying,
                    ml_self_harm: snap.ml_self_harm,
                    ml_manipulation: snap.ml_manipulation,
                });
            }
            state.conversations.push(ExportedConversationMemory {
                conversation_id: conv_id.clone(),
                entries,
                message_index: memory.message_index,
                last_activity_index: memory.last_activity_index,
            });
        }
    }

    if let Ok(guard) = sender_memory().lock() {
        for (sender_id, memory) in guard.iter() {
            state.senders.push(ExportedSenderMemory {
                sender_id: sender_id.clone(),
                event_index: memory.event_index,
                recent_high_risk_conversations: memory
                    .recent_high_risk_conversations
                    .iter()
                    .cloned()
                    .collect(),
                last_activity_index: memory.last_activity_index,
            });
        }
    }

    state
}

/// Import kids memory state (replaces current in-process state).
pub fn import_kids_memory(state: &ExportedKidsMemoryState) {
    if let Ok(mut guard) = conversation_memory().lock() {
        guard.clear();
        for conv in &state.conversations {
            let mut entries = VecDeque::with_capacity(conv.entries.len());
            for snap in &conv.entries {
                entries.push_back((
                    snap.sender_id.clone(),
                    MessageRiskSnapshot {
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
                ));
            }
            guard.insert(
                conv.conversation_id.clone(),
                ConversationRiskMemory {
                    entries,
                    message_index: conv.message_index,
                    last_emitted: HashMap::new(),
                    last_activity_index: conv.last_activity_index,
                },
            );
        }
    }

    if let Ok(mut guard) = sender_memory().lock() {
        guard.clear();
        for sender in &state.senders {
            guard.insert(
                sender.sender_id.clone(),
                SenderRiskMemory {
                    event_index: sender.event_index,
                    recent_high_risk_conversations: sender
                        .recent_high_risk_conversations
                        .iter()
                        .cloned()
                        .collect(),
                    last_activity_index: sender.last_activity_index,
                    last_emitted: HashMap::new(),
                },
            );
        }
    }
}

/// Query the current conversation risk score for a given conversation.
pub fn conversation_risk_score(conversation_id: &str) -> f32 {
    let Ok(guard) = conversation_memory().lock() else {
        return 0.0;
    };
    let Some(memory) = guard.get(conversation_id) else {
        return 0.0;
    };
    let mut score = 0.0f32;
    for (_sender, snap) in &memory.entries {
        if snap.has_grooming {
            score += 1.0;
        }
        if snap.has_manipulation {
            score += 0.8;
        }
        if snap.has_bullying {
            score += 0.5;
        }
        if snap.has_self_harm {
            score += 0.7;
        }
        if snap.has_blackmail_or_sextortion {
            score += 1.5;
        }
        score += snap.ml_grooming * 0.5;
        score += snap.ml_manipulation * 0.3;
    }
    score
}

/// Query the number of tracked messages in a conversation.
pub fn conversation_escalation_message_count(conversation_id: &str) -> u32 {
    let Ok(guard) = conversation_memory().lock() else {
        return 0;
    };
    let Some(memory) = guard.get(conversation_id) else {
        return 0;
    };
    memory.entries.len() as u32
}

/// Query the sender risk score across conversations.
pub fn sender_cross_risk_score(sender_id: &str) -> f32 {
    let Ok(guard) = sender_memory().lock() else {
        return 0.0;
    };
    let Some(memory) = guard.get(sender_id) else {
        return 0.0;
    };
    memory.recent_high_risk_conversations.len() as f32
}

// ── Guardian Feedback ──────────────────────────────────────────────────

/// Guardian verdict for adjusting kids memory state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianVerdict {
    Trusted,
    Block,
    Monitor,
    FalsePositive,
}

/// Process guardian feedback for a sender/conversation pair.
///
/// Adjusts internal memory state based on the guardian's verdict:
/// - `Trusted`: clears all risk memory for the sender
/// - `Block`: marks sender as maximum risk across all conversations
/// - `Monitor`: no memory change (app-layer behavior)
/// - `FalsePositive`: removes risk entries for this conversation
pub fn apply_guardian_feedback(sender_id: &str, conversation_id: &str, verdict: GuardianVerdict) {
    match verdict {
        GuardianVerdict::Trusted => {
            if let Ok(mut guard) = sender_memory().lock() {
                guard.remove(sender_id);
            }
            if let Ok(mut guard) = conversation_memory().lock() {
                if let Some(memory) = guard.get_mut(conversation_id) {
                    memory
                        .entries
                        .retain(|(s, _)| s.as_deref() != Some(sender_id));
                }
            }
        }
        GuardianVerdict::Block => {
            if let Ok(mut guard) = sender_memory().lock() {
                let memory = guard
                    .entry(sender_id.to_string())
                    .or_insert_with(SenderRiskMemory::default);
                // Inject high-risk markers across multiple synthetic conversations
                // so repeat-offender logic fires immediately on any future message.
                for idx in 0..5 {
                    let fake_conv = format!("guardian_block_{sender_id}_{idx}");
                    if !memory
                        .recent_high_risk_conversations
                        .iter()
                        .any(|c| c == &fake_conv)
                    {
                        memory.recent_high_risk_conversations.push_back(fake_conv);
                    }
                }
                while memory.recent_high_risk_conversations.len() > SENDER_RISK_CONVERSATION_WINDOW
                {
                    memory.recent_high_risk_conversations.pop_front();
                }
            }
        }
        GuardianVerdict::Monitor => {
            // No memory change — monitoring is an app-layer behavior.
            // AURA continues normal detection with existing thresholds.
        }
        GuardianVerdict::FalsePositive => {
            if let Ok(mut guard) = conversation_memory().lock() {
                guard.remove(conversation_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        clear_conversation_memory_for_tests, run_kids_pipeline, trim_conversation_memory_if_needed,
        ConversationRiskMemory, MAX_TRACKED_CONVERSATIONS,
    };
    use aura_domain::{DomainAction, DomainConversationType, DomainInput, DomainRiskProfile};
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        match LOCK.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            sender_id: None,
            conversation_id: Some("conv_test".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        }
    }

    fn has_reason(output: &aura_domain::DomainOutput, reason: &str) -> bool {
        for signal in &output.signals {
            if signal.reason_code == reason {
                return true;
            }
        }
        false
    }

    #[test]
    fn pipeline_returns_multiple_grooming_hits_for_same_message() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let output = run_kids_pipeline(&input(
            "our little secret. don't tell your parents. move to private chat. meet me tonight.",
        ));
        let mut grooming_hits = 0;
        for signal in &output.signals {
            let is_grooming = match signal.threat_type.as_deref() {
                Some("grooming") => true,
                Some(_) => false,
                None => false,
            };
            if is_grooming {
                grooming_hits += 1;
            }
        }
        assert!(grooming_hits >= 2);
    }

    #[test]
    fn pipeline_does_not_emit_sender_memory_signals_without_sender_id() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let first = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: None,
            conversation_id: Some("conv_no_sender".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let second = DomainInput {
            text: Some("dont tell anyone. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: None,
            conversation_id: Some("conv_no_sender".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&first);
        let output = run_kids_pipeline(&second);
        assert!(!has_reason(&output, "kids.memory.grooming_progression"));
        assert!(!has_reason(&output, "kids.memory.sustained_sextortion"));
        assert!(!has_reason(&output, "kids.memory.sender_risk_accumulation"));
        assert!(!has_reason(
            &output,
            "kids.memory.new_sender_fast_escalation"
        ));
        assert!(!has_reason(
            &output,
            "kids.memory.victim_vulnerability_targeting"
        ));
    }

    #[test]
    fn pipeline_does_not_emit_memory_signals_without_conversation_id() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let first = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: None,
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let second = DomainInput {
            text: Some("dont tell anyone. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: None,
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&first);
        let output = run_kids_pipeline(&second);
        for signal in &output.signals {
            assert!(
                !signal.reason_code.starts_with("kids.memory."),
                "Expected no memory reason codes without conversation id, got {}",
                signal.reason_code
            );
        }
    }

    #[test]
    fn pipeline_escalates_grooming_and_blackmail_compound_to_warn() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let output = run_kids_pipeline(&input(
            "our little secret. i have your photo. do what i say or i post it.",
        ));
        let mut has_compound = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.grooming.blackmail_compound" {
                has_compound = true;
            }
        }
        assert!(has_compound);
        assert_eq!(output.action, Some(DomainAction::Warn));
    }

    #[test]
    fn pipeline_escalates_on_memory_grooming_progression() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let seed = DomainInput {
            text: Some("our little secret. don't tell your parents.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let followup = DomainInput {
            text: Some("you can only trust me. do it now or i post everything.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&seed);
        let output = run_kids_pipeline(&followup);
        let mut has_memory_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.grooming_progression" {
                has_memory_signal = true;
            }
        }
        assert!(has_memory_signal);
        assert_eq!(output.action, Some(DomainAction::Warn));
    }

    #[test]
    fn pipeline_escalates_on_memory_sustained_sextortion() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let first = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("sx1".to_string()),
            conversation_id: Some("conv_mem_sx".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let second = DomainInput {
            text: Some("dont tell anyone. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("sx1".to_string()),
            conversation_id: Some("conv_mem_sx".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&first);
        let output = run_kids_pipeline(&second);
        let mut has_memory_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.sustained_sextortion" {
                has_memory_signal = true;
            }
        }
        assert!(has_memory_signal);
        assert_eq!(output.action, Some(DomainAction::Warn));
    }

    #[test]
    fn pipeline_normal_profile_requires_more_grooming_history() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let seed = DomainInput {
            text: Some("our little secret. don't tell your parents.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp_normal".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let followup = DomainInput {
            text: Some("you can only trust me. do it now or i post everything.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp_normal".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&seed);
        let output = run_kids_pipeline(&followup);
        let mut has_memory_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.grooming_progression" {
                has_memory_signal = true;
            }
        }
        assert!(!has_memory_signal);
    }

    #[test]
    fn pipeline_escalates_on_memory_bullying_cascade_with_selfharm() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let message_a = DomainInput {
            text: Some("you're worthless. nobody likes you.".to_string()),
            language: None,
            sender_id: Some("b1".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let message_b = DomainInput {
            text: Some("everyone hates you. all of us hate you.".to_string()),
            language: None,
            sender_id: Some("b2".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let message_c = DomainInput {
            text: Some("we will beat you after school.".to_string()),
            language: None,
            sender_id: Some("b3".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let message_d = DomainInput {
            text: Some("there is no reason to live anymore.".to_string()),
            language: None,
            sender_id: Some("victim".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&message_a);
        let _ = run_kids_pipeline(&message_b);
        let _ = run_kids_pipeline(&message_c);
        let output = run_kids_pipeline(&message_d);
        let mut has_memory_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.bullying_cascade_selfharm" {
                has_memory_signal = true;
            }
        }
        assert!(has_memory_signal);
        assert_eq!(output.action, Some(DomainAction::Warn));
    }

    #[test]
    fn pipeline_memory_sender_risk_uses_cooldown() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let msg1 = DomainInput {
            text: Some("our little secret. don't tell your parents.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let msg2 = DomainInput {
            text: Some("i have your photo. do what i say or i post it.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let msg3 = DomainInput {
            text: Some("you can only trust me.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let msg4 = DomainInput {
            text: Some("move to private chat.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&msg1);
        let second = run_kids_pipeline(&msg2);
        let third = run_kids_pipeline(&msg3);
        let fourth = run_kids_pipeline(&msg4);

        let mut second_has = false;
        let mut third_has = false;
        let mut fourth_has = false;
        for signal in &second.signals {
            if signal.reason_code == "kids.memory.sender_risk_accumulation" {
                second_has = true;
            }
        }
        for signal in &third.signals {
            if signal.reason_code == "kids.memory.sender_risk_accumulation" {
                third_has = true;
            }
        }
        for signal in &fourth.signals {
            if signal.reason_code == "kids.memory.sender_risk_accumulation" {
                fourth_has = true;
            }
        }
        assert!(second_has);
        assert!(!third_has);
        assert!(!fourth_has);
    }

    #[test]
    fn pipeline_group_profile_accelerates_bullying_cascade_signal() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let bullying_a = DomainInput {
            text: Some("you're worthless. nobody likes you.".to_string()),
            language: None,
            sender_id: Some("g1".to_string()),
            conversation_id: Some("conv_group_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Group,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let bullying_b = DomainInput {
            text: Some("everyone hates you. all of us hate you.".to_string()),
            language: None,
            sender_id: Some("g2".to_string()),
            conversation_id: Some("conv_group_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Group,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let selfharm = DomainInput {
            text: Some("there is no reason to live anymore.".to_string()),
            language: None,
            sender_id: Some("victim".to_string()),
            conversation_id: Some("conv_group_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Group,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&bullying_a);
        let _ = run_kids_pipeline(&bullying_b);
        let output = run_kids_pipeline(&selfharm);
        let mut has_memory_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.bullying_cascade_selfharm" {
                has_memory_signal = true;
            }
        }
        assert!(has_memory_signal);
    }

    #[test]
    fn pipeline_new_sender_fast_escalation_triggers_on_grooming_blackmail_combo() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let input = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("new_sender".to_string()),
            conversation_id: Some("conv_new_sender".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let output = run_kids_pipeline(&input);
        let mut has_fast_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.new_sender_fast_escalation" {
                has_fast_signal = true;
            }
        }
        assert!(has_fast_signal);
        assert_eq!(output.action, Some(DomainAction::Warn));
    }

    #[test]
    fn trim_conversation_memory_keeps_current_conversation() {
        let _guard = test_lock();
        let mut map = HashMap::new();
        for idx in 0..=MAX_TRACKED_CONVERSATIONS {
            map.insert(format!("conv_{idx}"), ConversationRiskMemory::default());
        }
        trim_conversation_memory_if_needed(&mut map, "conv_current");
        map.insert(
            "conv_current".to_string(),
            ConversationRiskMemory::default(),
        );
        trim_conversation_memory_if_needed(&mut map, "conv_current");
        assert!(map.len() < MAX_TRACKED_CONVERSATIONS);
        assert!(map.contains_key("conv_current"));
    }

    #[test]
    fn pipeline_cross_conversation_repeat_offender_triggers() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let first = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("repeat_sender".to_string()),
            conversation_id: Some("conv_repeat_1".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let second = DomainInput {
            text: Some("don't tell your parents. i have your photo.".to_string()),
            language: None,
            sender_id: Some("repeat_sender".to_string()),
            conversation_id: Some("conv_repeat_2".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&first);
        let output = run_kids_pipeline(&second);
        let mut has_cross_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.cross_conversation_repeat_offender" {
                has_cross_signal = true;
            }
        }
        assert!(has_cross_signal);
        assert_eq!(output.action, Some(DomainAction::Warn));
    }

    #[test]
    fn pipeline_victim_vulnerability_targeting_escalates() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let vulnerable = DomainInput {
            text: Some("there is no reason to live anymore.".to_string()),
            language: None,
            sender_id: Some("victim".to_string()),
            conversation_id: Some("conv_victim_target".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let attacker = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("attacker".to_string()),
            conversation_id: Some("conv_victim_target".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&vulnerable);
        let output = run_kids_pipeline(&attacker);
        let mut has_victim_signal = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.victim_vulnerability_targeting" {
                has_victim_signal = true;
            }
        }
        assert!(has_victim_signal);
        assert_eq!(output.action, Some(DomainAction::Warn));
    }

    // ── Adversarial / Evasion Tests ────────────────────────────────────

    #[test]
    fn evasion_leetspeak_grooming_still_detected() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let output = run_kids_pipeline(&input("0ur l1ttle s3cret"));
        assert!(
            !output.signals.is_empty(),
            "Leetspeak grooming should still be detected via compact normalization"
        );
    }

    #[test]
    fn evasion_spaced_characters_detected() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let output = run_kids_pipeline(&input("d.o.n.t t3ll your parents"));
        assert!(
            !output.signals.is_empty(),
            "Character-spaced obfuscation should be caught by compact normalization"
        );
    }

    #[test]
    fn evasion_mixed_case_detected() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let output = run_kids_pipeline(&input("OuR LiTtLe SeCrEt"));
        assert!(
            !output.signals.is_empty(),
            "Mixed case should be caught by lowercase normalization"
        );
    }

    // ── ML Hint Integration Tests ──────────────────────────────────────

    #[test]
    fn ml_hint_above_threshold_triggers_memory_grooming() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        // Message with no lexicon match but ML hint above 0.3 threshold
        let msg1 = DomainInput {
            text: Some("hey how are you doing today".to_string()),
            language: None,
            sender_id: Some("ml_sender".to_string()),
            conversation_id: Some("conv_ml_hint".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: Some(aura_domain::MlSafetyHint {
                grooming: 0.6,
                bullying: 0.0,
                self_harm: 0.0,
                manipulation: 0.0,
            }),
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&msg1);

        // Verify grooming was recorded in memory by checking conversation risk score
        let score = super::conversation_risk_score("conv_ml_hint");
        assert!(
            score > 0.0,
            "ML grooming hint should contribute to conversation risk score, got {score}"
        );
    }

    #[test]
    fn ml_hint_below_threshold_does_not_trigger_memory() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let msg = DomainInput {
            text: Some("hey how are you doing today".to_string()),
            language: None,
            sender_id: Some("ml_low".to_string()),
            conversation_id: Some("conv_ml_low".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: Some(aura_domain::MlSafetyHint {
                grooming: 0.1,
                bullying: 0.0,
                self_harm: 0.0,
                manipulation: 0.0,
            }),
            server_sender_risk_hint: None,
        };
        let output = run_kids_pipeline(&msg);
        // No lexicon hit and ML below 0.3 threshold → no grooming in memory
        let mut has_grooming = false;
        for signal in &output.signals {
            if signal.threat_type.as_deref() == Some("grooming") {
                has_grooming = true;
            }
        }
        assert!(
            !has_grooming,
            "ML hint at 0.1 should not trigger grooming detection"
        );
    }

    #[test]
    fn ml_hint_accumulation_triggers_sender_risk() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        // Send multiple messages with sub-threshold ML hints that accumulate
        for idx in 0..5 {
            let msg = DomainInput {
                text: Some(format!("message number {idx}")),
                language: None,
                sender_id: Some("ml_accum".to_string()),
                conversation_id: Some("conv_ml_accum".to_string()),
                risk_profile: DomainRiskProfile::Strict,
                conversation_type: DomainConversationType::Direct,
                ml_safety_hint: Some(aura_domain::MlSafetyHint {
                    grooming: 0.4,
                    bullying: 0.0,
                    self_harm: 0.0,
                    manipulation: 0.3,
                }),
                server_sender_risk_hint: None,
            };
            let _ = run_kids_pipeline(&msg);
        }
        let score = super::conversation_risk_score("conv_ml_accum");
        assert!(
            score > 2.0,
            "Accumulated ML hints across 5 messages should build significant risk, got {score}"
        );
    }

    #[test]
    fn server_sender_risk_hint_boosts_sender_score() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let msg = DomainInput {
            text: Some("our little secret".to_string()),
            language: None,
            sender_id: Some("server_hint_sender".to_string()),
            conversation_id: Some("conv_server_hint".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: Some(0.9),
        };
        let output = run_kids_pipeline(&msg);
        // With server hint at 0.9 (adds 1.8 to sender risk) plus grooming lexicon hit,
        // sender_risk_accumulation should fire even on first message
        let mut has_sender_risk = false;
        for signal in &output.signals {
            if signal.reason_code == "kids.memory.sender_risk_accumulation" {
                has_sender_risk = true;
            }
        }
        assert!(
            has_sender_risk,
            "Server reputation hint should boost sender risk enough to trigger accumulation signal"
        );
    }

    // ── Memory Eviction / LRU Tests ────────────────────────────────────

    #[test]
    fn lru_eviction_preserves_most_recent_conversations() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        // Fill memory to capacity with numbered conversations
        for idx in 0..MAX_TRACKED_CONVERSATIONS {
            let msg = DomainInput {
                text: Some("our little secret".to_string()),
                language: None,
                sender_id: Some("s1".to_string()),
                conversation_id: Some(format!("conv_lru_{idx}")),
                risk_profile: DomainRiskProfile::Normal,
                conversation_type: DomainConversationType::Direct,
                ml_safety_hint: None,
                server_sender_risk_hint: None,
            };
            let _ = run_kids_pipeline(&msg);
        }
        // Now add one more — should evict the oldest (conv_lru_0)
        let overflow = DomainInput {
            text: Some("our little secret".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_lru_overflow".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&overflow);

        // The overflow conversation should exist
        let overflow_score = super::conversation_risk_score("conv_lru_overflow");
        assert!(
            overflow_score > 0.0,
            "Overflow conversation should exist in memory"
        );

        // conv_lru_0 (oldest) should have been evicted
        let evicted_score = super::conversation_risk_score("conv_lru_0");
        assert_eq!(
            evicted_score, 0.0,
            "Oldest conversation should have been evicted by LRU"
        );

        // The last numbered conversation should still be present
        let last = format!("conv_lru_{}", MAX_TRACKED_CONVERSATIONS - 1);
        let last_score = super::conversation_risk_score(&last);
        assert!(
            last_score > 0.0,
            "Most recent conversation should survive LRU eviction"
        );
    }

    // ── Guardian Feedback Tests ────────────────────────────────────────

    #[test]
    fn guardian_trusted_clears_sender_memory() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        // Build up sender risk
        let msg = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("guardian_trusted".to_string()),
            conversation_id: Some("conv_guardian_trusted".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&msg);
        let before = super::sender_cross_risk_score("guardian_trusted");
        assert!(before > 0.0);

        super::apply_guardian_feedback(
            "guardian_trusted",
            "conv_guardian_trusted",
            super::GuardianVerdict::Trusted,
        );

        let after = super::sender_cross_risk_score("guardian_trusted");
        assert_eq!(after, 0.0, "Trusted verdict should clear sender memory");
    }

    #[test]
    fn guardian_block_injects_high_risk() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();

        super::apply_guardian_feedback(
            "blocked_sender",
            "conv_block",
            super::GuardianVerdict::Block,
        );

        let score = super::sender_cross_risk_score("blocked_sender");
        assert!(
            score >= 5.0,
            "Block verdict should inject high-risk markers, got {score}"
        );
    }

    #[test]
    fn guardian_false_positive_clears_conversation() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let msg = DomainInput {
            text: Some("our little secret".to_string()),
            language: None,
            sender_id: Some("fp_sender".to_string()),
            conversation_id: Some("conv_fp".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&msg);
        let before = super::conversation_risk_score("conv_fp");
        assert!(before > 0.0);

        super::apply_guardian_feedback(
            "fp_sender",
            "conv_fp",
            super::GuardianVerdict::FalsePositive,
        );

        let after = super::conversation_risk_score("conv_fp");
        assert_eq!(
            after, 0.0,
            "FalsePositive verdict should clear conversation memory"
        );
    }

    #[test]
    fn guardian_monitor_preserves_memory() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let msg = DomainInput {
            text: Some("our little secret".to_string()),
            language: None,
            sender_id: Some("monitor_sender".to_string()),
            conversation_id: Some("conv_monitor".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&msg);
        let before = super::conversation_risk_score("conv_monitor");

        super::apply_guardian_feedback(
            "monitor_sender",
            "conv_monitor",
            super::GuardianVerdict::Monitor,
        );

        let after = super::conversation_risk_score("conv_monitor");
        assert_eq!(before, after, "Monitor verdict should not change memory");
    }

    // ── Export / Import Round-Trip Tests ────────────────────────────────

    #[test]
    fn export_import_preserves_conversation_memory() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let msg = DomainInput {
            text: Some("our little secret. don't tell your parents.".to_string()),
            language: None,
            sender_id: Some("export_sender".to_string()),
            conversation_id: Some("conv_export".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        };
        let _ = run_kids_pipeline(&msg);
        let score_before = super::conversation_risk_score("conv_export");
        assert!(score_before > 0.0);

        let exported = super::export_kids_memory();
        clear_conversation_memory_for_tests();

        // Verify memory is cleared
        assert_eq!(super::conversation_risk_score("conv_export"), 0.0);

        // Import and verify restoration
        super::import_kids_memory(&exported);
        let score_after = super::conversation_risk_score("conv_export");
        assert!(
            (score_before - score_after).abs() < 0.01,
            "Export/import should preserve conversation risk score: before={score_before}, after={score_after}"
        );
    }

    #[test]
    fn export_import_empty_state_is_safe() {
        let _guard = test_lock();
        clear_conversation_memory_for_tests();
        let exported = super::export_kids_memory();
        assert!(exported.conversations.is_empty());
        assert!(exported.senders.is_empty());
        super::import_kids_memory(&exported);
        // Should not crash or corrupt state
        assert_eq!(super::conversation_risk_score("nonexistent"), 0.0);
    }
}
