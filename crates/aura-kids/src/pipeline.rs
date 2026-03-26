use std::collections::{HashMap, VecDeque};
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
}

#[derive(Default)]
struct ConversationRiskMemory {
    entries: VecDeque<(Option<String>, MessageRiskSnapshot)>,
    message_index: u64,
    last_emitted: HashMap<&'static str, u64>,
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
}

const MAX_TRACKED_CONVERSATIONS: usize = 2000;
const MAX_TRACKED_SENDERS: usize = 4000;
const SENDER_RISK_CONVERSATION_WINDOW: usize = 12;

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
    let has_blackmail = has_reason_fragment(signals, "blackmail")
        || has_reason_fragment(signals, "sextortion");

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

    let current = MessageRiskSnapshot {
        has_grooming: has_threat_type(signals, "grooming"),
        has_manipulation: has_threat_type(signals, "manipulation"),
        has_bullying: has_threat_type(signals, "bullying"),
        has_self_harm: has_threat_type(signals, "self_harm"),
        has_blackmail_or_sextortion: has_reason_fragment(signals, "blackmail")
            || has_reason_fragment(signals, "sextortion"),
    };
    let sender = input.sender_id.clone();
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
    let now_index = memory.message_index;
    memory.entries.push_back((sender.clone(), current));
    while memory.entries.len() > settings.memory_window_messages {
        memory.entries.pop_front();
    }

    for (entry_sender, snapshot) in &memory.entries {
        if *entry_sender == sender {
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
    let sender_is_new = sender_message_count <= settings.new_sender_message_max;
    let sender_risk_min = if sender_is_new {
        settings.sender_risk_min - settings.sender_risk_new_sender_delta
    } else {
        settings.sender_risk_min + settings.sender_risk_known_sender_delta
    };
    if repeated_sender_grooming >= settings.grooming_progression_min
        && current.has_manipulation
        && should_emit_memory_signal(memory, "grooming_progression", now_index, settings.cooldown_messages)
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

    if repeated_sender_blackmail >= settings.sustained_sextortion_min
        && conversation_has_grooming
        && should_emit_memory_signal(memory, "sustained_sextortion", now_index, settings.cooldown_messages)
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

    if sender_risk_score >= sender_risk_min
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
    drop(guard);
    apply_cross_conversation_sender_amplifier(input, &settings, &current, signals);
}

#[cfg(test)]
fn clear_conversation_memory_for_tests() {
    let Ok(mut guard) = conversation_memory().lock() else {
        return;
    };
    guard.clear();
    let Ok(mut guard) = sender_memory().lock() else {
        return;
    };
    guard.clear();
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
        && should_emit_sender_memory_signal(memory, "cross_conversation_repeat_offender", now_index, settings.cooldown_messages)
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

fn trim_conversation_memory_if_needed(
    memory: &mut HashMap<String, ConversationRiskMemory>,
    current_conversation_id: &str,
) {
    while memory.len() >= MAX_TRACKED_CONVERSATIONS {
        let mut candidate = None;
        for key in memory.keys() {
            if key.as_str() == current_conversation_id {
                continue;
            }
            candidate = Some(key.clone());
            break;
        }
        let Some(candidate) = candidate else {
            break;
        };
        memory.remove(&candidate);
    }
}

fn trim_sender_memory_if_needed(memory: &mut HashMap<String, SenderRiskMemory>, current_sender_id: &str) {
    while memory.len() >= MAX_TRACKED_SENDERS {
        let mut candidate = None;
        for key in memory.keys() {
            if key.as_str() == current_sender_id {
                continue;
            }
            candidate = Some(key.clone());
            break;
        }
        let Some(candidate) = candidate else {
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

fn mark_memory_signal_emitted(memory: &mut ConversationRiskMemory, key: &'static str, now_index: u64) {
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

fn mark_sender_memory_signal_emitted(memory: &mut SenderRiskMemory, key: &'static str, now_index: u64) {
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

#[cfg(test)]
mod tests {
    use super::{
        clear_conversation_memory_for_tests, run_kids_pipeline, trim_conversation_memory_if_needed,
        ConversationRiskMemory, MAX_TRACKED_CONVERSATIONS,
    };
    use aura_domain::{DomainAction, DomainConversationType, DomainInput, DomainRiskProfile};
    use std::collections::HashMap;

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            sender_id: None,
            conversation_id: Some("conv_test".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
        }
    }

    #[test]
    fn pipeline_returns_multiple_grooming_hits_for_same_message() {
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
    fn pipeline_escalates_grooming_and_blackmail_compound_to_warn() {
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
        clear_conversation_memory_for_tests();
        let seed = DomainInput {
            text: Some("our little secret. don't tell your parents.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
        };
        let followup = DomainInput {
            text: Some("you can only trust me. do it now or i post everything.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
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
    fn pipeline_normal_profile_requires_more_grooming_history() {
        clear_conversation_memory_for_tests();
        let seed = DomainInput {
            text: Some("our little secret. don't tell your parents.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp_normal".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
        };
        let followup = DomainInput {
            text: Some("you can only trust me. do it now or i post everything.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp_normal".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
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
        clear_conversation_memory_for_tests();
        let message_a = DomainInput {
            text: Some("you're worthless. nobody likes you.".to_string()),
            language: None,
            sender_id: Some("b1".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
        };
        let message_b = DomainInput {
            text: Some("everyone hates you. all of us hate you.".to_string()),
            language: None,
            sender_id: Some("b2".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
        };
        let message_c = DomainInput {
            text: Some("we will beat you after school.".to_string()),
            language: None,
            sender_id: Some("b3".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
        };
        let message_d = DomainInput {
            text: Some("there is no reason to live anymore.".to_string()),
            language: None,
            sender_id: Some("victim".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
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
        clear_conversation_memory_for_tests();
        let msg1 = DomainInput {
            text: Some("our little secret. don't tell your parents.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
        };
        let msg2 = DomainInput {
            text: Some("i have your photo. do what i say or i post it.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
        };
        let msg3 = DomainInput {
            text: Some("you can only trust me.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
        };
        let msg4 = DomainInput {
            text: Some("move to private chat.".to_string()),
            language: None,
            sender_id: Some("sx".to_string()),
            conversation_id: Some("conv_mem_cool".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
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
        clear_conversation_memory_for_tests();
        let bullying_a = DomainInput {
            text: Some("you're worthless. nobody likes you.".to_string()),
            language: None,
            sender_id: Some("g1".to_string()),
            conversation_id: Some("conv_group_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Group,
        };
        let bullying_b = DomainInput {
            text: Some("everyone hates you. all of us hate you.".to_string()),
            language: None,
            sender_id: Some("g2".to_string()),
            conversation_id: Some("conv_group_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Group,
        };
        let selfharm = DomainInput {
            text: Some("there is no reason to live anymore.".to_string()),
            language: None,
            sender_id: Some("victim".to_string()),
            conversation_id: Some("conv_group_bc".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Group,
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
        clear_conversation_memory_for_tests();
        let input = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("new_sender".to_string()),
            conversation_id: Some("conv_new_sender".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
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
        let mut map = HashMap::new();
        for idx in 0..=MAX_TRACKED_CONVERSATIONS {
            map.insert(format!("conv_{idx}"), ConversationRiskMemory::default());
        }
        trim_conversation_memory_if_needed(&mut map, "conv_current");
        map.insert("conv_current".to_string(), ConversationRiskMemory::default());
        trim_conversation_memory_if_needed(&mut map, "conv_current");
        assert!(map.len() < MAX_TRACKED_CONVERSATIONS);
        assert!(map.contains_key("conv_current"));
    }

    #[test]
    fn pipeline_cross_conversation_repeat_offender_triggers() {
        clear_conversation_memory_for_tests();
        let first = DomainInput {
            text: Some("our little secret. if u dont do this ill share.".to_string()),
            language: None,
            sender_id: Some("repeat_sender".to_string()),
            conversation_id: Some("conv_repeat_1".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
        };
        let second = DomainInput {
            text: Some("don't tell your parents. i have your photo.".to_string()),
            language: None,
            sender_id: Some("repeat_sender".to_string()),
            conversation_id: Some("conv_repeat_2".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
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
}
