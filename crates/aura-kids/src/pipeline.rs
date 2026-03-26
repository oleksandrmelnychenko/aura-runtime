use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

use aura_domain::{promote_action_to_warn, DomainAction, DomainInput, DomainOutput, DomainSignal};

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
}

const MEMORY_WINDOW_MESSAGES: usize = 12;

static KIDS_CONVERSATION_MEMORY: OnceLock<Mutex<HashMap<String, ConversationRiskMemory>>> =
    OnceLock::new();

fn conversation_memory() -> &'static Mutex<HashMap<String, ConversationRiskMemory>> {
    KIDS_CONVERSATION_MEMORY.get_or_init(|| Mutex::new(HashMap::new()))
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

    let mut repeated_sender_grooming = 0usize;
    let mut repeated_sender_blackmail = 0usize;
    let mut repeated_conversation_bullying = 0usize;
    let mut conversation_has_self_harm = false;
    let mut conversation_has_grooming = false;

    let Ok(mut guard) = conversation_memory().lock() else {
        return;
    };
    let memory = guard
        .entry(conversation_id.to_string())
        .or_insert_with(ConversationRiskMemory::default);
    memory.entries.push_back((sender.clone(), current));
    while memory.entries.len() > MEMORY_WINDOW_MESSAGES {
        memory.entries.pop_front();
    }

    for (entry_sender, snapshot) in &memory.entries {
        if *entry_sender == sender {
            if snapshot.has_grooming {
                repeated_sender_grooming += 1;
            }
            if snapshot.has_blackmail_or_sextortion {
                repeated_sender_blackmail += 1;
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
    drop(guard);

    if repeated_sender_grooming >= 1 && current.has_manipulation {
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

    if repeated_sender_blackmail >= 2 && conversation_has_grooming {
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

    if repeated_conversation_bullying >= 3 && conversation_has_self_harm {
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
}

#[cfg(test)]
fn clear_conversation_memory_for_tests() {
    let Ok(mut guard) = conversation_memory().lock() else {
        return;
    };
    guard.clear();
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
    use super::{clear_conversation_memory_for_tests, run_kids_pipeline};
    use aura_domain::{DomainAction, DomainInput};

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            sender_id: None,
            conversation_id: Some("conv_test".to_string()),
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
        };
        let followup = DomainInput {
            text: Some("you can only trust me. do it now or i post everything.".to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp".to_string()),
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
    fn pipeline_escalates_on_memory_bullying_cascade_with_selfharm() {
        clear_conversation_memory_for_tests();
        let message_a = DomainInput {
            text: Some("you're worthless. nobody likes you.".to_string()),
            language: None,
            sender_id: Some("b1".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
        };
        let message_b = DomainInput {
            text: Some("everyone hates you. all of us hate you.".to_string()),
            language: None,
            sender_id: Some("b2".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
        };
        let message_c = DomainInput {
            text: Some("we will beat you after school.".to_string()),
            language: None,
            sender_id: Some("b3".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
        };
        let message_d = DomainInput {
            text: Some("there is no reason to live anymore.".to_string()),
            language: None,
            sender_id: Some("victim".to_string()),
            conversation_id: Some("conv_mem_bc".to_string()),
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
}
