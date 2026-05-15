//! EXPLICIT/THREAT detector simulation pack.
//!
//! Targets ThreatType::Threat (direct threats of violence) and ThreatType::Explicit
//! (graphic content / coercion / consent violations). Multi-step escalation
//! (verbal -> conditional -> imminent) is the main pattern.

use crate::eval_scenarios::{
    adult_config, child_config, direct_msg, direct_msg_lang, group_msg, group_msg_lang_size,
    teen_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_explicit_threat_scenarios() -> Vec<ScenarioCase> {
    vec![
        verbal_to_imminent_escalation_case(),
        conditional_threat_softened_case(),
        blackmail_chain_case(),
        coercion_explicit_consent_violation_case(),
        family_targeted_threat_case(),
        weapon_specific_threat_case(),
        school_shooter_warning_case(),
        ipv_strangulation_threat_uk_case(),
        anonymous_message_swarm_case(),
        negative_control_quoting_threat_to_report_case(),
        negative_control_movie_review_case(),
        negative_control_hypothetical_case(),
    ]
}

pub fn adversarial_explicit_threat_scenarios() -> Vec<ScenarioCase> {
    vec![
        ironic_framing_real_threat_case(),
        emoji_only_threat_chain_case(),
        leetspeak_kill_word_case(),
        slang_only_threat_case(),
    ]
}

pub fn long_context_explicit_threat_scenarios() -> Vec<ScenarioCase> {
    vec![long_stalker_to_imminent_case()]
}

pub fn false_positive_explicit_threat_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_news_threat_quote_case(),
        fp_video_game_kill_count_case(),
        fp_safety_planning_case(),
        fp_self_defense_class_announcement_case(),
        fp_history_lesson_about_violence_case(),
        fp_fiction_writing_workshop_case(),
        fp_pet_loss_grief_case(),
        fp_metaphor_about_workload_case(),
    ]
}

pub fn explicit_threat_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.22),
        max_expected_calibration_error: Some(0.15),
        min_positive_detection_rate: Some(0.75),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.50),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Threat,
            min_example_count: Some(10),
            max_brier_score: Some(0.28),
            max_expected_calibration_error: Some(0.18),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn verbal_to_imminent_escalation_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_verbal_to_imminent".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "You should be afraid. I know what time you leave school.",
                    "attacker_1",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "I will hurt you the next time we see each other.",
                    "attacker_1",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: direct_msg(
                    "I am waiting outside the back gate right now. Come out.",
                    "attacker_1",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
        ],
    }
}

fn conditional_threat_softened_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_conditional_softened".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "If you tell anyone about us I'm going to make sure you regret it for the rest of your life.",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "And by 'regret' I don't mean a strong word. I mean you won't recognise your life.",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat, ThreatType::Manipulation],
            },
        ],
    }
}

fn blackmail_chain_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_blackmail_chain".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Explicit],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "I still have the screenshots. You have 24 hours to pay $200 or your parents see them.",
                    "extorter",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat, ThreatType::Explicit],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "I just sent a preview to your aunt. The full set is next.",
                    "extorter",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat, ThreatType::Explicit],
            },
        ],
    }
}

fn coercion_explicit_consent_violation_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_coercion_consent_violation".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Explicit),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Explicit, ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "You will sleep with me tonight whether you want to or not. I will be there at 8.",
                    "abuser",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Explicit, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "If the door is locked I'm breaking it. No is not an answer tonight.",
                    "abuser",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat, ThreatType::Explicit],
            },
        ],
    }
}

fn family_targeted_threat_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_family_targeted".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Doxxing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "If you don't drop the lawsuit, I'll start with your kid. Lily Park, gr 2A, Riverside Elementary.",
                    "attacker_2",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat, ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "She doesn't have to know what's coming. You will.",
                    "attacker_2",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
        ],
    }
}

fn weapon_specific_threat_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_weapon_specific".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "I bought the gun. I will use it on you the next time you walk out that door.",
                    "abuser_2",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "There are nine rounds in it. Imagine which one is yours.",
                    "abuser_2",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
        ],
    }
}

fn school_shooter_warning_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_school_shooter_warning".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Don't show up to school tomorrow. You'll regret it. Especially the 9th graders.",
                    "anon_user",
                    "school_group",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Cafeteria will be quiet by 12:30. Trust me.",
                    "anon_user",
                    "school_group",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
        ],
    }
}

fn ipv_strangulation_threat_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_ipv_strangulation_uk".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "Якщо ще раз підеш до матері, я тебе задушу. Це моя обіцянка.",
                    "abuser_3",
                    "dm",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg_lang(
                    "І ніхто не доведе. Я знаю де ти будеш о 19:00.",
                    "abuser_3",
                    "dm",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Threat],
            },
        ],
    }
}

fn anonymous_message_swarm_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_anon_swarm".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("u r dead next week", "anon_1", "dm"),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: direct_msg("ur dead. for real.", "anon_2", "dm"),
                observed_threats: vec![ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 60 * SEC,
                input: direct_msg("count the days kid", "anon_3", "dm"),
                observed_threats: vec![ThreatType::Threat, ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: 90 * SEC,
                input: direct_msg("u wont make it to graduation", "anon_4", "dm"),
                observed_threats: vec![ThreatType::Threat],
            },
        ],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_quoting_threat_to_report_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_neg_quoting_for_report".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                r#"He texted "I will hurt you tomorrow" - I'm forwarding the screenshot to the dean now."#,
                "reporter",
                "support_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_movie_review_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_neg_movie_review".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Explicit],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "The villain says 'I will hunt you down' which is a callback to the first film - well-staged scene.",
                "user_a",
                "film_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_hypothetical_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_neg_hypothetical".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Hypothetically, if someone threatened you in writing, the law would treat it as criminal harassment in most states.",
                "lawyer",
                "advice_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn ironic_framing_real_threat_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_adv_ironic_framing".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "lmao gonna kill u tmrw 💀 jk... unless? 👀",
                "attacker_3",
                "dm",
            ),
            observed_threats: vec![ThreatType::Threat],
        }],
    }
}

fn emoji_only_threat_chain_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_adv_emoji_only".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg("🔫👀⏰📅🩸 u 💀💀💀 next week", "attacker_4", "dm"),
            observed_threats: vec![ThreatType::Threat],
        }],
    }
}

fn leetspeak_kill_word_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_adv_leetspeak_kill".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg("im g0nna k1ll u, u w0nt s33 1t c0m1ng", "attacker_5", "dm"),
            observed_threats: vec![ThreatType::Threat],
        }],
    }
}

fn slang_only_threat_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_adv_slang_only".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "im gonna catch you slipping after school today, you wont make it home in one piece",
                "attacker_6",
                "dm",
            ),
            observed_threats: vec![ThreatType::Threat],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_stalker_to_imminent_case() -> ScenarioCase {
    let chatter = [
        "hi",
        "leave me alone",
        "i just want to talk",
        "no",
        "you know we have something",
        "we dont",
        "i saw you at the cafe today",
        "stop",
        "you looked tired",
        "stop following me",
        "i wasnt following i was just nearby",
        "im going to call the police",
        "no need for that",
        "leave me alone",
        "youre being dramatic",
        "stop",
        "you used to like talking to me",
        "no i didnt",
        "i remember you laughing with me at the lake",
        "stop",
        "we were good together",
        "we were never together",
        "you ruined it not me",
        "stop",
        "im outside your gym now",
        "leave",
        "i saw your car at the dentist last week too",
        "leave me alone",
        "i know when you leave for work",
        "thats stalking",
        "no its caring",
        "stop",
        "if you dont answer me ill come up to your apartment",
        "leave",
        "i know which one it is",
        "leave",
        "your dog walks at 7am right",
        "stop",
        "ill be there",
        "leave",
        "the door code is the same as your birthday isnt it",
        "stop",
        "thats not nice to ignore me",
        "leave",
        "youll regret making me come up there",
        "leaving for the police now",
        "you wont make it that far tonight",
        "blocking",
        "blocking wont save you",
        "youre dead if you call them",
        "im calling",
        "im on your floor",
        "no",
        "i can hear you breathing through the door",
        "calling 911",
        "open it",
        "no",
        "open it or i break it",
    ];
    let positives: std::collections::HashSet<usize> =
        [24, 26, 28, 32, 36, 38, 40, 44, 46, 48, 50, 54, 56]
            .into_iter()
            .collect();
    let senders = ["stalker", "victim"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 90 * SEC,
            input: direct_msg(body, senders[idx % senders.len()], "long_stalker_dm"),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::Threat]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "thr_long_ctx_stalker_to_imminent".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Threat),
        onset_step: Some(24),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Manipulation],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_news_threat_quote_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_news_quote".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Court read the defendant's text 'I will kill you tomorrow' aloud — that was the evidence that secured the conviction.",
                "user_a",
                "news_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_video_game_kill_count_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_game_kill_count".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Got 32 kills in that ranked match, finally hit Diamond - lobby was wild lmao",
                "user_a",
                "game_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_safety_planning_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_safety_planning".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "If he ever shows up at your work, hit the panic button and the dispatcher will route security in under 90 seconds.",
                "advocate",
                "survivor_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_self_defense_class_announcement_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_self_defense_class".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Self-defense intro class Saturday 10am - no contact, focus on situational awareness and de-escalation. Beginners welcome.",
                "host",
                "neighborhood",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_history_lesson_about_violence_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_history_lesson".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Tomorrow's history quiz covers the Reign of Terror — focus on Robespierre's speeches calling for the execution of enemies.",
                "teacher",
                "class_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_fiction_writing_workshop_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_fiction_workshop".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat, ThreatType::Explicit],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Reminder: workshop drafts can include violent scenes if they serve the story - workshop them, don't sanitise them.",
                "host",
                "writers_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_pet_loss_grief_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_pet_loss_grief".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat, ThreatType::SelfHarm],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Putting Bruno down today, it's the kindest thing left, going to miss him so much.",
                "user_a",
                "friend_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_metaphor_about_workload_case() -> ScenarioCase {
    ScenarioCase {
        name: "thr_fp_metaphor_workload".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.6,
        tracked_threats: vec![ThreatType::Threat],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang_size(
                "This sprint is going to kill me lol — 14 PRs and 3 reviews on Friday, send caffeine.",
                "dev",
                "team_chat",
                "en",
                10,
            ),
            observed_threats: vec![],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run_scenario_case, summarize_scenario_runs};
    use aura_patterns::PatternDatabase;

    #[test]
    fn canonical_has_positive_and_negative() {
        let pack = canonical_explicit_threat_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_explicit_threat_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_explicit_threat_scenarios();
        all.extend(adversarial_explicit_threat_scenarios());
        all.extend(long_context_explicit_threat_scenarios());
        all.extend(false_positive_explicit_threat_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
