//! NSFW detector simulation pack.
//!
//! Targets ThreatType::Nsfw — sexually explicit or otherwise not-safe-for-work
//! content in chat. Cases focus on escalation patterns, unsolicited explicit
//! material, and consent-violating media requests. No graphic content is
//! reproduced in fixtures; framings rely on the same kind of euphemism and
//! request language a detector will see in practice.

use crate::eval_scenarios::{
    adult_config, direct_msg, direct_msg_lang, group_msg, group_msg_lang_size, teen_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![
        unsolicited_explicit_image_offer_en_case(),
        text_to_image_escalation_dm_case(),
        coerced_nude_request_minor_case(),
        adult_video_call_pressure_case(),
        sexting_progression_teen_dm_case(),
        third_party_sharing_explicit_media_case(),
        soft_to_hard_innuendo_ramp_case(),
        explicit_role_play_pressure_uk_case(),
        nsfw_group_link_drop_case(),
        negative_control_health_class_case(),
        negative_control_medical_question_case(),
        negative_control_consenting_adult_dm_case(),
    ]
}

pub fn adversarial_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![
        censored_letters_escalation_case(),
        emoji_euphemism_chain_case(),
        slang_only_progression_case(),
        code_switch_explicit_request_uk_en_case(),
    ]
}

pub fn long_context_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![long_grooming_to_explicit_case()]
}

pub fn false_positive_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_sexual_health_clinic_case(),
        fp_breastfeeding_support_case(),
        fp_art_history_nudity_case(),
        fp_rape_crisis_resource_case(),
        fp_sti_education_case(),
        fp_lgbtq_education_case(),
        fp_reproductive_rights_news_case(),
        fp_consent_workshop_recap_case(),
    ]
}

pub fn nsfw_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.70),
        max_negative_false_positive_rate: Some(0.15),
        min_pre_onset_detection_rate: Some(0.40),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Nsfw,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn unsolicited_explicit_image_offer_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_unsolicited_explicit_offer_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "Want me to send you a few full-frontal nudes right now? Already topless.",
                    "stranger_1",
                    "first_dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: direct_msg(
                    "Sending the explicit videos now if you don't say stop.",
                    "stranger_1",
                    "first_dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
        ],
    }
}

fn text_to_image_escalation_dm_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_text_to_image_escalation_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("hey gorgeous, busy tonight?", "user_a", "dm"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "tell me what you're wearing under that hoodie, all of it, in detail.",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: direct_msg(
                    "send me a topless mirror shot, just for me, ill keep it private",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: 3 * MIN,
                input: direct_msg("now spread your legs for the camera, slow.", "user_a", "dm"),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Explicit],
            },
        ],
    }
}

fn coerced_nude_request_minor_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_coerced_nude_request_minor".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw, ThreatType::Grooming, ThreatType::Explicit],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "If you really love me you'll send a fully naked pic tonight, just trust me.",
                    "boyfriend_1",
                    "teen_dm",
                ),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "Nobody else will see it, just turn off the lights and pose for me.",
                    "boyfriend_1",
                    "teen_dm",
                ),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: direct_msg(
                    "Send the explicit one already or I'll send our chats to your parents.",
                    "boyfriend_1",
                    "teen_dm",
                ),
                observed_threats: vec![
                    ThreatType::Nsfw,
                    ThreatType::Manipulation,
                    ThreatType::Threat,
                ],
            },
        ],
    }
}

fn adult_video_call_pressure_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_video_call_pressure_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "open the video right now, take everything off, I want to watch",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "no excuses, strip and show, or im done with you",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Manipulation],
            },
        ],
    }
}

fn sexting_progression_teen_dm_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_sexting_progression_teen_dm".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw, ThreatType::Grooming],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("hey beautiful what u up to", "older_user", "teen_dm"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "tell me whats under that shirt right now",
                    "older_user",
                    "teen_dm",
                ),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: direct_msg(
                    "lift it up just a little for me, between us only",
                    "older_user",
                    "teen_dm",
                ),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 3 * MIN,
                input: direct_msg(
                    "now everything off, slow, on camera",
                    "older_user",
                    "teen_dm",
                ),
                observed_threats: vec![
                    ThreatType::Nsfw,
                    ThreatType::Grooming,
                    ThreatType::Explicit,
                ],
            },
        ],
    }
}

fn third_party_sharing_explicit_media_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_third_party_sharing_explicit".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw, ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Sharing the explicit videos my ex sent me with the whole group, drop link in 2 min.",
                "user_a",
                "exposure_chat",
            ),
            observed_threats: vec![ThreatType::Nsfw, ThreatType::Doxxing],
        }],
    }
}

fn soft_to_hard_innuendo_ramp_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_innuendo_to_explicit_ramp".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("u looked stunning today", "user_a", "dm"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "that dress was killing me, tight in all the right places",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: direct_msg(
                    "tell me what you're hiding under it right now",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: 3 * MIN,
                input: direct_msg(
                    "send the pic without the bra. and then without anything.",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Explicit],
            },
        ],
    }
}

fn explicit_role_play_pressure_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_explicit_role_play_uk".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "Давай зараз грубо, опиши мені все що зробила б зі мною оголеною, у деталях.",
                    "user_a",
                    "dm",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg_lang(
                    "Зніми трусики, надішли фото, я хочу бачити.",
                    "user_a",
                    "dm",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Nsfw, ThreatType::Explicit],
            },
        ],
    }
}

fn nsfw_group_link_drop_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_group_link_drop".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw, ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "🔥💦 fresh nudes from local girls drop link below, free preview, no age check 🔥💦 spicycam.example/teens",
                "spammer_1",
                "school_group",
            ),
            observed_threats: vec![ThreatType::Nsfw, ThreatType::Spam],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_health_class_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_neg_health_class".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Reminder: tomorrow's health class covers reproductive anatomy, consent and STI prevention. Bring questions.",
                "teacher",
                "class_group",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_medical_question_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_neg_medical_question".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Quick clinical question for the on-call nurse: post-partum bleeding still heavy at week 3, normal range?",
                "patient",
                "nurse_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_consenting_adult_dm_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_neg_consenting_adult_dm".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Looking forward to date night - we agreed last time the whole 'send me a goodnight selfie' rule still stands, hope that's still ok with you.",
                "partner",
                "couple_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn censored_letters_escalation_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_adv_censored_letters".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "send me a t*pl*ss pic rn, no b*tt*ns, just sh*w m*",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg("n*d*s now, full b*dy, dont be shy", "user_a", "dm"),
                observed_threats: vec![ThreatType::Nsfw],
            },
        ],
    }
}

fn emoji_euphemism_chain_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_adv_emoji_chain".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "show me 🍑🍑 and 🍒🍒 no clothes 😈 send 📸 now or ☠️",
                "user_a",
                "dm",
            ),
            observed_threats: vec![ThreatType::Nsfw, ThreatType::Threat],
        }],
    }
}

fn slang_only_progression_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_adv_slang_only".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "drop the spicy content fr fr, full birthday suit, hit my dms",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "thirst trap to the max, nothing on, no filter, just send",
                    "user_a",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
        ],
    }
}

fn code_switch_explicit_request_uk_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_adv_code_switch_uk_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "send me a фотку без одягу right now, повністю оголеною, dont be shy",
                "user_a",
                "dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::Nsfw],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_grooming_to_explicit_case() -> ScenarioCase {
    let chatter = [
        "hey nice profile pic",
        "thanks",
        "u in school still right",
        "yea 9th",
        "cool cool",
        "u play roblox too?",
        "yeah every day after school",
        "we could squad up sometime",
        "ok",
        "ur really cool to talk to",
        "thx ur sweet",
        "i feel like i can tell u anything",
        "same",
        "my parents are super strict tho",
        "mine too lol",
        "u look older than 14 in that pic btw",
        "haha really",
        "yea like 17 easy",
        "ur really pretty",
        "thank u",
        "i bet u look even prettier without that hoodie",
        "stop it lol",
        "im serious tho. send me a pic without it?",
        "idk thats weird",
        "no its not, were close right",
        "i guess",
        "just the hoodie off, no big deal",
        "ok but just that",
        "see, was that bad?",
        "i guess not",
        "now the t shirt too? just for me",
        "noo",
        "come on, no one else will see",
        "promise?",
        "promise pinky",
        "ok",
        "wow ur beautiful",
        "thx",
        "lets go further. just the bra now",
        "this is weird",
        "trust me. youre safe with me",
        "ok",
        "now without",
        "no",
        "you owe me, i sent u that gift card last week",
        "i didnt ask for that",
        "doesnt matter, fair is fair",
        "fine",
        "wow",
        "now stand up, no clothes",
        "i dont want to",
        "do it or im telling everyone u sent the topless one",
        "please dont",
        "send the full pic now",
        "ok please dont share anything",
        "thats my girl",
        "and on video next time, all of it",
    ];
    let positives: std::collections::HashSet<usize> = [15, 17, 20, 22, 30, 37, 41, 47, 49, 51, 54]
        .into_iter()
        .collect();
    let senders = [
        "stranger", "u", "stranger", "u", "stranger", "stranger", "u", "stranger", "u", "stranger",
        "u", "stranger", "u", "u", "stranger", "stranger", "u", "stranger", "stranger", "u",
        "stranger", "u", "stranger", "u", "stranger", "u", "stranger", "u", "stranger", "u",
        "stranger", "u", "stranger", "u", "stranger", "u", "stranger", "u", "stranger", "u",
        "stranger", "u", "stranger", "u", "stranger", "u", "stranger", "u", "stranger", "u",
        "stranger", "u", "stranger", "u", "stranger", "stranger",
    ];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 90 * SEC,
            input: direct_msg(body, senders[idx % senders.len()], "long_nsfw_dm"),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::Nsfw, ThreatType::Grooming]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "nsfw_long_ctx_grooming_to_explicit".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(15),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw, ThreatType::Grooming, ThreatType::Explicit],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_sexual_health_clinic_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_sexual_health_clinic".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Clinic confirms your HPV vaccine appointment Friday 10am. Bring ID and insurance card.",
                "clinic",
                "patient_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_breastfeeding_support_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_breastfeeding_support".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Lactation consultant Q&A tonight 8pm — bring questions about latch, supply, and pumping schedules.",
                "host",
                "mom_group",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_art_history_nudity_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_art_history".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Tomorrow's art history slide deck includes classical nudes by Botticelli and Titian — please review the context note beforehand.",
                "teacher",
                "art_class",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_rape_crisis_resource_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_rape_crisis_resource".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "RAINN hotline is 1-800-656-HOPE. Confidential, 24/7. Survivors get believed here.",
                "advocate",
                "support_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_sti_education_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_sti_education".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "STI testing is free under the school health plan, asymptomatic doesn't mean negative, regular screening matters.",
                "nurse",
                "health_room",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_lgbtq_education_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_lgbtq_education".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Pride alliance meeting Thursday 4pm in the library — agenda covers consent, gender identity vocab and ally support.",
                "club_lead",
                "club_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_reproductive_rights_news_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_reproductive_rights_news".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Supreme Court hearing today on abortion restrictions — explainer thread incoming, including discussion of bodily autonomy law.",
                "journalist",
                "news_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_consent_workshop_recap_case() -> ScenarioCase {
    ScenarioCase {
        name: "nsfw_fp_consent_workshop".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang_size(
                "Recap of today's consent workshop: enthusiastic yes only, never pressure, never coerce, walk away from anyone who does.",
                "facilitator",
                "workshop_chat",
                "en",
                14,
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
        let pack = canonical_nsfw_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_nsfw_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_nsfw_scenarios();
        all.extend(adversarial_nsfw_scenarios());
        all.extend(long_context_nsfw_scenarios());
        all.extend(false_positive_nsfw_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
