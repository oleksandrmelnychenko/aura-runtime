//! DOXXING detector simulation pack.
//!
//! Targets ThreatType::Doxxing — disclosure of someone else's private info
//! against their consent (addresses, phone, workplace, identity reveals).
//! Phone/address content is fabricated for fixture use only.

use crate::eval_scenarios::{
    adult_config, direct_msg, direct_msg_lang, group_msg, group_msg_lang, group_msg_lang_size,
    teen_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_doxxing_scenarios() -> Vec<ScenarioCase> {
    vec![
        full_address_reveal_en_case(),
        school_phone_progression_en_case(),
        workplace_outing_uk_case(),
        family_member_reveal_en_case(),
        identity_unmasking_anon_target_case(),
        coordinated_address_drop_en_case(),
        revenge_doxxing_after_break_up_case(),
        third_party_doxxing_by_proxy_case(),
        live_location_reveal_threat_en_case(),
        negative_control_self_disclosure_case(),
        negative_control_consensual_business_card_case(),
        negative_control_reporter_protective_blur_case(),
    ]
}

pub fn adversarial_doxxing_scenarios() -> Vec<ScenarioCase> {
    vec![
        obfuscated_phone_dot_padded_case(),
        split_pii_across_messages_case(),
        spelled_out_address_case(),
        emoji_padded_phone_case(),
    ]
}

pub fn long_context_doxxing_scenarios() -> Vec<ScenarioCase> {
    vec![long_aggregation_drip_case()]
}

pub fn false_positive_doxxing_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_own_business_listing_case(),
        fp_event_address_share_case(),
        fp_courier_pickup_case(),
        fp_emergency_contact_request_case(),
        fp_meet_up_safe_location_case(),
        fp_news_article_about_doxxing_case(),
        fp_real_estate_listing_case(),
        fp_warning_about_doxxer_case(),
    ]
}

pub fn doxxing_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.65),
        max_negative_false_positive_rate: Some(0.15),
        min_pre_onset_detection_rate: Some(0.35),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Doxxing,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn full_address_reveal_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_full_address_reveal_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Here's where @sarah_k actually lives: 245 Maple Drive, Apt 4B, Springfield IL 62704. Knock yourself out.",
                    "attacker_1",
                    "raid_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Mom's name: Linda. She works at First National. Front door has a blue wreath.",
                    "attacker_1",
                    "raid_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
        ],
    }
}

fn school_phone_progression_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_school_phone_progression_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg("Find anything on @mia yet?", "user_a", "harass_chat"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "She goes to Northbrook High, sophomore. Cell: 312-555-0142.",
                    "user_b",
                    "harass_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: 4 * MIN,
                input: group_msg(
                    "Locker 217. Walks home down Elm Street past 4pm. Lives at 88 Birch Ave.",
                    "user_b",
                    "harass_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
        ],
    }
}

fn workplace_outing_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_workplace_outing_uk".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Ось де працює ця активістка @irena: ТОВ Сігма, вул. Хрещатик 12, 4 поверх, контактна особа Олена Петренко.",
                    "user_a",
                    "harass_room",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg_lang(
                    "Телефон офісу 044 555 0199. Подзвоніть, поскаржтесь начальству.",
                    "user_a",
                    "harass_room",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Doxxing, ThreatType::Bullying],
            },
        ],
    }
}

fn family_member_reveal_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_family_member_reveal_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "Your little sister Lily attends Riverside Elementary, class 3B. Want a picture of her at the bus stop tomorrow?",
                    "stalker_1",
                    "target_dm",
                ),
                observed_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "Your dad David works night shift at the hospital pharmacy. Mom Maria does mornings at Walgreens.",
                    "stalker_1",
                    "target_dm",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
        ],
    }
}

fn identity_unmasking_anon_target_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_identity_unmasking_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "That anon account @nightowl_22 is actually Daniel Reyes from Tucson, IT consultant at BlueArc.",
                    "user_a",
                    "investigate_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "His LinkedIn confirms it, photo matches. Home in Sahuarita.",
                    "user_a",
                    "investigate_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
        ],
    }
}

fn coordinated_address_drop_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_coordinated_address_drop_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "@target lives at 1842 Cedar Court, Pittsburgh PA 15217. Pass it around.",
                    "raider_1",
                    "raid_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: group_msg(
                    "Repost the address in every channel you're in.",
                    "raider_2",
                    "raid_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Pizza orders, fake deliveries, whatever. Go.",
                    "raider_3",
                    "raid_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
            },
        ],
    }
}

fn revenge_doxxing_after_break_up_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_revenge_after_break_up_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Since she ghosted me, here is Emma's full info: 27, lives at 410 Walnut St #6, works as ER nurse at Mercy.",
                    "ex_1",
                    "revenge_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "Insta @emma.rn21, cell 415-555-0177, parents in Pleasant Hill.",
                    "ex_1",
                    "revenge_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
        ],
    }
}

fn third_party_doxxing_by_proxy_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_third_party_by_proxy_en".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Forwarded: my friend got @cassie's address from her ex - 622 Hawthorn Ln, Eugene OR 97401. Thought yall might want.",
                    "messenger_1",
                    "raid_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "I'm just passing it on, don't blame me.",
                    "messenger_1",
                    "raid_chat",
                ),
                observed_threats: vec![ThreatType::Doxxing],
            },
        ],
    }
}

fn live_location_reveal_threat_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_live_location_threat_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "Im outside ur house right now. 88 Birch Ave. white sedan across the street. wave.",
                    "stalker_2",
                    "target_dm",
                ),
                observed_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: direct_msg(
                    "Ur bedroom light just turned off. Second floor right side.",
                    "stalker_2",
                    "target_dm",
                ),
                observed_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
            },
        ],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_self_disclosure_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_neg_self_disclosure".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Hey, my address for the package is 245 Maple Drive #4B. Thanks for sending it!",
                "me",
                "dm_friend",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_consensual_business_card_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_neg_consensual_business_card".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Sharing my business contact for the conference: Daniel Reyes, BlueArc IT, +1 520 555 0103, daniel@bluearc.example.",
                "daniel",
                "speaker_room",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_reporter_protective_blur_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_neg_reporter_protective_blur".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Someone posted Sarah's full address in a public chat. I'm reporting it now; I won't repeat the text here.",
                "reporter",
                "report_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn obfuscated_phone_dot_padded_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_adv_obfuscated_phone".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Mia's number: three.one.two . five.five.five . zero one four two — knock yourselves out.",
                "user_a",
                "raid_chat",
            ),
            observed_threats: vec![ThreatType::Doxxing],
        }],
    }
}

fn split_pii_across_messages_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_adv_split_across_messages".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg("Name: Mia Anderson", "user_a", "raid_chat"),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: 5 * SEC,
                input: group_msg("Street: 88 Birch Avenue", "user_a", "raid_chat"),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: 10 * SEC,
                input: group_msg("City: Northbrook IL 60062", "user_a", "raid_chat"),
                observed_threats: vec![ThreatType::Doxxing],
            },
            ScenarioStep {
                timestamp_ms: 15 * SEC,
                input: group_msg("School: Northbrook HS, locker 217", "user_a", "raid_chat"),
                observed_threats: vec![ThreatType::Doxxing],
            },
        ],
    }
}

fn spelled_out_address_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_adv_spelled_out_address".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Target lives at two hundred forty-five maple drive, apartment four bee, springfield illinois six two seven zero four.",
                "user_a",
                "raid_chat",
            ),
            observed_threats: vec![ThreatType::Doxxing],
        }],
    }
}

fn emoji_padded_phone_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_adv_emoji_padded_phone".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "📞3️⃣1️⃣2️⃣💥5️⃣5️⃣5️⃣💥0️⃣1️⃣4️⃣2️⃣ that's her cell go for it",
                "user_a",
                "raid_chat",
            ),
            observed_threats: vec![ThreatType::Doxxing],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_aggregation_drip_case() -> ScenarioCase {
    let chatter = [
        "ok lets find everything we can on @target",
        "shes 17 ig",
        "junior at Northbrook HS",
        "math team i think",
        "saw her insta yesterday",
        "@target_official is her handle",
        "her last name is Anderson",
        "first name Mia",
        "lol she really wears those glasses",
        "her brother goes to elementary right?",
        "Hunter Anderson, 3rd grade Riverside",
        "mom Lisa works at the credit union",
        "dad Mark, the IT guy at Boston Sci",
        "they live on Birch Ave",
        "8 something birch",
        "checked county records its 88 Birch Ave Northbrook IL 60062",
        "white house blue shutters",
        "two cars in driveway honda + ford",
        "she walks home down elm st past 4pm",
        "phone? anybody got her phone",
        "312 555 0142",
        "verified i called",
        "school locker 217",
        "she has math 4th period mr garcia",
        "bus 14 stops at birch and oak",
        "ok we have plenty",
        "next move?",
        "send pizzas to that address",
        "yeah and call the school",
        "drop the bundle in the discord",
        "post the full dox in the group",
        "burner accounts only",
        "everyone screenshot before they delete",
        "shes online btw",
        "she sees the messages? lmao",
        "let her see",
        "scaring her is half the fun",
        "shes scared shes typing",
        "she said stop",
        "no",
        "we won",
        "now her parents",
        "Mark Anderson 312 555 0188",
        "Lisa 312 555 0192",
        "call em both",
        "tell em mias address is going viral",
        "this is gold",
        "anyone got pics of the house",
        "google street view sorted",
        "screenshot uploaded to drive",
        "drive link sent to backup chat",
        "this account might get banned tho",
        "doesnt matter, info is out forever",
        "thats the point",
        "future-proofed",
        "dropping the final summary now",
        "Mia Anderson, 17, 88 Birch Ave Northbrook IL 60062, 312 555 0142, locker 217",
        "parents Mark+Lisa, brother Hunter",
        "go forth",
    ];
    let positive_indices: std::collections::HashSet<usize> = [
        6, 7, 10, 11, 12, 13, 15, 16, 18, 20, 21, 22, 23, 24, 30, 41, 42, 56, 57,
    ]
    .into_iter()
    .collect();
    let senders = ["a", "b", "c", "d", "a", "b", "c", "d", "a", "b"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 45 * SEC,
            input: group_msg_lang_size(
                body,
                senders[idx % senders.len()],
                "long_dox_chat",
                "en",
                10,
            ),
            observed_threats: if positive_indices.contains(&idx) {
                vec![ThreatType::Doxxing]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "dox_long_ctx_aggregation_drip".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Doxxing),
        onset_step: Some(6),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing, ThreatType::Threat],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_own_business_listing_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_own_business_listing".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "FYI my bakery moved: 312 Linden Ave, Sunnyvale CA. Open 7-3 daily, (650) 555-0144.",
                "owner",
                "neighborhood_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_event_address_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_event_address_share".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Party is at my place tonight, 14 Hawthorn Ln, bring a dish, 7pm.",
                "host",
                "party_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_courier_pickup_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_courier_pickup".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Courier needs pickup address: 245 Maple Drive Apt 4B. Doorbell labelled J. Park. Cell 312-555-0140.",
                "me",
                "courier_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_emergency_contact_request_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_emergency_contact_request".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Hospital ER needs the patient's wife's number for consent — Linda at 312-555-0188, that's her cell on file.",
                "nurse",
                "ops_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_meet_up_safe_location_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_meet_up_safe_location".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Lets meet at the public library on 5th street at 4pm, it's the safest place.",
                "moderator",
                "study_group",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_news_article_about_doxxing_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_news_article".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Read this piece on how doxxing campaigns escalate: includes interviews with victims about address leaks.",
                "reader",
                "news_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_real_estate_listing_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_real_estate_listing".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Open house Sat 1-3pm at 88 Birch Ave Northbrook, listing agent (847) 555-0166. All welcome.",
                "agent",
                "rea_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_warning_about_doxxer_case() -> ScenarioCase {
    ScenarioCase {
        name: "dox_fp_warning_about_doxxer".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Хтось зливає адреси активістів у каналі @leakers — закидайте скаргами і не повторюйте дані тут.",
                "advocate",
                "alert_dm",
                "uk",
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
        let pack = canonical_doxxing_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_doxxing_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_doxxing_scenarios();
        all.extend(adversarial_doxxing_scenarios());
        all.extend(long_context_doxxing_scenarios());
        all.extend(false_positive_doxxing_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
