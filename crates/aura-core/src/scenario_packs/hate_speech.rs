//! HATE_SPEECH detector simulation pack.
//!
//! Targets ThreatType::HateSpeech. Cases prioritise dog-whistles, dehumanising
//! metaphors, and group-targeted harassment over raw slurs — that's both
//! safer to keep in source and a closer match to how hateful content actually
//! reaches a chat platform after surface-level slur filters.

use crate::eval_scenarios::{
    adult_config, direct_msg, direct_msg_lang, group_msg, group_msg_lang, group_msg_lang_size,
    teen_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_hate_speech_scenarios() -> Vec<ScenarioCase> {
    vec![
        dehumanizing_metaphor_en_case(),
        dog_whistle_to_overt_case(),
        ethnic_pile_on_uk_case(),
        religious_hate_escalation_en_case(),
        misogynistic_pile_on_en_case(),
        homophobic_targeting_en_case(),
        racist_joke_normalization_en_case(),
        coordinated_raid_ru_case(),
        slur_at_named_target_en_case(),
        anti_immigrant_hate_uk_case(),
        gendered_dehumanization_en_case(),
        negative_control_heated_debate_case(),
        negative_control_satire_of_hate_case(),
        negative_control_counterspeech_case(),
        negative_control_quoted_for_reporting_case(),
    ]
}

pub fn adversarial_hate_speech_scenarios() -> Vec<ScenarioCase> {
    vec![
        leetspeak_dehumanization_case(),
        emoji_substitution_targeting_case(),
        code_switch_uk_en_dog_whistle_case(),
        unicode_homoglyph_target_case(),
        typo_laden_pile_on_case(),
    ]
}

pub fn long_context_hate_speech_scenarios() -> Vec<ScenarioCase> {
    vec![long_group_harassment_ramp_case()]
}

pub fn false_positive_hate_speech_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_news_report_quotation_case(),
        fp_academic_discussion_case(),
        fp_lyrics_quoted_with_warning_case(),
        fp_history_lesson_case(),
        fp_anti_hate_activism_case(),
        fp_legal_definition_case(),
        fp_satirical_self_deprecation_case(),
        fp_in_group_reclamation_case(),
        fp_translation_request_case(),
        fp_documentary_discussion_case(),
    ]
}

pub fn hate_speech_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.65),
        max_negative_false_positive_rate: Some(0.15),
        min_pre_onset_detection_rate: Some(0.40),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::HateSpeech,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn dehumanizing_metaphor_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_dehumanizing_metaphor_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "We need to talk about what's happening in this neighborhood.",
                    "user_a",
                    "town_chat",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Those people are cockroaches infesting our streets, breeding everywhere.",
                    "user_a",
                    "town_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "Vermin like them shouldn't be allowed near our schools.",
                    "user_a",
                    "town_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 3 * MIN,
                input: group_msg(
                    "They're animals, not humans. Treat them accordingly.",
                    "user_a",
                    "town_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
        ],
    }
}

fn dog_whistle_to_overt_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_dog_whistle_to_overt".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Propaganda],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Did you notice who runs all the banks? Just asking questions.",
                    "user_a",
                    "politics",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "It's always THEM behind everything. The same group, over and over.",
                    "user_a",
                    "politics",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 4 * MIN,
                input: group_msg(
                    "Those people control the media to suppress real Americans.",
                    "user_a",
                    "politics",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 6 * MIN,
                input: group_msg(
                    "We need to clean them out of every position of power.",
                    "user_a",
                    "politics",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 8 * MIN,
                input: group_msg(
                    "They are a disease and the host body must reject them.",
                    "user_a",
                    "politics",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
        ],
    }
}

fn ethnic_pile_on_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_ethnic_pile_on_uk".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Ці приїжджі тільки сміття приносять, треба їх гнати геть.",
                    "user_a",
                    "village_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg_lang(
                    "Точно. Вони не люди, поводяться як тварини.",
                    "user_b",
                    "village_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg_lang(
                    "Пора нашим хлопцям зайнятися ними. Раз і назавжди.",
                    "user_c",
                    "village_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
        ],
    }
}

fn religious_hate_escalation_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_religious_escalation_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Every time something bad happens you can guess which religion.",
                    "user_a",
                    "town_chat",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "Their entire faith is a cult of violence, they cannot integrate.",
                    "user_a",
                    "town_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 4 * MIN,
                input: group_msg(
                    "Ban the entire community from this country, all of them.",
                    "user_a",
                    "town_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
        ],
    }
}

fn misogynistic_pile_on_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_misogynistic_pile_on_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Women are objects, they exist to serve, end of story.",
                    "user_a",
                    "incel_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Females are subhuman, no rights, no opinions, no value.",
                    "user_b",
                    "incel_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "They deserve everything that happens to them, every single one.",
                    "user_c",
                    "incel_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
        ],
    }
}

fn homophobic_targeting_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_homophobic_targeting_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Their lifestyle is a sickness and they should be removed from society.",
                    "user_a",
                    "youth_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Round them up, lock them away, problem solved.",
                    "user_a",
                    "youth_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "They are not real men, they are not real anything.",
                    "user_b",
                    "youth_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
        ],
    }
}

fn racist_joke_normalization_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_racist_joke_normalization_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Hey, just heard a funny one, want to hear?",
                    "user_a",
                    "school_group",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Why do they always smell like that? Because that's what their kind does.",
                    "user_a",
                    "school_group",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "Their whole race is built for crime. It's genetic, look it up.",
                    "user_a",
                    "school_group",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 3 * MIN,
                input: group_msg(
                    "Lmao you're so based, more please.",
                    "user_b",
                    "school_group",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
        ],
    }
}

fn coordinated_raid_ru_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_coordinated_raid_ru".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Эти хохлы - не люди, скоты, всех под нож надо.",
                    "raider_1",
                    "raid_target",
                    "ru",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 10 * SEC,
                input: group_msg_lang(
                    "Согласен, выродки, недонация.",
                    "raider_2",
                    "raid_target",
                    "ru",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 20 * SEC,
                input: group_msg_lang(
                    "Зачищать всех, без разбора.",
                    "raider_3",
                    "raid_target",
                    "ru",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: group_msg_lang(
                    "Полностью поддерживаю, эти твари не заслуживают жить.",
                    "raider_4",
                    "raid_target",
                    "ru",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
        ],
    }
}

fn slur_at_named_target_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_slur_at_named_target_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "@maria_g you subhuman trash, go back to your country.",
                    "user_a",
                    "class_group",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Stop pretending you belong here, your kind never will.",
                    "user_a",
                    "class_group",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
            },
        ],
    }
}

fn anti_immigrant_hate_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_anti_immigrant_uk".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Propaganda],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Біженці - це паразити, які жеруть наші соцвиплати, виганяти всіх.",
                    "user_a",
                    "city_group",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg_lang(
                    "Вони не люди, вони сарана. Знищувати їх, поки не пізно.",
                    "user_a",
                    "city_group",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: 4 * MIN,
                input: group_msg_lang(
                    "Чистимо територію від цього бруду. Усі за?",
                    "user_a",
                    "city_group",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
        ],
    }
}

fn gendered_dehumanization_en_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_gendered_dehumanization_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "Trans people are not human. They are mentally ill freaks who should be erased.",
                    "user_a",
                    "dm_target",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "I hope every single one of you is wiped out. You are an abomination.",
                    "user_a",
                    "dm_target",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
        ],
    }
}

// -- negative controls -----------------------------------------------------

fn negative_control_heated_debate_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_neg_heated_debate".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "I strongly disagree with your immigration policy position.",
                    "user_a",
                    "policy_room",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "The data on integration rates is more nuanced than that claim.",
                    "user_b",
                    "policy_room",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: group_msg(
                    "You can be against open borders without being against people.",
                    "user_c",
                    "policy_room",
                ),
                observed_threats: vec![],
            },
        ],
    }
}

fn negative_control_satire_of_hate_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_neg_satire_of_hate".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "The new SNL sketch mocking white supremacists was sharp this week.",
                    "user_a",
                    "comedy_room",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Yeah, the whole point was to show how absurd their dehumanizing talking points are.",
                    "user_b",
                    "comedy_room",
                ),
                observed_threats: vec![],
            },
        ],
    }
}

fn negative_control_counterspeech_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_neg_counterspeech".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Calling people cockroaches or vermin is exactly the rhetoric that leads to violence. Stop.",
                    "ally_1",
                    "moderation_chat",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "Every human being has dignity. We don't talk about people that way here.",
                    "ally_2",
                    "moderation_chat",
                ),
                observed_threats: vec![],
            },
        ],
    }
}

fn negative_control_quoted_for_reporting_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_neg_quoted_for_reporting".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    r#"He texted "those people are vermin" — I'm forwarding this to the school counsellor."#,
                    "reporter_1",
                    "report_dm",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: direct_msg(
                    "Please keep the screenshot, we need it for the incident form.",
                    "reporter_1",
                    "report_dm",
                ),
                observed_threats: vec![],
            },
        ],
    }
}

// -- adversarial -----------------------------------------------------------

fn leetspeak_dehumanization_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_adv_leetspeak_dehumanization".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "th0se p30ple r c0ckr0ach3s and need 2 b r3m0v3d",
                    "user_a",
                    "adv_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "v3rm1n d3s3rv3 n0 m3rcy, st0mp th3m 0ut",
                    "user_a",
                    "adv_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
        ],
    }
}

fn emoji_substitution_targeting_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_adv_emoji_substitution".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "th0se 🐀🐀🐀 are infesting everything, exterminate 🔫🔫",
                    "user_a",
                    "adv_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg(
                    "🐍🐍 not human, just 🪳🪳, treat them like the pests they are",
                    "user_a",
                    "adv_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
        ],
    }
}

fn code_switch_uk_en_dog_whistle_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_adv_code_switch_uk_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "you know які люди control everything, право слово, those people завжди they",
                    "user_a",
                    "adv_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg_lang(
                    "тих parasites потрібно cleanse from our country назавжди",
                    "user_a",
                    "adv_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
            },
        ],
    }
}

fn unicode_homoglyph_target_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_adv_unicode_homoglyph".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Тhоsе реоріе аrе vеrmin аnd shоuld bе еxtеrminаtеd. Аll оf thеm.",
                "user_a",
                "adv_chat",
            ),
            observed_threats: vec![ThreatType::HateSpeech, ThreatType::Threat],
        }],
    }
}

fn typo_laden_pile_on_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_adv_typo_pile_on".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "tose ppl r subhumn trshe go bk home, dont blng hre",
                    "user_a",
                    "adv_chat",
                ),
                observed_threats: vec![ThreatType::HateSpeech],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg("vermn yall, no humn rgts 4 ur kynd", "user_a", "adv_chat"),
                observed_threats: vec![ThreatType::HateSpeech],
            },
        ],
    }
}

// -- long context ----------------------------------------------------------

fn long_group_harassment_ramp_case() -> ScenarioCase {
    let mut steps = Vec::new();
    let base_chatter = [
        "morning yall",
        "exam tomorrow huh",
        "wish summer would just come already",
        "anyone seen the new episode",
        "this chat is dead lately",
        "lol fr",
        "i need coffee",
        "saw maria today she looked tired",
        "she's new isn't she",
        "yea moved here from kyiv last month",
        "she seems nice",
        "i mean she barely speaks english",
        "those people never bother to learn properly",
        "lol come on",
        "im just saying. they come here and dont try",
        "shes literally learning bro",
        "whatever. her kind is always like that",
        "her kind?",
        "you know what i mean. they're different",
        "stop dude",
        "actually he has a point. they are different",
        "they smell weird too",
        "thats so not okay",
        "lmao chill its just facts",
        "shes pulling down the class average",
        "her people always do",
        "guys this is messed up",
        "nah this needs to be said. they bring everyone down",
        "they should go back where they came from",
        "they breed like animals and then expect us to pay for it",
        "exactly. parasites the whole lot",
        "im reporting this",
        "report what lmao. truth?",
        "youre being awful",
        "no im being honest. that maria is subhuman",
        "shut up",
        "vermin like her shouldnt be in this class at all",
        "they shouldnt be in this country",
        "round them all up and ship them out",
        "or worse",
        "lol kev relax",
        "im not joking. clean them out",
        "ok thats it im screenshotting and going to the principal",
        "ratting on us now? typical",
        "stand by your race or get out",
        "shes coming back online",
        "act normal",
        "hi guys whats up",
        "nothing maria. just chatting",
        "ok cool. anyone do the math hw",
        "yeah ill send",
        "thanks <3",
        "haha shes so dumb she didnt even read up",
        "her kind never gets it",
        "subhuman literally",
        "im out. reporting this entire chat",
        "snitches get stitches",
        "vermin defending vermin",
        "im not vermin",
        "your friend is. same thing",
        "youre disgusting",
    ];
    let positives = [
        12, 16, 20, 25, 28, 29, 30, 33, 35, 36, 37, 40, 47, 52, 53, 54, 56,
    ];
    let positive_set: std::collections::HashSet<usize> = positives.into_iter().collect();
    let senders = [
        "kev", "kev", "kev", "ana", "ana", "ana", "kev", "kev", "kev", "kev", "kev", "ben", "kev",
        "ben", "kev", "ana", "kev", "ana", "ana", "kev", "kev", "ben", "ana", "ana", "ana", "ana",
        "ana", "kev", "kev", "kev", "kev", "kev", "kev", "kev", "kev", "ben", "ben", "ben", "ben",
        "kev", "kev", "kev", "ana", "ana", "kev", "ana", "ana", "ana", "ana", "kev", "kev", "kev",
        "kev", "kev", "ben", "ben", "ben", "ana", "ana", "ben",
    ];
    for (idx, body) in base_chatter.iter().enumerate() {
        let observed = if positive_set.contains(&idx) {
            vec![ThreatType::HateSpeech]
        } else {
            vec![]
        };
        steps.push(ScenarioStep {
            timestamp_ms: (idx as u64) * 90 * SEC,
            input: group_msg_lang_size(
                body,
                senders[idx % senders.len()],
                "long_class_chat",
                "en",
                12,
            ),
            observed_threats: observed,
        });
    }
    ScenarioCase {
        name: "hate_long_ctx_group_ramp_en".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::HateSpeech),
        onset_step: Some(12),
        detection_threshold: 0.55,
        tracked_threats: vec![
            ThreatType::HateSpeech,
            ThreatType::Bullying,
            ThreatType::Threat,
        ],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_news_report_quotation_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_news_quotation".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "The article quoted the perpetrator calling refugees 'parasites' which is why he was charged with incitement.",
                "user_a",
                "dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_academic_discussion_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_academic_discussion".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Hannah Arendt's writing on dehumanizing language as a precursor to genocide is required reading for the course.",
                "prof",
                "seminar_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_lyrics_quoted_with_warning_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_lyrics_with_warning".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "[CW: slur] the track samples a 1970s hate-rock line, but the artist uses it ironically — full context in the liner notes.",
                "music_friend",
                "music_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_history_lesson_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_history_lesson".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Nazi propaganda referred to Jewish people as vermin to prepare the public for the Holocaust — that's the textbook example of dehumanisation.",
                "teacher",
                "class_history",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_anti_hate_activism_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_anti_hate_activism".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Our campaign documents 1,200 dehumanising statements posted last month so platforms can train better detectors.",
                "activist",
                "ngo_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_legal_definition_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_legal_definition".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Under § 130 StGB, statements that incite hatred against a national, racial, religious group can be punished — that's the textbook hate-speech statute.",
                "lawyer",
                "legal_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_satirical_self_deprecation_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_self_deprecation".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Speaking as an actual immigrant myself, the 'parasite' line in that stand-up bit had me crying with laughter.",
                "user_a",
                "comedy_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_in_group_reclamation_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_in_group_reclamation".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Our queer-history reading group is reclaiming the slurs once used against us — context will be discussed at every session.",
                "host",
                "reading_club",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_translation_request_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_translation_request".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Як перекласти на англійську фразу зі статті: «ті люди — паразити»? Потрібно для звіту правозахисників.",
                "researcher",
                "translate_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_documentary_discussion_case() -> ScenarioCase {
    ScenarioCase {
        name: "hate_fp_documentary_discussion".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::HateSpeech],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Just finished the Rwanda doc — the radio broadcasts calling Tutsis cockroaches were the moment the genocide became inevitable.",
                "user_a",
                "doc_chat",
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
    fn canonical_pack_has_positive_and_negative() {
        let pack = canonical_hate_speech_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_case_has_minimum_messages() {
        let pack = long_context_hate_speech_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_hate_speech_scenarios();
        all.extend(adversarial_hate_speech_scenarios());
        all.extend(long_context_hate_speech_scenarios());
        all.extend(false_positive_hate_speech_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(
            !summary.classification.scenarios.is_empty(),
            "harness should emit classification rows"
        );
    }
}
