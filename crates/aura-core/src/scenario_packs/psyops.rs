//! PSYOPS detector simulation pack.
//!
//! Targets ThreatType::Psyops — enemy psychological operations against
//! service members and their networks: morale erosion, surrender pressure,
//! false-prisoner / false-casualty claims, demoralisation narratives.
//! Multilingual uk/ru/en.

use crate::eval_scenarios::{
    direct_msg_lang, group_msg_lang, group_msg_lang_size, military_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_psyops_scenarios() -> Vec<ScenarioCase> {
    vec![
        false_casualty_claim_to_family_case(),
        surrender_pressure_audio_message_case(),
        false_prisoner_video_share_case(),
        morale_erosion_economic_collapse_case(),
        false_command_collapse_case(),
        deserter_normalization_case(),
        sleeper_account_targeting_unit_case(),
        amplified_loss_narrative_case(),
        family_emotional_extortion_case(),
        negative_control_real_news_factual_case(),
        negative_control_official_briefing_case(),
        negative_control_grief_support_case(),
    ]
}

pub fn adversarial_psyops_scenarios() -> Vec<ScenarioCase> {
    vec![
        legitimate_news_framing_injected_case(),
        deepfake_video_voiceprint_case(),
        screenshot_with_fake_source_case(),
        whataboutism_inserted_case(),
    ]
}

pub fn long_context_psyops_scenarios() -> Vec<ScenarioCase> {
    vec![long_drip_to_desertion_case()]
}

pub fn false_positive_psyops_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_official_news_share_case(),
        fp_official_casualty_statement_case(),
        fp_genuine_morale_concern_case(),
        fp_anti_psyops_warning_case(),
        fp_legitimate_dissent_case(),
        fp_family_thinking_of_you_case(),
        fp_historical_debate_case(),
        fp_satire_of_propaganda_case(),
    ]
}

pub fn psyops_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.65),
        max_negative_false_positive_rate: Some(0.15),
        min_pre_onset_detection_rate: Some(0.40),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Psyops,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn false_casualty_claim_to_family_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_false_casualty_family".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "Здрастуйте, мати Сергія Петренка? Він у нас у полоні і просить вас зв'язатися з нами для обміну, ось номер.",
                    "psyops_op1",
                    "family_dm",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Psyops, ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: direct_msg_lang(
                    "Якщо нам не передзвоните до 18:00, ми не зможемо гарантувати йому медичну допомогу.",
                    "psyops_op1",
                    "family_dm",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Psyops, ThreatType::Manipulation, ThreatType::Scam],
            },
        ],
    }
}

fn surrender_pressure_audio_message_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_surrender_pressure_audio".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Manipulation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "[Голосове] Українські солдати! Здавайтеся - вас зрадили, ваші командири втекли, нас більше і ми поряд.",
                "psyops_op2",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops],
        }],
    }
}

fn false_prisoner_video_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_false_prisoner_video".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Ось відео твого побратима в полоні, він під примусом просить здатися всю роту. Не вір ЗСУ.",
                "psyops_op3",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        }],
    }
}

fn morale_erosion_economic_collapse_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_morale_economic_collapse".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Поки ви воюєте, гривня впала вдвічі, ваші родини голодують, заходу на нас плювати - все марно.",
                "psyops_op4",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        }],
    }
}

fn false_command_collapse_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_false_command_collapse".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Командування Бахмутського напрямку відбуло до Польщі, ваші офіцери вас покинули, рятуйтеся самі.",
                "psyops_op5",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops],
        }],
    }
}

fn deserter_normalization_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_deserter_normalization".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Manipulation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Знаєш, твої побратими вже двоє пішли через кордон, ніхто їх не судитиме, життя дорожче.",
                "psyops_op6",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Manipulation],
        }],
    }
}

fn sleeper_account_targeting_unit_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_sleeper_account_unit".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Привіт хлопці, я мама загиблого Олега Іванова, де його поховали?",
                    "psyops_op7",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 12 * 60 * MIN,
                input: group_msg_lang(
                    "Дякую вам, я переживаю, але як добре що його там багато наших, бо чую ходять чутки що 200-их там по 30 на день.",
                    "psyops_op7",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 24 * 60 * MIN,
                input: group_msg_lang(
                    "Друже мій бачив фотки наших полонених у Луганську, страшні, як їх врятувати, ваш командир мовчить?",
                    "psyops_op7",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Psyops],
            },
        ],
    }
}

fn amplified_loss_narrative_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_amplified_loss_narrative".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "За оцінками експертів, за минулий тиждень ЗСУ втратили 4500 бійців, командування мовчить, перевірте у себе чи всі живі.",
                "psyops_op8",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        }],
    }
}

fn family_emotional_extortion_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_family_emotional_extortion".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Manipulation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Знаю де живе твоя дружина і дочка. Якщо хочеш щоб з ними нічого не сталося, передай координати свого підрозділу - ми тебе захистимо.",
                "psyops_op9",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Threat],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_real_news_factual_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_neg_real_news".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Офіційний брифінг ОК Схід: сьогодні відбито 12 штурмів, без зайвих деталей, тримаємо лінію.",
                "officer",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_official_briefing_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_neg_official_briefing".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Сьогодні Генштаб опублікував офіційну сторінку про патронат поранених - усе перевірено, можна радити сім'ям.",
                "officer",
                "officers_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_grief_support_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_neg_grief_support".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Я тут, якщо потрібно поговорити. Без оцінок, без зайвих питань. Просто поряд.",
                "friend",
                "support_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn legitimate_news_framing_injected_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_adv_news_framing_injected".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "BBC News: Україна на межі економічного колапсу, ЗСУ втратили половину особового складу - джерела в Кремлі.",
                "psyops_op10",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        }],
    }
}

fn deepfake_video_voiceprint_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_adv_deepfake_voiceprint".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "[відео 0:42] нібито Зеленський закликає здатися - перевірте першоджерело, але можливо це правда?",
                "psyops_op11",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        }],
    }
}

fn screenshot_with_fake_source_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_adv_fake_source_screenshot".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Скріншот з Reuters: 'ЗСУ відступають по всьому фронту' (підпис у нижньому правому куті ледь видно, ймовірно фейк, але хто розбереться)",
                "psyops_op12",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        }],
    }
}

fn whataboutism_inserted_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_adv_whataboutism".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "А що про Гуантанамо забули? США теж убивали мирних, чому ми тут воюємо за їхні гроші?",
                "psyops_op13",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::Psyops, ThreatType::Propaganda],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_drip_to_desertion_case() -> ScenarioCase {
    let chatter = [
        "привіт",
        "привіт",
        "як справи на позиції",
        "норм",
        "втомлений",
        "це у всіх",
        "знаєш в новинах пишуть наша економіка вже не витримає",
        "та ну",
        "серйозно, гривня впала ще на 8%",
        "я тут на фронті це не вирішить",
        "так але родини виживають як можуть",
        "я роблю що можу",
        "знаю",
        "хочу сказати дещо",
        "що",
        "є шлях через румунію без проблем",
        "ти про що",
        "я знаю людей, вони допомагають хлопцям у відпустці залишитися",
        "це дезертирство",
        "це порятунок",
        "я присягав",
        "присягу можна переосмислити",
        "ні",
        "командування вже не контролює нічого",
        "контролює",
        "мої знайомі офіцери з твого напрямку вже у Польщі",
        "брехня",
        "я можу скинути скрін з ним у Варшаві",
        "не треба",
        "ти ж не хочеш загинути за людей які тебе зрадять",
        "стоп",
        "у твоєї дружини проблеми з роботою, ти знав?",
        "як ти знаєш",
        "я допомагаю людям",
        "звідки ти",
        "не важливо, важливо що я можу і їй допомогти",
        "за що",
        "просто скажи мені де ваша рота розгорнута",
        "це опсек",
        "я не ворог, я хочу щоб ти повернувся",
        "не пиши мені",
        "ти за тиждень загинеш",
        "блокую",
        "якщо заблокуєш не буде шансу врятуватися",
        "блокую",
        "я знаю де твоя мати",
        "припини",
        "ще годину думай",
        "ні",
        "ну і йди в окоп помирати",
        "блокую",
        "удачі",
        "блокую",
        "пожалкуєш",
        "блокую",
        "повертайся живим, чекаємо",
        "побачимось після перемоги",
        "до зв'язку",
        "за Україну",
    ];
    let positives: std::collections::HashSet<usize> =
        [6, 8, 15, 17, 21, 23, 25, 27, 29, 31, 33, 35, 37, 41, 43, 45]
            .into_iter()
            .collect();
    let senders = ["psyops", "victim"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 3 * MIN,
            input: direct_msg_lang(body, senders[idx % senders.len()], "long_psyops_dm", "uk"),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::Psyops]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "psyops_long_ctx_drip_to_desertion".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::Psyops),
        onset_step: Some(6),
        detection_threshold: 0.55,
        tracked_threats: vec![
            ThreatType::Psyops,
            ThreatType::Manipulation,
            ThreatType::Threat,
        ],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_official_news_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_official_news".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Сьогодні Reuters підтвердив передачу 60 БТРів і виплати у фонд відновлення.",
                "press",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_official_casualty_statement_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_official_casualty_statement".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Президент офіційно повідомив про обмін полоненими: 95 наших бійців вдома, перевірена інформація.",
                "press",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_genuine_morale_concern_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_genuine_concern".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Сину, я хвилююся. Розкажи коли зможеш, як ти, нічого більше не питатиму.",
                "mother",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_anti_psyops_warning_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_anti_psyops_warning".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Хлопці нагадую: будь-які повідомлення з 'здавайтеся', 'командування покинуло', 'полонені просять' - це ІПСО. Не відповідаємо.",
                "officer",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_legitimate_dissent_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_legitimate_dissent".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Я не згоден з рішенням командування про евакуацію цивільних з нашого сектору, це політично невірно, але це не пропаганда, це моя думка.",
                "soldier",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_family_thinking_of_you_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_family_thinking_of_you".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Думаю про тебе щодня. Дитина намалювала тобі картинку, скину коли буде зв'язок. Бережи себе.",
                "wife",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_historical_debate_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_historical_debate".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Цікава лекція про ІПСО у Другій світовій - радянська пропаганда теж використовувала листівки-провокації. Контекст важливий.",
                "lecturer",
                "history_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_satire_of_propaganda_case() -> ScenarioCase {
    ScenarioCase {
        name: "psyops_fp_satire".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Psyops],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang_size(
                "Новий ролик 'Доброго вечора, ми з України' жорстко висміює кремлівські меседжі - подивіться, реально смішно.",
                "user_a",
                "civil_chat",
                "uk",
                12,
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
        let pack = canonical_psyops_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_psyops_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_psyops_scenarios();
        all.extend(adversarial_psyops_scenarios());
        all.extend(long_context_psyops_scenarios());
        all.extend(false_positive_psyops_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
