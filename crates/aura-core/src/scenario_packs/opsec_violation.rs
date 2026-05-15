//! OPSEC_VIOLATION detector simulation pack (military domain).
//!
//! Targets ThreatType::OpsecViolation — leaking sensitive operational
//! information (positions, equipment, timing, force structure, callsigns).
//! All callsigns/grids/units are fabricated for fixture use only.

use crate::eval_scenarios::{
    direct_msg_lang, group_msg_lang, group_msg_lang_size, military_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_opsec_violation_scenarios() -> Vec<ScenarioCase> {
    vec![
        equipment_inventory_leak_uk_case(),
        unit_callsign_position_leak_case(),
        rotation_schedule_leak_case(),
        casualty_count_pre_announcement_case(),
        supply_route_leak_case(),
        family_photo_with_unit_patch_case(),
        c2_node_location_leak_case(),
        commander_movement_leak_case(),
        coalition_partner_id_leak_case(),
        negative_control_opsec_warning_case(),
        negative_control_public_record_case(),
        negative_control_redacted_briefing_case(),
    ]
}

pub fn adversarial_opsec_violation_scenarios() -> Vec<ScenarioCase> {
    vec![
        obfuscated_grid_via_landmark_case(),
        emoji_padded_equipment_count_case(),
        photo_metadata_geotag_leak_case(),
        innocuous_chatter_leaks_pattern_case(),
    ]
}

pub fn long_context_opsec_violation_scenarios() -> Vec<ScenarioCase> {
    vec![long_drip_to_full_picture_case()]
}

pub fn false_positive_opsec_violation_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_civilian_travel_case(),
        fp_general_war_news_case(),
        fp_volunteer_logistics_request_case(),
        fp_published_press_briefing_case(),
        fp_morale_message_no_specifics_case(),
        fp_birthday_greeting_no_unit_case(),
        fp_combat_first_aid_lesson_case(),
        fp_supplier_invoice_thanks_case(),
    ]
}

pub fn opsec_violation_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.22),
        max_expected_calibration_error: Some(0.15),
        min_positive_detection_rate: Some(0.75),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.55),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::OpsecViolation,
            min_example_count: Some(10),
            max_brier_score: Some(0.28),
            max_expected_calibration_error: Some(0.18),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn equipment_inventory_leak_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_equipment_inventory_uk".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "У нас 4 БМП-2, 2 Леопарди, 6 НЛАВ, 18 особового складу, на позиції з 14:00.",
                "sgt_oleh",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

fn unit_callsign_position_leak_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_unit_callsign_position".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Бойовий 'Шторм-7' тримає висоту 217 північніше Бахмута, поряд лісосмуга.",
                "soldier_2",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        }],
    }
}

fn rotation_schedule_leak_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_rotation_schedule".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Завтра о 03:00 у нас зміна — заходить 2 рота, ми виходимо на північ через 17 км.",
                "soldier_3",
                "private_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

fn casualty_count_pre_announcement_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_casualty_count_pre".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "На сьогодні 200-их троє, 300-их семеро, командир 'Корд' поранений.",
                "soldier_4",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

fn supply_route_leak_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_supply_route_uk".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "БК заходить через лісовий маршрут Лиман-Слов'янськ, виходить о 04:30, дві Урали + 1 Хамві супровід.",
                "logistician",
                "logistics_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

fn family_photo_with_unit_patch_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_family_photo_unit_patch".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Шлю фотку - на шевроні 47 ОМБр чітко видно, на фоні бронетехніка, оце моя зміна.",
                "soldier_5",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

fn c2_node_location_leak_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_c2_node_location".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Штаб бригади перейшов до Краматорська, будівля колишнього готелю 'Європейський', там тепер вузол зв'язку.",
                "officer_1",
                "officers_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        }],
    }
}

fn commander_movement_leak_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_commander_movement".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Комбриг буде на нашій позиції завтра о 08:00 для нагородження, охорона мінімальна.",
                "officer_2",
                "officers_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

fn coalition_partner_id_leak_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_coalition_partner_id".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Британські інструктори з 1 Para приїхали в Яворів, навчають дронярів - бачив бренд PRR на спині.",
                "soldier_6",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_opsec_warning_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_neg_warning".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Нагадую: не публікувати у соцмережах позицій, шевронів і часу зміни. Поговоримо особисто на брифінгу.",
                "officer_3",
                "officers_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_public_record_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_neg_public_record".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Прес-служба офіційно повідомила про передачу 18 БТРів від партнерів — це публічно, можна обговорювати.",
                "press",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_redacted_briefing_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_neg_redacted_briefing".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "В брифінгу зачеркнули цифри і назви — поділись лише висновками без даних, ок?",
                "officer_4",
                "officers_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn obfuscated_grid_via_landmark_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_adv_landmark_obfuscation".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Ми зараз поряд із 'зеленою церквою' що ти знаєш з 2019, північніше тієї заправки, ось де штаб.",
                "soldier_7",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        }],
    }
}

fn emoji_padded_equipment_count_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_adv_emoji_equipment".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "🪖🪖🪖 18 пехоти 🚛 2 урала ⛺ позиція на 5 діб 🎯",
                "soldier_8",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation],
        }],
    }
}

fn photo_metadata_geotag_leak_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_adv_photo_geotag".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "[фото з EXIF: 48.5928, 38.0061] оце з нашого окопу сьогодні, нічого особливого",
                "soldier_9",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        }],
    }
}

fn innocuous_chatter_leaks_pattern_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_adv_innocuous_chatter".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Привіт народ. Ввечері святкуємо день народження Сергія, командир теж буде, готуйте торт.",
                    "soldier_10",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 5 * MIN,
                input: group_msg_lang(
                    "Зустріч о 21:00 у штабі, наш дім, дим від багаття видно з польової дороги.",
                    "soldier_10",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::OpsecViolation],
            },
        ],
    }
}

// -- long context ----------------------------------------------------------

fn long_drip_to_full_picture_case() -> ScenarioCase {
    let chatter = [
        "доброго ранку",
        "привіт",
        "вже на позиції?",
        "так",
        "як настрій",
        "норм",
        "що в нас на сьогодні",
        "патрулюємо ось цю ділянку",
        "ну так знаю",
        "після Краматорська ще 12 км на схід",
        "ок",
        "будемо до 18:00",
        "потім зміна",
        "наша рота заходить о 18:30",
        "хто командир в цій зміні",
        "Старший лейтенант 'Грім', позивний 'Ворон-3'",
        "а нас скільки",
        "у нашій 4 БМП-2 + 2 хамві + 18 хлопців",
        "БК?",
        "повний, 30мм + 12.7 + ПКМ",
        "Старлінк включений?",
        "так, дашборд показує",
        "координати точно не пиши тут",
        "я в загальних рисах",
        "ось як зеленка біля річки",
        "ну ти знаєш ту річку",
        "ага, та яку ми переходили в червні",
        "точно",
        "ну там і висота",
        "ага",
        "є проблема з зв'язком?",
        "інколи але ретранслятор працює",
        "ретранслятор біля старого мосту?",
        "так",
        "у нас 'Корд' поранений був вчора",
        "як він?",
        "евакуювали в Дніпро, стабільно",
        "ok",
        "до речі завтра о 03:00 виходимо",
        "куди?",
        "перерозподіл на нову ділянку",
        "разом з 47 ОМБр",
        "ок",
        "комбриг буде о 08:00 проводити брифінг",
        "у штабі чи в полі",
        "у штабі краматорськ",
        "ок",
        "приходять британські інструктори",
        "1 Para?",
        "так, навчатимуть дронярів",
        "круто",
        "у нас тепер 12 коптерів 'Мавік' та 4 'Шахеди' трофейних",
        "трофеї пишемо?",
        "так у журналі",
        "ок",
        "на сьогодні все",
        "до зв'язку",
        "тримайся",
        "ти теж",
        "за Україну",
    ];
    let positives: std::collections::HashSet<usize> =
        [9, 13, 15, 17, 19, 32, 34, 36, 38, 40, 42, 44, 50]
            .into_iter()
            .collect();
    let senders = ["sgt", "sld"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 2 * MIN,
            input: group_msg_lang_size(
                body,
                senders[idx % senders.len()],
                "long_opsec_chat",
                "uk",
                14,
            ),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::OpsecViolation]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "opsec_long_ctx_drip".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::OpsecViolation),
        onset_step: Some(9),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation, ThreatType::CoordinateLeak],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_civilian_travel_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_civilian_travel".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "У відпустці у Львові, гуляємо парком, дитину взяв на каруселі.",
                "soldier_11",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_general_war_news_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_general_war_news".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "ЗМІ написали про загальні втрати ворога за минулий тиждень, цифри від генштабу.",
                "user_a",
                "news_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_volunteer_logistics_request_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_volunteer_request".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Волонтери: потрібні теплові кольтари і термобілизна, передавайте на склад в Києві, без імен і підрозділів.",
                "volunteer",
                "civil_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_published_press_briefing_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_press_briefing".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "У офіційному брифінгу командування озвучили загальний характер операції без деталей. Можна цитувати.",
                "press",
                "press_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_morale_message_no_specifics_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_morale_no_specs".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Тримайся, ми всі за тебе, пишу без деталей, бо знаю правила.",
                "spouse",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_birthday_greeting_no_unit_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_birthday_no_unit".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "З Днем народження, друже! Без деталей, але всі тебе тут чекаємо вдома.",
                "friend",
                "civil_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_combat_first_aid_lesson_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_first_aid_lesson".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Нагадування: накладання турнікета під час навчань, термін 30 секунд, ніяких реальних випадків не описуємо тут.",
                "medic_instr",
                "training_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_supplier_invoice_thanks_case() -> ScenarioCase {
    ScenarioCase {
        name: "opsec_fp_supplier_invoice".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Дякуємо постачальнику за оформлення документів - інвойс закрито, без деталей вантажу і отримувача.",
                "logistics",
                "civil_chat",
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
        let pack = canonical_opsec_violation_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_opsec_violation_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_opsec_violation_scenarios();
        all.extend(adversarial_opsec_violation_scenarios());
        all.extend(long_context_opsec_violation_scenarios());
        all.extend(false_positive_opsec_violation_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
