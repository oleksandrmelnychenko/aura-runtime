//! COORDINATE_LEAK detector simulation pack (military domain).
//!
//! Targets ThreatType::CoordinateLeak — disclosure of geographic position
//! information that could enable kinetic targeting. Covers explicit decimal
//! / MGRS grids, landmark triangulation, and progressive narrowing.
//! All coordinates are fabricated for fixture use.

use crate::eval_scenarios::{
    direct_msg_lang, group_msg_lang, group_msg_lang_size, military_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_coordinate_leak_scenarios() -> Vec<ScenarioCase> {
    vec![
        decimal_lat_lon_share_case(),
        mgrs_grid_share_case(),
        triangulation_via_two_landmarks_case(),
        casual_to_tactical_grid_case(),
        photo_geotag_caption_case(),
        what3words_grid_case(),
        commercial_map_link_share_case(),
        sequential_landmark_drip_case(),
        radio_relay_grid_relay_case(),
        negative_control_civilian_meet_location_case(),
        negative_control_tourist_check_in_case(),
        negative_control_opsec_warning_about_grids_case(),
    ]
}

pub fn adversarial_coordinate_leak_scenarios() -> Vec<ScenarioCase> {
    vec![
        spelled_out_decimal_coords_case(),
        emoji_padded_grid_case(),
        rot13_grid_case(),
        landmark_chain_no_numbers_case(),
    ]
}

pub fn long_context_coordinate_leak_scenarios() -> Vec<ScenarioCase> {
    vec![long_triangulation_drip_case()]
}

pub fn false_positive_coordinate_leak_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_tourist_landmark_case(),
        fp_logistics_warehouse_address_case(),
        fp_civilian_restaurant_share_case(),
        fp_historical_battle_grid_case(),
        fp_published_press_target_grid_case(),
        fp_volunteer_drop_address_civilian_case(),
        fp_real_estate_grid_published_case(),
        fp_anti_geotag_warning_case(),
    ]
}

pub fn coordinate_leak_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.20),
        max_expected_calibration_error: Some(0.14),
        min_positive_detection_rate: Some(0.80),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.60),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::CoordinateLeak,
            min_example_count: Some(10),
            max_brier_score: Some(0.25),
            max_expected_calibration_error: Some(0.16),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn decimal_lat_lon_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_decimal_lat_lon".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Наша позиція 48.5928, 38.0061. Тримаємо до 18:00.",
                "soldier_1",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak],
        }],
    }
}

fn mgrs_grid_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_mgrs_grid".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Грід 37T GS 12345 67890, ми тут. Чекаємо подвозу БК.",
                "soldier_2",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak],
        }],
    }
}

fn triangulation_via_two_landmarks_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_triangulation_landmarks".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Видно церкву Андріївську звідси і антенну вежу на горбі.",
                    "soldier_3",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::CoordinateLeak],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg_lang(
                    "Точно північ-захід від тієї вежі, 2.5 км, у тіні лісу.",
                    "soldier_3",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::CoordinateLeak],
            },
        ],
    }
}

fn casual_to_tactical_grid_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_casual_to_tactical".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Біля старого комбайнового заводу.",
                    "soldier_4",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: group_msg_lang(
                    "Якщо точніше 48.5921N 38.0042E - північна стіна, цех 2.",
                    "soldier_4",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::CoordinateLeak],
            },
        ],
    }
}

fn photo_geotag_caption_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_photo_geotag_caption".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "[фото з EXIF lat:48.5928 lon:38.0061] ось наша позиція на світанку, відсилаю мамі",
                "soldier_5",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        }],
    }
}

fn what3words_grid_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_what3words".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "what3words ///shelves.cliff.amazed - саме там наша точка.",
                "soldier_6",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak],
        }],
    }
}

fn commercial_map_link_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_commercial_map_link".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Ось у Гугл картах: https://maps.example.com/?q=48.5928,38.0061 - ми саме у позначеному місці.",
                "soldier_7",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak],
        }],
    }
}

fn sequential_landmark_drip_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_sequential_landmark_drip".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang("Місто N", "soldier_8", "platoon_chat", "uk"),
                observed_threats: vec![ThreatType::CoordinateLeak],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: group_msg_lang("Південна околиця", "soldier_8", "platoon_chat", "uk"),
                observed_threats: vec![ThreatType::CoordinateLeak],
            },
            ScenarioStep {
                timestamp_ms: 60 * SEC,
                input: group_msg_lang(
                    "Старий завод цементу - наш цех 3",
                    "soldier_8",
                    "platoon_chat",
                    "uk",
                ),
                observed_threats: vec![ThreatType::CoordinateLeak],
            },
        ],
    }
}

fn radio_relay_grid_relay_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_radio_relay_grid".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Ретранслятор сидить на координаті 48.6017N 37.9923E - не пишемо в загальний.",
                "soldier_9",
                "officers_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_civilian_meet_location_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_neg_civilian_meet".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Зустріч у відпустку: кафе 'Гніздо' на вулиці Лесі Українки у Львові, о 18:00.",
                "spouse",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_tourist_check_in_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_neg_tourist_check_in".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "У Карпатах, гора Хом'як, рекомендую маршрут на вихідні.",
                "user_a",
                "civil_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_opsec_warning_about_grids_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_neg_opsec_warning".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Нагадую: не публікувати в чатах декаду-градусів типу 48.5928 38.0061 - це грід, його можна використати.",
                "officer",
                "officers_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn spelled_out_decimal_coords_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_adv_spelled_out".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Сорок вісім крапка п'ять дев'ять два вісім, тридцять вісім крапка нуль нуль шість один.",
                "soldier_10",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak],
        }],
    }
}

fn emoji_padded_grid_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_adv_emoji_padded_grid".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "🧭4️⃣8️⃣🟢5️⃣9️⃣2️⃣8️⃣ N ➖ 3️⃣8️⃣🟢0️⃣0️⃣6️⃣1️⃣ E 📌",
                "soldier_11",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak],
        }],
    }
}

fn rot13_grid_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_adv_rot13".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "rot13 grid: gjraglsvir cbvag svir avar gjb rvtug, guerr rvtug mreb mreb fvk bar (Decoded: 48.5928, 38.0061)",
                "soldier_12",
                "officers_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak],
        }],
    }
}

fn landmark_chain_no_numbers_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_adv_landmark_chain".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Біля 'зеленого мосту', потім ліворуч повз 'червону хатинку', потім за лісом біля 'старого кладовища' - там ми.",
                "soldier_13",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_triangulation_drip_case() -> ScenarioCase {
    let chatter = [
        "доброго ранку народ",
        "як ніч",
        "тихо",
        "мене розбудило о 04 коли роздавали БК",
        "де ми сьогодні",
        "недалеко від вчорашньої позиції",
        "ну так де саме",
        "у тому самому селі",
        "село починається на К",
        "усього 4 будинки в західній частині",
        "поряд струмок",
        "за струмком 2 км лісосмуга",
        "на іншому березі видно силос",
        "силос радянський, старий",
        "далі за силосом дорога Т01-04",
        "далі лежить шосе Бахмут-Краматорськ",
        "ми північніше шосе на 3 км",
        "та антенна вежа на горбі",
        "якщо стати на вежу видно нас",
        "грубо 48.59 пн і 38.0 сх",
        "точніше 48.5928 38.0061",
        "а як же ОПСЕК",
        "ну це ж серед своїх",
        "усе одно не пиши",
        "усе одно нагадую що чати не захищені",
        "ок видаляю",
        "видаляй обидва",
        "ок",
        "пардон",
        "наступного разу не пиши",
        "так",
        "тримай OPSEC",
        "як з БК",
        "повний",
        "патруль о 14",
        "ага",
        "командир сказав не ризикувати",
        "ок",
        "до речі вже сюди скидали пару разів дрони",
        "поряд впав один",
        "як близько",
        "метрів 300 на схід",
        "він не вибухнув",
        "сапери забрали",
        "сапери чиї",
        "наші бригадні",
        "ок",
        "повний відпочинок до зміни",
        "ага",
        "о 18 зміна",
        "знаю",
        "сонце сідає о 19",
        "ага",
        "відбий до ночі",
        "відбій",
        "за Україну",
        "до ранку",
    ];
    let positives: std::collections::HashSet<usize> =
        [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
            .into_iter()
            .collect();
    let senders = ["sgt", "sld"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 90 * SEC,
            input: group_msg_lang_size(
                body,
                senders[idx % senders.len()],
                "long_coord_chat",
                "uk",
                12,
            ),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::CoordinateLeak]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "coord_long_ctx_triangulation".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::CoordinateLeak),
        onset_step: Some(8),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak, ThreatType::OpsecViolation],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_tourist_landmark_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_tourist_landmark".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Софіївський собор у Києві - чудово виглядає на світанку, рекомендую візит у відпустку.",
                "friend",
                "civil_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_logistics_warehouse_address_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_warehouse_address".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Склад БТЗ-12 у Львові: вулиця Промислова 4. Туди передаємо все, що не до фронту.",
                "logistician",
                "civil_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_civilian_restaurant_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_restaurant_share".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Привіт. Той ресторан 'Криївка' у Львові на площі Ринок - чудовий, веди дружину туди коли приїдеш.",
                "buddy",
                "civil_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_historical_battle_grid_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_historical_battle".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Битва під Крутами 1918 року відбулася на координаті 50.95 N 32.50 E приблизно - історичні дослідники узгодили.",
                "historian",
                "civil_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_published_press_target_grid_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_published_press_grid".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Преса повідомляє про офіційно підтверджене знищення складу боєприпасів ворога біля 47.30 N 36.21 E - все вже у новинах.",
                "press",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_volunteer_drop_address_civilian_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_volunteer_drop_civilian".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Адреса волонтерської точки у Києві: вулиця Хрещатик 12, без військового статусу, прийом завжди о 10-18.",
                "volunteer",
                "civil_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_real_estate_grid_published_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_real_estate_grid".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Продається будинок у селі Ходоси 49.81 N 24.05 E (це у відкритих оголошеннях, civicallow).",
                "broker",
                "civil_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_anti_geotag_warning_case() -> ScenarioCase {
    ScenarioCase {
        name: "coord_fp_anti_geotag_warning".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::CoordinateLeak],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang_size(
                "Хлопці, не публікуйте фото з геотегами в EXIF, налаштуйте телефон щоб метадані стирались - інструкція по @safety_bot.",
                "safety_bot",
                "platoon_chat",
                "uk",
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
        let pack = canonical_coordinate_leak_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_coordinate_leak_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_coordinate_leak_scenarios();
        all.extend(adversarial_coordinate_leak_scenarios());
        all.extend(long_context_coordinate_leak_scenarios());
        all.extend(false_positive_coordinate_leak_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
