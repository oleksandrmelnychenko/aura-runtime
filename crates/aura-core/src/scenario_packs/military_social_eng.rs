//! MILITARY_SOCIAL_ENG detector simulation pack.
//!
//! Targets ThreatType::MilitarySocialEng — pretexting and impersonation
//! attempts targeting military personnel: fake recruiters, fake commanders,
//! romance honeypots, journalist impostors, supplier impersonation.

use crate::eval_scenarios::{
    direct_msg_lang, group_msg_lang, group_msg_lang_size, military_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_military_social_eng_scenarios() -> Vec<ScenarioCase> {
    vec![
        fake_recruiter_volunteer_unit_case(),
        fake_commander_rank_query_case(),
        romance_honeypot_unit_id_case(),
        fake_journalist_unit_query_case(),
        fake_supplier_qr_code_case(),
        fake_medic_evac_request_case(),
        fake_chaplain_morale_check_case(),
        veteran_lookup_pretext_case(),
        spousal_lookup_pretext_case(),
        negative_control_real_journalist_case(),
        negative_control_volunteer_logistics_case(),
        negative_control_legit_recruiter_case(),
    ]
}

pub fn adversarial_military_social_eng_scenarios() -> Vec<ScenarioCase> {
    vec![
        spoofed_callsign_relay_case(),
        encrypted_app_pivot_request_case(),
        photo_with_fake_identity_case(),
        code_switch_command_pretext_case(),
    ]
}

pub fn long_context_military_social_eng_scenarios() -> Vec<ScenarioCase> {
    vec![long_romance_honeypot_arc_case()]
}

pub fn false_positive_military_social_eng_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_real_command_drill_case(),
        fp_legit_medic_check_case(),
        fp_logistics_known_supplier_case(),
        fp_press_officer_published_case(),
        fp_veteran_reunion_case(),
        fp_family_check_no_unit_case(),
        fp_recruiter_via_official_portal_case(),
        fp_internal_red_team_drill_case(),
    ]
}

pub fn military_social_eng_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.22),
        max_expected_calibration_error: Some(0.15),
        min_positive_detection_rate: Some(0.72),
        max_negative_false_positive_rate: Some(0.12),
        min_pre_onset_detection_rate: Some(0.50),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::MilitarySocialEng,
            min_example_count: Some(10),
            max_brier_score: Some(0.28),
            max_expected_calibration_error: Some(0.18),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn fake_recruiter_volunteer_unit_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fake_recruiter_unit".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Я з відділу комплектування '47 ОМБр'. Підтвердіть номер частини, ваше звання, дату народження та позицію поточну для перевірки в реєстрі.",
                "se_op1",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng],
        }],
    }
}

fn fake_commander_rank_query_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fake_commander_rank".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Майор Іванов, штаб ОК Південь. Терміново передайте координати вашого спостережного пункту і список особового складу.",
                "se_op2",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        }],
    }
}

fn romance_honeypot_unit_id_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_romance_honeypot_unit".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "Привіт, чула про захисників, хочу познайомитися з тим, хто реально служить.",
                    "se_op3",
                    "dating_dm",
                    "uk",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 12 * 60 * MIN,
                input: direct_msg_lang(
                    "А ти в якій бригаді? Я з повагою, просто хочу зрозуміти контекст життя.",
                    "se_op3",
                    "dating_dm",
                    "uk",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 24 * 60 * MIN,
                input: direct_msg_lang(
                    "Цікаво де ваша зміна, можу хоч уявити де ти, без деталей звісно... ну якщо хочеш скинь фото в формі.",
                    "se_op3",
                    "dating_dm",
                    "uk",
                ),
                observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Manipulation],
            },
        ],
    }
}

fn fake_journalist_unit_query_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fake_journalist".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Я журналіст незалежного видання, готую матеріал про вашу бригаду. Підтвердіть позицію і дайте 2-3 цитати про якість техніки.",
                "se_op4",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng],
        }],
    }
}

fn fake_supplier_qr_code_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fake_supplier_qr".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Доставка військових ноутбуків від Volunteer Fund. Відсканьте QR за посиланням і заповніть форму одержання з паспортом.",
                "se_op5",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Phishing],
        }],
    }
}

fn fake_medic_evac_request_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fake_medic_evac".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Я фельдшер ОМБ, у нас 300-ий з вашого підрозділу. Скажіть точно де ваша позиція для евакуації.",
                "se_op6",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        }],
    }
}

fn fake_chaplain_morale_check_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fake_chaplain".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Manipulation],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Капелан Богдан, відділ психологічної підтримки. Поділіться вашим настроєм і станом відносин в колективі для звіту.",
                "se_op7",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng],
        }],
    }
}

fn veteran_lookup_pretext_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_veteran_lookup".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Я з фонду ветеранів, шукаю Олега Петренка з 47 ОМБр для виплат. Підтвердіть його позицію і телефон родини.",
                "se_op8",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng],
        }],
    }
}

fn spousal_lookup_pretext_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_spousal_lookup".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Я з районного штабу, мені потрібен контакт дружини сержанта Іванова для термінової виплати. Дайте її номер та адресу.",
                "se_op9",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::Doxxing],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_real_journalist_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_neg_real_journalist".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Анна, кореспондент Hromadske, акредитована при ОВА. Запит на інтерв'ю через прес-офіцера бригади, всі деталі через нього.",
                "journalist",
                "press_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_volunteer_logistics_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_neg_volunteer_logistics".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Здравія! Volunteer Hub Львів - готові передати теплий одяг. Передаємо на офіційний склад БТЗ-12, ваш логіст підтвердить.",
                "volunteer",
                "civil_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_legit_recruiter_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_neg_legit_recruiter".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "ЦК ЗСУ: переведення можливе через офіційний рапорт командиру, на дзвінок або повідомлення не реагуйте, всі процедури тільки через ваш штаб.",
                "ck_zsu",
                "info_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn spoofed_callsign_relay_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_adv_spoofed_callsign".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "'Ворон-3', доповідай. Командир сказав негайно надіслати координати на захищений канал через цей бот.",
                "se_op10",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        }],
    }
}

fn encrypted_app_pivot_request_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_adv_encrypted_pivot".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Перейдіть зі мною на 'безпечний' Threema, ось мій ID, тільки там можемо обговорити деталі обміну полонених.",
                "se_op11",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng],
        }],
    }
}

fn photo_with_fake_identity_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_adv_photo_fake_identity".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "[фото у формі ЗСУ] я Андрій з 93 ОМБр, ось моя бойова, дай мені позицію вашої роти швидко, у нас зв'язок просів.",
                "se_op12",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        }],
    }
}

fn code_switch_command_pretext_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_adv_code_switch".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "HQ here, command line, urgent transmission. Підтвердіть unit ID and current position immediately.",
                "se_op13",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::MilitarySocialEng, ThreatType::OpsecViolation],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_romance_honeypot_arc_case() -> ScenarioCase {
    let chatter = [
        "Привіт. Знайшла твій профіль, ти у формі - вражає.",
        "привіт",
        "як справи у тебе там",
        "норм",
        "я волонтерка, плету сітки",
        "круто",
        "куди вам слати наступну партію",
        "не пишу адреси, через офіційний канал",
        "розумію, але ж ти такий хороший, я просто хочу допомогти конкретно тобі",
        "дякую",
        "як тебе звати повністю",
        "Олег",
        "Олег а звання?",
        "не пишу",
        "ну хоч позивний? я не з ворогом",
        "ні",
        "розумію",
        "розкажи як виглядає типовий день",
        "встаю, патрулюємо, повертаюсь, сплю",
        "а спиш на позиції чи в населеному пункті",
        "не скажу",
        "як ти суворо",
        "так треба",
        "ти молодець",
        "просто роблю свою справу",
        "хочеш я приїду до тебе у відпустку",
        "не можу зараз говорити про це",
        "куди ти у відпустку коли буде",
        "не пишу про маршрути",
        "хочу зустріти тебе вокзалі",
        "не пишу маршрути",
        "ти тримаєш OPSEC, я тебе все більше поважаю",
        "це обов'язок",
        "до речі підкажи в якій ви бригаді щоб я могла надіслати посилку",
        "через офіційний канал",
        "а який канал",
        "не пишу",
        "у вас є старлінк? у мене знайомий хоче нам ще передати кілька",
        "це ОПСЕК",
        "розумію розумію",
        "знаєш я тут чула що у твоєму напрямку важко, чи правда",
        "коментарів не даю",
        "ти такий захист, прямо хочу поцілувати в форму",
        "дякую",
        "дай хоч номер частини щоб я могла привезти подарунок особисто",
        "ні",
        "я ж не ворог",
        "будь ласка не пиши такі питання",
        "ти став такий холодний",
        "пиши через офіційний канал",
        "ти не довіряєш мені?",
        "не маю права",
        "це образливо",
        "перепрошую",
        "якщо не дасиш номер частини я перестану писати",
        "перестань пиши, не дам",
        "блокую",
        "ок",
        "не пожалкуй",
        "за Україну",
    ];
    let positives: std::collections::HashSet<usize> = [14, 19, 28, 30, 34, 36, 38, 40, 44, 50, 54]
        .into_iter()
        .collect();
    let senders = ["honeypot", "victim"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 7 * MIN,
            input: direct_msg_lang(body, senders[idx % senders.len()], "long_mse_dm", "uk"),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::MilitarySocialEng]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "mse_long_ctx_honeypot_arc".to_string(),
        config: military_config(),
        primary_threat: Some(ThreatType::MilitarySocialEng),
        onset_step: Some(14),
        detection_threshold: 0.55,
        tracked_threats: vec![
            ThreatType::MilitarySocialEng,
            ThreatType::OpsecViolation,
            ThreatType::Manipulation,
        ],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_real_command_drill_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_real_command_drill".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Тренування з реагування на ОПСЕК сьогодні о 14:00, інструктор з нашого батальйону. Без зайвих питань у чаті, все на місці.",
                "officer",
                "platoon_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_legit_medic_check_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_legit_medic_check".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Я наш медик, перевіряю стан після вчорашнього інциденту - як спина? Без деталей місця, просто симптоми.",
                "our_medic",
                "private_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_logistics_known_supplier_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_known_supplier".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Поточний постачальник: підтверджую отримання вашого запиту через офіційну систему, документи через ваш ЛЗВ.",
                "supplier",
                "logistics_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_press_officer_published_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_press_officer".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Прес-офіцер бригади опублікував офіційне інтерв'ю - акредитована журналістка, всі цитати погоджені. Можна шерити.",
                "press_officer",
                "info_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_veteran_reunion_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_veteran_reunion".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang(
                "Зустріч ветеранів через 'Ветеранський хаб' у Львові цієї суботи, реєстрація через офіційний сайт. Деталей про сьогоднішні підрозділи там не обговорюємо.",
                "vet_hub",
                "civil_chat",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_family_check_no_unit_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_family_check".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Привіт, я знаю що зараз непросто, питань не маю, просто хочу сказати що люблю і дочка чекає.",
                "wife",
                "family_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_recruiter_via_official_portal_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_recruiter_via_portal".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Якщо є питання щодо контракту - звертайтеся на портал recruit.mil.gov.ua, всі вакансії та форми там. Через чат документи не приймаємо.",
                "official_recruiter",
                "info_dm",
                "uk",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_internal_red_team_drill_case() -> ScenarioCase {
    ScenarioCase {
        name: "mse_fp_red_team_drill".to_string(),
        config: military_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::MilitarySocialEng],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang_size(
                "Команда контррозвідки повідомляє: завтра проведено внутрішню перевірку чатів на social engineering - не передавайте дані навіть 'своїм'.",
                "counter_int",
                "officers_chat",
                "uk",
                16,
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
        let pack = canonical_military_social_eng_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_military_social_eng_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_military_social_eng_scenarios();
        all.extend(adversarial_military_social_eng_scenarios());
        all.extend(long_context_military_social_eng_scenarios());
        all.extend(false_positive_military_social_eng_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
