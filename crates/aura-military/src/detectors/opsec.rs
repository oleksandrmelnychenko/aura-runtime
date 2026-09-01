use std::sync::OnceLock;

use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};
use regex::Regex;

use crate::{lexicon, text::scan_variants_with_leet};

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    for variant in scan_variants_with_leet(text) {
        if let Some(signal) = match_lexical_rules(&variant, lexicon::opsec_rules()) {
            return Some(signal);
        }
        if let Some(signal) = detect_regex(&variant) {
            return Some(signal);
        }
    }
    None
}

pub fn detect_all(input: &DomainInput) -> Vec<DomainSignal> {
    let Some(text) = input.text.as_deref() else {
        return Vec::new();
    };
    let mut signals = Vec::new();
    let mut seen_keys: Vec<String> = Vec::new();

    for variant in scan_variants_with_leet(text) {
        for signal in match_all_lexical_rules(&variant, lexicon::opsec_rules()) {
            push_unique_signal(signal, &mut signals, &mut seen_keys);
        }
        for signal in detect_all_regex(&variant) {
            push_unique_signal(signal, &mut signals, &mut seen_keys);
        }
    }
    signals
}

fn push_unique_signal(
    signal: DomainSignal,
    signals: &mut Vec<DomainSignal>,
    seen_keys: &mut Vec<String>,
) {
    if !seen_keys.contains(&signal.threat_key) {
        seen_keys.push(signal.threat_key.clone());
        signals.push(signal);
    }
}

fn detect_regex(text: &str) -> Option<DomainSignal> {
    let lower = text.to_lowercase();
    let public_source = looks_like_public_source(&lower);

    if callsign_regex().is_match(&lower)
        || quoted_callsign_regex().is_match(&lower)
        || unquoted_callsign_position_regex().is_match(&lower)
    {
        return Some(DomainSignal {
            threat_key: "opsec_callsign_leak".to_string(),
            reason_code: "military.opsec.callsign_leak".to_string(),
            score: 0.87,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && unit_designation_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_unit_designation".to_string(),
            reason_code: "military.opsec.unit_designation".to_string(),
            score: 0.88,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && c2_node_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_c2_node".to_string(),
            reason_code: "military.opsec.c2_node".to_string(),
            score: 0.90,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(97),
            action: None,
        });
    }
    if !public_source && command_figure_movement_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_commander_movement".to_string(),
            reason_code: "military.opsec.commander_movement".to_string(),
            score: 0.89,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && equipment_count_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_equipment_count".to_string(),
            reason_code: "military.opsec.equipment_count".to_string(),
            score: 0.90,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(97),
            action: None,
        });
    }
    if rotation_timing_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_rotation_timing".to_string(),
            reason_code: "military.opsec.rotation_timing".to_string(),
            score: 0.89,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && ammo_supply_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_ammo_supply".to_string(),
            reason_code: "military.opsec.ammo_supply".to_string(),
            score: 0.85,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if grid_reference_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_grid_reference".to_string(),
            reason_code: "military.opsec.grid_reference".to_string(),
            score: 0.93,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(99),
            action: None,
        });
    }
    if !public_source && personnel_count_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "opsec_personnel_count".to_string(),
            reason_code: "military.opsec.personnel_count".to_string(),
            score: 0.86,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
        });
    }
    None
}

fn detect_all_regex(text: &str) -> Vec<DomainSignal> {
    let lower = text.to_lowercase();
    let public_source = looks_like_public_source(&lower);
    let mut signals = Vec::new();

    if callsign_regex().is_match(&lower)
        || quoted_callsign_regex().is_match(&lower)
        || unquoted_callsign_position_regex().is_match(&lower)
    {
        signals.push(DomainSignal {
            threat_key: "opsec_callsign_leak".to_string(),
            reason_code: "military.opsec.callsign_leak".to_string(),
            score: 0.87,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && unit_designation_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_unit_designation".to_string(),
            reason_code: "military.opsec.unit_designation".to_string(),
            score: 0.88,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && c2_node_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_c2_node".to_string(),
            reason_code: "military.opsec.c2_node".to_string(),
            score: 0.90,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(97),
            action: None,
        });
    }
    if !public_source && command_figure_movement_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_commander_movement".to_string(),
            reason_code: "military.opsec.commander_movement".to_string(),
            score: 0.89,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && equipment_count_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_equipment_count".to_string(),
            reason_code: "military.opsec.equipment_count".to_string(),
            score: 0.90,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(97),
            action: None,
        });
    }
    if rotation_timing_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_rotation_timing".to_string(),
            reason_code: "military.opsec.rotation_timing".to_string(),
            score: 0.89,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(96),
            action: None,
        });
    }
    if !public_source && ammo_supply_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_ammo_supply".to_string(),
            reason_code: "military.opsec.ammo_supply".to_string(),
            score: 0.85,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if grid_reference_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_grid_reference".to_string(),
            reason_code: "military.opsec.grid_reference".to_string(),
            score: 0.93,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("critical".to_string()),
            priority: Some(99),
            action: None,
        });
    }
    if !public_source && personnel_count_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "opsec_personnel_count".to_string(),
            reason_code: "military.opsec.personnel_count".to_string(),
            score: 0.86,
            threat_type: Some("opsec_violation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
        });
    }
    signals
}

fn looks_like_public_source(lower: &str) -> bool {
    public_source_regex().is_match(lower)
}

fn public_source_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:прес[\-\s]?служб[аи]|пресслужб[аи]|press[\-\s]?service|press[\-\s]?release|офіційно\s+(?:повідомил|оголосил|підтвердил|заявил)|официально\s+(?:сообщ|объявил|подтверд|заяв)|officially\s+(?:announced|confirmed|reported|stated)|\bзмі\s+(?:повідом|написал|опублікувал|оголосил)|\bсми\s+(?:сообщ|написал|опублико|объявил)|(?:media|press|news)\s+(?:reported|wrote|published|announced)|генштаб|генеральний\s+штаб|генеральный\s+штаб|general\s+staff|пресцентр|press\s+(?:center|centre)|reuters|associated\s+press|\bbbc\b|\bdpa\b|tass|cnn|українська\s+правда|hromadske|укрінформ|reuters\.com|bbc\.com|за\s+(?:даними|оцінками)\s+(?:прес|зм|генштаб|reuters|bbc|reuters\.com)|відкрит(?:і|их)\s+джерел|public\s+(?:record|domain|sources)|opens\s+source|оголоси(?:в|ла|ли)\s+(?:в|на)\s+(?:брифінг|конференц|прес))"#,
        )
        .expect("invalid public source regex")
    })
}

fn callsign_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:\bпозивний|\bпозивной|\bcallsign|\bcall[\s\-]?sign)\s*[:\-\s]\s*\w+"#)
            .expect("invalid callsign regex")
    })
}

fn quoted_callsign_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Quoted unit/squad/operator codename:  "Шторм-7", 'Ворон-3', «Корд», "Eagle-2".
        // Common prefixes that introduce a callsign in casual chat:
        //   командир/командира/комбат/бойовий/боевой/група + quoted name.
        Regex::new(
            r#"(?i)(?:командир(?:а)?|комбат(?:а)?|комбриг(?:а)?|бойов(?:ий|ого|у)|боев(?:ой|ого|ому)|групп(?:а|и|у)|операт(?:ор|ора)|екіпаж(?:у)?|расчёт(?:а)?)\s*['"«"]([\p{L}\d\-]+)['"»"]"#,
        )
        .expect("invalid quoted callsign regex")
    })
}

fn unquoted_callsign_position_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:бойов(?:ий|ого|у)|боев(?:ой|ого|ому))\s+[\p{L}]{3,}\s+\d{1,3}\s+[^.\n]{0,80}?\b(?:тримає|держит|holds?)\s+(?:висоту|высоту|height)\s+\d{2,4}"#,
        )
        .expect("invalid unquoted callsign position regex")
    })
}

fn unit_designation_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Numbered UA brigade/regiment formats: 47 ОМБр, 93 ОМБ, 25-та ОДШБр, 79 ОДШБр, 3-я ОШБр.
        // Or foreign units explicitly named: "1 Para", "82nd Airborne", "1st SFG", "3 Commando".
        Regex::new(
            r#"(?i)\b\d{1,3}(?:[\-\s]?(?:та|я|ой|ї))?\s*(?:омб[р]?|одшбр|ошбр|омбр|обтгр|опбр|обмп|оп\b|омпб|опдбр|омпбр|омпз|омббр)\b|\b(?:\d{1,3}(?:st|nd|rd|th)?\s*)?(?:para(?:chute)?|airborne|commando|marine[s]?|ranger[s]?|s(?:p|f)g|seal[s]?|spetsnaz)\b"#,
        )
        .expect("invalid unit designation regex")
    })
}

fn c2_node_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Command-and-control node location leak: "штаб ... перейшов/розгорнули/у/в",
        // "вузол зв'язку", "командний пункт", "КП", "TOC" + location/building.
        Regex::new(
            r#"(?i)(?:штаб\s+(?:бригад|батальйон|роти|полку|корпусу)(?:и|у|ів)?\s+(?:перейш|розгорнул|перебазув|перемісти|стоїть|у\s|в\s|на\s)|штаб\s+перейш|штаб\s+розгорнул|вузол\s+зв(?:'|)язку|комм?андн(?:ий|ого)\s+пункт|\bкп\b\s+(?:бригад|роти)|\btoc\b\s+(?:moved|located|at|deployed))"#,
        )
        .expect("invalid c2 node regex")
    })
}

fn command_figure_movement_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Movement of a command figure with time anchor.
        // "Комбриг буде на нашій позиції завтра о 08:00", "Commander arrives at 10:00".
        Regex::new(
            r#"(?i)(?:комбриг|комбат|командир\s+бригад|командир\s+полку|командир\s+роти|комполку|combat\s+commander|brigade\s+commander|battalion\s+commander)\s+(?:буде|прибуде|приїде|відвідає|відвідує|inspects|inspecting|visit|visits|arrives|arriving|will\s+be|due)\s+(?:[^.\n]{0,80}?)\b(?:о|в|at|around)\s*\d{1,2}[\s:\.]\d{2}"#,
        )
        .expect("invalid command figure movement regex")
    })
}

fn equipment_count_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\d+\s*(?:бмп|бтр|танк(?:ів|и|а|ов)?|leopard|leopard[\-\s]?[12]|бредлі|bradley|гаубиц(?:ь|я|і)|howitzer|stryker|страйкер|мста|m777|himars|хаймарс|javelin|джавелін|nlaw|нлав|stinger|стінгер|patriot|патріот|gepard|гепард|iris[\-\s]?t|nasams|hawk|marder|мардер|урал(?:а|ов|ів|и)?|камаз(?:а|ов|и)?|хамві|hummer|humvee|kraz|краз|оплот|т[\-\s]?64|т[\-\s]?72|т[\-\s]?80|т[\-\s]?84|т[\-\s]?90|пехоти|пехота|особового\s+складу)"#,
        )
        .expect("invalid equipment count regex")
    })
}

fn rotation_timing_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Bidirectional: keyword + time OR time + keyword.
        Regex::new(
            r#"(?i)(?:(?:ротація|зміна|виїзд|відхід|марш|відбуття|підвіз|відправлення|rotation|departure|movement|convoy|relief|reposition)\s*(?:о|в|at|around|by)?\s*\d{1,2}[\s:\.]\d{2}|(?:о|в|at|around)\s*\d{1,2}[\s:\.]\d{2}\s*[^.\n]{0,40}?(?:ротаці|зміна|зміни|зміну|виїзд|виходимо|виходить|виходять|заходить|заходять|марш|підвіз|rotation|depart|leave|move|convoy|relief))"#,
        )
        .expect("invalid rotation timing regex")
    })
}

fn ammo_supply_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:залишилось|осталось|лишилось|left|remaining|have)\s*\d+\s*(?:бк|снарядів|снарядов|патронів|патронов|мін|мин|ракет|rounds|shells|ammo|missiles|пзрк|рпг|rpg)|(?:бк|боєкомплект|боекомплект|ammo|ammunition)\s*(?:на\s*)?(?:\d+|нуль|zero|вичерпано|кончается|закінчується)"#,
        )
        .expect("invalid ammo supply regex")
    })
}

fn grid_reference_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:квадрат|grid|square|mgrs|мгрс)\s*[:\-\s]?\s*\d{2}\s*[A-Za-z\p{Cyrillic}]{1,3}\s*\d{4,10}|\b\d{2}[A-Z]\s?[A-Z]{2}\s?\d{4,10}\b"#,
        )
        .expect("invalid grid reference regex")
    })
}

fn personnel_count_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:скільки\s+людей|сколько\s+людей|how\s+many\s+(?:soldiers|men|people|troops))|\d+\s*(?:бійців|бойцов|поранених|раненых|двохсотих|трьохсотих|двухсотых|трёхсотых|wounded|kia|soldiers|troops|casualties)|(?:(?:в\s+нас|у\s+нас|we\s+have|our\s+(?:unit|squad|platoon))\s+\d+\s*(?:людей|чоловік|человек|people|men))|(?:\d+[\-\s]*(?:их|ых|ого|ого)\s+(?:двохсот|трьохсот|двухсот|трёхсот)|(?:двохсот|трьохсот|двухсот|трёхсот)(?:их|ых|ого)?\s+(?:\d+|двоє|троє|четверо|п'ятеро|шестеро|семеро|восьмеро|двое|трое|четверо|пятеро|шестеро|семеро|восьмеро))"#,
        )
        .expect("invalid personnel count regex")
    })
}

#[cfg(test)]
mod tests {
    use super::{detect, detect_all};
    use aura_domain::{DomainConversationType, DomainInput, DomainRiskProfile};

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: Some("uk".to_string()),
            language_evidence: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    fn input_no_lang(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            language_evidence: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    #[test]
    fn detect_callsign_ua() {
        let signal = detect(&input("позивний: Сокіл, ми на місці"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
    }

    #[test]
    fn detect_callsign_with_frequency() {
        let signal = detect(&input("позивний Сокіл, частота 149.5"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
        assert_eq!(s.reason_code, "military.opsec.callsign_leak");
    }

    #[test]
    fn detect_callsign_ru() {
        let signal = detect(&input("позивной Ястреб, приём"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
    }

    #[test]
    fn detect_callsign_en() {
        let signal = detect(&input("callsign Eagle, standing by"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_callsign_leak");
    }

    #[test]
    fn detect_equipment_count() {
        let signal = detect(&input("у нас 3 БМП і 2 танки"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_equipment_count");
    }

    #[test]
    fn detect_equipment_count_leopard() {
        let signal = detect(&input("у нас 3 БМП та 2 Leopard"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_equipment_count");
        assert!(s.score >= 0.9);
    }

    #[test]
    fn detect_equipment_count_himars() {
        let signal = detect(&input("маємо 4 HIMARS на позиції"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_equipment_count");
    }

    #[test]
    fn detect_rotation_timing() {
        let signal = detect(&input("ротація о 04:30 завтра"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_rotation_timing");
    }

    #[test]
    fn detect_rotation_timing_morning() {
        let signal = detect(&input("ротація о 06:00 ранку"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_rotation_timing");
        assert_eq!(s.reason_code, "military.opsec.rotation_timing");
    }

    #[test]
    fn detect_rotation_timing_en() {
        let signal = detect(&input("rotation at 06:00 tomorrow"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_rotation_timing");
    }

    #[test]
    fn detect_ammo_supply() {
        let signal = detect(&input("залишилось 12 снарядів, патронів мало"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_ammo_supply");
    }

    #[test]
    fn detect_grid_reference() {
        let signal = detect(&input("квадрат 36T UQ 12345678"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_grid_reference");
    }

    #[test]
    fn detect_personnel_count_ua() {
        let signal = detect(&input("в нас 24 бійців на позиції"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
    }

    #[test]
    fn detect_personnel_count_wounded() {
        let signal = detect(&input("45 бійців, 8 поранених"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
        assert_eq!(s.reason_code, "military.opsec.personnel_count");
    }

    #[test]
    fn detect_personnel_count_ru() {
        let signal = detect(&input("у нас 30 бойцов, 5 раненых"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
    }

    #[test]
    fn detect_personnel_count_en() {
        let signal = detect(&input("we have 50 soldiers in the area"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "opsec_personnel_count");
    }

    #[test]
    fn detect_all_multiple_violations() {
        let signals = detect_all(&input("позивний Сокіл, у нас 3 БМП, ротація о 06:00"));
        assert!(signals.len() >= 2);
        let keys: Vec<&str> = signals.iter().map(|s| s.threat_key.as_str()).collect();
        assert!(keys.contains(&"opsec_callsign_leak"));
        assert!(keys.contains(&"opsec_equipment_count"));
        assert!(keys.contains(&"opsec_rotation_timing"));
    }

    #[test]
    fn detect_all_deduplicates() {
        let signals = detect_all(&input("позивний Сокіл, ми тут"));
        let callsign_count = signals
            .iter()
            .filter(|s| s.threat_key == "opsec_callsign_leak")
            .count();
        assert_eq!(callsign_count, 1);
    }

    #[test]
    fn detect_none_for_benign() {
        let signal = detect(&input("добрий день, як справи"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_benign_military_talk() {
        let signal = detect(&input("Служу Україні!"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_generic_patriotic() {
        let signal = detect(&input("Слава Україні! Героям Слава!"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_empty_text() {
        let inp = DomainInput {
            text: None,
            language: None,
            language_evidence: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Normal,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        };
        assert!(detect(&inp).is_none());
        assert!(detect_all(&inp).is_empty());
    }

    #[test]
    fn detect_severity_is_high() {
        let signal = detect(&input("позивний Сокіл, частота 149.5")).unwrap();
        assert_eq!(signal.severity.as_deref(), Some("high"));
        assert_eq!(signal.threat_type.as_deref(), Some("opsec_violation"));
    }

    #[test]
    fn detect_grid_severity_is_critical() {
        let signal = detect(&input("квадрат 36T UQ 12345678")).unwrap();
        assert_eq!(signal.severity.as_deref(), Some("critical"));
        assert_eq!(signal.priority, Some(99));
    }

    #[test]
    fn detect_no_lang_field_still_works() {
        let signal = detect(&input_no_lang("позивний Сокіл, частота 149.5"));
        assert!(signal.is_some());
    }
}
