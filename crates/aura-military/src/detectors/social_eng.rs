use std::sync::OnceLock;

use aura_domain::{match_all_lexical_rules, match_lexical_rules, DomainInput, DomainSignal};
use regex::Regex;

use crate::{lexicon, text::scan_variants_with_leet};

pub fn detect(input: &DomainInput) -> Option<DomainSignal> {
    let text = input.text.as_deref()?;
    for variant in scan_variants_with_leet(text) {
        if let Some(signal) = match_lexical_rules(&variant, lexicon::social_eng_rules()) {
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
    detect_all_for_text(text)
}

fn detect_all_for_text(text: &str) -> Vec<DomainSignal> {
    let mut signals = Vec::new();
    let mut seen_keys: Vec<String> = Vec::new();

    for variant in scan_variants_with_leet(text) {
        for signal in match_all_lexical_rules(&variant, lexicon::social_eng_rules()) {
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

    if fake_app_update_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_fake_app_update".to_string(),
            reason_code: "military.social_eng.fake_app_update".to_string(),
            score: 0.91,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if credential_phishing_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_credential_phishing".to_string(),
            reason_code: "military.social_eng.credential_phishing".to_string(),
            score: 0.90,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(93),
            action: None,
        });
    }
    if position_probing_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_position_probing".to_string(),
            reason_code: "military.social_eng.position_probing".to_string(),
            score: 0.86,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
        });
    }
    if fake_volunteer_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_fake_volunteer".to_string(),
            reason_code: "military.social_eng.fake_volunteer".to_string(),
            score: 0.85,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(89),
            action: None,
        });
    }
    if command_impersonation_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_command_impersonation".to_string(),
            reason_code: "military.social_eng.command_impersonation".to_string(),
            score: 0.92,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
        });
    }
    if pretext_with_info_request_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_pretext_info_request".to_string(),
            reason_code: "military.social_eng.pretext_info_request".to_string(),
            score: 0.88,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(92),
            action: None,
        });
    }
    if honeypot_info_probing_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_honeypot_info_probe".to_string(),
            reason_code: "military.social_eng.honeypot_info_probe".to_string(),
            score: 0.86,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
        });
    }
    if fake_identity_position_request_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_fake_identity_position_request".to_string(),
            reason_code: "military.social_eng.fake_identity_position_request".to_string(),
            score: 0.87,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(91),
            action: None,
        });
    }
    if encrypted_app_pivot_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_encrypted_app_pivot".to_string(),
            reason_code: "military.social_eng.encrypted_app_pivot".to_string(),
            score: 0.84,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("medium".to_string()),
            priority: Some(88),
            action: None,
        });
    }
    if family_lookup_pretext_regex().is_match(&lower) {
        return Some(DomainSignal {
            threat_key: "social_eng_family_lookup".to_string(),
            reason_code: "military.social_eng.family_lookup".to_string(),
            score: 0.88,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(91),
            action: None,
        });
    }
    None
}

fn detect_all_regex(text: &str) -> Vec<DomainSignal> {
    let lower = text.to_lowercase();
    let mut signals = Vec::new();

    if fake_app_update_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_fake_app_update".to_string(),
            reason_code: "military.social_eng.fake_app_update".to_string(),
            score: 0.91,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(94),
            action: None,
        });
    }
    if credential_phishing_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_credential_phishing".to_string(),
            reason_code: "military.social_eng.credential_phishing".to_string(),
            score: 0.90,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(93),
            action: None,
        });
    }
    if position_probing_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_position_probing".to_string(),
            reason_code: "military.social_eng.position_probing".to_string(),
            score: 0.86,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
        });
    }
    if fake_volunteer_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_fake_volunteer".to_string(),
            reason_code: "military.social_eng.fake_volunteer".to_string(),
            score: 0.85,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(89),
            action: None,
        });
    }
    if command_impersonation_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_command_impersonation".to_string(),
            reason_code: "military.social_eng.command_impersonation".to_string(),
            score: 0.92,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(95),
            action: None,
        });
    }
    if pretext_with_info_request_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_pretext_info_request".to_string(),
            reason_code: "military.social_eng.pretext_info_request".to_string(),
            score: 0.88,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(92),
            action: None,
        });
    }
    if honeypot_info_probing_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_honeypot_info_probe".to_string(),
            reason_code: "military.social_eng.honeypot_info_probe".to_string(),
            score: 0.86,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
        });
    }
    if fake_identity_position_request_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_fake_identity_position_request".to_string(),
            reason_code: "military.social_eng.fake_identity_position_request".to_string(),
            score: 0.87,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(91),
            action: None,
        });
    }
    if encrypted_app_pivot_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_encrypted_app_pivot".to_string(),
            reason_code: "military.social_eng.encrypted_app_pivot".to_string(),
            score: 0.84,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("medium".to_string()),
            priority: Some(88),
            action: None,
        });
    }
    if family_lookup_pretext_regex().is_match(&lower) {
        signals.push(DomainSignal {
            threat_key: "social_eng_family_lookup".to_string(),
            reason_code: "military.social_eng.family_lookup".to_string(),
            score: 0.88,
            threat_type: Some("military_social_eng".to_string()),
            severity: Some("high".to_string()),
            priority: Some(91),
            action: None,
        });
    }
    signals
}

fn fake_app_update_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:(?:оновлення|обновление|update)\s+(?:додатку\s+)?(?:дія|дії|диа|diia|тцк|резерв\+?|reserve\+?|oberig|оберіг))|(?:(?:дія|diia|тцк|резерв\+?|reserve\+?|оберіг|oberig)\s+(?:оновлення|обновление|update|нова\s+версія|новая\s+версия|new\s+version))|(?:(?:завантажте|скачайте|download|install)\s+(?:нову?\s+)?(?:дію|дия|diia|тцк|резерв|reserve|оберіг))"#,
        )
        .expect("invalid fake app update regex")
    })
}

fn credential_phishing_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:підтвердіть\s+(?:ваш\s+)?акаунт|подтвердите\s+(?:ваш\s+)?аккаунт|verify\s+your\s+(?:account|identity)|введіть\s+(?:пароль|логін|код)|введите\s+(?:пароль|логин|код)|enter\s+your\s+(?:password|login|code)|надішліть\s+(?:одноразовий\s+)?код|отправьте\s+(?:одноразовый\s+)?код|send\s+(?:your\s+)?(?:one[\s\-]?time\s+)?code|(?:термінова|срочная|urgent)\s+(?:верифікація|верификация|verification))"#,
        )
        .expect("invalid credential phishing regex")
    })
}

fn position_probing_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:де\s+ви\s+(?:стоїте|знаходитесь|зараз)|где\s+вы\s+(?:стоите|находитесь|сейчас)|where\s+(?:are\s+you|is\s+your\s+(?:position|unit|squad))|скільки\s+(?:вас|у\s+вас\s+людей|в\s+підрозділі)|сколько\s+(?:вас|у\s+вас\s+людей|в\s+подразделении)|how\s+many\s+(?:are\s+(?:you|there)|in\s+your\s+(?:unit|squad|platoon))|скинь\s+(?:геолокацію|локацію|координати|позицію)|скинь\s+(?:геолокацию|локацию|координаты|позицию)|send\s+(?:your\s+)?(?:location|coordinates|position|geo))"#,
        )
        .expect("invalid position probing regex")
    })
}

fn fake_volunteer_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:від\s+волонтерської\s+організації|от\s+волонтёрской\s+организации|from\s+(?:a\s+)?volunteer\s+(?:organization|group))|(?:(?:волонтери|волонтёры|volunteers)\s+(?:збирають|собирают|collecting)\s+(?:дані|данные|data|info))|(?:(?:гуманітарна|гуманитарная|humanitarian)\s+(?:допомога|помощь|aid)[\s\S]{1,40}(?:скинь|відправ|отправь|send)\s+(?:позицію|координати|позицию|координаты|location|position))"#,
        )
        .expect("invalid fake volunteer regex")
    })
}

fn command_impersonation_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:терміновий\s+наказ|срочный\s+приказ|urgent\s+order|urgent\s+transmission)|(?:(?:наказ|приказ|order|directive)\s+(?:від|от|from)\s+(?:штабу|командування|командования|hq|headquarters|command))|(?:(?:негайно|немедленно|immediately|терміново|срочно)\s+(?:доповісти|доложить|report|відправити|отправить|надіслати|надсилайте|send|передайте|передайти)\s+(?:координати|позицію|координаты|позицию|coordinates|position))|(?:(?:це|это|this\s+is)\s+(?:новий|новый|new)\s+(?:командир|commander|начальник))|(?:hq\s+here\s*,?\s*command\s+line)|(?:командир\s+сказав\s+(?:негайно|терміново)\s+надіслати)"#,
        )
        .expect("invalid command impersonation regex")
    })
}

fn pretext_with_info_request_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // First-person pretext role + later imperative info request.
        // Roles: відділ комплектування, журналіст, фельдшер ОМБ, капелан,
        // фонд ветеранів, районний штаб, Volunteer Fund, etc.
        // Requests: підтвердіть/передайте/дайте/скажіть/дай мені/скиньте + sensitive thing.
        Regex::new(
            r#"(?is)(?:я\s+(?:з\s+)?(?:відділ(?:у|а)\s+комплектування|фонду\s+ветеран(?:ів|ов)|районного\s+штаб(?:у|а)|нацгвардії|тцк\s+та\s+сп)|я\s+(?:журналіст|кореспондент|репортер)|я\s+(?:фельдшер|медик)\s+(?:омб|обм|моб|нашої\s+бригад)|капелан\s+\w+\s*[,.]?\s*(?:відділ\s+психолог|психологічн)|i'?m\s+(?:from|with)\s+(?:the\s+)?(?:recruiting|recruitment|veteran[s']?\s+fund|district\s+(?:hq|headquarters))|press\s+officer|i'?m\s+(?:a|an)\s+(?:journalist|correspondent|chaplain|medic|paramedic)|volunteer\s*fund[\s\S]{0,60}?(?:доставка|delivery|delivers|відсканьте|qr|паспорт)|(?:доставка|delivery)[\s\S]{0,80}?(?:volunteer\s*fund|волонтерського\s+фонду))[\s\S]{0,260}?(?:підтв\w{0,8}\s+(?:номер\s+частини|ваше\s+звання|позицію|його\s+позицію|особу|unit\s+id)|терміново\s+передайте\s+координати|terміново\s+передайте\s+координати|передайте\s+координати|дайте\s+(?:її|його|ваш(?:і|у))?\s*(?:номер|адресу|телефон|контакт)|скажіть\s+(?:точно\s+)?де\s+ваша\s+позиція|дай\s+мені\s+позицію|поділіться\s+(?:вашим|своїм)\s+(?:настроєм|станом)|confirm\s+(?:your\s+)?(?:unit\s+id|current\s+position)|відсканьте\s+qr|share\s+your\s+(?:morale|status)|під\s+підпис\s+з\s+паспортом|з\s+паспортом|реєстр(?:і|у)\s+для\s+перевірки|дайте\s+цитати)"#,
        )
        .expect("invalid pretext info request regex")
    })
}

fn honeypot_info_probing_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)(?:(?:цікаво|хочу|ну\s+хоч|ун\s+хоч|розкажи|підкажи)[\s\S]{0,100}?(?:де\s+(?:ваша\s+)?зміна|уявити\s+де\s+ти|в\s+якій\s+(?:ви\s+)?бригаді|позив\w*|номер\s+частини|старлінк|позиці\w*)[\s\S]{0,140}?(?:скинь\s+фото\s+в\s+формі|фото\s+в\s+формі|я\s+(?:не\s+з|ж\s+не)\s+ворог|без\s+деталей|просто\s+хочу|допомогти\s+конкретно\s+тобі)|(?:я\s+(?:не\s+з|ж\s+не)\s+ворог)[\s\S]{0,80}?(?:позив\w*|номер\s+частини|бригад\w*))"#,
        )
        .expect("invalid honeypot info probing regex")
    })
}

fn fake_identity_position_request_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)(?:фото\s+у\s+формі|я\s+\w+\s+з\s+\d{1,3}\s+омбр|ось\s+моя\s+бойова|зв'?язок\s+просів)[\s\S]{0,180}?(?:дай\s+мені\s+позицію|позицію\s+ваш\w+\s+рот\w+|скинь\s+позицію|current\s+position|send\s+(?:your\s+)?position)"#,
        )
        .expect("invalid fake identity position request regex")
    })
}

fn encrypted_app_pivot_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Asking the target to switch to a "more secure" app where attacker has more control.
        Regex::new(
            r#"(?is)(?:перейдіть\s+(?:зі\s+мною\s+)?(?:на|до|н)\s+[\s'"«»„"']*(?:безпечн(?:ий|у|ого)|secure|приватн(?:ий|у)|private)?[\s'"«»„"']*(?:threema|signal|telegram\s+secret|wickr|element|wire|session|briar|ricochet)|switch\s+to\s+(?:a\s+)?(?:more\s+)?(?:secure|private|encrypted)\s+(?:app|channel|chat)|let'?s\s+move\s+(?:this|the\s+chat)\s+to\s+(?:threema|signal|wickr|wire|session)|ось\s+мій\s+id\s+(?:на\s+|у\s+)?(?:threema|signal|wickr))[\s\S]{0,160}?(?:тільки\s+там|only\s+there|деталі|details|обмін(?:у|и)\s+полонен|prisoners?\s+(?:swap|exchange))"#,
        )
        .expect("invalid encrypted app pivot regex")
    })
}

fn family_lookup_pretext_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Pretexting role + request for family member's contact info / address.
        Regex::new(
            r#"(?is)(?:я\s+(?:з\s+)?(?:районного\s+штаб|фонду\s+ветеран|тцк|нацгвардії|пресслужби|press\s+service)|i'?m\s+(?:from|with)\s+(?:district\s+hq|recruiting|the\s+veteran[s']?\s+fund))[\s\S]{0,200}?(?:контакт\s+(?:дружини|чоловіка|матері|батька|сина|дочки)|дайте\s+(?:її|його)?\s*(?:номер|телефон|адресу|контакт)\s+(?:дружини|сім(?:'|)ї|родини)|телефон\s+(?:родини|сім(?:'|)ї)|для\s+(?:термінової\s+виплати|виплати)|(?:wife|husband|mother|father)'?s\s+(?:number|phone|address)|family\s+contact\s+info)"#,
        )
        .expect("invalid family lookup pretext regex")
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
            sender_id: Some("s1".to_string()),
            conversation_id: Some("c1".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
        }
    }

    #[test]
    fn detect_fake_app_update_diia() {
        let signal = detect(&input(
            "Терміново! Оновлення додатку Дія, завантажте нову версію",
        ));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_fake_app_update");
        assert_eq!(s.reason_code, "military.social_eng.fake_app_update");
    }

    #[test]
    fn detect_diia_phishing_security_update() {
        let signal = detect(&input("оновлення безпеки Дія, перейдіть за посиланням"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_diia_phishing_ru() {
        let signal = detect(&input("обновление Диа, скачайте новую версию"));
        assert!(signal.is_some());
    }

    #[test]
    fn detect_credential_phishing() {
        let signal = detect(&input("Підтвердіть ваш акаунт, введіть пароль"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_credential_phishing");
        assert_eq!(s.reason_code, "military.social_eng.credential_phishing");
    }

    #[test]
    fn detect_position_probing_ua() {
        let signal = detect(&input("де ви стоїте зараз, скинь геолокацію"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_position_probing");
        assert_eq!(s.reason_code, "military.social_eng.position_probing");
    }

    #[test]
    fn detect_position_probing_coordinates() {
        let signal = detect(&input("скинь координати підрозділу"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_position_probing_ru() {
        let signal = detect(&input("где вы находитесь сейчас"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_position_probing");
    }

    #[test]
    fn detect_fake_volunteer() {
        let signal = detect(&input(
            "від волонтерської організації, скинь позицію для доставки",
        ));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_fake_volunteer_humanitarian() {
        let signal = detect(&input(
            "гуманітарна допомога для вашого підрозділу, скинь позицію для доставки",
        ));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_command_impersonation() {
        let signal = detect(&input("терміновий наказ від штабу, доповісти координати"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_command_impersonation");
        assert_eq!(s.reason_code, "military.social_eng.command_impersonation");
    }

    #[test]
    fn detect_command_spoofing_send_code() {
        let signal = detect(&input("терміновий наказ від командування, надішліть код"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(
            s.reason_code.contains("social_eng"),
            "reason_code: {}",
            s.reason_code
        );
    }

    #[test]
    fn detect_command_impersonation_en() {
        let signal = detect(&input("urgent order from headquarters, report coordinates"));
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.threat_key, "social_eng_command_impersonation");
    }

    #[test]
    fn detect_all_multiple() {
        let signals = detect_all(&input(
            "Підтвердіть акаунт. Терміновий наказ від штабу. Скинь геолокацію.",
        ));
        assert!(signals.len() >= 2);
        let keys: Vec<&str> = signals.iter().map(|s| s.threat_key.as_str()).collect();
        assert!(keys.contains(&"social_eng_credential_phishing"));
        assert!(keys.contains(&"social_eng_command_impersonation"));
        assert!(keys.contains(&"social_eng_position_probing"));
    }

    #[test]
    fn detect_all_deduplicates() {
        let signals = detect_all(&input("терміновий наказ від штабу"));
        let cmd_count = signals
            .iter()
            .filter(|s| s.threat_key == "social_eng_command_impersonation")
            .count();
        assert_eq!(cmd_count, 1);
    }

    #[test]
    fn detect_none_for_benign() {
        let signal = detect(&input("привіт, як справи на передовій"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_real_volunteer() {
        let signal = detect(&input("зібрали допомогу для фронту"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_general_support() {
        let signal = detect(&input("волонтери привезли їжу та воду"));
        assert!(signal.is_none());
    }

    #[test]
    fn detect_none_for_empty_text() {
        let inp = DomainInput {
            text: None,
            language: None,
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
    fn detect_threat_type_is_military_social_eng() {
        let signal = detect(&input("терміновий наказ від штабу")).unwrap();
        assert_eq!(signal.threat_type.as_deref(), Some("military_social_eng"));
    }

    #[test]
    fn detect_command_impersonation_highest_priority() {
        let signal = detect(&input("терміновий наказ від штабу")).unwrap();
        assert_eq!(signal.priority, Some(95));
    }

    #[test]
    fn detect_pretext_chaplain_uk() {
        let signal = detect(&input(
            "Капелан Богдан, відділ психологічної підтримки. Поділіться вашим настроєм і станом відносин в колективі для звіту.",
        ));
        assert!(signal.is_some(), "chaplain pretext should fire");
    }

    #[test]
    fn detect_pretext_with_emoji_padding() {
        let signal = detect(&input(
            "Я з відділу комплектування 💯 '47 ОМБр'. Підтвердіть 💯 номер частини, 🔥 ваше 💯 звання.",
        ));
        assert!(signal.is_some(), "emoji-padded pretext should fire");
    }

    #[test]
    fn detect_fake_supplier_with_typo_repaired_fund() {
        let signal = detect(&input(
            "Доставка військових ноутбуків від Volunteer Fnd. Відсканьте QR за посиланням і заповніть форму одержання з паспортом.",
        ));
        assert!(
            signal.is_some(),
            "typo-repaired Volunteer Fund pretext should fire"
        );
    }

    #[test]
    fn detect_fake_medic_with_swapped_unit_abbrev() {
        let signal = detect(&input(
            "Я фельдшер МОБ, у нас 300-ий з вашого підрозділу. Скажіть точно де ваша позиція для евакуації.",
        ));
        assert!(
            signal.is_some(),
            "swapped ОМБ abbreviation should still fire"
        );
    }

    #[test]
    fn detect_pretext_with_zero_width_padding() {
        let signal = detect(&input(
            "Я з відділу к\u{200B}ом\u{200B}пл\u{200B}ек\u{200B}ту\u{200B}ва\u{200B}нн\u{200B}я '47 ОМБр'. Підтвердіть номер частини.",
        ));
        assert!(signal.is_some(), "zero-width padded pretext should fire");
    }

    #[test]
    fn detect_code_switch_with_leetspeak() {
        let signal = detect(&input(
            "HQ h3r3, c0mm4nd l1n3, urg3n7 7r4n5m15510n. Підтвердіть un17 1D and curr3n7 p051710n imm3d1473ly.",
        ));
        assert!(signal.is_some(), "leet code-switch pretext should fire");
    }

    #[test]
    fn detect_honeypot_info_probe() {
        let signal = detect(&input(
            "Цікаво де ваша зміна, можу хоч уявити де ти, без деталей звісно... ну якщо хочеш скинь фото в формі.",
        ));
        assert!(
            signal.is_some(),
            "honeypot location/photo probe should fire"
        );
    }

    #[test]
    fn detect_fake_identity_position_request() {
        let signal = detect(&input(
            "[фото у формі ЗСУ] я Андрій з 93 ОМБр, ось моя бойова, дай мені позицію вашої роти швидко, у нас зв'язок просів.",
        ));
        assert!(
            signal.is_some(),
            "fake identity position request should fire"
        );
    }

    #[test]
    fn detect_encrypted_app_pivot_threema() {
        let signal = detect(&input(
            "Перейдіть зі мною на 'безпечний' Threema, ось мій ID, тільки там можемо обговорити деталі обміну полонених.",
        ));
        assert!(signal.is_some(), "threema pivot should fire");
    }
}
