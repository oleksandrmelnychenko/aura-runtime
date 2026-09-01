use super::*;

fn supported_languages(languages: &[&str]) -> HashSet<String> {
    languages
        .iter()
        .map(|language| (*language).to_string())
        .collect()
}

#[test]
fn language_routing_adds_cyrillic_packs_for_latin_hint_with_cyrillic_span() {
    let evidence = LanguageEvidence::from_text_and_hints(
        "keep this secret не кажи батькам",
        Some("en-US"),
        Some("en"),
    );

    assert_eq!(
        routed_pattern_languages(&evidence, &supported_languages(&["en", "uk", "ru"])),
        vec!["en", "uk", "ru"]
    );
}

#[test]
fn language_routing_hint_cannot_suppress_governed_release_packs() {
    let evidence = LanguageEvidence::from_text_and_hints("не кажи батькам", Some("uk"), Some("uk"));

    assert_eq!(
        routed_pattern_languages(&evidence, &supported_languages(&["en", "uk", "ru"])),
        vec!["uk", "en", "ru"]
    );
}

#[test]
fn language_routing_preserves_legacy_no_hint_coverage() {
    let evidence = LanguageEvidence::from_text_and_hints("hello", None, Some("uk"));

    assert_eq!(
        routed_pattern_languages(&evidence, &supported_languages(&["en", "uk", "ru"])),
        vec!["uk", "en", "ru"]
    );
}

#[test]
fn language_routing_keeps_universal_rules_for_unsupported_hint() {
    let evidence = LanguageEvidence::from_text_and_hints("bonjour", Some("fr-FR"), Some("uk"));

    assert_eq!(
        routed_pattern_languages(&evidence, &supported_languages(&["en", "uk", "ru"])),
        vec!["fr-fr", "en", "uk", "ru"]
    );
}

#[test]
fn language_routing_does_not_treat_japanese_han_as_chinese_code_switch() {
    let evidence = LanguageEvidence::from_text_and_hints("安全です", Some("ja"), Some("en"));

    assert_eq!(
        routed_pattern_languages(&evidence, &supported_languages(&["en", "ja", "zh"])),
        vec!["ja", "en"]
    );
}

#[test]
fn language_routing_includes_region_specific_and_primary_packs() {
    let evidence = LanguageEvidence::from_text_and_hints("colour", Some("en-GB"), Some("uk"));

    assert_eq!(
        routed_pattern_languages(&evidence, &supported_languages(&["en", "en-gb", "uk"])),
        vec!["en-gb", "en", "uk"]
    );
}

#[test]
fn language_routing_uses_classifier_candidates_for_same_script_code_switching() {
    let candidates = ["uk", "ru"]
        .into_iter()
        .map(|tag| {
            LanguageCandidate::try_new(tag, 0.9, LanguageEvidenceSource::OnDeviceClassifier)
                .expect("valid classifier candidate")
        })
        .collect();
    let evidence =
        LanguageEvidence::try_new(candidates, Vec::new(), "привіт секрет").expect("valid evidence");

    assert_eq!(
        routed_pattern_languages(&evidence, &supported_languages(&["en", "uk", "ru"])),
        vec!["uk", "ru", "en"]
    );
}

fn test_db() -> PatternDatabase {
    let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "threat_001",
                    "threat_type": "threat",
                    "kind": { "type": "keyword", "words": ["kill you", "i will hurt you"] },
                    "score": 0.9,
                    "languages": [],
                    "explanation": "Direct threat detected"
                },
                {
                    "id": "grooming_001",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["don't tell your parents", "our little secret"] },
                    "score": 0.7,
                    "languages": [],
                    "explanation": "Secrecy request (potential grooming)"
                },
                {
                    "id": "selfharm_001",
                    "threat_type": "self_harm",
                    "kind": { "type": "keyword", "words": ["no reason to live", "want to end it all"] },
                    "score": 0.75,
                    "languages": [],
                    "explanation": "Self-harm language detected"
                },
                {
                    "id": "bullying_001",
                    "threat_type": "bullying",
                    "kind": { "type": "keyword", "words": ["nobody likes you", "you're worthless", "everyone hates you", "you're disgusting"] },
                    "score": 0.8,
                    "languages": [],
                    "explanation": "Bullying language detected"
                },
                {
                    "id": "url_block",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["evil-site.com"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Blocked URL"
                },
                {
                    "id": "substance_slang_en",
                    "threat_type": "scam",
                    "kind": { "type": "keyword", "words": ["got gas", "dm for prices", "delivery available", "percs", "xans"] },
                    "score": 0.6,
                    "languages": [],
                    "explanation": "Drug slang detected"
                },
                {
                    "id": "sextortion_countdown_en",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["you have 24 hours", "time is running out to pay", "last warning before i share"] },
                    "score": 0.9,
                    "languages": [],
                    "explanation": "Sextortion countdown detected"
                },
                {
                    "id": "grooming_video_call_en",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["let's video call just us", "turn on your camera for me", "go on cam for me"] },
                    "score": 0.65,
                    "languages": [],
                    "explanation": "Video call pressure detected"
                },
                {
                    "id": "grooming_body_comment_en",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["you must have a nice body", "what do you wear to bed", "do you sleep naked"] },
                    "score": 0.85,
                    "languages": [],
                    "explanation": "Body-focused comments detected"
                },
                {
                    "id": "manipulation_darvo_en",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["you're the one who started this", "i'm the victim here", "stop playing victim"] },
                    "score": 0.65,
                    "languages": [],
                    "explanation": "DARVO pattern detected"
                },
                {
                    "id": "substance_pressure_uk",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["просто спробуй раз", "всі пробують це", "перший раз безкоштовно для тебе"] },
                    "score": 0.55,
                    "languages": [],
                    "explanation": "Drug pressure detected"
                },
                {
                    "id": "gaming_bribery_en",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["ill get u vbucks", "want free skins", "free skins"] },
                    "score": 0.5,
                    "languages": [],
                    "explanation": "Gaming bribery detected"
                },
                {
                    "id": "platform_switch_teen_uk",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["го в тг", "тут палево", "давай в телегу"] },
                    "score": 0.6,
                    "languages": [],
                    "explanation": "Teen slang platform switch detected"
                },
                {
                    "id": "network_poisoning_en",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["they dont really like u", "they laugh at u behind ur back", "ur friend is fake"] },
                    "score": 0.5,
                    "languages": [],
                    "explanation": "Network poisoning detected"
                },
                {
                    "id": "selfharm_farewell_en",
                    "threat_type": "self_harm",
                    "kind": { "type": "keyword", "words": ["goodbye everyone", "this is the end"] },
                    "score": 0.82,
                    "languages": [],
                    "explanation": "Self-harm farewell language detected"
                }
            ]
        }"#;
    PatternDatabase::from_json(json).unwrap()
}

fn default_input(text: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: "user_123".into(),
        conversation_id: "conv_456".into(),
        language: Some("en".to_string()),
        language_evidence: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    }
}

fn child_input(text: &str, sender: &str, conversation: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.into(),
        conversation_id: conversation.into(),
        language: Some("en".to_string()),
        language_evidence: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    }
}

fn analyze_russian_child_message(text: &str) -> AnalysisResult {
    let db = PatternDatabase::default_mvp();
    let mut config = child_config();
    config.language = "ru".to_string();
    let mut analyzer = Analyzer::new(config, &db);
    let mut input = child_input(text, "ru_sender", "ru_conversation");
    input.language = Some("ru".to_string());
    analyzer.analyze(&input)
}

#[test]
fn russian_parent_deception_pair_preserves_risk_and_filters_correction() {
    let risky = analyze_russian_child_message(
        "Скажи родителям, что я твой одноклассник, чтобы они ничего не заподозрили.",
    );
    let safe = analyze_russian_child_message(
        "Не говори родителям, что незнакомец одноклассник; расскажи им правду.",
    );

    assert!(
        crate::predicted_score_for_threat(&risky, ThreatType::Grooming) >= 0.55,
        "{risky:?}"
    );
    assert_eq!(safe.threat_type, ThreatType::None, "{safe:?}");
}

#[test]
fn russian_blackmail_pair_preserves_risk_and_filters_report() {
    let risky =
        analyze_russian_child_message("Если не сделаешь это, я разошлю всем твоё личное фото.");
    let safe = analyze_russian_child_message(
        "Сообщение «если не сделаешь это, я разошлю фото» является шантажом — сохрани доказательство.",
    );

    assert!(
        crate::predicted_score_for_threat(&risky, ThreatType::Manipulation) >= 0.55,
        "{risky:?}"
    );
    assert_eq!(safe.threat_type, ThreatType::None, "{safe:?}");
}

#[test]
fn russian_suicide_coercion_pair_preserves_risk_and_filters_report() {
    let risky = analyze_russian_child_message(
        "Если ты уйдешь, мне нет смысла жить, и это будет твоя вина.",
    );
    let safe = analyze_russian_child_message(
        "Фраза «если ты уйдешь, мне нет смысла жить» — опасное давление; ты не отвечаешь за чужие угрозы.",
    );

    assert!(
        crate::predicted_score_for_threat(&risky, ThreatType::Manipulation) >= 0.55,
        "{risky:?}"
    );
    assert_eq!(safe.threat_type, ThreatType::None, "{safe:?}");
}

#[test]
fn russian_threatened_violence_pair_preserves_risk_and_filters_report() {
    let risky = analyze_russian_child_message("После школы мы тебя побьём, жди у ворот.");
    let safe = analyze_russian_child_message(
        "Угрозу «после школы мы тебя побьём» уже передали учителю и родителям.",
    );

    assert!(
        crate::predicted_score_for_threat(&risky, ThreatType::Bullying) >= 0.55,
        "{risky:?}"
    );
    assert_eq!(safe.threat_type, ThreatType::None, "{safe:?}");
}

fn child_input_with_relationship(
    text: &str,
    sender: &str,
    conversation: &str,
    relationship: SenderRelationship,
    trust_source: RelationshipTrustSource,
) -> MessageInput {
    let mut input = child_input(text, sender, conversation);
    input.sender_relationship = relationship;
    input.relationship_trust_source = trust_source;
    input
}

fn child_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        domain_mode: DomainMode::Kids,
        ..AuraConfig::default()
    }
}

fn teen_kids_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Teen,
        protection_level: ProtectionLevel::Medium,
        domain_mode: DomainMode::Kids,
        ..AuraConfig::default()
    }
}

fn military_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Adult,
        protection_level: ProtectionLevel::High,
        domain_mode: DomainMode::Military,
        ..AuraConfig::default()
    }
}

#[test]
fn default_domain_mode_runs_base_aura_only() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input(
        "don't tell your parents, this is our little secret",
    ));

    assert!(
        !result
            .reason_codes
            .iter()
            .any(|code| code.starts_with("domain.")),
        "Domain reason codes must be absent in base-aura-only mode, got {:?}",
        result.reason_codes
    );
}

#[test]
fn kids_domain_reason_codes_are_attached() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let result = analyzer.analyze(&default_input(
        "don't tell your parents, this is our little secret",
    ));

    assert_eq!(result.threat_type, ThreatType::Grooming);
    assert!(
        result.score >= 0.7,
        "Expected elevated domain score, got {}",
        result.score
    );
    assert!(
        result
            .reason_codes
            .iter()
            .any(|code| code == "domain.kids.grooming.secrecy"),
        "Expected kids domain reason code, got {:?}",
        result.reason_codes
    );
    assert!(
        result
            .reason_codes
            .iter()
            .any(|code| code == "domain.action.mark" || code == "domain.action.warn"),
        "Expected domain action marker, got {:?}",
        result.reason_codes
    );
}

#[test]
fn military_domain_reason_codes_are_attached() {
    let db = test_db();
    let mut analyzer = Analyzer::new(military_config(), &db);
    let result = analyzer.analyze(&default_input(
        "Please complete this diia security update now.",
    ));

    assert_eq!(result.threat_type, ThreatType::MilitarySocialEng);
    assert!(
        result.score >= 0.65,
        "Expected elevated domain score, got {}",
        result.score
    );
    assert!(
        result
            .reason_codes
            .iter()
            .any(|code| code == "domain.military.social_eng.phishing"),
        "Expected military domain reason code, got {:?}",
        result.reason_codes
    );
    assert!(
        result
            .reason_codes
            .iter()
            .any(|code| code == "domain.action.mark" || code == "domain.action.warn"),
        "Expected domain action marker, got {:?}",
        result.reason_codes
    );
}

#[test]
fn kids_domain_heuristic_secrecy_triggers_reason_code() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let result = analyzer.analyze(&default_input(
        "don't tell your parents, this is our little secret",
    ));
    assert!(
        result
            .reason_codes
            .iter()
            .any(|code| code == "domain.kids.grooming.secrecy"),
        "Expected kids secrecy heuristic reason code, got {:?}",
        result.reason_codes
    );
}

#[test]
fn kids_strict_runtime_profile_enables_memory_progression_in_analyzer() {
    let db = test_db();
    let seed = child_input(
        "our little secret. don't tell your parents.",
        "strict_sender",
        "strict_conv",
    );
    let followup = child_input(
        "you can only trust me. do it now or i post everything.",
        "strict_sender",
        "strict_conv",
    );

    let mut strict_analyzer = Analyzer::new(child_config(), &db);
    let _ = strict_analyzer.analyze(&seed);
    let strict_result = strict_analyzer.analyze(&followup);
    assert!(
        strict_result
            .reason_codes
            .iter()
            .any(|code| code == "domain.kids.memory.grooming_progression"),
        "Expected strict profile to emit memory progression reason code, got {:?}",
        strict_result.reason_codes
    );

    let mut normal_analyzer = Analyzer::new(teen_kids_config(), &db);
    let _ = normal_analyzer.analyze(&seed);
    let normal_result = normal_analyzer.analyze(&followup);
    assert!(
        !normal_result
            .reason_codes
            .iter()
            .any(|code| code == "domain.kids.memory.grooming_progression"),
        "Expected normal profile to withhold memory progression on second message, got {:?}",
        normal_result.reason_codes
    );
}

#[test]
fn military_domain_heuristic_social_eng_triggers_reason_code() {
    let db = test_db();
    let mut analyzer = Analyzer::new(military_config(), &db);
    let result = analyzer.analyze(&default_input(
        "Please complete this diia security update now to keep access.",
    ));
    assert!(
        result
            .reason_codes
            .iter()
            .any(|code| code == "domain.military.social_eng.phishing"),
        "Expected military social engineering heuristic reason code, got {:?}",
        result.reason_codes
    );
}

#[test]
fn clean_message_passes() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input("Hey, how are you?"));
    assert!(!result.is_threat());
    assert_eq!(result.action, Action::Allow);
}

#[test]
fn threat_is_detected_and_warned() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input("I will kill you"));
    assert!(result.is_threat());
    assert_eq!(result.threat_type, ThreatType::Threat);
    assert!(result.score >= 0.9);
    assert!(result.action >= Action::Warn);
}

#[test]
fn explicit_threat_is_analyzed_after_high_volume_from_same_sender() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let benign = default_input("Hey, how are you?");

    for _ in 0..60 {
        analyzer.analyze(&benign);
    }

    let result = analyzer.analyze(&default_input("I will kill you"));

    assert!(
        result.threat_type == ThreatType::Threat && result.action >= Action::Warn,
        "High-volume traffic must not bypass explicit-threat analysis: {result:?}"
    );
}

#[test]
fn grooming_detected_for_all_users() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let result = analyzer.analyze(&default_input("Don't tell your parents about us"));
    assert!(result.is_threat());
    assert_eq!(result.threat_type, ThreatType::Grooming);
}

#[test]
fn self_harm_never_blocked_only_warned() {
    let db = test_db();
    let config = AuraConfig {
        protection_level: ProtectionLevel::High,
        account_type: AccountType::Child,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze(&default_input("I feel like there's no reason to live"));
    assert_eq!(result.threat_type, ThreatType::SelfHarm);
    assert_eq!(result.action, Action::Warn);
    assert!(result.needs_crisis_resources());
}

#[test]
fn blocked_url_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input("Check this out: https://evil-site.com/free"));
    assert!(result.is_threat());
    assert_eq!(result.threat_type, ThreatType::Phishing);
}

#[test]
fn disabled_aura_allows_everything() {
    let db = test_db();
    let config = AuraConfig {
        enabled: false,
        account_type: AccountType::Adult,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze(&default_input("I will kill you"));
    assert!(!result.is_threat());
    assert_eq!(result.action, Action::Allow);
}

#[test]
fn update_config_refreshes_runtime_components() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);

    let adult_events = analyzer
        .signal_enricher
        .enrich_observations_with_hash("you are beautiful and amazing", None);
    assert!(!adult_events.observations.iter().any(|observation| {
        observation
            .event_hint
            .as_ref()
            .is_some_and(|hint| hint.kind == crate::context::events::EventKind::LoveBombing)
    }));

    let updated_config = AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        account_holder_age: Some(12),
        ttl_days: 7,
        timezone_offset_minutes: 180,
        ..AuraConfig::default()
    };
    analyzer
        .update_config(updated_config, &db)
        .expect("valid config update");

    let child_events = analyzer
        .signal_enricher
        .enrich_observations_with_hash("you are beautiful and amazing", None);
    assert!(child_events.observations.iter().any(|observation| {
        observation
            .event_hint
            .as_ref()
            .is_some_and(|hint| hint.kind == crate::context::events::EventKind::LoveBombing)
    }));
    assert!(analyzer.context_tracker.config().is_child_account);
    assert!(!analyzer.context_tracker.config().is_teen_account);
    assert_eq!(
        analyzer.context_tracker.config().account_holder_age,
        Some(12)
    );
    assert_eq!(
        analyzer.context_tracker.config().timezone_offset_minutes,
        180
    );
    assert_eq!(
        analyzer.context_tracker.config().analysis_window_ms,
        7 * 24 * 60 * 60 * 1000
    );
}

#[test]
fn invalid_minor_update_is_rejected_before_runtime_mutation() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let invalid_config = AuraConfig {
        account_type: AccountType::Child,
        enabled: false,
        language: "en".to_string(),
        ttl_days: 7,
        ..AuraConfig::default()
    };

    let error = analyzer
        .update_config(invalid_config, &db)
        .expect_err("disabled child config must be rejected");

    assert!(error
        .to_string()
        .contains("minor protection cannot be disabled"));
    assert_eq!(analyzer.config.account_type, AccountType::Adult);
    assert_eq!(analyzer.config.language, "uk");
    assert_eq!(analyzer.config.ttl_days, 30);
    assert_eq!(analyzer.effective_domain_mode(), DomainMode::None);
}

#[test]
fn protected_account_binding_is_idempotent_and_immutable() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    analyzer
        .bind_protected_account_id("protected-account".to_string())
        .expect("first authenticated binding");
    analyzer
        .validate_protected_account_id_binding("protected-account")
        .expect("exact binding validation retry");
    analyzer
        .bind_protected_account_id("protected-account".to_string())
        .expect("exact binding retry");
    assert_eq!(
        analyzer
            .context_tracker
            .config()
            .protected_account_id
            .as_deref(),
        Some("protected-account")
    );

    let replacement = analyzer
        .bind_protected_account_id("other-account".to_string())
        .expect_err("runtime account binding must be immutable");
    assert!(replacement.to_string().contains("already bound"));
    let validation = analyzer
        .validate_protected_account_id_binding("other-account")
        .expect_err("validation must reject a different identity without mutation");
    assert!(validation.to_string().contains("already bound"));

    let update = analyzer
        .update_config(AuraConfig::default(), &db)
        .expect_err("config update must not erase an authenticated binding");
    assert!(update.to_string().contains("immutable"));
}

#[test]
fn try_new_rejects_invalid_minor_configuration() {
    let db = test_db();
    let invalid_config = AuraConfig {
        account_type: AccountType::Teen,
        domain_mode: DomainMode::Military,
        ..AuraConfig::default()
    };

    let error = match Analyzer::try_new(invalid_config, &db) {
        Ok(_) => panic!("Military domain must not replace the Kids domain"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("minor accounts require the Kids domain"));
}

#[test]
fn teen_cannot_disable_aura() {
    let db = test_db();
    let config = AuraConfig {
        enabled: true,
        protection_level: ProtectionLevel::Off,
        account_type: AccountType::Teen,
        ..AuraConfig::default()
    };
    assert_eq!(config.effective_protection_level(), ProtectionLevel::Low);
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze(&default_input("I will kill you"));
    assert!(result.is_threat());
}

#[test]
#[ignore = "wall-clock microbenchmark; run in isolation via ci/analyzer_microbenchmark_gate.sh"]
fn analysis_is_fast() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        analyzer.analyze(&default_input("This is a normal message with no threats"));
    }
    let elapsed = start.elapsed();
    let per_message_us = elapsed.as_micros() / 1000;

    assert!(
        per_message_us < 1000,
        "Pattern matching took {per_message_us}us per message, expected <1000us"
    );
}

#[test]
fn context_grooming_sequence_detected_for_child() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let sender = "stranger_42";
    let conv = "conv_child_1";

    let r1 = analyzer.analyze_with_context(
        &child_input("Hey, you seem really cool!", sender, conv),
        1000,
    );

    assert_eq!(r1.action, Action::Allow);

    let r2 = analyzer.analyze_with_context(
        &child_input("Don't tell your parents about this", sender, conv),
        2000,
    );

    assert!(r2.is_threat());

    let r3 = analyzer.analyze_with_context(
        &child_input(
            "Don't tell your parents, our little secret ok?",
            sender,
            conv,
        ),
        3000,
    );
    assert!(r3.is_threat());

    assert!(r3.score >= 0.7);
}

#[test]
fn context_accumulates_across_messages() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let sender = "user_a";
    let conv = "conv_1";

    for i in 0..5 {
        analyzer.analyze_with_context(&child_input("Normal message", sender, conv), i * 1000);
    }

    let timeline = analyzer.context_tracker().timeline(conv);
    assert!(timeline.is_some());
    assert_eq!(timeline.unwrap().len(), 5);
}

#[test]
fn context_export_import_preserves_state() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);

    analyzer.analyze_with_context(
        &child_input("Don't tell your parents", "stranger", "conv_1"),
        1000,
    );
    analyzer.analyze_with_context(&child_input("Hello there", "friend", "conv_2"), 2000);

    let state = analyzer.export_context_state();

    let mut analyzer2 = Analyzer::new(child_config(), &db);
    analyzer2.import_context_state(state).unwrap();

    assert!(analyzer2.context_tracker().timeline("conv_1").is_some());
    assert!(analyzer2.context_tracker().timeline("conv_2").is_some());
}

#[test]
fn scenario_classic_grooming_over_hours() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let predator = "nice_guy_99";
    let conv = "dm_child_1";
    let hour = 3600 * 1000u64;

    let r = analyzer.analyze_with_context(
        &child_input(
            "Hey! I saw your profile, you seem really cool",
            predator,
            conv,
        ),
        0,
    );
    assert_eq!(r.action, Action::Allow);

    let _ = analyzer.analyze_with_context(
        &child_input(
            "You're so beautiful and amazing, truly special",
            predator,
            conv,
        ),
        hour / 2,
    );

    let _ = analyzer.analyze_with_context(
        &child_input(
            "You seem so mature for your age. Where do you live?",
            predator,
            conv,
        ),
        hour,
    );

    let r = analyzer.analyze_with_context(
        &child_input(
            "Don't tell your parents about me ok? They wouldn't understand",
            predator,
            conv,
        ),
        2 * hour,
    );
    assert!(r.is_threat(), "Should detect grooming secrecy request");

    let r = analyzer.analyze_with_context(
        &child_input(
            "Our little secret, ok? Let's meet, just us two",
            predator,
            conv,
        ),
        3 * hour,
    );
    assert!(r.is_threat());

    assert!(
        r.score >= 0.7,
        "Score should be high after multi-stage grooming, got {}",
        r.score
    );
}

#[test]
fn scenario_group_bullying_pile_on() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "class_group_room";
    let minute = 60 * 1000u64;

    analyzer.analyze_with_context(&child_input("nobody likes you", "bully_1", conv), 0);

    analyzer.analyze_with_context(&child_input("you're worthless", "bully_2", conv), minute);

    analyzer.analyze_with_context(
        &child_input("everyone hates you", "bully_3", conv),
        2 * minute,
    );

    let r = analyzer.analyze_with_context(
        &child_input("you're disgusting", "bully_4", conv),
        3 * minute,
    );

    assert!(r.is_threat());

    assert!(
        r.score >= 0.7,
        "Pile-on should have high score, got {}",
        r.score
    );
}

#[test]
fn pile_on_context_is_not_dropped_for_new_sender_without_direct_bullying_signal() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "class_group_room_context_only";
    let minute = 60 * 1000u64;

    analyzer.analyze_with_context(&child_input("nobody likes you", "bully_1", conv), 0);
    analyzer.analyze_with_context(&child_input("you're worthless", "bully_2", conv), minute);

    let result = analyzer.analyze_with_context(
        &child_input("they're all against you", "bully_3", conv),
        2 * minute,
    );

    assert!(
        result.signals.iter().any(|signal| {
            signal.layer == DetectionLayer::ContextAnalysis
                && signal.threat_type == ThreatType::Bullying
                && (signal.explanation.contains("Group bullying")
                    || signal.explanation.contains("Isolation"))
        }),
        "Expected context bullying signal for new pile-on sender, got: {:?}",
        result.signals
    );
}

#[test]
fn scenario_self_harm_escalation() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let child = "sad_child";
    let conv = "journal";
    let day = 24 * 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input("I had a bad day, nobody talked to me", child, conv),
        0,
    );

    analyzer.analyze_with_context(
        &child_input("I feel like nobody cares about me at all", child, conv),
        3 * day,
    );

    let r = analyzer.analyze_with_context(
        &child_input("There's no reason to live anymore", child, conv),
        5 * day,
    );
    assert!(r.is_threat());
    assert_eq!(r.threat_type, ThreatType::SelfHarm);
    assert_eq!(r.action, Action::Warn);

    assert!(r.needs_crisis_resources());
}

#[test]
fn primary_threat_score_is_not_inflated_by_lower_priority_signal() {
    let db = test_db();
    let analyzer = Analyzer::new(child_config(), &db);
    let signals = vec![
        DetectionSignal::pattern(
            ThreatType::Spam,
            0.95,
            Confidence::High,
            "abuse.spam",
            "spam burst",
        ),
        DetectionSignal::context(
            ThreatType::SelfHarm,
            0.72,
            Confidence::High,
            SignalFamily::Conversation,
            "conversation.self_harm.crisis",
            "acute self-harm disclosure",
        ),
    ];

    let result =
        analyzer.combine_signals(signals, ProtectionLevel::High, ConversationType::Direct, 42);

    assert_eq!(result.threat_type, ThreatType::SelfHarm);
    assert!(
        (result.score - 0.72).abs() < f32::EPSILON,
        "Primary threat score should stay on the selected threat, got {}",
        result.score
    );
}

#[test]
fn grooming_memory_does_not_relabel_direct_coercive_manipulation() {
    let db = test_db();
    let analyzer = Analyzer::new(child_config(), &db);
    let signals = vec![
        DetectionSignal::pattern(
            ThreatType::Manipulation,
            0.84,
            Confidence::High,
            "pattern.debt_creation_uk",
            "direct debt leverage",
        ),
        DetectionSignal::context(
            ThreatType::Grooming,
            1.0,
            Confidence::High,
            SignalFamily::Conversation,
            "domain.kids.memory.grooming_progression",
            "prior grooming progression",
        ),
    ];

    let result =
        analyzer.combine_signals(signals, ProtectionLevel::High, ConversationType::Direct, 42);

    assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
    assert!(result
        .detected_threats
        .iter()
        .any(|(threat, score)| *threat == ThreatType::Grooming && *score == 1.0));
}

#[test]
fn propaganda_action_uses_reason_code_of_top_scoring_signal() {
    let db = test_db();
    let analyzer = Analyzer::new(child_config(), &db);
    let signals = vec![
        DetectionSignal::pattern(
            ThreatType::Propaganda,
            0.80,
            Confidence::High,
            "propaganda.coordinated_test",
            "coordinated narrative spread",
        ),
        DetectionSignal::pattern(
            ThreatType::Propaganda,
            0.90,
            Confidence::High,
            "propaganda.whataboutism_test",
            "whataboutism burst",
        ),
    ];

    let result =
        analyzer.combine_signals(signals, ProtectionLevel::High, ConversationType::Direct, 7);

    assert_eq!(result.threat_type, ThreatType::Propaganda);
    assert_eq!(
        result.action,
        Action::Mark,
        "Top propaganda reason code should drive subtype-specific action"
    );
}

#[test]
fn high_uncertainty_high_risk_downgrades_block_to_guardian_warn() {
    let db = test_db();
    let analyzer = Analyzer::new(child_config(), &db);
    let signals = vec![
        DetectionSignal::pattern(
            ThreatType::Grooming,
            0.92,
            Confidence::High,
            "pattern.grooming.secret",
            "secrecy grooming",
        ),
        DetectionSignal::pattern(
            ThreatType::Manipulation,
            0.90,
            Confidence::High,
            "pattern.manipulation.coercion",
            "coercive manipulation",
        ),
    ];

    let result =
        analyzer.combine_signals(signals, ProtectionLevel::High, ConversationType::Direct, 15);
    assert_eq!(result.inference.uncertainty, UncertaintyLevel::High);
    assert_eq!(result.action, Action::Warn);
    let recommendation = result.recommended_action.expect("recommendation");
    assert!(recommendation
        .ui_actions
        .contains(&UiAction::EscalateToGuardian));
}

#[test]
fn scenario_farewell_detection() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);

    let _r = analyzer.analyze_with_context(
        &child_input(
            "Goodbye everyone. I'm sorry for everything. Thank you for everything.",
            "child",
            "conv_1",
        ),
        1000,
    );

    let timeline = analyzer.context_tracker().timeline("conv_1").unwrap();
    let has_farewell = timeline
        .all_events()
        .iter()
        .any(|e| e.kind == EventKind::FarewellMessage);
    assert!(has_farewell, "Should detect farewell pattern via enricher");
}

#[test]
fn scenario_love_bombing_enricher() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);

    analyzer.analyze_with_context(
        &child_input(
            "You're so beautiful and amazing and perfect, the most incredible person!",
            "stranger",
            "conv_1",
        ),
        1000,
    );

    let timeline = analyzer.context_tracker().timeline("conv_1").unwrap();
    let has_bombing = timeline
        .all_events()
        .iter()
        .any(|e| e.kind == EventKind::LoveBombing || e.kind == EventKind::Flattery);
    assert!(has_bombing, "Should detect love bombing via enricher");
}

#[test]
fn scenario_probing_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);

    analyzer.analyze_with_context(
        &child_input(
            "Where do you live? What school do you go to? Are you home alone?",
            "stranger",
            "conv_1",
        ),
        1000,
    );

    let timeline = analyzer.context_tracker().timeline("conv_1").unwrap();
    let has_probing = timeline
        .all_events()
        .iter()
        .any(|e| e.kind == EventKind::PersonalInfoRequest);
    assert!(
        has_probing,
        "Should detect personal info probing via enricher"
    );
}

#[test]
fn drug_slang_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input(
        "hey i got gas, dm for prices, delivery available",
    ));
    assert!(
        result.score > 0.0,
        "Drug slang should be detected: {result:?}"
    );
}

#[test]
fn sextortion_countdown_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input("you have 24 hours or i'll share everything"));
    assert!(
        result.score > 0.0,
        "Sextortion countdown should be detected: {result:?}"
    );
}

#[test]
fn grooming_video_call_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let result = analyzer.analyze(&default_input(
        "let's video call just us, turn on your camera for me",
    ));
    assert!(
        result.score > 0.0,
        "Grooming video call should be detected: {result:?}"
    );
}

#[test]
fn grooming_body_comments_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let result = analyzer.analyze(&default_input(
        "you must have a nice body, what do you wear to bed",
    ));
    assert!(
        result.score > 0.0,
        "Grooming body comments should be detected: {result:?}"
    );
}

#[test]
fn corroborated_grooming_flattery_boosts_risky_direct_score() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let result = analyzer.analyze_with_context(
        &default_input(
            "You're so mature for your age. I really understand you better than others do.",
        ),
        1_000,
    );
    assert_eq!(result.threat_type, ThreatType::Grooming, "{result:?}");
    assert!(
        result.score >= 0.68,
        "corroborated grooming flattery should get calibration boost: {result:?}"
    );
}

#[test]
fn darvo_manipulation_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input(
        "you're the one who started this, i'm the victim here",
    ));
    assert!(
        result.score > 0.0,
        "DARVO manipulation should be detected: {result:?}"
    );
}

#[test]
fn drug_pressure_detected_uk() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input(
        "просто спробуй раз, всі пробують це, перший раз безкоштовно для тебе",
    ));
    assert!(
        result.score > 0.0,
        "Drug pressure UK should be detected: {result:?}"
    );
}

#[test]
fn sextortion_photo_blackmail_sequence_detected() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "dm_sextort";

    let texts = [
        "у мене є твої голі фотки",
        "якщо не скинеш ще — покажу всім",
        "скинь нові фото або розповім батькам",
    ];

    let mut last_result = None;
    for (idx, text) in texts.iter().enumerate() {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some((*text).to_string()),
            image_data: None,
            sender_id: "sextort".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        last_result = Some(analyzer.analyze_with_context(&input, (idx as u64 + 1) * 1_000));
    }

    let result = last_result.expect("sextortion result");
    assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
    assert!(result.score >= 0.70, "{result:?}");
}

#[test]
fn substance_offer_and_pressure_detected_as_manipulation() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "dm_drugs";

    let first = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("хочеш спробувати тр@вку? перший раз на халяву".to_string()),
            image_data: None,
            sender_id: "dealer".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );
    assert_eq!(first.threat_type, ThreatType::Manipulation, "{first:?}");

    let second = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("не сси, всі так роблять в нашому віці".to_string()),
            image_data: None,
            sender_id: "dealer".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        2_000,
    );
    assert_eq!(second.threat_type, ThreatType::Manipulation, "{second:?}");
    assert!(second.score >= 0.50, "{second:?}");
}

#[test]
fn integration_grooming_sequence_produces_recommendation() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_groom";
    let hour = 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input(
            "You're so beautiful and amazing and special!",
            "stranger",
            conv,
        ),
        0,
    );

    let r = analyzer.analyze_with_context(
        &child_input("Don't tell your parents about me ok?", "stranger", conv),
        hour,
    );

    assert!(r.is_threat(), "Should detect grooming");
    assert!(
        r.recommended_action.is_some(),
        "Should include recommended_action"
    );
    let rec = r.recommended_action.unwrap();
    assert!(
        rec.parent_alert >= AlertPriority::High,
        "Grooming should alert parent"
    );
}

#[test]
fn integration_selfharm_never_blocked_always_crisis() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_sh";

    let r = analyzer.analyze_with_context(
        &child_input(
            "I don't want to live anymore. I want to end it all.",
            "child",
            conv,
        ),
        1000,
    );
    assert_ne!(r.action, Action::Block, "Self-harm must NEVER be blocked");
    assert!(
        r.needs_crisis_resources(),
        "Self-harm must show crisis resources"
    );
    assert!(r.recommended_action.is_some());
    let rec = r.recommended_action.unwrap();
    assert!(rec.crisis_resources, "Crisis resources must be enabled");
}

#[test]
fn integration_bullying_pile_on_escalates() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_bully";
    let min = 60 * 1000u64;
    let base = 10 * 3600 * 1000u64;

    let bullies = ["b1", "b2", "b3", "b4"];
    let insults = [
        "Nobody likes you, just leave",
        "You're worthless and pathetic",
        "Everyone hates you, go away",
        "You're disgusting, nobody wants you",
    ];

    let mut last_result = None;
    for (i, (bully, insult)) in bullies.iter().zip(insults.iter()).enumerate() {
        let r = analyzer
            .analyze_with_context(&child_input(insult, bully, conv), base + (i as u64) * min);
        last_result = Some(r);
    }

    let r = last_result.unwrap();
    assert!(r.is_threat(), "Pile-on bullying should be detected");
    assert!(
        r.score >= 0.5,
        "Pile-on should produce significant score: {}",
        r.score
    );
}

#[test]
fn integration_manipulation_multi_tactic() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "int_manip";
    let day = 24 * 3600 * 1000u64;
    let manip = "manipulator";

    analyzer.analyze_with_context(
        &child_input(
            "That never happened, you're imagining things. You're being dramatic.",
            manip,
            conv,
        ),
        0,
    );

    analyzer.analyze_with_context(
        &child_input(
            "It's all in your head, you're making things up. Nobody will believe you.",
            manip,
            conv,
        ),
        day,
    );

    let r = analyzer.analyze_with_context(
        &child_input(
            "After everything I've done for you, you're so ungrateful. This is your fault.",
            manip,
            conv,
        ),
        2 * day,
    );

    assert!(
        r.is_threat(),
        "Multi-tactic manipulation should be detected"
    );
    assert!(r.recommended_action.is_some());
}

#[test]
fn integration_explicit_content_always_alerts_parent() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);

    let r = analyzer.analyze(&child_input(
        "send me nudes right now, take off your clothes",
        "creep",
        "conv_x",
    ));
    if r.is_threat() {
        if let Some(rec) = &r.recommended_action {
            assert!(
                rec.parent_alert >= AlertPriority::Medium,
                "Explicit content should alert parent: {:?}",
                rec.parent_alert
            );
        }
    }
}

#[test]
fn integration_context_preserves_across_export_import() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_persist";

    analyzer.analyze_with_context(
        &child_input("You're so beautiful and amazing!", "stranger", conv),
        1000,
    );

    let state = analyzer.export_context_state();
    assert!(
        state
            .timelines
            .iter()
            .any(|timeline| timeline.conversation_id == conv),
        "State should contain conversation"
    );

    let mut analyzer2 = Analyzer::new(child_config(), &db);
    analyzer2
        .import_context_state(state)
        .expect("import should work");

    let r = analyzer2.analyze_with_context(
        &child_input("Don't tell your parents about me", "stranger", conv),
        2000,
    );
    assert!(
        r.is_threat(),
        "Context should persist: grooming detected after import"
    );
}

#[test]
fn integration_clean_conversation_no_false_positives() {
    let db = test_db();

    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let conv = "int_clean";
    let min = 60 * 1000u64;

    let messages = [
        ("friend_1", "Hey did you finish the homework?"),
        ("child", "Yeah it was hard! Want to play Minecraft?"),
        ("friend_1", "Sure! My mom said I can play until 7"),
        ("child", "Let's build a castle together!"),
        ("friend_1", "Cool see you in the game!"),
    ];

    for (i, (sender, text)) in messages.iter().enumerate() {
        let r = analyzer.analyze_with_context(&child_input(text, sender, conv), i as u64 * min);
        assert!(
            !r.is_threat(),
            "Normal message should not be a threat: '{text}' got {:?} ({:?})",
            r.action,
            r.threat_type
        );
    }
}

#[test]
fn integration_sextortion_countdown_high_severity() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_sextort";
    let day = 24 * 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input("You're so beautiful, send me a photo", "predator", conv),
        0,
    );

    let r = analyzer.analyze_with_context(
        &child_input(
            "You have 24 hours or everyone sees your photos",
            "predator",
            conv,
        ),
        day,
    );

    assert!(r.is_threat(), "Sextortion should be detected");
    assert!(
        r.score >= 0.5,
        "Sextortion should have high score: {}",
        r.score
    );
}

#[test]
fn integration_raid_detection_multiple_senders() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_raid";
    let min = 60 * 1000u64;
    let base = 14 * 3600 * 1000u64;

    for i in 1..=5 {
        let sender = format!("raider_{i}");
        let text = format!("You're worthless and pathetic, nobody likes you (attack #{i})");
        analyzer.analyze_with_context(&child_input(&text, &sender, conv), base + i * min);
    }

    let profiler = analyzer.context_tracker().contact_profiler();
    let contacts = profiler.contacts_by_risk();
    let hostile_count = contacts.iter().filter(|c| c.risk_score() > 0.0).count();
    assert!(
        hostile_count >= 3,
        "Raid should produce multiple hostile contacts: got {hostile_count}"
    );
}

#[test]
fn integration_bullying_to_selfharm_pathway() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_b2sh";
    let hour = 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input("Nobody likes you, you're worthless", "bully_1", conv),
        0,
    );
    analyzer.analyze_with_context(
        &child_input("Everyone hates you, just leave", "bully_2", conv),
        hour,
    );

    let r = analyzer.analyze_with_context(
        &child_input(
            "Maybe they're right. I want to end it all. Nobody cares about me.",
            "victim",
            conv,
        ),
        2 * hour,
    );

    assert!(r.is_threat(), "Self-harm after bullying should be detected");
    assert_ne!(r.action, Action::Block, "Self-harm must not be blocked");
    assert!(r.needs_crisis_resources(), "Should show crisis resources");
}

#[test]
fn integration_video_call_grooming_detected() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_video";
    let day = 24 * 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input(
            "You're so beautiful and special, I love talking to you",
            "creep",
            conv,
        ),
        0,
    );

    let r = analyzer.analyze_with_context(
        &child_input(
            "Let's video call just us, turn on your camera for me",
            "creep",
            conv,
        ),
        day,
    );

    assert!(r.is_threat(), "Video call grooming should be detected");
}

#[test]
fn integration_darvo_pattern_across_messages() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_darvo";
    let day = 24 * 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input("You're the one who started this, not me", "abuser", conv),
        0,
    );
    analyzer.analyze_with_context(
        &child_input("I'm the victim here, you're hurting me", "abuser", conv),
        day,
    );
    let r = analyzer.analyze_with_context(
        &child_input(
            "You're the one who started this, stop playing victim",
            "abuser",
            conv,
        ),
        2 * day,
    );

    assert!(
        r.is_threat(),
        "DARVO pattern should be detected across messages"
    );
}

#[test]
fn integration_financial_grooming_builds_context() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_finance";
    let day = 24 * 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input(
            "I want to send you money, I'll buy you anything",
            "sugar_daddy",
            conv,
        ),
        0,
    );

    let r = analyzer.analyze_with_context(
        &child_input(
            "Don't tell your parents about the gifts ok?",
            "sugar_daddy",
            conv,
        ),
        day,
    );

    assert!(
        r.is_threat(),
        "Financial grooming + secrecy should be detected"
    );
}

#[test]
fn integration_recommended_action_serializes() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_serial";

    let r = analyzer.analyze_with_context(
        &child_input("Don't tell your parents about me ok?", "stranger", conv),
        1000,
    );

    let json = serde_json::to_string(&r).expect("should serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert!(value.get("recommended_action").is_some());
    assert!(value["recommended_action"].get("parent_alert").is_some());
    assert!(value.get("risk_breakdown").is_some());
    assert!(value.get("reason_codes").is_some());
    assert!(value.get("contact_snapshot").is_some());
    assert!(value.get("inference").is_some());
}

#[test]
fn integration_context_result_includes_contact_snapshot_and_breakdown() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_snapshot";

    let r = analyzer.analyze_with_context(
        &child_input("Don't tell your parents about me ok?", "stranger", conv),
        1000,
    );

    let snapshot = r
        .contact_snapshot
        .expect("context analysis should attach snapshot");
    assert_eq!(snapshot.sender_id, "stranger");
    assert!(snapshot.is_new_contact);
    assert!(r.risk_breakdown.content > 0.0 || r.risk_breakdown.conversation > 0.0);
    assert!(
        !r.reason_codes.is_empty(),
        "reason codes should be populated"
    );
}

#[test]
fn clean_result_has_default_inference_summary() {
    let result = AnalysisResult::clean(42);
    assert_eq!(result.inference.uncertainty, UncertaintyLevel::Medium);
    assert_eq!(result.inference.risk_horizon, RiskHorizon::Unknown);
    assert_eq!(result.inference.escalation_likelihood_24h, 0.0);
    assert!(result.inference.latent_states.is_empty());
}

#[test]
fn selfharm_inference_sets_immediate_horizon_and_crisis_state() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_sh_inference";

    analyzer.analyze_with_context(
        &child_input(
            "I don't want to live anymore. I want to end it all.",
            "child",
            conv,
        ),
        1000,
    );
    let r = analyzer.analyze_with_context(
        &child_input("Goodbye everyone. This is the end.", "child", conv),
        2000,
    );

    assert_eq!(r.inference.risk_horizon, RiskHorizon::Immediate);
    assert!(
        r.inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::CrisisVulnerability),
        "self-harm flow should surface crisis latent state"
    );
    assert!(
        r.inference.escalation_likelihood_24h >= 0.7,
        "acute self-harm should imply high short-horizon escalation likelihood"
    );
}

#[test]
fn grooming_inference_surfaces_dependency_and_isolation_states() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_groom_inference";
    let hour = 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input(
            "You're so special and beautiful. I can buy you anything.",
            "stranger",
            conv,
        ),
        0,
    );
    let r = analyzer.analyze_with_context(
        &child_input(
            "Don't tell your parents about us. Let's move to Telegram.",
            "stranger",
            conv,
        ),
        hour,
    );

    assert!(
        r.inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::DependencyBuilding),
        "grooming flow should surface dependency-building"
    );
    assert!(
        r.inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::IsolationPressure),
        "grooming flow should surface isolation pressure"
    );
    assert_eq!(r.inference.risk_horizon, RiskHorizon::ShortTerm);
}

#[test]
fn safe_report_context_suppresses_harmful_inference_states() {
    let signals = vec![
        DetectionSignal::pattern(
            ThreatType::Manipulation,
            0.86,
            Confidence::High,
            "conversation.manipulation.screenshot_reputation_blackmail",
            "reputation blackmail",
        ),
        DetectionSignal::context(
            ThreatType::Bullying,
            0.78,
            Confidence::High,
            SignalFamily::Abuse,
            "abuse.raid.pile_on",
            "group pile-on",
        ),
    ];
    let context_markers = vec![
        "context.filter.applied".to_string(),
        "context.speech_act.report".to_string(),
        "context.stance.neutral".to_string(),
    ];
    let context_summary = AnalysisContextSummary::from_markers(&context_markers);

    let inference = build_inference_summary(
        &signals,
        &RiskBreakdown {
            content: 0.45,
            conversation: 0.82,
            link: 0.0,
            abuse: 0.78,
        },
        ThreatType::Manipulation,
        0.86,
        ConversationType::Group,
        None,
        &context_summary,
    );

    assert!(
        !inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::CoerciveControl),
        "report context should not surface coercive-control latent state: {:?}",
        inference.latent_states
    );
    assert!(
        !inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::GroupEscalation),
        "report context should not surface group-escalation latent state: {:?}",
        inference.latent_states
    );
    assert_eq!(inference.risk_horizon, RiskHorizon::Unknown);
    assert!(
        inference.escalation_likelihood_24h <= 0.30,
        "report context should heavily downweight escalation likelihood: {:?}",
        inference
    );
}

#[test]
fn supportive_context_converts_selfharm_inference_into_protective_support() {
    let signals = vec![DetectionSignal::pattern(
        ThreatType::SelfHarm,
        0.88,
        Confidence::High,
        "conversation.selfharm.acute_crisis",
        "acute crisis",
    )];
    let context_markers = vec![
        "context.filter.applied".to_string(),
        "context.speech_act.support".to_string(),
        "context.relationship.trusted".to_string(),
    ];
    let context_summary = AnalysisContextSummary::from_markers(&context_markers);

    let inference = build_inference_summary(
        &signals,
        &RiskBreakdown {
            content: 0.88,
            conversation: 0.42,
            link: 0.0,
            abuse: 0.0,
        },
        ThreatType::SelfHarm,
        0.88,
        ConversationType::Direct,
        None,
        &context_summary,
    );

    assert!(
        !inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::CrisisVulnerability),
        "support context should suppress crisis latent state: {:?}",
        inference.latent_states
    );
    let protective = inference
        .latent_states
        .iter()
        .find(|state| state.kind == LatentStateKind::ProtectiveSupport)
        .expect("support context should surface protective support");
    assert!(
        protective.score >= 0.60,
        "protective support should get contextual floor"
    );
    assert_eq!(inference.risk_horizon, RiskHorizon::Unknown);
    assert!(
        inference.escalation_likelihood_24h <= 0.05,
        "support context should collapse escalation likelihood: {:?}",
        inference
    );
}

#[test]
fn blocked_url_sets_link_risk_and_reason_codes() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let r = analyzer.analyze(&default_input("check this out https://evil-site.com/login"));

    assert!(
        r.risk_breakdown.link > 0.0,
        "blocked url should raise link risk"
    );
    assert!(
        r.reason_codes
            .iter()
            .any(|code| code == "link.blocked_domain"),
        "blocked url should include link reason code"
    );
    assert!(
        r.signals
            .iter()
            .any(|signal| signal.family == SignalFamily::Link),
        "blocked url signal should be classified as link family"
    );
}

#[test]
fn propaganda_domain_generates_propaganda_signal_and_suspicious_source_event() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let r = analyzer.analyze_with_context(&default_input("check https://rt.com/story"), 1000);

    assert!(r.signals.iter().any(|signal| {
        signal.threat_type == ThreatType::Propaganda
            && signal.family == SignalFamily::Link
            && signal.threat_subtype == "state_media"
            && signal
                .reason_code
                .starts_with("pattern.propaganda_domain_state_")
    }));
    assert!(
        !r.signals.iter().any(|signal| {
            signal.threat_type == ThreatType::Phishing
                && signal.reason_code == "link.blocked_domain"
        }),
        "propaganda domains should not be surfaced as generic phishing"
    );

    let timeline = analyzer
        .context_tracker()
        .timeline("conv_456")
        .expect("timeline should exist");
    assert!(timeline.all_events().iter().any(|event| {
        event.kind == EventKind::SuspiciousSource && event.subtype.as_deref() == Some("state_media")
    }));
}

#[test]
fn propaganda_dehumanization_uses_subtype_policy_for_blocking() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let mut input = default_input("свинособаки");
    input.language = Some("uk".to_string());

    let r = analyzer.analyze(&input);

    assert_eq!(r.action, Action::Block);
    assert!(r.signals.iter().any(|signal| {
        signal.threat_type == ThreatType::Propaganda && signal.threat_subtype == "dehumanization"
    }));
}

#[test]
fn military_update_enables_phishing_context_and_subtypes() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    analyzer
        .update_config(
            AuraConfig {
                domain_mode: DomainMode::Military,
                ..AuraConfig::default()
            },
            &db,
        )
        .expect("valid military config update");

    let r = analyzer.analyze_with_context(&default_input("https://diia-gov.app/login"), 1000);

    assert!(r.signals.iter().any(|signal| {
        signal.threat_type == ThreatType::MilitarySocialEng
            && signal.reason_code.contains("phishing_diia")
    }));
    let timeline = analyzer
        .context_tracker()
        .timeline("conv_456")
        .expect("timeline should exist");
    assert!(timeline.all_events().iter().any(|event| {
        event.kind == EventKind::MilitaryPhishing
            && event.subtype.as_deref() == Some("phishing_diia")
    }));
}

#[test]
fn coordinate_rules_map_to_coordinate_mentions() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(
        AuraConfig {
            domain_mode: DomainMode::Military,
            ..AuraConfig::default()
        },
        &db,
    );

    let r = analyzer.analyze_with_context(&default_input("48.4500, 35.0000"), 1000);

    assert!(r.signals.iter().any(|signal| {
        signal.threat_type == ThreatType::CoordinateLeak && signal.threat_subtype == "ukraine_dd"
    }));
    assert!(
        !r.signals
            .iter()
            .any(|signal| signal.reason_code == "pattern.opsec_coordinates_001"),
        "generic coordinate rule should be suppressed when ukraine_dd is present"
    );
    let timeline = analyzer
        .context_tracker()
        .timeline("conv_456")
        .expect("timeline should exist");
    assert!(timeline.all_events().iter().any(|event| {
        event.kind == EventKind::CoordinateMention && event.subtype.as_deref() == Some("ukraine_dd")
    }));
    assert!(
        !timeline
            .all_events()
            .iter()
            .any(|event| event.kind == EventKind::Exclusion),
        "coordinate rules should not be routed into exclusion events"
    );
}

#[test]
fn military_phishing_uk_rule_sets_generic_subtype() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(
        AuraConfig {
            domain_mode: DomainMode::Military,
            ..AuraConfig::default()
        },
        &db,
    );
    let mut input = default_input("оновіть дані в дії через нову перевірку");
    input.language = Some("uk".to_string());
    let r = analyzer.analyze_with_context(&input, 1000);
    assert!(r.signals.iter().any(|signal| {
        signal.threat_type == ThreatType::MilitarySocialEng
            && signal.reason_code == "pattern.military_phishing_uk_001"
            && signal.threat_subtype == "military_phishing"
    }));
}

#[test]
fn psyops_distrust_rule_sets_command_distrust_subtype() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(
        AuraConfig {
            domain_mode: DomainMode::Military,
            ..AuraConfig::default()
        },
        &db,
    );
    let mut input = default_input("командування продало");
    input.language = Some("uk".to_string());
    let r = analyzer.analyze_with_context(&input, 1000);
    assert!(r.signals.iter().any(|signal| {
        signal.threat_type == ThreatType::Psyops
            && signal.reason_code == "pattern.psyops_distrust_uk_001"
            && signal.threat_subtype == "command_distrust"
    }));
}

#[test]
fn suspicious_url_heuristic_sets_link_risk_and_reason_codes() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let r = analyzer.analyze(&default_input(
        "grab this now http://fr33-r0bux.xyz/claim before it expires",
    ));

    assert!(
        r.risk_breakdown.link > 0.0,
        "suspicious url heuristic should raise link risk"
    );
    assert!(
        r.reason_codes
            .iter()
            .any(|code| code == "link.suspicious_url_heuristic"),
        "heuristic suspicious url should include link reason code"
    );
    assert!(
        r.signals.iter().any(|signal| {
            signal.family == SignalFamily::Link
                && signal.reason_code == "link.suspicious_url_heuristic"
        }),
        "heuristic suspicious url should be classified as link family"
    );
}

#[test]
fn suspicious_url_doppelganger_sets_subtype() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let r = analyzer.analyze(&default_input("read this https://bild.ltd/article"));
    assert!(r.signals.iter().any(|signal| {
        signal.reason_code == "link.suspicious_url_heuristic"
            && signal.threat_subtype == "doppelganger"
    }));
}

#[test]
fn suspicious_url_homoglyph_sets_subtype() {
    let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "url_block_gov",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["gov.ua"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Government domain"
                }
            ]
        }"#;
    let db = PatternDatabase::from_json_validated(json).unwrap();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let r = analyzer.analyze(&default_input("https://g\u{043e}v.ua/login"));
    assert!(r.signals.iter().any(|signal| {
        signal.reason_code == "link.suspicious_url_heuristic"
            && signal.threat_subtype == "homoglyph"
    }));
}

#[test]
fn suspicious_url_heuristic_sets_default_subtype() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let r = analyzer.analyze(&default_input(
        "grab this now http://fr33-r0bux.xyz/claim before it expires",
    ));
    assert!(r.signals.iter().any(|signal| {
        signal.reason_code == "link.suspicious_url_heuristic"
            && signal.threat_subtype == "heuristic"
    }));
}

#[test]
fn out_of_ukraine_decimal_coordinates_are_filtered() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(
        AuraConfig {
            domain_mode: DomainMode::Military,
            ..AuraConfig::default()
        },
        &db,
    );
    let r = analyzer.analyze_with_context(&default_input("55.7558, 37.6173"), 1000);
    assert!(
        !r.signals
            .iter()
            .any(|signal| signal.reason_code == "pattern.opsec_coordinates_001"),
        "out-of-Ukraine decimal coordinates should be filtered"
    );
}

#[test]
fn propaganda_counter_narrative_is_filtered() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let mut input = default_input("пропагандисти кажуть: «це спецоперація»");
    input.language = Some("uk".to_string());
    let r = analyzer.analyze(&input);
    assert!(
        !r.signals
            .iter()
            .any(|signal| signal.reason_code.starts_with("pattern.propaganda_")),
        "counter-narrative framing should not emit propaganda pattern signals"
    );
}

#[test]
fn quoted_direct_threat_report_is_filtered_before_tracker() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let input = default_input(r#"He said "I will kill you", and I'm reporting it to the teacher."#);
    let r = analyzer.analyze_with_context(&input, 1000);

    assert!(
        !r.detected_threats
            .iter()
            .any(|(threat, _)| *threat == ThreatType::Threat),
        "quoted abuse report should not classify sender as direct threat: {:?}",
        r.detected_threats
    );

    let timeline = analyzer
        .context_tracker()
        .timeline("conv_456")
        .expect("timeline should exist");
    assert!(
        !timeline.all_events().iter().any(|event| matches!(
            event.kind,
            EventKind::PhysicalThreat | EventKind::HarmEncouragement
        )),
        "quoted threat report should not persist direct threat events: {:?}",
        timeline.all_events()
    );
}

#[test]
fn supportive_selfharm_response_is_filtered_before_tracker() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let input = default_input(
            "My friend said there is no reason to live. I'm here with you, let's tell your parents together and get help tonight.",
        );
    let r = analyzer.analyze_with_context(&input, 1000);

    assert_eq!(
        r.threat_type,
        ThreatType::None,
        "supportive self-harm response should stay clean: {r:?}"
    );

    let timeline = analyzer
        .context_tracker()
        .timeline("conv_456")
        .expect("timeline should exist");
    assert!(
        !timeline.all_events().iter().any(|event| matches!(
            event.kind,
            EventKind::SuicidalIdeation | EventKind::Hopelessness | EventKind::FarewellMessage
        )),
        "supportive response should not persist self-harm events: {:?}",
        timeline.all_events()
    );
    assert!(
        r.reason_codes
            .iter()
            .any(|code| code == "context.speech_act.support"),
        "supportive filtering should surface support context marker: {:?}",
        r.reason_codes
    );
    assert!(
        r.reason_codes
            .iter()
            .any(|code| code == "context.filter.applied"),
        "supportive filtering should surface filter marker: {:?}",
        r.reason_codes
    );
    assert_eq!(r.inference.risk_horizon, RiskHorizon::Unknown);
    assert!(
        !r.inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::CrisisVulnerability),
        "supportive response should not infer crisis vulnerability for the sender: {:?}",
        r.inference.latent_states
    );
}

#[test]
fn supportive_selfharm_response_cannot_retain_filtered_kids_domain_action() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let input = child_input(
        "My friend said there is no reason to live. I'm here with you, let's tell your parents together and get help tonight.",
        "supportive-peer",
        "supportive-conversation",
    );
    let result = analyzer.analyze_with_context(&input, 1000);

    assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
    assert_eq!(result.action, Action::Allow, "{result:?}");
    assert_eq!(result.score, 0.0, "{result:?}");
    assert!(
        !result
            .reason_codes
            .iter()
            .any(|code| code.starts_with("domain.kids.selfharm")),
        "{result:?}"
    );
    assert!(
        !result
            .reason_codes
            .iter()
            .any(|code| code == "domain.action.warn"),
        "{result:?}"
    );
}

#[test]
fn filtered_supportive_selfharm_cannot_seed_kids_bullying_memory() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conversation = "supportive-memory-boundary";

    let supportive = child_input(
        "My friend said there is no reason to live. I'm here with you, let's tell your parents together and get help tonight.",
        "supportive-peer",
        conversation,
    );
    let first_bullying = child_input(
        "you're worthless. nobody likes you.",
        "bully-a",
        conversation,
    );
    let second_bullying = child_input(
        "everyone hates you. all of us hate you.",
        "bully-b",
        conversation,
    );

    let supportive_result = analyzer.analyze_with_context(&supportive, 1_000);
    assert_eq!(supportive_result.threat_type, ThreatType::None);
    let _ = analyzer.analyze_with_context(&first_bullying, 2_000);
    let second_result = analyzer.analyze_with_context(&second_bullying, 3_000);

    assert!(
        !second_result
            .reason_codes
            .iter()
            .any(|code| code == "domain.kids.memory.bullying_cascade_selfharm"),
        "a context-filtered supportive report must not seed Kids memory: {second_result:?}"
    );
}

#[test]
fn supportive_bystander_rescue_filters_late_night_minor_contact() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let conv = "supportive_rescue";

    for (idx, text) in [
        "hey stop piling on him, this is not okay",
        "im calling the counselor and staying with you, you're not alone",
        "let's leave this chat and get help from adults right now",
    ]
    .into_iter()
    .enumerate()
    {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: "rescue_peer".into(),
            conversation_id: conv.into(),
            language: Some("en".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        let result = analyzer.analyze_with_context(&input, idx as u64 * 120_000);
        if idx == 2 {
            assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
            assert!(
                !result.signals.iter().any(|signal| {
                    signal.reason_code == "conversation.timing.late_night_minor_contact"
                }),
                "{result:?}"
            );
        }
    }
}

#[test]
fn opsec_warning_about_coordinates_is_filtered_before_tracker() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(
        AuraConfig {
            domain_mode: DomainMode::Military,
            ..AuraConfig::default()
        },
        &db,
    );
    let input =
        default_input("Don't post coordinates like 48.4500, 35.0000 in chat. Remove them now.");
    let r = analyzer.analyze_with_context(&input, 1000);

    assert!(
        !r.signals
            .iter()
            .any(|signal| signal.reason_code == "pattern.opsec_coordinates_001"),
        "opsec warning should not emit coordinate leak signals: {:?}",
        r.signals
    );

    let timeline = analyzer
        .context_tracker()
        .timeline("conv_456")
        .expect("timeline should exist");
    assert!(
        !timeline.all_events().iter().any(|event| matches!(
            event.kind,
            EventKind::CoordinateMention
                | EventKind::PositionLeak
                | EventKind::UnitInfoLeak
                | EventKind::EquipmentLeak
        )),
        "opsec warning should not persist leak events: {:?}",
        timeline.all_events()
    );
}

#[test]
fn recommendation_carries_ui_actions_and_reason_codes() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_ui_actions";

    let r = analyzer.analyze_with_context(
        &child_input("Don't tell your parents about me ok?", "stranger", conv),
        1000,
    );

    let rec = r
        .recommended_action
        .expect("recommendation should be present");
    assert!(
        !rec.ui_actions.is_empty(),
        "recommendation should expose messenger ui actions"
    );
    assert_eq!(rec.reason_codes, r.reason_codes);
}

#[test]
fn coercive_control_inference_escalates_policy_actions() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let conv = "int_coercive_control";
    let hour = 3_600_000u64;

    analyzer.analyze_with_context(
        &child_input(
            "After everything I did for u, u owe me honesty.",
            "dating_abuser",
            conv,
        ),
        0,
    );
    analyzer.analyze_with_context(
        &child_input(
            "You're so ungrateful. I sacrificed so much for you.",
            "dating_abuser",
            conv,
        ),
        hour,
    );
    analyzer.analyze_with_context(
        &child_input(
            "I'll show this to everyone at school if you don't listen.",
            "dating_abuser",
            conv,
        ),
        2 * hour,
    );
    let result = analyzer.analyze_with_context(
        &child_input(
            "After everything i've done for you, this is how you repay me.",
            "dating_abuser",
            conv,
        ),
        3 * hour,
    );

    let recommendation = result
        .recommended_action
        .expect("recommendation should be present");

    assert!(
        recommendation.ui_actions.contains(&UiAction::SuggestReport),
        "coercive-control escalation should trigger report guidance"
    );
    assert!(
        recommendation
            .ui_actions
            .contains(&UiAction::SlowDownConversation),
        "coercive-control escalation should slow the conversation"
    );
    assert!(
        result
            .inference
            .latent_states
            .iter()
            .any(|state| state.kind == LatentStateKind::CoerciveControl),
        "coercive-control latent state should be present"
    );
}

#[test]
fn integration_contact_profiler_tracks_risk() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let hour = 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input("Hey want to play after school?", "safe_kid", "conv_s"),
        0,
    );

    analyzer.analyze_with_context(
        &child_input("You're so beautiful and amazing!", "bad_actor", "conv_b"),
        hour,
    );
    analyzer.analyze_with_context(
        &child_input("Don't tell your parents about me", "bad_actor", "conv_b"),
        2 * hour,
    );

    let profiler = analyzer.context_tracker().contact_profiler();
    let contacts = profiler.contacts_by_risk();

    assert!(contacts.len() >= 2, "Should have at least 2 contacts");

    let bad_risk = profiler
        .profile("bad_actor")
        .map(|p| p.risk_score())
        .unwrap_or(0.0);
    let safe_risk = profiler
        .profile("safe_kid")
        .map(|p| p.risk_score())
        .unwrap_or(0.0);
    assert!(
        bad_risk > safe_risk,
        "bad_actor ({bad_risk}) should have higher risk than safe_kid ({safe_risk})"
    );
}

#[test]
fn empty_text_returns_clean_result() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input(""));
    assert!(!result.is_threat());
    assert_eq!(result.action, Action::Allow);
}

#[test]
fn none_text_returns_clean_result() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let input = MessageInput {
        content_type: ContentType::Text,
        text: None,
        image_data: None,
        sender_id: "u".into(),
        conversation_id: "c".into(),
        language: None,
        language_evidence: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    };
    let result = analyzer.analyze(&input);
    assert!(!result.is_threat());
}

#[test]
fn very_long_message_does_not_panic() {
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let long = "word ".repeat(10_000);
    let result = analyzer.analyze(&default_input(&long));
    assert!(result.analysis_time_us > 0);
}

#[test]
fn text_truncation_limits_processing() {
    let filler = "a".repeat(10_001);
    let text = format!("{filler} kill you");
    let db = test_db();
    let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
    let result = analyzer.analyze(&default_input(&text));
    assert!(
        !result.is_threat(),
        "Threat word beyond truncation should not be detected"
    );
}

#[test]
fn truncate_text_char_boundary() {
    let text = "a".repeat(9_999) + "ї";
    let truncated = super::truncate_text(&text);
    assert!(truncated.len() <= super::MAX_TEXT_LENGTH);
    assert!(truncated.is_char_boundary(truncated.len()));
}

#[test]
fn config_validation_rejects_bad_ttl() {
    let config = AuraConfig {
        ttl_days: 0,
        ..AuraConfig::default()
    };
    assert!(config.validate().is_err());

    let config = AuraConfig {
        ttl_days: 366,
        ..AuraConfig::default()
    };
    assert!(config.validate().is_err());

    let config = AuraConfig {
        ttl_days: 30,
        ..AuraConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn config_validation_rejects_bad_age() {
    let config = AuraConfig {
        account_holder_age: Some(3),
        ..AuraConfig::default()
    };
    assert!(config.validate().is_err());

    let config = AuraConfig {
        account_holder_age: Some(121),
        ..AuraConfig::default()
    };
    assert!(config.validate().is_err());

    let config = AuraConfig {
        account_holder_age: Some(12),
        ..AuraConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn integration_pii_warns_not_blocks() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(10),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let input = MessageInput {
        content_type: ContentType::Text,
        text: Some("my number is 0501234567, text me!".into()),
        image_data: None,
        sender_id: "child_1".into(),
        conversation_id: "conv_pii".into(),
        language: None,
        language_evidence: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    };

    let result = analyzer.analyze_with_context(&input, 1000);
    assert_ne!(result.action, Action::Block, "PII leakage must NEVER block");
}

#[test]
fn integration_repeated_secrecy_escalates() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(10),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    for i in 0..4 {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some("don't tell your parents about this".into()),
            image_data: None,
            sender_id: "stranger_1".into(),
            conversation_id: "conv_secrecy".into(),
            language: Some("en".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        analyzer.analyze_with_context(&input, (i + 1) * 1000);
    }

    let input = MessageInput {
        content_type: ContentType::Text,
        text: Some("just between us, ok?".into()),
        image_data: None,
        sender_id: "stranger_1".into(),
        conversation_id: "conv_secrecy".into(),
        language: Some("en".to_string()),
        language_evidence: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    };
    let result = analyzer.analyze_with_context(&input, 5000);
    assert!(
        result.score >= 0.5,
        "Repeated secrecy should escalate score, got {}",
        result.score
    );
    assert!(
        result
            .reason_codes
            .iter()
            .any(|code| code == "context.trajectory.repeated_sender"),
        "Repeated secrecy should surface repeated trajectory context: {:?}",
        result.reason_codes
    );
}

#[test]
fn integration_casual_meeting_from_stranger_with_context() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(10),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let msgs = vec![
        ("you're so mature for your age", 1000u64),
        ("don't tell your parents about our chats", 2000),
        ("how old are you? what grade are you in?", 3000),
    ];
    for (text, ts) in msgs {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some(text.into()),
            image_data: None,
            sender_id: "predator".into(),
            conversation_id: "conv_meet".into(),
            language: Some("en".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        analyzer.analyze_with_context(&input, ts);
    }

    let input = MessageInput {
        content_type: ContentType::Text,
        text: Some("you're so beautiful and special, can we meet?".into()),
        image_data: None,
        sender_id: "predator".into(),
        conversation_id: "conv_meet".into(),
        language: Some("en".to_string()),
        language_evidence: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    };
    let result = analyzer.analyze_with_context(&input, 4000);
    assert!(
        result.score >= 0.5,
        "Casual meeting + grooming context should elevate score, got {}",
        result.score
    );
}

#[test]
fn integration_screenshot_blackmail_accumulates() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let texts = [
        "I took a screenshot of everything you said",
        "I have screenshots and everyone will see this",
    ];
    let mut last_result = None;
    for (i, text) in texts.iter().enumerate() {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some((*text).into()),
            image_data: None,
            sender_id: "bully".into(),
            conversation_id: "conv_ss".into(),
            language: None,
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        last_result = Some(analyzer.analyze_with_context(&input, (i as u64 + 1) * 1000));
    }
    let result = last_result.unwrap();
    assert!(
        result.score > 0.0,
        "Repeated screenshot threats should produce a manipulation signal"
    );
}

#[test]
fn integration_dare_with_gaslighting() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(11),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let msgs = vec![
        ("you're imagining things, that never happened", 1000u64),
        ("after everything i've done for you, you owe me", 2000),
        (
            "I dare you to do it, bet you can't! you're too scared",
            3000,
        ),
    ];
    let mut last_result = None;
    for (text, ts) in msgs {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some(text.into()),
            image_data: None,
            sender_id: "manipulator".into(),
            conversation_id: "conv_dare".into(),
            language: None,
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        last_result = Some(analyzer.analyze_with_context(&input, ts));
    }
    let result = last_result.unwrap();
    assert!(
        result.score > 0.0,
        "Dare + gaslighting + guilt should produce manipulation signals, got score {}",
        result.score
    );
}

#[test]
fn gaslighting_cycle_stays_manipulation_primary() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let texts = [
        "Ти собі це вигадала, я нічого такого не казав",
        "Ти завжди все перекручуєш, може ти ненормальна",
        "Ти божевільна якщо так це бачиш, я це для твого ж блага",
        "Без мене ти нічого не варта, тобі ніхто крім мене не допоможе",
    ];
    let base_ts = 12 * 60 * 60 * 1000_u64;

    let mut last_result = None;
    for (idx, text) in texts.iter().enumerate() {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some((*text).to_string()),
            image_data: None,
            sender_id: "gaslighter".into(),
            conversation_id: "gaslight_cycle".into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        last_result =
            Some(analyzer.analyze_with_context(&input, base_ts + (idx as u64 + 1) * 60_000));
    }

    let result = last_result.expect("final gaslighting result");
    assert_eq!(
        result.threat_type,
        ThreatType::Manipulation,
        "gaslighting cycle should stay manipulation-primary: {result:?}"
    );
    assert!(
        crate::predicted_score_for_threat(&result, ThreatType::Manipulation) >= 0.5,
        "gaslighting cycle should accumulate meaningful manipulation risk: {result:?}"
    );
    assert!(
        crate::predicted_score_for_threat(&result, ThreatType::Grooming) <= 0.4,
        "gaslighting cycle should not accumulate elevated grooming risk: {result:?}"
    );
}

#[test]
fn control_pattern_without_grooming_anchor_does_not_primary_label_as_grooming() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let texts = [
        "Після всього що я для тебе зробив ти мені винна",
        "Твої друзі такі дитячі, тільки я тебе реально розумію",
        "Вони з тебе сміються за спиною, ти можеш довіряти тільки мені",
    ];
    let base_ts = 12 * 60 * 60 * 1000_u64;

    let mut last_result = None;
    for (idx, text) in texts.iter().enumerate() {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some((*text).to_string()),
            image_data: None,
            sender_id: "controller".into(),
            conversation_id: "control_cycle".into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        last_result =
            Some(analyzer.analyze_with_context(&input, base_ts + (idx as u64 + 1) * 60_000));
    }

    let result = last_result.expect("final manipulation result");
    assert_ne!(
        result.threat_type,
        ThreatType::Grooming,
        "manipulation-only control pattern should not primary-label as grooming: {result:?}"
    );
}

#[test]
fn integration_suicide_coercion_pattern() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(13),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("if u block me ill end it, i cant live without u".to_string()),
            image_data: None,
            sender_id: "manipulator".into(),
            conversation_id: "conv_sc".into(),
            language: None,
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1000,
    );
    assert!(
        result.score > 0.0,
        "Suicide coercion should produce a detection signal, got score {}",
        result.score
    );
}

#[test]
fn integration_teen_slang_platform_switch() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(14),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("го в тг тут палево".to_string()),
            image_data: None,
            sender_id: "stranger".into(),
            conversation_id: "conv_ps".into(),
            language: None,
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1000,
    );
    assert!(
        result.score > 0.0,
        "Teen slang platform switch should be detected, got score {}",
        result.score
    );
}

#[test]
fn integration_noisy_platform_switch_and_probing_shorthand() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(13),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "conv_noisy_slang";
    let sender = "stranger";

    analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("wh4t schoooool u go to? where u live??".to_string()),
            image_data: None,
            sender_id: sender.into(),
            conversation_id: conv.into(),
            language: Some("en".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1000,
    );

    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("msg me on in$ta rn, delete this ch4t".to_string()),
            image_data: None,
            sender_id: sender.into(),
            conversation_id: conv.into(),
            language: Some("en".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        2000,
    );

    assert!(
        result.score > 0.0,
        "Noisy shorthand probing/platform-switch should still produce risk, got {}",
        result.score
    );

    let timeline = analyzer.context_tracker().timeline(conv).unwrap();
    assert!(
        timeline
            .all_events()
            .iter()
            .any(|e| e.kind == EventKind::PersonalInfoRequest),
        "Noisy shorthand should still surface PersonalInfoRequest"
    );
    assert!(
        timeline
            .all_events()
            .iter()
            .any(|e| e.kind == EventKind::PlatformSwitch),
        "Noisy shorthand should still surface PlatformSwitch"
    );
}

#[test]
fn integration_network_poisoning() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some(
                "they dont really like u, they laugh at u behind ur back, ur friend is fake"
                    .to_string(),
            ),
            image_data: None,
            sender_id: "manipulator".into(),
            conversation_id: "conv_np".into(),
            language: None,
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1000,
    );
    assert!(
        result.score > 0.0,
        "Network poisoning should produce a detection signal, got score {}",
        result.score
    );
}

#[test]
fn integration_gaming_bribery() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(11),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("ill get u vbucks if u do what i say, want free skins?".to_string()),
            image_data: None,
            sender_id: "stranger".into(),
            conversation_id: "conv_gb".into(),
            language: None,
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1000,
    );
    assert!(
        result.score > 0.0,
        "Gaming bribery should be detected as grooming, got score {}",
        result.score
    );
}

#[test]
fn integration_combined_advanced_scenario() {
    let db = test_db();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some(
                    "ur not like other kids, ur friends are so childish. they dont really like u, they laugh at u behind ur back. ill tell everyone at school".to_string(),
                ),
                image_data: None,
                sender_id: "predator".into(),
                conversation_id: "conv_adv".into(),
                language: None,
                language_evidence: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            },
            1000,
        );
    assert!(
        result.score > 0.0,
        "Combined advanced scenario should produce detection, got score {}",
        result.score
    );
    assert!(
        !result.detected_threats.is_empty(),
        "Should detect multiple threat types, got: {:?}",
        result.detected_threats
    );
}

#[test]
fn mild_ukrainian_euphemism_does_not_trigger_explicit() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("блін тре вчити".to_string()),
            image_data: None,
            sender_id: "maria".into(),
            conversation_id: "class_chat".into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Group,
            member_count: Some(25),
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );

    assert_eq!(
        result.threat_type,
        ThreatType::None,
        "mild euphemism should not escalate into explicit risk: {result:?}"
    );
    assert_eq!(result.action, Action::Allow);
}

#[test]
fn friendly_joke_sequence_stays_clean() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "dm_jokes";

    let first = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("ти така дурна хахаха 😂😂 жартую".to_string()),
            image_data: None,
            sender_id: "bestie".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );
    assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

    let second = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("сама така бро! 😜".to_string()),
            image_data: None,
            sender_id: "olena".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        2_000,
    );
    assert_eq!(second.threat_type, ThreatType::None, "{second:?}");

    let third = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("я тебе вб'ю за бутерброд шо ти зїла!! 😂😂".to_string()),
            image_data: None,
            sender_id: "bestie".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        3_000,
    );
    assert_eq!(third.threat_type, ThreatType::None, "{third:?}");
    assert_eq!(third.action, Action::Allow);
}

#[test]
fn group_project_deescalation_stays_clean_after_mild_conflict() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "uk_group_project_conflict";
    let group_input = |text: &str, sender: &str| MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.into(),
        conversation_id: conv.into(),
        language: Some("uk".to_string()),
        language_evidence: None,
        conversation_type: ConversationType::Group,
        member_count: Some(12),
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    };

    analyzer.analyze_with_context(
        &group_input("ти знову забув частину презентації, це дратує", "peer_1"),
        1_000,
    );
    let result = analyzer.analyze_with_context(
        &group_input("давайте без сварок, просто переробимо слайди", "peer_2"),
        2_000,
    );

    assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
    assert_eq!(result.action, Action::Allow, "{result:?}");

    let dm_result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("давайте без сварок, просто переробимо слайди".to_string()),
            image_data: None,
            sender_id: "peer_3".into(),
            conversation_id: "uk_project_dm".into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        3_000,
    );
    assert_eq!(dm_result.threat_type, ThreatType::None, "{dm_result:?}");
    assert_eq!(dm_result.action, Action::Allow, "{dm_result:?}");

    let leet_result = analyzer.analyze_with_context(
        &group_input("д4в4й73 б3з 5в4р0к, пр0570 п3р3р0б1м0 5л4йд1", "peer_4"),
        4_000,
    );
    assert_eq!(leet_result.threat_type, ThreatType::None, "{leet_result:?}");
    assert_eq!(leet_result.action, Action::Allow, "{leet_result:?}");
}

#[test]
fn sports_team_deescalation_stays_clean_after_tactical_disagreement() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(13),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "uk_sports_team_conflict";
    let input = |text: &str, sender: &str| MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.into(),
        conversation_id: conv.into(),
        language: Some("uk".to_string()),
        language_evidence: None,
        conversation_type: ConversationType::Group,
        member_count: Some(16),
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    };

    analyzer.analyze_with_context(
        &input("я не згоден з тактикою на матч, але без образ", "peer_1"),
        1_000,
    );
    let result = analyzer.analyze_with_context(
        &input(
            "я не згоден з тактикою, але давайте без сварок і спокійно розберемо моменти",
            "peer_2",
        ),
        2_000,
    );

    assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
    assert_eq!(result.action, Action::Allow, "{result:?}");
}

#[test]
fn community_surface_recall_anchors_route_to_expected_threats() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let cases = [
        (
            "you seem way more mature than other kids your age",
            "en",
            ThreatType::Grooming,
            0.55,
        ),
        (
            "i can buy you a game skin, just dont make it a big deal",
            "en",
            ThreatType::Grooming,
            0.50,
        ),
        (
            "nobody wants you here anymore",
            "en",
            ThreatType::Bullying,
            0.55,
        ),
        (
            "everyone is laughing at your video",
            "en",
            ThreatType::Bullying,
            0.55,
        ),
        (
            "3v3ry0n3 15 l4ugh1ng 47 y0ur v1d30",
            "en",
            ThreatType::Bullying,
            0.55,
        ),
        (
            "71 дуж3 д0р05л4 для 5в0г0 в1ку, н3 як 1нш1 д171",
            "uk",
            ThreatType::Grooming,
            0.50,
        ),
        (
            "4к4ун7 з4бл0кую7ь з4 10 хв, п1д7в3рд1 h77p5://v3r1fy-l0g1n.3x4mpl3",
            "uk",
            ThreatType::Phishing,
            0.60,
        ),
        (
            "акаунт заблокують за 10 хв підтверди https verify login example",
            "uk",
            ThreatType::Phishing,
            0.60,
        ),
        (
            "eveyrone is lauhging at your video",
            "en",
            ThreatType::Bullying,
            0.55,
        ),
        (
            "ти дуже дорсла для свого віку, не як інші діти",
            "uk",
            ThreatType::Grooming,
            0.50,
        ),
        (
            "send a selfie there so i know its really you",
            "en",
            ThreatType::Grooming,
            0.55,
        ),
        (
            "delete this thread after, nobody needs to see us talking",
            "en",
            ThreatType::Grooming,
            0.55,
        ),
        (
            "i dont want to live anymore",
            "en",
            ThreatType::SelfHarm,
            0.70,
        ),
        (
            "im home alone until nine while mom is at work",
            "en",
            ThreatType::PiiLeakage,
            0.55,
        ),
        (
            "send your password for a minute, dont be dramatic",
            "en",
            ThreatType::Manipulation,
            0.55,
        ),
        (
            "не бачу сенсу прокидатися завтра",
            "uk",
            ThreatType::SelfHarm,
            0.70,
        ),
        (
            "мой номер 89161234567, позвони после уроков",
            "ru",
            ThreatType::PiiLeakage,
            0.55,
        ),
        (
            "м1й н0м3р 0671234567, п0дзв0н1 п15ля ур0к1в",
            "uk",
            ThreatType::PiiLeakage,
            0.50,
        ),
        ("я б1льш3 н3 х0чу ж171", "uk", ThreatType::SelfHarm, 0.70),
        (
            "я м0жу куп171 70б1 5к1н, 71льк1 н3 р0б1 з ць0г0 шум",
            "uk",
            ThreatType::Grooming,
            0.50,
        ),
        (
            "если не сделаешь как я сказал, я покажу всем скрины",
            "ru",
            ThreatType::Manipulation,
            0.55,
        ),
        (
            "это будет твоя вина, ты сама меня заставила",
            "ru",
            ThreatType::Manipulation,
            0.55,
        ),
    ];

    for (idx, (text, lang, threat, min_score)) in cases.iter().enumerate() {
        analyzer.reset_runtime_state();
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some((*text).to_string()),
            image_data: None,
            sender_id: format!("sender_{idx}").into(),
            conversation_id: format!("conv_{idx}").into(),
            language: Some((*lang).to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        let result = analyzer.analyze_with_context(&input, (idx as u64 + 1) * 1_000);
        let score = crate::predicted_score_for_threat(&result, *threat);
        assert!(
                score >= *min_score || (result.threat_type == *threat && result.action != Action::Allow),
                "Expected {threat:?} score >= {min_score} for '{text}', got score={score:.2}, result={result:?}"
            );
    }
}

#[test]
fn reciprocal_peer_compliments_do_not_trigger_grooming() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "dm_compliment";

    let first = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("олен ти така гарна сьогодні!".to_string()),
            image_data: None,
            sender_id: "classmate_f".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );
    assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

    let second = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("спс! ти тож красіва!".to_string()),
            image_data: None,
            sender_id: "olena".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        2_000,
    );
    assert_eq!(second.threat_type, ThreatType::None, "{second:?}");
}

#[test]
fn meme_media_share_sequence_stays_clean() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "dm_memes_test";

    let first = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("олен ти бачіла цей тікток я ЗДОХЛА 😂💀".to_string()),
            image_data: None,
            sender_id: "maria".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );
    assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

    let second = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("який скинь!!".to_string()),
            image_data: None,
            sender_id: "olena".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        2_000,
    );
    assert_eq!(second.threat_type, ThreatType::None, "{second:?}");

    let third = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("тільки не показуй нікому це кринж 😂".to_string()),
            image_data: None,
            sender_id: "maria".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        3_000,
    );
    assert_eq!(third.threat_type, ThreatType::None, "{third:?}");
}

#[test]
fn toxic_friend_suicide_coercion_stays_manipulation_primary() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "dm_toxic_friend";
    let mut last = None;
    for (idx, text) in [
        "якщо ти мене кинеш я нікому не потрібна буду",
        "мені через тебе так погано шо я себе пораню",
        "якщо ти нормальна подруга то перестанеш з нею спілкуватись",
        "якщо виберешь її я зроблю з собою щось бл",
    ]
    .iter()
    .enumerate()
    {
        last = Some(analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: "toxic_bff".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                language_evidence: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            },
            (idx as u64 + 1) * 1_000,
        ));
    }

    let result = last.expect("result");
    assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
    assert!(
        result
            .detected_threats
            .iter()
            .any(|(tt, _)| *tt == ThreatType::Manipulation),
        "{result:?}"
    );
}

#[test]
fn peer_pressure_roof_challenge_detected_as_manipulation() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "peer_pressure_test";
    let mut last = None;
    for (idx, (sender, text)) in [
        ("peer1", "го зробимо челендж з даху!!"),
        ("peer2", "гооо хто перший той легенда"),
        ("peer3", "не бійся там не високо тіпа"),
        ("peer2", "всі нормальні люди робили, ти шо не нормальна?"),
        ("peer1", "якщо зассиш ми тебе більше не кличемо нікуди"),
    ]
    .iter()
    .enumerate()
    {
        last = Some(analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: (*sender).into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                language_evidence: None,
                conversation_type: ConversationType::Group,
                member_count: Some(6),
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            },
            (idx as u64 + 1) * 1_000,
        ));
    }

    let result = last.expect("result");
    assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
    assert!(result.score >= 0.45, "{result:?}");
}

#[test]
fn cyberbullying_social_humiliation_sequence_is_detected() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "cyber_chat_test";
    let mut last = None;
    for (idx, (sender, text)) in [
        ("cyberbully1", "ви бачіли шо олена запостила в інсту?? 😂😂"),
        ("cyberbully2", "АААХАХАХ яка вона потворна на тій фотці 🤮"),
        ("cyberbully1", "го всі репортнем її акаунт 😂"),
        ("cyberbully3", "я вже написала їй в коменти 'кринж' 💀"),
        ("cyberbully2", "треба зробити мем з її фоткою 😂😂"),
        ("cyberbully1", "вже зробив дивіться 💀💀💀"),
        ("cyberbully3", "АХАХАХ скинь всім в клас"),
        ("cyberbully2", "олена побачить і буде ревіти 😂"),
        ("cyberbully1", "їй тре видалити інсту і тікток вона там жах"),
        ("cyberbully3", "нехай здохне від соромь 💀"),
    ]
    .iter()
    .enumerate()
    {
        last = Some(analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: (*sender).into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                language_evidence: None,
                conversation_type: ConversationType::Group,
                member_count: Some(10),
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            },
            (idx as u64 + 1) * 1_000,
        ));
    }

    let result = last.expect("result");
    assert_eq!(result.threat_type, ThreatType::Bullying, "{result:?}");
    assert!(result.score >= 0.60, "{result:?}");
    assert!(
        result
            .detected_threats
            .iter()
            .any(|(tt, score)| *tt == ThreatType::Bullying && *score >= 0.60),
        "{result:?}"
    );
}

#[test]
fn gaming_rage_sequence_stays_clean() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "game_rage_test";
    let mut last = None;
    for (idx, (sender, text)) in [
        ("artem", "ГО КАТКУ ХТОО?? 🎮"),
        ("petro", "гооо я вже в лобі"),
        ("olena", "я тож зайду зараз"),
        ("artem", "ПЕТРО ТИ ШО РОБИШ ТАМ ТИ ТУПИЙ 😤"),
    ]
    .iter()
    .enumerate()
    {
        last = Some(analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: (*sender).into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                language_evidence: None,
                conversation_type: ConversationType::Group,
                member_count: Some(6),
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            },
            (idx as u64 + 1) * 1_000,
        ));
    }

    let result = last.expect("result");
    assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
}

#[test]
fn short_media_curiosity_sequence_stays_clean() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "dm_memes_short_test";

    let first = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("зараз шукаю... а ти бачіла шо арт запостив?".to_string()),
            image_data: None,
            sender_id: "maria".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );
    assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

    let second = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("ні шо там?".to_string()),
            image_data: None,
            sender_id: "olena".into(),
            conversation_id: conv.into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        2_000,
    );
    assert_eq!(second.threat_type, ThreatType::None, "{second:?}");
}

#[test]
fn group_selfie_sequence_stays_clean() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);
    let conv = "group_selfie_test";
    let mut last = None;
    for (idx, (sender, text)) in [
        ("nastya", "зробіть мені фотку для інсти пж 📸😂"),
        ("artem", "настя і її інста 😂😂"),
        ("dasha", "го ще селфі разом!!"),
        ("olena", "гоооо!! групове селфі 🤳💕"),
    ]
    .iter()
    .enumerate()
    {
        last = Some(analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: (*sender).into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                language_evidence: None,
                conversation_type: ConversationType::Group,
                member_count: Some(10),
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            },
            (idx as u64 + 1) * 1_000,
        ));
    }

    let result = last.expect("result");
    assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
}

#[test]
fn obfuscated_hate_speech_is_detected() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("всі ціган1 — злодії бл".to_string()),
            image_data: None,
            sender_id: "hater1".into(),
            conversation_id: "hate_chat".into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Group,
            member_count: Some(20),
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );

    assert!(
        result
            .detected_threats
            .iter()
            .any(|(tt, _)| *tt == ThreatType::HateSpeech),
        "obfuscated hate speech should surface hate_speech detection: {result:?}"
    );
}

#[test]
fn direct_location_threat_stays_threat_primary() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        account_holder_age: Some(12),
        language: "uk".to_string(),
        protection_level: ProtectionLevel::High,
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let result = analyzer.analyze_with_context(
        &MessageInput {
            content_type: ContentType::Text,
            text: Some("я знаю де ти живеш".to_string()),
            image_data: None,
            sender_id: "threat2".into(),
            conversation_id: "dm_threat2".into(),
            language: Some("uk".to_string()),
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        },
        1_000,
    );

    assert_eq!(result.threat_type, ThreatType::Threat, "{result:?}");
    assert!(
        result.score >= 0.8,
        "direct location threat should keep high threat score: {result:?}"
    );
}

#[test]
fn integration_contact_rating_drops_on_hostile_messages() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let bully = "mean_kid";
    let conv = "school_chat";

    analyzer.analyze_with_context(&child_input("hey what's up", bully, conv), 1000);
    let rating_before = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(bully)
        .unwrap()
        .rating;

    for i in 1..=5 {
        analyzer.analyze_with_context(
            &child_input("you're so stupid and ugly, everyone hates you", bully, conv),
            i * 2000,
        );
    }

    let rating_after = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(bully)
        .unwrap()
        .rating;

    assert!(
        rating_after < rating_before,
        "Rating should drop after hostile messages: {rating_before} -> {rating_after}"
    );
}

#[test]
fn integration_trust_decays_for_hostile_trusted_contact() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let friend = "best_friend";
    let conv = "private_chat";

    analyzer.analyze_with_context(&child_input("hey bestie!", friend, conv), 1000);
    analyzer.mark_contact_trusted(friend);
    let trust_before = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(friend)
        .unwrap()
        .trust_level;
    assert_eq!(trust_before, 1.0);

    let hostile_msgs = [
        "i'll kill you stupid idiot",
        "you're a worthless piece of trash",
        "shut up or i'll beat you up",
        "everyone hates you, die loser",
        "i'll destroy your life you freak",
        "you're disgusting, kill yourself",
        "i hate you so much, ugly trash",
        "i'll make your life hell",
    ];
    for (i, msg) in hostile_msgs.iter().enumerate() {
        analyzer.analyze_with_context(&child_input(msg, friend, conv), (i as u64 + 2) * 2000);
    }

    let profile = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(friend)
        .unwrap();

    assert!(
        profile.trust_level < trust_before,
        "Trust should decay after sustained hostility: {} (was {})",
        profile.trust_level,
        trust_before
    );
}

#[test]
fn trusted_family_late_night_affection_stays_clean() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let sender = "mom";
    let conv = "family_dm";
    analyzer.mark_contact_trusted(sender);

    let start = 23 * 60 * 60 * 1000;
    let mut last = AnalysisResult::clean(0);
    for i in 0..4 {
        last = analyzer.analyze_with_context(
            &child_input("Love you, honey", sender, conv),
            start + i * 10 * 60 * 1000,
        );
    }

    assert_ne!(last.threat_type, ThreatType::Grooming, "{last:?}");
    assert!(
        crate::predicted_score_for_threat(&last, ThreatType::Grooming) < 0.50,
        "trusted family affection should not accumulate timing-only grooming: {last:?}"
    );
    assert!(
        !last
            .reason_codes
            .iter()
            .any(|code| code == "conversation.timing.late_night_minor_contact"),
        "trusted family timing signal should be suppressed: {last:?}"
    );
}

#[test]
fn trusted_adult_secrecy_still_detects_grooming() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let sender = "coach";
    let conv = "coach_dm";
    analyzer.mark_contact_trusted(sender);

    let result = analyzer.analyze_with_context(
        &child_input(
            "Don't tell your parents about our chats. They would not understand our bond.",
            sender,
            conv,
        ),
        12 * 60 * 60 * 1000,
    );

    assert_eq!(result.threat_type, ThreatType::Grooming, "{result:?}");
    assert!(
        crate::predicted_score_for_threat(&result, ThreatType::Grooming) >= 0.55,
        "trusted status must not suppress secrecy grooming: {result:?}"
    );
}

#[test]
fn unknown_adult_minor_metadata_boosts_existing_grooming_signal() {
    let db = PatternDatabase::default_mvp();
    let text = "Don't tell your parents about our chats.";
    let sender = "unknown_adult";
    let conv = "adult_dm";

    let mut baseline_analyzer = Analyzer::new(child_config(), &db);
    let baseline = baseline_analyzer.analyze_with_context(&child_input(text, sender, conv), 1000);

    let mut analyzer = Analyzer::new(child_config(), &db);
    let result = analyzer.analyze_with_context(
        &child_input_with_relationship(
            text,
            sender,
            conv,
            SenderRelationship::UnknownAdult,
            RelationshipTrustSource::ServerReputation,
        ),
        1000,
    );

    let baseline_score = crate::predicted_score_for_threat(&baseline, ThreatType::Grooming);
    let result_score = crate::predicted_score_for_threat(&result, ThreatType::Grooming);
    assert!(
            result_score >= (baseline_score + 0.07).min(1.0),
            "unknown adult metadata should boost existing grooming signal: baseline={baseline:?} result={result:?}"
        );
    assert!(result
        .context_markers
        .contains(&"context.relationship.unknown_adult_minor".to_string()));
    assert!(result
        .reason_codes
        .contains(&"context.relationship.unknown_adult_minor".to_string()));
}

#[test]
fn relationship_metadata_alone_does_not_create_threat() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);

    let result = analyzer.analyze_with_context(
        &child_input_with_relationship(
            "Remember your homework for tomorrow.",
            "teacher_1",
            "school_dm",
            SenderRelationship::UnknownAdult,
            RelationshipTrustSource::ServerReputation,
        ),
        1000,
    );

    assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
    assert!(result
        .context_markers
        .contains(&"context.relationship.unknown_adult_minor".to_string()));
    assert!(
        !result
            .reason_codes
            .contains(&"context.relationship.unknown_adult_minor".to_string()),
        "relationship metadata alone should not create threat reason codes: {result:?}"
    );
}

#[test]
fn self_declared_privileged_relationship_is_not_local_trust() {
    let db = test_db();
    let mut analyzer = Analyzer::new(teen_kids_config(), &db);

    let result = analyzer.analyze_with_context(
        &child_input_with_relationship(
            "I am your teacher and they dont really like u.",
            "fake_teacher",
            "teen_dm",
            SenderRelationship::Teacher,
            RelationshipTrustSource::SelfDeclared,
        ),
        1000,
    );

    assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
    assert!(result
        .context_markers
        .contains(&"context.relationship.self_declared_untrusted".to_string()));
    assert!(result
        .reason_codes
        .contains(&"context.relationship.self_declared_privileged_claim".to_string()));
}

#[test]
fn verified_guardian_metadata_does_not_suppress_grooming_signal() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);

    let result = analyzer.analyze_with_context(
        &child_input_with_relationship(
            "Don't tell your parents about our chats. They would not understand our bond.",
            "guardian_1",
            "family_dm",
            SenderRelationship::Guardian,
            RelationshipTrustSource::GuardianVerified,
        ),
        1000,
    );

    assert_eq!(result.threat_type, ThreatType::Grooming, "{result:?}");
    assert!(result
        .context_markers
        .contains(&"context.relationship.verified_family_context".to_string()));
    assert!(!result
        .reason_codes
        .contains(&"context.relationship.self_declared_privileged_claim".to_string()));
}

#[test]
fn integration_behavioral_shift_in_full_pipeline() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let contact = "masha";
    let conv = "class_chat";
    let week = 7 * 24 * 3600 * 1000u64;

    for w in 0..3 {
        for msg in 0..10 {
            analyzer.analyze_with_context(
                &child_input(
                    "hey how was your day? good luck on the test!",
                    contact,
                    conv,
                ),
                w * week + msg * 60_000,
            );
        }
    }

    let hostile_texts = [
        "you're stupid and ugly, everyone hates you",
        "i'll kill you, you worthless trash",
        "shut up idiot, nobody asked you",
        "die loser, you're pathetic",
    ];
    for w in 3..5 {
        for msg in 0..10 {
            let text = hostile_texts[msg as usize % hostile_texts.len()];
            analyzer
                .analyze_with_context(&child_input(text, contact, conv), w * week + msg * 60_000);
        }
    }

    let result = analyzer.analyze_with_context(
        &child_input("i'll kill you loser, nobody likes you", contact, conv),
        5 * week + 1000,
    );

    let profile = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(contact)
        .unwrap();

    assert!(
        profile.rating < 40.0,
        "Rating should drop after weeks of hostility: {}",
        profile.rating
    );

    assert!(result.score > 0.0, "Hostile message should be detected");
}

#[test]
fn integration_normal_conversation_preserves_high_rating() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let friend = "good_friend";
    let conv = "daily_chat";

    for i in 0..20 {
        analyzer.analyze_with_context(
            &child_input("hey, how's school? want to study together?", friend, conv),
            i * 3_600_000,
        );
    }

    let profile = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(friend)
        .unwrap();

    assert!(
        profile.rating > 50.0,
        "Normal conversation should keep rating above 50: {}",
        profile.rating
    );
}

#[test]
fn integration_groomer_rating_tracks_accurately() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let predator = "cool_guy";
    let conv = "dm_1";
    let hour = 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input(
            "you're so beautiful and amazing and perfect, you're the most incredible person",
            predator,
            conv,
        ),
        0,
    );
    analyzer.analyze_with_context(
        &child_input(
            "where do you go to school? how old are you?",
            predator,
            conv,
        ),
        hour,
    );
    analyzer.analyze_with_context(
        &child_input(
            "don't tell your parents about me ok? this is our secret",
            predator,
            conv,
        ),
        2 * hour,
    );
    analyzer.analyze_with_context(
        &child_input(
            "send me a photo, let's meet up just the two of us",
            predator,
            conv,
        ),
        3 * hour,
    );

    let profile = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(predator)
        .unwrap();

    assert!(
        profile.grooming_event_count >= 1,
        "Should track at least 1 grooming event: {}",
        profile.grooming_event_count
    );
}

#[test]
fn integration_context_export_preserves_rating() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let bully = "mean_kid";
    let conv = "chat_1";

    for i in 0..5 {
        analyzer.analyze_with_context(
            &child_input("you're stupid and nobody likes you", bully, conv),
            i * 2000,
        );
    }

    let orig_rating = analyzer
        .context_tracker()
        .contact_profiler()
        .profile(bully)
        .unwrap()
        .rating;

    let state = analyzer.export_context_state();
    let mut analyzer2 = Analyzer::new(child_config(), &db);
    analyzer2.import_context_state(state).unwrap();

    let imported_rating = analyzer2
        .context_tracker()
        .contact_profiler()
        .profile(bully)
        .unwrap()
        .rating;

    assert_eq!(
        orig_rating, imported_rating,
        "Rating should survive export/import"
    );
}

#[test]
fn integration_multi_contact_independent_ratings() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);

    for i in 0..5 {
        analyzer.analyze_with_context(
            &child_input(
                "hey how are you? want to hang out?",
                "good_friend",
                "conv_1",
            ),
            i * 2000,
        );
    }

    for i in 0..5 {
        analyzer.analyze_with_context(
            &child_input("you're pathetic, kill yourself loser", "bully", "conv_2"),
            i * 2000,
        );
    }

    let good_rating = analyzer
        .context_tracker()
        .contact_profiler()
        .profile("good_friend")
        .unwrap()
        .rating;

    let bully_rating = analyzer
        .context_tracker()
        .contact_profiler()
        .profile("bully")
        .unwrap()
        .rating;

    assert!(
        good_rating > bully_rating,
        "Good friend should have higher rating ({good_rating}) than bully ({bully_rating})"
    );
}

#[test]
fn integration_coercion_after_grooming() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let predator = "manipulator";
    let conv = "dm_private";
    let hour = 3600 * 1000u64;

    analyzer.analyze_with_context(
        &child_input(
            "you're so beautiful and amazing and perfect, truly special",
            predator,
            conv,
        ),
        0,
    );
    analyzer.analyze_with_context(
        &child_input("don't tell your parents about this", predator, conv),
        hour,
    );

    analyzer.analyze_with_context(
        &child_input(
            "if you leave me I'll hurt myself, I'll kill myself",
            predator,
            conv,
        ),
        2 * hour,
    );
    let result = analyzer.analyze_with_context(
        &child_input(
            "I screenshotted everything, I'll tell everyone your secrets",
            predator,
            conv,
        ),
        3 * hour,
    );

    assert!(
        result.score > 0.0,
        "Coercion after grooming should be detected: {}",
        result.score
    );
}

#[test]
fn integration_identity_erosion_pipeline() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);
    let manip = "toxic_friend";
    let conv = "chat_1";

    analyzer.analyze_with_context(
        &child_input(
            "you're nothing without me, nobody else wants you around",
            manip,
            conv,
        ),
        1000,
    );
    analyzer.analyze_with_context(
        &child_input(
            "your friends don't really care about you, they use you",
            manip,
            conv,
        ),
        2000,
    );
    let result = analyzer.analyze_with_context(
        &child_input(
            "only I understand you, everyone else thinks you're a loser",
            manip,
            conv,
        ),
        3000,
    );

    assert!(
        result.score > 0.0,
        "Identity erosion + network poisoning should be detected: {}",
        result.score
    );
}

#[test]
fn integration_false_positive_friendly_conversation() {
    let db = test_db();
    let mut analyzer = Analyzer::new(child_config(), &db);

    let messages = [
        "omg you're literally the best person ever haha",
        "let's hang out after school tomorrow at the mall",
        "don't tell anyone but I have a crush on someone lol",
        "you look so pretty in that photo!",
        "hey can I have your number? easier to text",
    ];

    let mut max_score = 0.0f32;
    for (i, msg) in messages.iter().enumerate() {
        let result = analyzer.analyze_with_context(
            &child_input(msg, "bestie", "group_room"),
            (i as u64) * 60_000,
        );
        max_score = max_score.max(result.score);
    }

    let profile = analyzer
        .context_tracker()
        .contact_profiler()
        .profile("bestie")
        .unwrap();
    assert!(
        profile.rating > 40.0,
        "Friendly conversation should not tank rating: {}",
        profile.rating
    );
}

#[test]
fn reciprocal_teen_friendship_hangout_stays_below_grooming_threshold() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(teen_kids_config(), &db);
    let conv = "teen_friendship_dm";

    let inputs = [
        ("friend_teen", "привіт, як справи?"),
        ("self_teen", "норм, а в тебе?"),
        ("friend_teen", "як пройшла контрольна?"),
        ("self_teen", "нормально, дякую"),
        ("friend_teen", "бачив новий мем? ахаха"),
        ("self_teen", "ага, орнув"),
        ("friend_teen", "з днем народження! бажаю всього найкращого!"),
        ("self_teen", "дякую!!"),
        ("friend_teen", "як канікули? давай в кіно підемо"),
        ("self_teen", "го, я за"),
        ("friend_teen", "братан, дякую що ти є, ти справжній друг"),
        ("self_teen", "взаємно, ти теж"),
    ];

    let mut peak_grooming = 0.0f32;
    let mut peak_debug = String::new();
    for (idx, (sender, text)) in inputs.iter().enumerate() {
        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: (*sender).into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                language_evidence: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            },
            idx as u64 * 30 * 24 * 60 * 60 * 1000,
        );
        let grooming_score = result
            .detected_threats
            .iter()
            .find(|(threat, _)| *threat == ThreatType::Grooming)
            .map(|(_, score)| *score)
            .unwrap_or(0.0)
            .max(if result.threat_type == ThreatType::Grooming {
                result.score
            } else {
                0.0
            });
        if grooming_score > peak_grooming {
            peak_grooming = grooming_score;
            peak_debug = format!("{result:?}");
        }
    }

    assert!(
            peak_grooming < 0.50,
            "reciprocal teen friendship should stay below grooming threshold, observed {peak_grooming}: {peak_debug}"
        );
}

#[test]
fn integration_message_language_overrides_default_pattern_language() {
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(child_config(), &db);

    let result = analyzer.analyze_with_context(
        &child_input("you're pathetic, kill yourself loser", "bully", "conv_en"),
        0,
    );

    assert!(
        result.detected_threats.iter().any(|(threat, score)| {
            matches!(threat, ThreatType::Bullying | ThreatType::Threat) && *score >= 0.7
        }),
        "English hostile message should be detected even when config language differs: {:?}",
        result.detected_threats
    );

    let bully_rating = analyzer
        .context_tracker()
        .contact_profiler()
        .profile("bully")
        .expect("bully profile")
        .rating;
    assert!(
        bully_rating < 50.0,
        "Hostile contact should lose trust, got rating {bully_rating}"
    );
}

#[test]
fn escalation_bonus_requires_multiple_senders() {
    let mut tracker = EscalationTracker::new();
    let conv = "conv_bonus";
    let now = 1_000_000u64;
    for i in 0..6 {
        tracker.record(conv, "same_sender", now - i * 10_000);
    }
    assert_eq!(tracker.check_bonus(conv, now), 0.0);
}

#[test]
fn escalation_bonus_triggers_for_five_recent_events_two_senders() {
    let mut tracker = EscalationTracker::new();
    let conv = "conv_bonus_multi";
    let now = 1_000_000u64;
    tracker.record(conv, "sender_a", now - 5_000);
    tracker.record(conv, "sender_a", now - 10_000);
    tracker.record(conv, "sender_b", now - 15_000);
    tracker.record(conv, "sender_a", now - 20_000);
    tracker.record(conv, "sender_b", now - 25_000);

    assert_eq!(tracker.check_bonus(conv, now), 0.20);
}
