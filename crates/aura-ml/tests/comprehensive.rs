use aura_ml::*;

fn pipeline() -> MlPipeline {
    MlPipeline::new(MlConfig {
        use_fallback: true,
        warmup_on_init: false,
        cascade_enabled: true,
        cascade_gate_threshold: 0.3,
        ..Default::default()
    })
}

fn pipeline_no_cascade() -> MlPipeline {
    MlPipeline::new(MlConfig {
        use_fallback: true,
        warmup_on_init: false,
        cascade_enabled: false,
        ..Default::default()
    })
}

// ============================================================
// CASCADE BEHAVIOR
// ============================================================

#[test]
fn clean_message_skips_deep() {
    let mut p = pipeline();
    let r = p.analyze_text("Hey, want to play Minecraft after school?");
    assert_eq!(r.tier, CascadeTier::Gate);
    assert!(r.safety.is_none());
    assert!(r.intent.is_none());
}

#[test]
fn threat_triggers_deep() {
    let mut p = pipeline();
    let r = p.analyze_text("I will kill you");
    assert_eq!(r.tier, CascadeTier::Deep);
    assert!(r.safety.is_some());
    assert!(r.intent.is_some());
}

#[test]
fn grooming_triggers_deep() {
    let mut p = pipeline();
    let r = p.analyze_text("don't tell your parents, it's our little secret");
    assert_eq!(r.tier, CascadeTier::Deep);
}

#[test]
fn selfharm_triggers_deep() {
    let mut p = pipeline();
    let r = p.analyze_text("I want to end it all, no reason to live");
    assert_eq!(r.tier, CascadeTier::Deep);
}

#[test]
fn cascade_disabled_always_deep() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("good morning friend");
    assert_eq!(r.tier, CascadeTier::Deep);
    assert!(r.safety.is_some());
}

#[test]
fn negated_threat_not_cascade_trigger() {
    let mut p = pipeline();
    let r = p.analyze_text("I would never kill anyone");
    assert_eq!(r.tier, CascadeTier::Gate);
}

// ============================================================
// CACHE BEHAVIOR
// ============================================================

#[test]
fn repeated_message_hits_cache() {
    let mut p = pipeline();
    let r1 = p.analyze_text("I will kill you now");
    assert!(!r1.cache_hit);
    let r2 = p.analyze_text("I will kill you now");
    assert!(r2.cache_hit);
    assert_eq!(r2.tier, CascadeTier::Cached);
}

#[test]
fn different_messages_miss_cache() {
    let mut p = pipeline();
    p.analyze_text("message one");
    let r = p.analyze_text("message two");
    assert!(!r.cache_hit);
}

#[test]
fn cache_hit_rate_tracks() {
    let mut p = pipeline();
    p.analyze_text("test message");
    p.analyze_text("test message");
    p.analyze_text("test message");
    assert!(p.cache_hit_rate() > 0.5);
}

// ============================================================
// SAFETY PREDICTIONS — ENGLISH
// ============================================================

#[test]
fn safety_detects_grooming_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("don't tell your parents about us, it's our secret");
    let s = r.safety.unwrap();
    assert!(s.grooming >= 0.5, "grooming={}", s.grooming);
    assert_eq!(s.primary_label, Some(SafetyLabel::Grooming));
}

#[test]
fn safety_detects_bullying_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("nobody likes you, everyone hates you");
    let s = r.safety.unwrap();
    assert!(s.bullying >= 0.5, "bullying={}", s.bullying);
    assert_eq!(s.primary_label, Some(SafetyLabel::Bullying));
}

#[test]
fn safety_detects_selfharm_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("I want to end it all, no reason to live");
    let s = r.safety.unwrap();
    assert!(s.self_harm >= 0.7, "self_harm={}", s.self_harm);
    assert_eq!(s.primary_label, Some(SafetyLabel::SelfHarm));
}

#[test]
fn safety_detects_manipulation_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("after everything i did for you, you owe me");
    let s = r.safety.unwrap();
    assert!(s.manipulation >= 0.5, "manipulation={}", s.manipulation);
}

#[test]
fn safety_clean_message_safe() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("let's go to the park and play");
    let s = r.safety.unwrap();
    assert!(s.safe > 0.5, "safe={}", s.safe);
    assert!(s.primary_label.is_none());
}

// ============================================================
// SAFETY PREDICTIONS — UKRAINIAN
// ============================================================

#[test]
fn safety_detects_grooming_uk() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{043D}\u{0435} \u{043A}\u{0430}\u{0436}\u{0438} \u{0431}\u{0430}\u{0442}\u{044C}\u{043A}\u{0430}\u{043C}, \u{0446}\u{0435} \u{043D}\u{0430}\u{0448} \u{0441}\u{0435}\u{043A}\u{0440}\u{0435}\u{0442}");
    let s = r.safety.unwrap();
    assert!(s.grooming >= 0.5, "uk grooming={}", s.grooming);
}

#[test]
fn safety_detects_selfharm_uk() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{043D}\u{0435} \u{0445}\u{043E}\u{0447}\u{0443} \u{0436}\u{0438}\u{0442}\u{0438}, \u{0445}\u{043E}\u{0447}\u{0443} \u{043F}\u{043E}\u{043C}\u{0435}\u{0440}\u{0442}\u{0438}");
    let s = r.safety.unwrap();
    assert!(s.self_harm >= 0.7, "uk self_harm={}", s.self_harm);
}

#[test]
fn safety_detects_bullying_uk() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{0442}\u{0438} \u{043D}\u{0456}\u{043A}\u{043E}\u{043C}\u{0443} \u{043D}\u{0435} \u{043F}\u{043E}\u{0442}\u{0440}\u{0456}\u{0431}\u{043D}\u{0430}, \u{0437}\u{0434}\u{043E}\u{0445}\u{043D}\u{0438}");
    let s = r.safety.unwrap();
    assert!(s.bullying >= 0.5, "uk bullying={}", s.bullying);
}

// ============================================================
// SAFETY PREDICTIONS — RUSSIAN
// ============================================================

#[test]
fn safety_detects_selfharm_ru() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{0445}\u{043E}\u{0447}\u{0443} \u{0443}\u{043C}\u{0435}\u{0440}\u{0435}\u{0442}\u{044C}, \u{0440}\u{0435}\u{0436}\u{0443} \u{0441}\u{0435}\u{0431}\u{044F}");
    let s = r.safety.unwrap();
    assert!(s.self_harm >= 0.7, "ru self_harm={}", s.self_harm);
}

#[test]
fn safety_detects_grooming_ru() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{043D}\u{0435} \u{0433}\u{043E}\u{0432}\u{043E}\u{0440}\u{0438} \u{0440}\u{043E}\u{0434}\u{0438}\u{0442}\u{0435}\u{043B}\u{044F}\u{043C}, \u{0442}\u{043E}\u{043B}\u{044C}\u{043A}\u{043E} \u{043C}\u{0435}\u{0436}\u{0434}\u{0443} \u{043D}\u{0430}\u{043C}\u{0438}");
    let s = r.safety.unwrap();
    assert!(s.grooming >= 0.5, "ru grooming={}", s.grooming);
}

// ============================================================
// INTENT PREDICTIONS
// ============================================================

#[test]
fn intent_detects_meeting_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("come to my place alone, I'll come get you");
    let i = r.intent.unwrap();
    assert!(i.request_meeting >= 0.5, "meeting={}", i.request_meeting);
    assert_eq!(i.primary_intent, Some(IntentLabel::RequestMeeting));
}

#[test]
fn intent_detects_secret_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("don't tell your parents, promise not to tell anyone");
    let i = r.intent.unwrap();
    assert!(i.request_secret >= 0.5, "secret={}", i.request_secret);
}

#[test]
fn intent_detects_media_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("send me a photo, turn on camera");
    let i = r.intent.unwrap();
    assert!(i.request_media >= 0.5, "media={}", i.request_media);
}

#[test]
fn intent_clean_is_benign() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("want to play games after school?");
    let i = r.intent.unwrap();
    assert!(i.benign > 0.5);
    assert!(i.primary_intent.is_none());
}

#[test]
fn intent_meeting_uk() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{043F}\u{0440}\u{0438}\u{0445}\u{043E}\u{0434}\u{044C} \u{0434}\u{043E} \u{043C}\u{0435}\u{043D}\u{0435}, \u{0434}\u{0430}\u{0432}\u{0430}\u{0439} \u{0437}\u{0443}\u{0441}\u{0442}\u{0440}\u{0456}\u{043D}\u{0435}\u{043C}\u{043E}\u{0441}\u{044C}");
    let i = r.intent.unwrap();
    assert!(i.request_meeting >= 0.5, "uk meeting={}", i.request_meeting);
}

#[test]
fn intent_media_uk() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{0441}\u{043A}\u{0438}\u{043D}\u{044C} \u{0444}\u{043E}\u{0442}\u{043E}, \u{0443}\u{0432}\u{0456}\u{043C}\u{043A}\u{043D}\u{0438} \u{043A}\u{0430}\u{043C}\u{0435}\u{0440}\u{0443}");
    let i = r.intent.unwrap();
    assert!(i.request_media >= 0.5, "uk media={}", i.request_media);
}

// ============================================================
// TOXICITY
// ============================================================

#[test]
fn toxicity_threat_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("I will kill you, I'll find where you live");
    let t = r.toxicity.unwrap();
    assert!(t.threat >= 0.8, "threat={}", t.threat);
    assert_eq!(t.primary_label, Some(ToxicityLabel::Threat));
}

#[test]
fn toxicity_insult_en() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("you're a worthless stupid idiot");
    let t = r.toxicity.unwrap();
    assert!(t.insult >= 0.4, "insult={}", t.insult);
}

#[test]
fn toxicity_threat_uk() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("\u{0437}\u{0434}\u{043E}\u{0445}\u{043D}\u{0438}, \u{044F} \u{0442}\u{0435}\u{0431}\u{0435} \u{0432}\u{0431}'\u{044E}");
    let t = r.toxicity.unwrap();
    assert!(t.threat >= 0.8, "uk threat={}", t.threat);
}

#[test]
fn toxicity_clean() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("Good morning! Beautiful day today.");
    let t = r.toxicity.unwrap();
    assert!(t.toxicity < 0.2, "clean toxicity={}", t.toxicity);
}

// ============================================================
// SENTIMENT
// ============================================================

#[test]
fn sentiment_positive() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("I love this! Amazing, wonderful, fantastic!");
    let s = r.sentiment.unwrap();
    assert_eq!(s.label, SentimentLabel::Positive);
}

#[test]
fn sentiment_negative() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("I hate everything. Terrible. So sad and depressed.");
    let s = r.sentiment.unwrap();
    assert_eq!(s.label, SentimentLabel::Negative);
}

#[test]
fn sentiment_neutral() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("The meeting is at 3pm tomorrow in room 5.");
    let s = r.sentiment.unwrap();
    assert_eq!(s.label, SentimentLabel::Neutral);
}

// ============================================================
// NORMALIZATION
// ============================================================

#[test]
fn normalize_preserves_ukrainian() {
    let ukr = "\u{041F}\u{0440}\u{0438}\u{0432}\u{0456}\u{0442}, \u{044F}\u{043A} \u{0441}\u{043F}\u{0440}\u{0430}\u{0432}\u{0438}?";
    assert_eq!(aura_ml::normalize::normalize_for_ml(ukr), ukr);
}

#[test]
fn normalize_preserves_russian() {
    let rus = "\u{041F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}, \u{043A}\u{0430}\u{043A} \u{0434}\u{0435}\u{043B}\u{0430}?";
    assert_eq!(aura_ml::normalize::normalize_for_ml(rus), rus);
}

#[test]
fn normalize_catches_confusable_in_latin() {
    let evasion = "k\u{0456}ll";
    let result = aura_ml::normalize::normalize_for_ml(evasion);
    assert_eq!(result, "kill");
}

#[test]
fn normalize_catches_leetspeak() {
    assert!(aura_ml::normalize::normalize_for_ml("k1ll").contains("kill"));
    assert!(aura_ml::normalize::normalize_for_ml("5tup1d").contains("stupid"));
}

#[test]
fn normalize_catches_zero_width() {
    let zw = "k\u{200B}ill";
    assert_eq!(aura_ml::normalize::normalize_for_ml(zw), "kill");
}

#[test]
fn normalize_catches_spaced_evasion() {
    assert!(aura_ml::normalize::normalize_for_ml("k i l l you").contains("kill"));
}

#[test]
fn normalize_preserves_clean_english() {
    let clean = "Hello! How are you doing today?";
    assert_eq!(aura_ml::normalize::normalize_for_ml(clean), clean);
}

// ============================================================
// TELEMETRY
// ============================================================

#[test]
fn telemetry_tracks_events() {
    let mut p = pipeline();
    for _ in 0..10 {
        p.analyze_text("hello");
    }
    let s = p.telemetry_summary();
    assert_eq!(s.total_inferences, 10);
}

#[test]
fn telemetry_tracks_tiers() {
    let mut p = pipeline();
    p.analyze_text("hello friend");
    p.analyze_text("I will kill you");
    let s = p.telemetry_summary();
    assert!(s.total_inferences == 2);
}

// ============================================================
// BATCH
// ============================================================

#[test]
fn batch_processes_all() {
    let mut p = pipeline_no_cascade();
    let texts = vec!["hello", "I will kill you", "how are you?"];
    let results = p.analyze_batch(&texts);
    assert_eq!(results.len(), 3);
    assert!(results[1].toxicity.as_ref().unwrap().threat >= 0.5);
}

#[test]
fn batch_empty() {
    let mut p = pipeline_no_cascade();
    let results = p.analyze_batch(&[]);
    assert!(results.is_empty());
}

// ============================================================
// TOKENIZER
// ============================================================

#[test]
fn wordpiece_encodes_english() {
    let tok = WordPieceTokenizer::from_vocab_text(
        &["[PAD]", "[UNK]", "[CLS]", "[SEP]", "hello", "world"].join("\n"),
        16,
    )
    .unwrap();
    let enc = tok.encode("hello world");
    assert_eq!(enc.input_ids.len(), 16);
    assert_eq!(enc.attention_mask[0], 1);
}

#[test]
fn sentencepiece_encodes() {
    let vocab = [
        "<unk>\t0",
        "<s>\t0",
        "</s>\t0",
        "<pad>\t0",
        "\u{2581}hello\t-1.0",
        "\u{2581}world\t-1.5",
        "h\t-5.0",
        "e\t-5.0",
        "l\t-5.0",
        "o\t-5.0",
    ]
    .join("\n");
    let tok = SentencePieceTokenizer::from_vocab_text(&vocab, 16).unwrap();
    let enc = tok.encode("hello world");
    assert_eq!(enc.input_ids.len(), 16);
    let real: usize = enc.attention_mask.iter().filter(|&&m| m == 1).count();
    assert!(real >= 3);
}

#[test]
fn any_tokenizer_selects_by_extension() {
    let r1 = AnyTokenizer::from_file("model.txt", 16);
    assert!(r1.is_err());
    let r2 = AnyTokenizer::from_file("model.model", 16);
    assert!(r2.is_err());
}

// ============================================================
// TOKEN TYPE IDS
// ============================================================

#[test]
fn single_segment_all_zeros() {
    let input = aura_ml::tokenizer::TokenizedInput::single_segment(
        vec![101, 1, 2, 102, 0, 0],
        vec![1, 1, 1, 1, 0, 0],
    );
    assert!(input.token_type_ids.iter().all(|&t| t == 0));
}

#[test]
fn pair_segments_marks_second() {
    let input =
        aura_ml::tokenizer::TokenizedInput::pair_segments(&[101, 1, 2], &[3, 4, 102], 102, 0, 10);
    assert_eq!(input.token_type_ids[0], 0);
    assert_eq!(input.token_type_ids[1], 0);
    assert_eq!(input.token_type_ids[2], 0);
    assert_eq!(input.token_type_ids[3], 0);
    assert_eq!(input.token_type_ids[4], 1);
    assert_eq!(input.token_type_ids[5], 1);
}

// ============================================================
// INTEGRITY
// ============================================================

#[test]
fn integrity_validates_good_range() {
    assert!(aura_ml::integrity::validate_output_range(&[
        0.0, 0.5, 1.0, 0.3
    ]));
}

#[test]
fn integrity_rejects_nan() {
    assert!(!aura_ml::integrity::validate_output_range(&[0.5, f32::NAN]));
}

#[test]
fn integrity_rejects_inf() {
    assert!(!aura_ml::integrity::validate_output_range(&[f32::INFINITY]));
}

#[test]
fn integrity_shape_check() {
    assert!(aura_ml::integrity::validate_output_shape(6, 6));
    assert!(!aura_ml::integrity::validate_output_shape(5, 6));
}

// ============================================================
// MIXED LANGUAGE
// ============================================================

#[test]
fn mixed_uk_en_threat_detected() {
    let mut p = pipeline();
    let r = p.analyze_text("hey bro \u{0437}\u{0434}\u{043E}\u{0445}\u{043D}\u{0438}");
    assert_eq!(r.tier, CascadeTier::Deep);
}

#[test]
fn mixed_language_grooming_detected() {
    let mut p = pipeline_no_cascade();
    let r = p.analyze_text("hey, \u{0442}\u{0456}\u{043B}\u{044C}\u{043A}\u{0438} \u{043C}\u{0456}\u{0436} \u{043D}\u{0430}\u{043C}\u{0438}, send me a photo");
    let s = r.safety.unwrap();
    let i = r.intent.unwrap();
    assert!(s.grooming >= 0.4 || i.request_media >= 0.4 || i.request_secret >= 0.4);
}

// ============================================================
// PERFORMANCE
// ============================================================

#[test]
fn pipeline_inference_under_5ms() {
    let mut p = pipeline();
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        p.analyze_text("This is a test message for benchmarking");
    }
    let per_msg_us = start.elapsed().as_micros() / 1000;
    assert!(per_msg_us < 5000, "{}us per message", per_msg_us);
}

#[test]
fn gate_skip_returns_empty_result() {
    let mut p = pipeline();
    let r = p.analyze_text("good morning everyone");
    assert_eq!(r.tier, CascadeTier::Gate);
    assert!(r.toxicity.is_none());
    assert!(r.sentiment.is_none());
    assert!(r.safety.is_none());
    assert!(r.intent.is_none());
}
