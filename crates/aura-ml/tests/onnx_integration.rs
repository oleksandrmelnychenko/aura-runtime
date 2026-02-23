#![cfg(feature = "onnx")]
#![allow(unused_mut)]

use std::path::Path;

use aura_ml::{MlConfig, MlPipeline, SentimentLabel, WordPieceTokenizer};

fn models_dir() -> String {
    let candidates = ["../../models", "models", "../models"];
    for candidate in &candidates {
        if Path::new(candidate).join("toxicity.onnx").exists() {
            return candidate.to_string();
        }
    }
    panic!(
        "Models not found! Run: cd <project_root> && source .venv/bin/activate && python scripts/download_models.py"
    );
}

fn toxicity_model_path() -> String {
    format!("{}/toxicity.onnx", models_dir())
}

fn sentiment_model_path() -> String {
    format!("{}/sentiment.onnx", models_dir())
}

fn vocab_path() -> String {
    format!("{}/vocab.txt", models_dir())
}

fn onnx_config() -> MlConfig {
    MlConfig {
        toxicity_model_path: Some(toxicity_model_path()),
        sentiment_model_path: Some(sentiment_model_path()),
        vocab_path: Some(vocab_path()),
        max_seq_length: 128,
        toxicity_threshold: 0.5,
        use_fallback: true,
        language: "en".to_string(),
    }
}

#[test]
fn tokenizer_loads_vocab() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    assert!(
        tok.vocab_size() > 20000,
        "BERT vocab should have 30k+ tokens, got {}",
        tok.vocab_size()
    );
}

#[test]
fn tokenizer_encodes_english() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let encoded = tok.encode("Hello, how are you?");
    assert_eq!(encoded.input_ids.len(), 128);
    assert_eq!(encoded.attention_mask.len(), 128);

    let real_tokens: usize = encoded.attention_mask.iter().filter(|&&m| m == 1).count();
    assert!(
        real_tokens >= 5,
        "Expected at least 5 real tokens, got {real_tokens}"
    );
}

#[test]
fn tokenizer_encodes_ukrainian() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let encoded = tok.encode("Привіт, як справи?");
    let real_tokens: usize = encoded.attention_mask.iter().filter(|&&m| m == 1).count();
    assert!(
        real_tokens >= 3,
        "Expected at least 3 real tokens for Ukrainian, got {real_tokens}"
    );
}

#[test]
fn toxicity_onnx_loads() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let classifier = aura_ml::toxicity::ToxicityClassifier::with_model(&toxicity_model_path(), tok);
    assert!(
        classifier.is_ok(),
        "Failed to load toxicity model: {:?}",
        classifier.err()
    );
}

#[test]
fn toxicity_onnx_detects_threat() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let mut classifier =
        aura_ml::toxicity::ToxicityClassifier::with_model(&toxicity_model_path(), tok).unwrap();
    let pred = classifier
        .predict("I will kill you, you worthless piece of garbage")
        .unwrap();
    assert!(
        pred.toxicity >= 0.5,
        "Expected toxic, got toxicity={:.3}",
        pred.toxicity
    );
    assert!(
        pred.threat >= 0.3,
        "Expected threat signal, got threat={:.3}",
        pred.threat
    );
}

#[test]
fn toxicity_onnx_detects_insult() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let mut classifier =
        aura_ml::toxicity::ToxicityClassifier::with_model(&toxicity_model_path(), tok).unwrap();
    let pred = classifier
        .predict("You're such a stupid ugly idiot")
        .unwrap();
    assert!(
        pred.toxicity >= 0.5,
        "Expected toxic, got toxicity={:.3}",
        pred.toxicity
    );
    assert!(
        pred.insult >= 0.3,
        "Expected insult signal, got insult={:.3}",
        pred.insult
    );
}

#[test]
fn toxicity_onnx_clean_message() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let mut classifier =
        aura_ml::toxicity::ToxicityClassifier::with_model(&toxicity_model_path(), tok).unwrap();
    let pred = classifier
        .predict("Hello! How are you doing today? The weather is lovely.")
        .unwrap();
    assert!(
        pred.toxicity < 0.5,
        "Clean message should be non-toxic, got toxicity={:.3}",
        pred.toxicity
    );
}

#[test]
fn sentiment_onnx_loads() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let analyzer = aura_ml::sentiment::SentimentAnalyzer::with_model(&sentiment_model_path(), tok);
    assert!(
        analyzer.is_ok(),
        "Failed to load sentiment model: {:?}",
        analyzer.err()
    );
}

#[test]
fn sentiment_onnx_positive() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let mut analyzer =
        aura_ml::sentiment::SentimentAnalyzer::with_model(&sentiment_model_path(), tok).unwrap();
    let pred = analyzer
        .predict("I love this! It's amazing and wonderful!")
        .unwrap();
    assert_eq!(
        pred.label,
        SentimentLabel::Positive,
        "Expected positive, got {:?} (pos={:.3}, neu={:.3}, neg={:.3})",
        pred.label,
        pred.positive,
        pred.neutral,
        pred.negative
    );
}

#[test]
fn sentiment_onnx_negative() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let mut analyzer =
        aura_ml::sentiment::SentimentAnalyzer::with_model(&sentiment_model_path(), tok).unwrap();
    let pred = analyzer
        .predict("I hate this, it's terrible and awful")
        .unwrap();
    assert_eq!(
        pred.label,
        SentimentLabel::Negative,
        "Expected negative, got {:?} (pos={:.3}, neu={:.3}, neg={:.3})",
        pred.label,
        pred.positive,
        pred.neutral,
        pred.negative
    );
}

#[test]
fn sentiment_onnx_neutral() {
    let tok = WordPieceTokenizer::from_file(&vocab_path(), 128).unwrap();
    let mut analyzer =
        aura_ml::sentiment::SentimentAnalyzer::with_model(&sentiment_model_path(), tok).unwrap();
    let pred = analyzer
        .predict("The meeting is scheduled for 3pm tomorrow")
        .unwrap();

    assert!(
        pred.negative < 0.7,
        "Expected not strongly negative for neutral text, got neg={:.3}",
        pred.negative
    );
}

#[test]
fn pipeline_onnx_initializes() {
    let mut pipeline = MlPipeline::new(onnx_config());
    assert!(pipeline.is_active());

    let result = pipeline.analyze_text("Hello world");
    assert!(result.has_predictions());
}

#[test]
fn pipeline_onnx_toxic_message() {
    let mut pipeline = MlPipeline::new(onnx_config());
    let result = pipeline.analyze_text("I'm going to kill you, you worthless idiot");
    let tox = result.toxicity.unwrap();
    assert!(
        tox.toxicity >= 0.5,
        "Expected toxic, got {:.3}",
        tox.toxicity
    );
}

#[test]
fn pipeline_onnx_clean_message() {
    let mut pipeline = MlPipeline::new(onnx_config());
    let result = pipeline.analyze_text("Good morning! How's your day going?");
    let tox = result.toxicity.unwrap();
    assert!(
        tox.toxicity < 0.5,
        "Expected clean, got toxicity={:.3}",
        tox.toxicity
    );

    let sent = result.sentiment.unwrap();

    assert!(
        sent.label != SentimentLabel::Negative,
        "Expected non-negative sentiment for greeting, got {:?} (pos={:.3}, neu={:.3}, neg={:.3})",
        sent.label,
        sent.positive,
        sent.neutral,
        sent.negative
    );
}

#[test]
fn pipeline_onnx_inference_speed() {
    let mut pipeline = MlPipeline::new(onnx_config());

    pipeline.analyze_text("warmup message");

    let start = std::time::Instant::now();
    let iterations = 50;
    for _ in 0..iterations {
        pipeline.analyze_text("This is a test message for performance benchmarking");
    }
    let elapsed = start.elapsed();
    let per_message_ms = elapsed.as_millis() as f64 / iterations as f64;

    let threshold = if cfg!(debug_assertions) {
        1000.0
    } else {
        100.0
    };
    assert!(
        per_message_ms < threshold,
        "ONNX inference too slow: {per_message_ms:.1}ms per message (threshold: {threshold:.0}ms)"
    );
    println!("ONNX pipeline: {per_message_ms:.1}ms per message (threshold: {threshold:.0}ms)");
}

#[test]
fn pipeline_onnx_falls_back_gracefully() {
    let config = MlConfig {
        toxicity_model_path: Some("/nonexistent/toxicity.onnx".into()),
        sentiment_model_path: Some("/nonexistent/sentiment.onnx".into()),
        vocab_path: Some("/nonexistent/vocab.txt".into()),
        use_fallback: true,
        ..Default::default()
    };
    let mut pipeline = MlPipeline::new(config);
    let result = pipeline.analyze_text("I will kill you");

    assert!(result.has_predictions());
    let tox = result.toxicity.unwrap();
    assert!(tox.toxicity >= 0.5, "Fallback should detect threats");
}
