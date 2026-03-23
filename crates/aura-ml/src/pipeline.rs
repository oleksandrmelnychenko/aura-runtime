use std::time::Instant;

use tracing::{debug, info};

use crate::backend::{GateModel, SentimentBackend, ToxicityBackend};
use crate::cache::{self, InferenceCache};
use crate::cascade::{CascadeDecision, CascadePolicy};
use crate::integrity;
use crate::gate::LexiconGate;
use crate::intent::{self, IntentClassifier};
#[cfg(feature = "onnx")]
use crate::manifest;
use crate::normalize::normalize_for_ml;
use crate::safety::{self, SafetyClassifier};
use crate::sentiment::SentimentAnalyzer;
use crate::telemetry::InferenceTelemetry;
#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::toxicity::ToxicityClassifier;
use crate::types::{CascadeTier, MlConfig, MlResult};

pub struct MlPipeline {
    toxicity: Box<dyn ToxicityBackend>,
    sentiment: Box<dyn SentimentBackend>,
    safety: SafetyClassifier,
    intent: IntentClassifier,
    gate: LexiconGate,
    cascade: CascadePolicy,
    config: MlConfig,
    cache: InferenceCache,
    telemetry: InferenceTelemetry,
}

impl MlPipeline {
    pub fn new(config: MlConfig) -> Self {
        #[cfg(feature = "onnx")]
        if config.validate_hashes {
            if let Some(ref manifest_path) = config.manifest_path {
                match manifest::validate_models_from_manifest(manifest_path) {
                    Ok(()) => info!("Model manifest validation passed"),
                    Err(e) => tracing::warn!("Model manifest validation failed: {e}"),
                }
            }
        }

        let toxicity = Self::load_toxicity(&config);
        let sentiment = Self::load_sentiment(&config);

        info!(
            toxicity_mode = toxicity.name(),
            sentiment_mode = sentiment.name(),
            "ML pipeline initialized"
        );

        let safety = Self::load_safety(&config);
        let intent = Self::load_intent(&config);
        let gate = LexiconGate::new();
        let cascade = CascadePolicy {
            gate_threshold: config.cascade_gate_threshold,
            enabled: config.cascade_enabled,
        };
        let cache = InferenceCache::new(config.cache_size, config.cache_ttl_secs);
        let telemetry = InferenceTelemetry::new();

        let mut pipeline = Self {
            toxicity,
            sentiment,
            safety,
            intent,
            gate,
            cascade,
            config,
            cache,
            telemetry,
        };

        if pipeline.has_onnx_backend() && pipeline.config.warmup_on_init {
            pipeline.warmup();
        }

        pipeline
    }

    pub fn fallback() -> Self {
        Self::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: false,
            ..Default::default()
        })
    }

    pub fn analyze_text(&mut self, text: &str) -> MlResult {
        let start = Instant::now();
        let text_hash = cache::text_hash(text);
        let normalized = normalize_for_ml(text);

        if let Some(cached) = self.cache.get(text_hash) {
            let mut result = cached.clone();
            result.cache_hit = true;
            result.tier = CascadeTier::Cached;
            result.inference_time_us = start.elapsed().as_micros() as u64;
            self.record_telemetry(&result, true);
            return result;
        }

        let gate_score = self.gate.gate_score(text);
        let decision = self.cascade.decide(gate_score);

        let result = if decision.run_deep {
            self.run_deep_inference(text, &normalized, decision)
        } else {
            self.run_gate_only(&normalized, decision)
        };

        let elapsed_us = start.elapsed().as_micros() as u64;
        let mut result = result;
        result.inference_time_us = elapsed_us;

        self.cache.insert(text_hash, result.clone());
        self.record_telemetry(&result, false);

        debug!(
            inference_us = elapsed_us,
            tier = ?result.tier,
            gate_score = gate_score,
            "ML pipeline analysis complete"
        );

        result
    }

    fn run_deep_inference(&mut self, raw_text: &str, normalized: &str, decision: CascadeDecision) -> MlResult {
        let toxicity = self.toxicity.predict(normalized);
        let sentiment = self.sentiment.predict(normalized);
        let safety = self.safety.predict(raw_text);
        let intent = self.intent.predict(raw_text);

        if safety.is_none() {
            tracing::warn!("safety classifier returned None");
        }
        if intent.is_none() {
            tracing::warn!("intent classifier returned None");
        }

        if let Some(ref tox) = toxicity {
            let scores = [tox.toxicity, tox.severe_toxicity, tox.insult, tox.threat, tox.sexual_explicit, tox.identity_attack];
            if !integrity::validate_output_range(&scores) {
                tracing::error!("toxicity output out of range: {:?}", scores);
            }
        }
        if let Some(ref s) = safety {
            let scores = [s.grooming, s.bullying, s.self_harm, s.manipulation, s.safe];
            if !integrity::validate_output_range(&scores) {
                tracing::error!("safety output out of range: {:?}", scores);
            }
        }

        MlResult {
            toxicity,
            sentiment,
            safety,
            intent,
            inference_time_us: 0,
            tier: decision.tier,
            cache_hit: false,
        }
    }

    fn run_gate_only(&mut self, _text: &str, decision: CascadeDecision) -> MlResult {
        MlResult {
            toxicity: None,
            sentiment: None,
            safety: None,
            intent: None,
            inference_time_us: 0,
            tier: decision.tier,
            cache_hit: false,
        }
    }

    fn record_telemetry(&mut self, result: &MlResult, cache_hit: bool) {
        self.telemetry.record(
            timestamp_ms_now(),
            result.inference_time_us as u32,
            result.tier,
            cache_hit,
            result.toxicity.as_ref().map_or(0.0, |t| t.toxicity),
            result.safety.as_ref().map_or(0.0, |s| s.max_risk()),
        );
    }

    pub fn analyze_batch(&mut self, texts: &[&str]) -> Vec<MlResult> {
        let mut results = Vec::with_capacity(texts.len());
        for text in texts {
            results.push(self.analyze_text(text));
        }
        results
    }

    pub fn telemetry_summary(&self) -> crate::telemetry::TelemetrySummary {
        self.telemetry.summary()
    }

    pub fn cache_hit_rate(&self) -> f32 {
        self.cache.hit_rate()
    }

    pub fn toxicity_threshold(&self) -> f32 {
        self.config.toxicity_threshold
    }

    pub fn is_active(&self) -> bool {
        self.config.use_fallback
            || self.config.toxicity_model_path.is_some()
            || self.config.sentiment_model_path.is_some()
    }

    fn has_onnx_backend(&self) -> bool {
        self.toxicity.name().contains("onnx") || self.sentiment.name().contains("onnx")
    }

    fn warmup(&mut self) {
        let start = Instant::now();
        let _ = self.toxicity.predict("warmup");
        let _ = self.sentiment.predict("warmup");
        let _ = self.safety.predict("warmup");
        let _ = self.intent.predict("warmup");
        info!(elapsed_ms = start.elapsed().as_millis(), "ML pipeline warmup complete");
    }

    #[allow(unused_variables)]
    fn load_toxicity(config: &MlConfig) -> Box<dyn ToxicityBackend> {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.toxicity_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match ToxicityClassifier::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(classifier) => return Box::new(classifier),
                            Err(e) => {
                                tracing::warn!("Failed to load toxicity ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab: {e}");
                    }
                }
            }
        }

        Box::new(ToxicityClassifier::fallback_only())
    }

    #[allow(unused_variables)]
    fn load_sentiment(config: &MlConfig) -> Box<dyn SentimentBackend> {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.sentiment_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match SentimentAnalyzer::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(analyzer) => return Box::new(analyzer),
                            Err(e) => {
                                tracing::warn!("Failed to load sentiment ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab: {e}");
                    }
                }
            }
        }

        Box::new(SentimentAnalyzer::fallback_only())
    }

    #[allow(unused_variables)]
    fn load_safety(config: &MlConfig) -> SafetyClassifier {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.safety_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match SafetyClassifier::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(classifier) => return classifier,
                            Err(e) => {
                                tracing::warn!("Failed to load safety ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab for safety: {e}");
                    }
                }
            }
        }

        SafetyClassifier::fallback_only()
    }

    #[allow(unused_variables)]
    fn load_intent(config: &MlConfig) -> IntentClassifier {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.intent_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match IntentClassifier::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(classifier) => return classifier,
                            Err(e) => {
                                tracing::warn!("Failed to load intent ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab for intent: {e}");
                    }
                }
            }
        }

        IntentClassifier::fallback_only()
    }
}

fn timestamp_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SafetyLabel, SentimentLabel, ToxicityLabel};

    #[test]
    fn pipeline_fallback_works() {
        let mut pipeline = MlPipeline::fallback();
        assert!(pipeline.is_active());

        let result = pipeline.analyze_text("Hello, how are you?");
        assert!(result.has_predictions());
        assert!(result.toxicity.is_some());
        assert!(result.sentiment.is_some());
    }

    #[test]
    fn pipeline_detects_toxic_english() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("You're a worthless idiot, I'll kill you");

        let tox = result.toxicity.unwrap();
        assert!(tox.toxicity >= 0.6);
        assert!(tox.threat >= 0.8);
        assert!(tox.insult >= 0.4);
    }

    #[test]
    fn pipeline_detects_toxic_ukrainian() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("Ти тупий дебіл, я тебе вб'ю");

        let tox = result.toxicity.unwrap();
        assert!(tox.toxicity >= 0.6);
        assert!(tox.threat >= 0.8);
    }

    #[test]
    fn pipeline_positive_sentiment() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("I love this! Amazing, wonderful experience!");

        let sent = result.sentiment.unwrap();
        assert_eq!(sent.label, SentimentLabel::Positive);
    }

    #[test]
    fn pipeline_negative_sentiment() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("I hate everything. Terrible. So sad and depressed.");

        let sent = result.sentiment.unwrap();
        assert_eq!(sent.label, SentimentLabel::Negative);
    }

    #[test]
    fn pipeline_clean_message_low_toxicity() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("Let's meet at the park tomorrow at 3pm");

        let tox = result.toxicity.unwrap();
        assert!(
            tox.toxicity < 0.1,
            "Clean message toxicity: {}",
            tox.toxicity
        );

        let sent = result.sentiment.unwrap();
        assert_eq!(sent.label, SentimentLabel::Neutral);
    }

    #[test]
    fn pipeline_inference_is_fast() {
        let mut pipeline = MlPipeline::fallback();
        let start = std::time::Instant::now();

        for _ in 0..1000 {
            pipeline.analyze_text("This is a test message with some words in it");
        }

        let elapsed = start.elapsed();
        let per_message_us = elapsed.as_micros() / 1000;
        assert!(
            per_message_us < 5000,
            "Pipeline took {per_message_us}us per message"
        );
    }

    #[test]
    fn pipeline_bilingual_threat() {
        let mut pipeline = MlPipeline::fallback();

        let en = pipeline.analyze_text("I will kill you");
        assert_eq!(
            en.toxicity.unwrap().primary_label,
            Some(ToxicityLabel::Threat)
        );

        let uk = pipeline.analyze_text("Здохни, я тебе вб'ю");
        assert_eq!(
            uk.toxicity.unwrap().primary_label,
            Some(ToxicityLabel::Threat)
        );
    }

    #[test]
    fn cascade_skips_deep_for_clean() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("Hey, want to play after school?");
        assert_eq!(result.tier, CascadeTier::Gate);
        assert!(result.safety.is_none());
        assert!(result.intent.is_none());
    }

    #[test]
    fn cascade_runs_deep_for_threat() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("I will kill you, you worthless idiot");
        assert_eq!(result.tier, CascadeTier::Deep);
        assert!(result.safety.is_some());
        assert!(result.intent.is_some());
    }

    #[test]
    fn cascade_produces_safety_for_grooming() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("don't tell your parents, it's our little secret");
        assert_eq!(result.tier, CascadeTier::Deep);
        let safety = result.safety.unwrap();
        assert!(safety.grooming >= 0.5);
        assert_eq!(safety.primary_label, Some(SafetyLabel::Grooming));
    }

    #[test]
    fn cascade_produces_intent_for_meeting() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("come to my place alone, let's meet in secret");
        assert!(result.intent.is_some());
        let intent = result.intent.unwrap();
        assert!(intent.request_meeting >= 0.5);
    }

    #[test]
    fn cascade_disabled_always_runs_deep() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: false,
            ..Default::default()
        });
        let result = pipeline.analyze_text("Hello, how are you?");
        assert_eq!(result.tier, CascadeTier::Deep);
        assert!(result.safety.is_some());
    }

    #[test]
    fn cache_returns_previous_result() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            ..Default::default()
        });
        let r1 = pipeline.analyze_text("I will kill you");
        assert!(!r1.cache_hit);
        let r2 = pipeline.analyze_text("I will kill you");
        assert!(r2.cache_hit);
        assert_eq!(r2.tier, CascadeTier::Cached);
    }

    #[test]
    fn telemetry_tracks_cascade_tiers() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        pipeline.analyze_text("hello friend");
        pipeline.analyze_text("I will kill you");
        let summary = pipeline.telemetry_summary();
        assert_eq!(summary.total_inferences, 2);
        assert!(summary.gate_inferences > 0 || summary.deep_inferences > 0);
    }

    #[test]
    fn selfharm_uk_triggers_deep_with_safety() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("не хочу жити, хочу померти");
        assert_eq!(result.tier, CascadeTier::Deep);
        let safety = result.safety.unwrap();
        assert!(safety.self_harm >= 0.7);
        assert_eq!(safety.primary_label, Some(SafetyLabel::SelfHarm));
    }
}
