use std::time::Instant;

use tracing::{debug, info};

use crate::sentiment::SentimentAnalyzer;
#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::toxicity::ToxicityClassifier;
use crate::types::{MlConfig, MlResult};

pub struct MlPipeline {
    toxicity: ToxicityClassifier,
    sentiment: SentimentAnalyzer,
    config: MlConfig,
}

impl MlPipeline {
    pub fn new(config: MlConfig) -> Self {
        let toxicity = Self::load_toxicity(&config);
        let sentiment = Self::load_sentiment(&config);

        info!(
            toxicity_mode = if config.toxicity_model_path.is_some() {
                "onnx"
            } else {
                "fallback"
            },
            sentiment_mode = if config.sentiment_model_path.is_some() {
                "onnx"
            } else {
                "fallback"
            },
            "ML pipeline initialized"
        );

        Self {
            toxicity,
            sentiment,
            config,
        }
    }

    pub fn fallback() -> Self {
        Self::new(MlConfig {
            use_fallback: true,
            ..Default::default()
        })
    }

    pub fn analyze_text(&mut self, text: &str) -> MlResult {
        let start = Instant::now();

        let toxicity = self.toxicity.predict(text);
        let sentiment = self.sentiment.predict(text);

        let elapsed = start.elapsed();
        let inference_time_us = elapsed.as_micros() as u64;

        debug!(
            inference_us = inference_time_us,
            has_toxicity = toxicity.is_some(),
            has_sentiment = sentiment.is_some(),
            "ML pipeline analysis complete"
        );

        MlResult {
            toxicity,
            sentiment,
            inference_time_us,
        }
    }

    pub fn toxicity_threshold(&self) -> f32 {
        self.config.toxicity_threshold
    }

    pub fn is_active(&self) -> bool {
        self.config.use_fallback
            || self.config.toxicity_model_path.is_some()
            || self.config.sentiment_model_path.is_some()
    }

    fn load_toxicity(config: &MlConfig) -> ToxicityClassifier {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.toxicity_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => match ToxicityClassifier::with_model(model_path, tokenizer) {
                        Ok(classifier) => return classifier,
                        Err(e) => {
                            tracing::warn!("Failed to load toxicity ONNX model: {e}");
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab: {e}");
                    }
                }
            }
        }

        if config.use_fallback {
            ToxicityClassifier::fallback_only()
        } else {
            ToxicityClassifier::fallback_only()
        }
    }

    fn load_sentiment(_config: &MlConfig) -> SentimentAnalyzer {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.sentiment_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => match SentimentAnalyzer::with_model(model_path, tokenizer) {
                        Ok(analyzer) => return analyzer,
                        Err(e) => {
                            tracing::warn!("Failed to load sentiment ONNX model: {e}");
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab: {e}");
                    }
                }
            }
        }

        SentimentAnalyzer::fallback_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SentimentLabel, ToxicityLabel};

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
}
