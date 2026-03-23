use crate::types::{SentimentPrediction, ToxicityPrediction};

/// Backend trait for toxicity classification.
pub trait ToxicityBackend: Send {
    fn predict(&mut self, text: &str) -> Option<ToxicityPrediction>;
    fn name(&self) -> &str;
}

/// Backend trait for sentiment analysis.
pub trait SentimentBackend: Send {
    fn predict(&mut self, text: &str) -> Option<SentimentPrediction>;
    fn name(&self) -> &str;
}

/// Gate model trait for cascade Tier 1 decisions.
///
/// Runs on lexicon features (cheap, <1ms) to decide whether
/// the expensive ONNX model needs to run.
pub trait GateModel: Send {
    /// Returns a risk score in `[0.0, 1.0]` based on cheap features.
    fn gate_score(&self, text: &str) -> f32;
    fn name(&self) -> &str;
}
