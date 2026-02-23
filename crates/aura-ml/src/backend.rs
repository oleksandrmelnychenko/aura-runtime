use crate::types::{SentimentPrediction, ToxicityPrediction};

/// Backend trait for toxicity classification.
pub trait ToxicityBackend: Send {
    fn predict(&self, text: &str) -> Option<ToxicityPrediction>;
    fn name(&self) -> &str;
}

/// Backend trait for sentiment analysis.
pub trait SentimentBackend: Send {
    fn predict(&self, text: &str) -> Option<SentimentPrediction>;
    fn name(&self) -> &str;
}
