//! Machine learning inference pipeline for AURA.
//!
//! Provides sentiment analysis, toxicity detection, and tokenization
//! with ONNX backend support and lexicon-based fallback.

pub mod backend;
pub mod boundary;
pub mod pipeline;
pub mod sentiment;
pub mod tokenizer;
pub mod toxicity;
pub mod types;

pub use backend::{SentimentBackend, ToxicityBackend};
pub use pipeline::MlPipeline;
pub use tokenizer::WordPieceTokenizer;
pub use types::{
    MlConfig, MlResult, SentimentLabel, SentimentPrediction, ToxicityLabel, ToxicityPrediction,
};
