//! Machine learning inference pipeline for AURA.
//!
//! Provides sentiment analysis, toxicity detection, child safety classification,
//! and intent detection with ONNX backend support and lexicon-based fallback.
//!
//! Key modules:
//! - [`pipeline`] — orchestrator with cascade, caching, and telemetry
//! - [`normalize`] — adversarial text normalization (leetspeak, confusables, zero-width)
//! - [`cache`] — LRU inference result cache
//! - [`telemetry`] — fixed-size ring buffer for inference metrics
//! - [`manifest`] — SHA-256 model file validation

pub mod backend;
pub mod batch;
pub mod boundary;
pub mod cache;
pub mod cascade;
pub mod gate;
pub mod integrity;
pub mod intent;
pub mod manifest;
pub mod normalize;
pub mod pipeline;
pub mod safety;
pub mod sentiment;
pub mod telemetry;
pub mod tokenizer;
pub mod tokenizer_sp;
pub mod toxicity;
pub mod types;

pub use backend::{GateModel, SentimentBackend, ToxicityBackend};
pub use pipeline::MlPipeline;
pub use tokenizer::WordPieceTokenizer;
pub use tokenizer_sp::{AnyTokenizer, SentencePieceTokenizer, Tokenizer};
pub use types::{
    CascadeTier, IntentLabel, IntentPrediction, MlConfig, MlResult, MultiHeadPrediction,
    SafetyLabel, SafetyPrediction, SentimentLabel, SentimentPrediction, ToxicityLabel,
    ToxicityPrediction,
};
