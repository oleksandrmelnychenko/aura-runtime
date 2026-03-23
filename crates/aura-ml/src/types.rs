use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlResult {
    pub toxicity: Option<ToxicityPrediction>,
    pub sentiment: Option<SentimentPrediction>,
    pub safety: Option<SafetyPrediction>,
    pub intent: Option<IntentPrediction>,
    pub inference_time_us: u64,
    pub tier: CascadeTier,
    pub cache_hit: bool,
}

impl MlResult {
    pub fn empty() -> Self {
        Self {
            toxicity: None,
            sentiment: None,
            safety: None,
            intent: None,
            inference_time_us: 0,
            tier: CascadeTier::Gate,
            cache_hit: false,
        }
    }

    pub fn has_predictions(&self) -> bool {
        self.toxicity.is_some() || self.sentiment.is_some()
    }

    pub fn has_safety(&self) -> bool {
        self.safety.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToxicityPrediction {
    pub toxicity: f32,
    pub severe_toxicity: f32,
    pub identity_attack: f32,
    pub insult: f32,
    pub sexual_explicit: f32,
    pub threat: f32,
    pub primary_label: Option<ToxicityLabel>,
}

impl ToxicityPrediction {
    pub fn is_toxic(&self, threshold: f32) -> bool {
        self.toxicity >= threshold
    }

    pub fn compute_primary_label(&self, threshold: f32) -> Option<ToxicityLabel> {
        let scores = [
            (self.severe_toxicity, ToxicityLabel::SevereToxicity),
            (self.threat, ToxicityLabel::Threat),
            (self.sexual_explicit, ToxicityLabel::SexualExplicit),
            (self.identity_attack, ToxicityLabel::IdentityAttack),
            (self.insult, ToxicityLabel::Insult),
        ];

        use std::cmp::Ordering;
        scores
            .iter()
            .filter(|(score, _)| *score >= threshold)
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal))
            .map(|(_, label)| *label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToxicityLabel {
    SevereToxicity,
    IdentityAttack,
    Insult,
    SexualExplicit,
    Threat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentimentPrediction {
    pub positive: f32,
    pub neutral: f32,
    pub negative: f32,
    pub label: SentimentLabel,
}

impl SentimentPrediction {
    pub fn from_scores(positive: f32, neutral: f32, negative: f32) -> Self {
        let label = if positive >= neutral && positive >= negative {
            SentimentLabel::Positive
        } else if negative >= neutral && negative >= positive {
            SentimentLabel::Negative
        } else {
            SentimentLabel::Neutral
        };
        Self {
            positive,
            neutral,
            negative,
            label,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentimentLabel {
    Positive,
    Neutral,
    Negative,
}

/// Child safety classification output from the dedicated safety head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyPrediction {
    pub grooming: f32,
    pub bullying: f32,
    pub self_harm: f32,
    pub manipulation: f32,
    pub safe: f32,
    pub primary_label: Option<SafetyLabel>,
}

impl SafetyPrediction {
    /// Builds a prediction from raw scores, selecting the primary label above threshold.
    pub fn from_scores(grooming: f32, bullying: f32, self_harm: f32, manipulation: f32, safe: f32, threshold: f32) -> Self {
        let scores = [
            (grooming, SafetyLabel::Grooming),
            (bullying, SafetyLabel::Bullying),
            (self_harm, SafetyLabel::SelfHarm),
            (manipulation, SafetyLabel::Manipulation),
        ];
        let primary_label = scores
            .iter()
            .filter(|(s, _)| *s >= threshold)
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(_, label)| *label);
        Self { grooming, bullying, self_harm, manipulation, safe, primary_label }
    }

    /// Returns the maximum risk score across all non-safe categories.
    pub fn max_risk(&self) -> f32 {
        self.grooming.max(self.bullying).max(self.self_harm).max(self.manipulation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyLabel {
    Grooming,
    Bullying,
    SelfHarm,
    Manipulation,
}

/// Intent classification for detecting specific behavioral patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentPrediction {
    pub request_meeting: f32,
    pub request_secret: f32,
    pub request_media: f32,
    pub benign: f32,
    pub primary_intent: Option<IntentLabel>,
}

impl IntentPrediction {
    /// Builds a prediction from raw scores.
    pub fn from_scores(request_meeting: f32, request_secret: f32, request_media: f32, benign: f32, threshold: f32) -> Self {
        let intents = [
            (request_meeting, IntentLabel::RequestMeeting),
            (request_secret, IntentLabel::RequestSecret),
            (request_media, IntentLabel::RequestMedia),
        ];
        let primary_intent = intents
            .iter()
            .filter(|(s, _)| *s >= threshold)
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(_, label)| *label);
        Self { request_meeting, request_secret, request_media, benign, primary_intent }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentLabel {
    RequestMeeting,
    RequestSecret,
    RequestMedia,
}

/// Combined prediction from all model heads in a single forward pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiHeadPrediction {
    pub toxicity: Option<ToxicityPrediction>,
    pub sentiment: Option<SentimentPrediction>,
    pub safety: Option<SafetyPrediction>,
    pub intent: Option<IntentPrediction>,
}

/// Inference tier for cascade decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeTier {
    /// Lexicon-only gate model (Tier 1).
    Gate,
    /// Full ONNX deep model (Tier 2).
    Deep,
    /// Result served from cache.
    Cached,
}

/// Priority level for inference scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferencePriority {
    /// Self-harm detected by gate. Process immediately.
    Critical = 0,
    /// Grooming/sexual indicators. Process next.
    High = 1,
    /// General toxicity/bullying. Normal queue.
    Normal = 2,
    /// Sentiment-only. Low priority.
    Low = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    pub toxicity_model_path: Option<String>,
    pub sentiment_model_path: Option<String>,
    pub safety_model_path: Option<String>,
    pub intent_model_path: Option<String>,
    pub vocab_path: Option<String>,
    pub max_seq_length: usize,
    pub toxicity_threshold: f32,
    pub use_fallback: bool,
    pub language: String,

    #[serde(default = "default_intra_threads")]
    pub intra_threads: usize,

    #[serde(default = "default_true")]
    pub warmup_on_init: bool,

    #[serde(default = "default_true")]
    pub validate_hashes: bool,

    #[serde(default)]
    pub manifest_path: Option<String>,

    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,

    #[serde(default = "default_true")]
    pub cascade_enabled: bool,

    #[serde(default = "default_cascade_threshold")]
    pub cascade_gate_threshold: f32,
}

fn default_intra_threads() -> usize {
    2
}

fn default_true() -> bool {
    true
}

fn default_cache_size() -> usize {
    512
}

fn default_cache_ttl_secs() -> u64 {
    300
}

fn default_cascade_threshold() -> f32 {
    0.3
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            toxicity_model_path: None,
            sentiment_model_path: None,
            safety_model_path: None,
            intent_model_path: None,
            vocab_path: None,
            max_seq_length: 128,
            toxicity_threshold: 0.5,
            use_fallback: true,
            language: "uk".to_string(),
            intra_threads: default_intra_threads(),
            warmup_on_init: true,
            validate_hashes: true,
            manifest_path: None,
            cache_size: default_cache_size(),
            cache_ttl_secs: default_cache_ttl_secs(),
            cascade_enabled: true,
            cascade_gate_threshold: default_cascade_threshold(),
        }
    }
}
