use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlResult {
    pub toxicity: Option<ToxicityPrediction>,

    pub sentiment: Option<SentimentPrediction>,

    pub inference_time_us: u64,
}

impl MlResult {
    pub fn empty() -> Self {
        Self {
            toxicity: None,
            sentiment: None,
            inference_time_us: 0,
        }
    }

    pub fn has_predictions(&self) -> bool {
        self.toxicity.is_some() || self.sentiment.is_some()
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

        scores
            .iter()
            .filter(|(score, _)| *score >= threshold)
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap())
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    pub toxicity_model_path: Option<String>,

    pub sentiment_model_path: Option<String>,

    pub vocab_path: Option<String>,

    pub max_seq_length: usize,

    pub toxicity_threshold: f32,

    pub use_fallback: bool,

    pub language: String,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            toxicity_model_path: None,
            sentiment_model_path: None,
            vocab_path: None,
            max_seq_length: 128,
            toxicity_threshold: 0.5,
            use_fallback: true,
            language: "uk".to_string(),
        }
    }
}
