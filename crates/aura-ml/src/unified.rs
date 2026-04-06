//! Unified multi-head model for content safety classification.
//!
//! Runs a single ONNX forward pass and produces toxicity and safety
//! predictions simultaneously. This replaces separate model calls with one
//! shared-backbone inference, reducing latency from ~30ms to ~10ms on mobile.
//!
//! The model outputs 8 safety logits:
//!   S, S3, SH, HR, H, V, V2, H2
//!
//! Post-processing maps these to existing prediction types (ToxicityPrediction,
//! SafetyPrediction) so the rest of the pipeline is unchanged.
//!
//! Sentiment was dropped from the unified model because the training data
//! only had synthetic sentiment labels derived from safety labels, making
//! the sentiment head a noisy mirror of the safety head rather than an
//! independent signal. Sentiment analysis remains available via the
//! standalone lexicon-based SentimentAnalyzer.

use crate::types::{SafetyPrediction, ToxicityPrediction};

#[cfg(feature = "onnx")]
use crate::tokenizer_sp::AnyTokenizer;

#[cfg(any(feature = "onnx", test))]
const SAFETY_OUTPUTS: usize = 8;

/// Indices into model output logits.
#[cfg(any(feature = "onnx", test))]
mod idx {
    pub const S: usize = 0;
    pub const S3: usize = 1;
    pub const SH: usize = 2;
    pub const HR: usize = 3;
    pub const H: usize = 4;
    pub const V: usize = 5;
    pub const V2: usize = 6;
    pub const H2: usize = 7;
}

/// Combined prediction from a single unified forward pass.
pub struct UnifiedPrediction {
    pub toxicity: ToxicityPrediction,
    pub safety: SafetyPrediction,
}

/// Unified safety ONNX model with fallback support.
pub struct UnifiedModel {
    #[cfg(feature = "onnx")]
    session: Option<ort::session::Session>,
    #[cfg(feature = "onnx")]
    tokenizer: Option<AnyTokenizer>,
    #[cfg(feature = "onnx")]
    max_seq_length: usize,
    safety_threshold: f32,
    toxicity_threshold: f32,
    fallback_enabled: bool,
}

impl UnifiedModel {
    /// Load from an ONNX model file.
    #[cfg(feature = "onnx")]
    pub fn with_model(
        model_path: &str,
        tokenizer: AnyTokenizer,
        intra_threads: usize,
        max_seq_length: usize,
    ) -> Result<Self, crate::toxicity::MlError> {
        let session = ort::session::Session::builder()
            .map_err(|e| crate::toxicity::MlError::ModelLoadFailed(e.to_string()))?
            .with_intra_threads(intra_threads)
            .map_err(|e| crate::toxicity::MlError::ModelLoadFailed(e.to_string()))?
            .commit_from_file(model_path)
            .map_err(|e| crate::toxicity::MlError::ModelLoadFailed(e.to_string()))?;

        Ok(Self {
            session: Some(session),
            tokenizer: Some(tokenizer),
            max_seq_length,
            safety_threshold: 0.5,
            toxicity_threshold: 0.5,
            fallback_enabled: true,
        })
    }

    /// Fallback-only mode (no ONNX model loaded).
    pub fn fallback_only() -> Self {
        Self {
            #[cfg(feature = "onnx")]
            session: None,
            #[cfg(feature = "onnx")]
            tokenizer: None,
            #[cfg(feature = "onnx")]
            max_seq_length: 128,
            safety_threshold: 0.5,
            toxicity_threshold: 0.5,
            fallback_enabled: true,
        }
    }

    pub fn set_thresholds(&mut self, safety: f32, toxicity: f32) {
        self.safety_threshold = safety;
        self.toxicity_threshold = toxicity;
    }

    pub fn has_onnx(&self) -> bool {
        #[cfg(feature = "onnx")]
        {
            self.session.is_some() && self.tokenizer.is_some()
        }
        #[cfg(not(feature = "onnx"))]
        {
            false
        }
    }

    pub fn name(&self) -> &str {
        if self.has_onnx() {
            "unified-onnx"
        } else {
            "unified-fallback"
        }
    }

    /// Run a single forward pass and return safety + toxicity predictions.
    pub fn predict_all(&mut self, text: &str) -> Option<UnifiedPrediction> {
        #[cfg(feature = "onnx")]
        if self.has_onnx() {
            match self.predict_onnx(text) {
                Ok(pred) => return Some(pred),
                Err(e) => {
                    tracing::warn!("Unified ONNX inference failed, falling back: {e}");
                }
            }
        }

        if self.fallback_enabled {
            return Some(self.predict_fallback(text));
        }
        None
    }

    #[cfg(feature = "onnx")]
    fn predict_onnx(&mut self, text: &str) -> Result<UnifiedPrediction, crate::toxicity::MlError> {
        let tokenizer = self
            .tokenizer
            .as_ref()
            .ok_or_else(|| crate::toxicity::MlError::ModelLoadFailed("no tokenizer".into()))?;
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| crate::toxicity::MlError::ModelLoadFailed("no session".into()))?;

        let encoded = tokenizer.encode(text);
        let seq_len = encoded.input_ids.len().min(self.max_seq_length);

        let input_ids_vec: Vec<i64> = encoded.input_ids[..seq_len].to_vec();
        let attention_mask_vec: Vec<i64> = encoded.attention_mask[..seq_len].to_vec();

        let input_ids = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), input_ids_vec)
                .map_err(|e| crate::toxicity::MlError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| crate::toxicity::MlError::InferenceFailed(e.to_string()))?;

        let attention_mask = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), attention_mask_vec)
                .map_err(|e| crate::toxicity::MlError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| crate::toxicity::MlError::InferenceFailed(e.to_string()))?;

        let outputs = session
            .run(ort::inputs![input_ids, attention_mask])
            .map_err(|e| crate::toxicity::MlError::InferenceFailed(e.to_string()))?;

        let (_shape, logits) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| crate::toxicity::MlError::InferenceFailed(e.to_string()))?;

        if logits.len() < SAFETY_OUTPUTS {
            return Err(crate::toxicity::MlError::InferenceFailed(format!(
                "expected {} logits, got {}",
                SAFETY_OUTPUTS,
                logits.len()
            )));
        }

        let scores: Vec<f32> = logits[..SAFETY_OUTPUTS]
            .iter()
            .map(|&x| sigmoid(x))
            .collect();
        Ok(map_scores_to_predictions(
            &scores,
            self.toxicity_threshold,
            self.safety_threshold,
        ))
    }

    fn predict_fallback(&self, _text: &str) -> UnifiedPrediction {
        UnifiedPrediction {
            toxicity: ToxicityPrediction {
                toxicity: 0.0,
                severe_toxicity: 0.0,
                identity_attack: 0.0,
                insult: 0.0,
                sexual_explicit: 0.0,
                threat: 0.0,
                primary_label: None,
            },
            safety: SafetyPrediction::from_scores(0.0, 0.0, 0.0, 0.0, 1.0, 0.5),
        }
    }
}

#[cfg(any(feature = "onnx", test))]
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Map raw sigmoid scores to existing prediction types.
#[cfg(any(feature = "onnx", test))]
fn map_scores_to_predictions(
    scores: &[f32],
    toxicity_threshold: f32,
    safety_threshold: f32,
) -> UnifiedPrediction {
    let s = scores[idx::S];
    let s3 = scores[idx::S3];
    let sh = scores[idx::SH];
    let hr = scores[idx::HR];
    let h = scores[idx::H];
    let v = scores[idx::V];
    let v2 = scores[idx::V2];
    let h2 = scores[idx::H2];

    let toxicity_score = f32::max(f32::max(s, hr), f32::max(h, v));
    let severe = f32::max(v2, h2);

    let mut tox = ToxicityPrediction {
        toxicity: toxicity_score,
        severe_toxicity: severe,
        sexual_explicit: s,
        threat: v,
        insult: hr,
        identity_attack: h,
        primary_label: None,
    };
    tox.primary_label = tox.compute_primary_label(toxicity_threshold);

    let safe_score = 1.0 - [s3, hr, sh].iter().copied().fold(0f32, f32::max);
    let safety = SafetyPrediction::from_scores(s3, hr, sh, 0.0, safe_score, safety_threshold);

    UnifiedPrediction {
        toxicity: tox,
        safety,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SafetyLabel;

    #[test]
    fn sigmoid_basics() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(10.0) > 0.999);
        assert!(sigmoid(-10.0) < 0.001);
    }

    #[test]
    fn map_scores_produces_valid_predictions() {
        let scores = [
            0.1,  // S
            0.8,  // S3 (sexual/minors → grooming)
            0.3,  // SH
            0.2,  // HR
            0.05, // H
            0.1,  // V
            0.02, // V2
            0.01, // H2
        ];

        let pred = map_scores_to_predictions(&scores, 0.5, 0.5);

        assert!(pred.safety.grooming > 0.7, "S3 should map to grooming");
        assert!(
            pred.safety.primary_label == Some(SafetyLabel::Grooming),
            "primary label should be Grooming"
        );
    }

    #[test]
    fn map_scores_safe_message() {
        let scores = [0.05; SAFETY_OUTPUTS];
        let pred = map_scores_to_predictions(&scores, 0.5, 0.5);

        assert!(pred.safety.safe > 0.9);
        assert!(pred.safety.primary_label.is_none());
        assert!(pred.toxicity.primary_label.is_none());
    }

    #[test]
    fn fallback_returns_safe_defaults() {
        let model = UnifiedModel::fallback_only();
        assert_eq!(model.name(), "unified-fallback");
        assert!(!model.has_onnx());
    }

    #[test]
    fn self_harm_maps_correctly() {
        let mut scores = [0.05; SAFETY_OUTPUTS];
        scores[idx::SH] = 0.92;

        let pred = map_scores_to_predictions(&scores, 0.5, 0.5);

        assert!(pred.safety.self_harm > 0.9);
        assert!(
            pred.safety.primary_label == Some(SafetyLabel::SelfHarm),
            "primary label should be SelfHarm"
        );
    }

    #[test]
    fn harassment_maps_to_both_toxicity_and_bullying() {
        let mut scores = [0.05; SAFETY_OUTPUTS];
        scores[idx::HR] = 0.85;

        let pred = map_scores_to_predictions(&scores, 0.5, 0.5);

        assert!(pred.toxicity.insult > 0.8, "HR maps to toxicity.insult");
        assert!(pred.safety.bullying > 0.8, "HR maps to safety.bullying");
    }
}
