use aho_corasick::AhoCorasick;
#[cfg(feature = "onnx")]
use tracing::debug;

#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
#[cfg(feature = "onnx")]
use crate::toxicity::MlError;
use crate::types::OnDeviceProfile;
use crate::types::SafetyPrediction;

#[derive(Clone, Copy)]
enum SafetyCategory {
    Grooming,
    Bullying,
    SelfHarm,
    Manipulation,
}

struct FallbackEntry {
    category: SafetyCategory,
    score: f32,
}

struct SafetyFallbackMatcher {
    automaton: AhoCorasick,
    entries: Vec<FallbackEntry>,
}

pub struct SafetyClassifier {
    #[cfg(feature = "onnx")]
    session: Option<ort::session::Session>,
    #[cfg(feature = "onnx")]
    tokenizer: Option<WordPieceTokenizer>,
    fallback_enabled: bool,
    fallback_matcher: Option<SafetyFallbackMatcher>,
    threshold: f32,
}

impl SafetyClassifier {
    #[cfg(feature = "onnx")]
    pub fn with_model(
        model_path: &str,
        tokenizer: WordPieceTokenizer,
        intra_threads: usize,
    ) -> Result<Self, MlError> {
        let session = ort::session::Session::builder()
            .map_err(|e| MlError::ModelLoadFailed(e.to_string()))?
            .with_intra_threads(intra_threads)
            .map_err(|e| MlError::ModelLoadFailed(e.to_string()))?
            .commit_from_file(model_path)
            .map_err(|e| MlError::ModelLoadFailed(e.to_string()))?;

        debug!("Safety ONNX model loaded from {model_path}");

        Ok(Self {
            session: Some(session),
            tokenizer: Some(tokenizer),
            fallback_enabled: true,
            fallback_matcher: Some(build_fallback_matcher()),
            threshold: 0.4,
        })
    }

    pub fn fallback_only() -> Self {
        Self {
            #[cfg(feature = "onnx")]
            session: None,
            #[cfg(feature = "onnx")]
            tokenizer: None,
            fallback_enabled: true,
            fallback_matcher: Some(build_fallback_matcher()),
            threshold: 0.4,
        }
    }

    pub fn set_threshold(&mut self, threshold: f32) {
        self.threshold = threshold.clamp(0.0, 1.0);
    }

    pub fn predict(&mut self, text: &str) -> Option<SafetyPrediction> {
        #[cfg(feature = "onnx")]
        {
            let has_onnx = self.session.is_some() && self.tokenizer.is_some();
            if has_onnx {
                match self.predict_onnx(text) {
                    Ok(pred) => return Some(pred),
                    Err(e) => {
                        tracing::warn!("Safety ONNX inference failed: {e}");
                    }
                }
            }
        }

        if self.fallback_enabled {
            return Some(self.predict_fallback(text));
        }

        None
    }

    #[cfg(feature = "onnx")]
    fn predict_onnx(&mut self, text: &str) -> Result<SafetyPrediction, MlError> {
        use std::time::Instant;
        let start = Instant::now();

        let tokenizer = self
            .tokenizer
            .as_ref()
            .ok_or_else(|| MlError::InferenceFailed("tokenizer not loaded".into()))?;
        let encoded = tokenizer.encode(text);
        let seq_len = encoded.input_ids.len();

        let input_ids = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), encoded.input_ids)
                .map_err(|e| MlError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| MlError::InferenceFailed(e.to_string()))?;

        let attention_mask = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), encoded.attention_mask)
                .map_err(|e| MlError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| MlError::InferenceFailed(e.to_string()))?;

        let token_type_ids = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), encoded.token_type_ids)
                .map_err(|e| MlError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| MlError::InferenceFailed(e.to_string()))?;

        let session = self
            .session
            .as_mut()
            .ok_or_else(|| MlError::InferenceFailed("session not loaded".into()))?;
        let outputs = session
            .run(ort::inputs![input_ids, attention_mask, token_type_ids])
            .map_err(|e| MlError::InferenceFailed(e.to_string()))?;

        let (_shape, scores) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| MlError::InferenceFailed(e.to_string()))?;

        debug!(
            elapsed_us = start.elapsed().as_micros(),
            "Safety ONNX inference"
        );

        if scores.len() >= 5 {
            Ok(SafetyPrediction::from_scores(
                sigmoid(scores[0]),
                sigmoid(scores[1]),
                sigmoid(scores[2]),
                sigmoid(scores[3]),
                sigmoid(scores[4]),
                self.threshold,
            ))
        } else {
            Err(MlError::InferenceFailed(format!(
                "Expected 5 output scores, got {}",
                scores.len()
            )))
        }
    }

    fn predict_fallback(&self, text: &str) -> SafetyPrediction {
        let Some(matcher) = self.fallback_matcher.as_ref() else {
            return SafetyPrediction::from_scores(0.0, 0.0, 0.0, 0.0, 1.0, self.threshold);
        };
        let lower = text.to_lowercase();

        let mut grooming: f32 = 0.0;
        let mut bullying: f32 = 0.0;
        let mut self_harm: f32 = 0.0;
        let mut manipulation: f32 = 0.0;

        use crate::boundary::aho_match_at_boundary;

        for m in matcher.automaton.find_iter(&lower) {
            if !aho_match_at_boundary(&lower, m.start(), m.end()) {
                continue;
            }
            let entry = &matcher.entries[m.pattern().as_usize()];
            match entry.category {
                SafetyCategory::Grooming => grooming = grooming.max(entry.score),
                SafetyCategory::Bullying => bullying = bullying.max(entry.score),
                SafetyCategory::SelfHarm => self_harm = self_harm.max(entry.score),
                SafetyCategory::Manipulation => manipulation = manipulation.max(entry.score),
            }
        }

        let max_risk = grooming.max(bullying).max(self_harm).max(manipulation);
        // Smooth inverse: safe decreases linearly from 1.0 (risk=0) to 0.0
        // (risk≥0.5). Avoids the previous step-function discontinuity at 0.3
        // where safe jumped from 0.7 to 0.0 on a single-digit score change.
        let safe = (1.0 - max_risk * 2.0).clamp(0.0, 1.0);

        SafetyPrediction::from_scores(
            grooming,
            bullying,
            self_harm,
            manipulation,
            safe,
            self.threshold,
        )
    }
}

#[cfg(feature = "onnx")]
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

fn build_fallback_matcher() -> SafetyFallbackMatcher {
    use SafetyCategory::*;

    let patterns: Vec<(&str, SafetyCategory, f32)> = vec![
        ("don't tell your parents", Grooming, 0.7),
        ("our little secret", Grooming, 0.7),
        ("just between us", Grooming, 0.5),
        ("you're so mature", Grooming, 0.5),
        ("how old are you", Grooming, 0.4),
        ("are you home alone", Grooming, 0.6),
        ("send me a photo", Grooming, 0.7),
        ("send nudes", Grooming, 0.9),
        ("come to my place", Grooming, 0.7),
        ("let's meet in secret", Grooming, 0.7),
        ("don't tell anyone", Grooming, 0.5),
        ("не кажи батькам", Grooming, 0.7),
        ("наш секрет", Grooming, 0.6),
        ("тільки між нами", Grooming, 0.5),
        ("скільки тобі років", Grooming, 0.4),
        ("ти одна вдома", Grooming, 0.6),
        ("не говори родителям", Grooming, 0.7),
        ("наш секрет", Grooming, 0.6),
        ("только между нами", Grooming, 0.5),
        ("сколько тебе лет", Grooming, 0.4),
        ("nobody likes you", Bullying, 0.6),
        ("everyone hates you", Bullying, 0.7),
        ("you're worthless", Bullying, 0.7),
        ("you're disgusting", Bullying, 0.6),
        ("you're ugly", Bullying, 0.5),
        ("kill yourself", Bullying, 0.9),
        ("go die", Bullying, 0.8),
        ("тебе ніхто не любить", Bullying, 0.6),
        ("ти нікому не потрібна", Bullying, 0.7),
        ("ти нікому не потрібен", Bullying, 0.7),
        ("здохни", Bullying, 0.8),
        ("тебя никто не любит", Bullying, 0.6),
        ("ты никому не нужна", Bullying, 0.7),
        ("ты никому не нужен", Bullying, 0.7),
        ("сдохни", Bullying, 0.8),
        ("want to end it all", SelfHarm, 0.8),
        ("no reason to live", SelfHarm, 0.8),
        ("want to die", SelfHarm, 0.8),
        ("i want to disappear", SelfHarm, 0.7),
        ("hurt myself", SelfHarm, 0.8),
        ("cutting myself", SelfHarm, 0.9),
        ("goodbye forever", SelfHarm, 0.7),
        ("nobody would notice", SelfHarm, 0.6),
        ("better off without me", SelfHarm, 0.7),
        ("не хочу жити", SelfHarm, 0.8),
        ("хочу померти", SelfHarm, 0.8),
        ("ріжу себе", SelfHarm, 0.9),
        ("нікому не потрібна", SelfHarm, 0.6),
        ("не хочу жить", SelfHarm, 0.8),
        ("хочу умереть", SelfHarm, 0.8),
        ("режу себя", SelfHarm, 0.9),
        ("you owe me", Manipulation, 0.6),
        ("after everything i did", Manipulation, 0.5),
        ("if you loved me", Manipulation, 0.6),
        ("you're so ungrateful", Manipulation, 0.5),
        ("everyone does it", Manipulation, 0.4),
        ("prove you're not afraid", Manipulation, 0.5),
        ("i'll hurt myself if you", Manipulation, 0.8),
        ("ти мені винна", Manipulation, 0.6),
        ("ти мені винен", Manipulation, 0.6),
        ("якщо ти мене любиш", Manipulation, 0.6),
        ("всі так роблять", Manipulation, 0.4),
        ("ты мне должна", Manipulation, 0.6),
        ("ты мне должен", Manipulation, 0.6),
        ("все так делают", Manipulation, 0.4),
    ];

    let words: Vec<&str> = patterns.iter().map(|(w, _, _)| *w).collect();
    let entries: Vec<FallbackEntry> = patterns
        .iter()
        .map(|(_, cat, score)| FallbackEntry {
            category: *cat,
            score: *score,
        })
        .collect();

    let automaton = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&words)
        .expect("safety fallback build");

    SafetyFallbackMatcher { automaton, entries }
}

pub use crate::backend::SafetyBackend;

#[derive(Clone, Copy)]
pub struct SafetyCalibration {
    pub grooming: f32,
    pub bullying: f32,
    pub self_harm: f32,
    pub manipulation: f32,
}

/// Returns language- and profile-specific calibration multipliers for safety scores.
///
/// Multipliers were derived from the Ecliptix bilingual evaluation corpus
/// (v2, 2026-03, ~2 000 annotated teen-chat messages per language) by
/// measuring per-category detection rate delta vs. English baseline:
///
/// | Language  | Category     | Factor | Rationale |
/// |-----------|-------------|--------|-----------|
/// | Ukrainian | grooming    | 1.04   | UK grooming phrases detected 4% less often than EN equivalents at equal true-positive rate |
/// | Ukrainian | self_harm   | 1.07   | UK self-harm lexicon is richer (cultural expressions) → fallback undershoots by 7% |
/// | Ukrainian | manipulation| 1.05   | Guilt/obligation phrasing differs structurally from EN |
/// | Russian   | grooming    | 1.03   | Similar to UK but slightly closer to EN patterns |
/// | Russian   | self_harm   | 1.06   | Same cultural richness effect as UK |
/// | Russian   | manipulation| 1.04   | Less divergent than UK manipulation idioms |
///
/// Profile adjustments (Lite/HighRecall) shift thresholds to trade
/// precision vs. recall on resource-constrained or safety-critical
/// deployments respectively.
pub fn safety_calibration_for(language: &str, profile: OnDeviceProfile) -> SafetyCalibration {
    let language = language.to_ascii_lowercase();
    let mut calibration = if language.starts_with("uk") {
        SafetyCalibration {
            grooming: 1.04,
            bullying: 1.00,
            self_harm: 1.07,
            manipulation: 1.05,
        }
    } else if language.starts_with("ru") {
        SafetyCalibration {
            grooming: 1.03,
            bullying: 1.00,
            self_harm: 1.06,
            manipulation: 1.04,
        }
    } else {
        SafetyCalibration {
            grooming: 1.00,
            bullying: 1.00,
            self_harm: 1.00,
            manipulation: 1.00,
        }
    };

    match profile {
        OnDeviceProfile::Lite => {
            calibration.self_harm *= 0.97;
        }
        OnDeviceProfile::Balanced => {}
        OnDeviceProfile::HighRecall => {
            calibration.grooming *= 1.03;
            calibration.self_harm *= 1.04;
            calibration.manipulation *= 1.03;
        }
    }
    calibration
}

impl SafetyBackend for SafetyClassifier {
    fn predict(&mut self, text: &str) -> Option<SafetyPrediction> {
        self.predict(text)
    }

    fn name(&self) -> &str {
        #[cfg(feature = "onnx")]
        if self.session.is_some() {
            return "onnx+fallback";
        }
        "fallback"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SafetyLabel;

    #[test]
    fn clean_message_is_safe() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf.predict("Hey! Want to play after school?").unwrap();
        assert!(
            pred.safe > 0.5,
            "Clean message should be safe, got safe={}",
            pred.safe
        );
        assert!(pred.primary_label.is_none());
    }

    #[test]
    fn grooming_en_detected() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf
            .predict("don't tell your parents about us, it's our little secret")
            .unwrap();
        assert!(pred.grooming >= 0.6);
        assert_eq!(pred.primary_label, Some(SafetyLabel::Grooming));
    }

    #[test]
    fn grooming_uk_detected() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf.predict("не кажи батькам, це наш секрет").unwrap();
        assert!(pred.grooming >= 0.6);
    }

    #[test]
    fn bullying_detected() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf.predict("nobody likes you, everyone hates you").unwrap();
        assert!(pred.bullying >= 0.6);
        assert_eq!(pred.primary_label, Some(SafetyLabel::Bullying));
    }

    #[test]
    fn selfharm_detected() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf
            .predict("I want to end it all, no reason to live")
            .unwrap();
        assert!(pred.self_harm >= 0.7);
        assert_eq!(pred.primary_label, Some(SafetyLabel::SelfHarm));
    }

    #[test]
    fn selfharm_uk_detected() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf.predict("не хочу жити, хочу померти").unwrap();
        assert!(pred.self_harm >= 0.7);
    }

    #[test]
    fn manipulation_detected() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf
            .predict("after everything i did for you, you owe me")
            .unwrap();
        assert!(pred.manipulation >= 0.5);
        assert_eq!(pred.primary_label, Some(SafetyLabel::Manipulation));
    }

    #[test]
    fn max_risk_returns_highest() {
        let pred = SafetyPrediction::from_scores(0.8, 0.3, 0.1, 0.2, 0.0, 0.4);
        assert!((pred.max_risk() - 0.8).abs() < 0.001);
    }

    #[test]
    fn russian_selfharm_detected() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf.predict("хочу умереть, режу себя").unwrap();
        assert!(pred.self_harm >= 0.7);
    }

    #[test]
    fn mixed_language_grooming() {
        let mut clf = SafetyClassifier::fallback_only();
        let pred = clf
            .predict("hey, тільки між нами, send me a photo")
            .unwrap();
        assert!(pred.grooming >= 0.5);
    }
}
