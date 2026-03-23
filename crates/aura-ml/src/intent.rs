use aho_corasick::AhoCorasick;
use tracing::debug;

#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::toxicity::MlError;
use crate::types::IntentPrediction;

#[derive(Clone, Copy)]
enum IntentCategory {
    Meeting,
    Secret,
    Media,
}

struct FallbackEntry {
    category: IntentCategory,
    score: f32,
}

struct IntentFallbackMatcher {
    automaton: AhoCorasick,
    entries: Vec<FallbackEntry>,
}

pub struct IntentClassifier {
    #[cfg(feature = "onnx")]
    session: Option<ort::session::Session>,
    #[cfg(feature = "onnx")]
    tokenizer: Option<WordPieceTokenizer>,
    fallback_enabled: bool,
    fallback_matcher: Option<IntentFallbackMatcher>,
    threshold: f32,
}

impl IntentClassifier {
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

        debug!("Intent ONNX model loaded from {model_path}");

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

    pub fn predict(&mut self, text: &str) -> Option<IntentPrediction> {
        #[cfg(feature = "onnx")]
        {
            let has_onnx = self.session.is_some() && self.tokenizer.is_some();
            if has_onnx {
                match self.predict_onnx(text) {
                    Ok(pred) => return Some(pred),
                    Err(e) => {
                        tracing::warn!("Intent ONNX inference failed: {e}");
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
    fn predict_onnx(&mut self, text: &str) -> Result<IntentPrediction, MlError> {
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
            "Intent ONNX inference"
        );

        if scores.len() >= 4 {
            Ok(IntentPrediction::from_scores(
                sigmoid(scores[0]),
                sigmoid(scores[1]),
                sigmoid(scores[2]),
                sigmoid(scores[3]),
                self.threshold,
            ))
        } else {
            Err(MlError::InferenceFailed(format!(
                "Expected 4 output scores, got {}",
                scores.len()
            )))
        }
    }

    fn predict_fallback(&self, text: &str) -> IntentPrediction {
        let Some(matcher) = self.fallback_matcher.as_ref() else {
            return IntentPrediction::from_scores(0.0, 0.0, 0.0, 1.0, self.threshold);
        };
        let lower = text.to_lowercase();

        let mut meeting: f32 = 0.0;
        let mut secret: f32 = 0.0;
        let mut media: f32 = 0.0;

        use crate::boundary::aho_match_at_boundary;

        for m in matcher.automaton.find_iter(&lower) {
            if !aho_match_at_boundary(&lower, m.start(), m.end()) {
                continue;
            }
            let entry = &matcher.entries[m.pattern().as_usize()];
            match entry.category {
                IntentCategory::Meeting => meeting = meeting.max(entry.score),
                IntentCategory::Secret => secret = secret.max(entry.score),
                IntentCategory::Media => media = media.max(entry.score),
            }
        }

        let max_intent = meeting.max(secret).max(media);
        let benign = if max_intent < 0.3 {
            1.0 - max_intent
        } else {
            0.0
        };

        IntentPrediction::from_scores(meeting, secret, media, benign, self.threshold)
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

fn build_fallback_matcher() -> IntentFallbackMatcher {
    use IntentCategory::*;

    let patterns: Vec<(&str, IntentCategory, f32)> = vec![
        ("let's meet", Meeting, 0.6),
        ("can we meet", Meeting, 0.5),
        ("come to my place", Meeting, 0.7),
        ("meet me", Meeting, 0.5),
        ("where do you live", Meeting, 0.5),
        ("i can pick you up", Meeting, 0.6),
        ("come alone", Meeting, 0.7),
        ("let's meet in secret", Meeting, 0.8),
        ("i'll come get you", Meeting, 0.6),
        ("давай зустрінемось", Meeting, 0.6),
        ("приходь до мене", Meeting, 0.7),
        ("де ти живеш", Meeting, 0.5),
        ("приїду за тобою", Meeting, 0.6),
        ("давай встретимся", Meeting, 0.6),
        ("приходи ко мне", Meeting, 0.7),
        ("где ты живешь", Meeting, 0.5),
        ("don't tell anyone", Secret, 0.6),
        ("don't tell your parents", Secret, 0.7),
        ("our little secret", Secret, 0.7),
        ("keep this between us", Secret, 0.6),
        ("just between us", Secret, 0.5),
        ("promise not to tell", Secret, 0.6),
        ("your parents wouldn't understand", Secret, 0.6),
        ("не кажи нікому", Secret, 0.6),
        ("не кажи батькам", Secret, 0.7),
        ("тільки між нами", Secret, 0.5),
        ("обіцяй що нікому", Secret, 0.6),
        ("не говори никому", Secret, 0.6),
        ("не говори родителям", Secret, 0.7),
        ("только между нами", Secret, 0.5),
        ("send me a photo", Media, 0.7),
        ("send nudes", Media, 0.9),
        ("show me", Media, 0.4),
        ("take a picture", Media, 0.5),
        ("video call", Media, 0.4),
        ("turn on camera", Media, 0.6),
        ("send a selfie", Media, 0.5),
        ("show me your", Media, 0.6),
        ("скинь фото", Media, 0.7),
        ("покажи себе", Media, 0.5),
        ("увімкни камеру", Media, 0.6),
        ("відеодзвінок", Media, 0.4),
        ("скинь фотку", Media, 0.7),
        ("покажи себя", Media, 0.5),
        ("включи камеру", Media, 0.6),
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
        .expect("intent fallback build");

    IntentFallbackMatcher { automaton, entries }
}

pub trait IntentBackend: Send {
    fn predict(&mut self, text: &str) -> Option<IntentPrediction>;
    fn name(&self) -> &str;
}

impl IntentBackend for IntentClassifier {
    fn predict(&mut self, text: &str) -> Option<IntentPrediction> {
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
    use crate::types::IntentLabel;

    #[test]
    fn clean_message_is_benign() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf.predict("Hey! Want to play Minecraft?").unwrap();
        assert!(pred.benign > 0.5);
        assert!(pred.primary_intent.is_none());
    }

    #[test]
    fn meeting_request_en() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf
            .predict("come to my place alone, I'll come get you")
            .unwrap();
        assert!(pred.request_meeting >= 0.6);
        assert_eq!(pred.primary_intent, Some(IntentLabel::RequestMeeting));
    }

    #[test]
    fn meeting_request_uk() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf.predict("давай зустрінемось, приходь до мене").unwrap();
        assert!(pred.request_meeting >= 0.6);
    }

    #[test]
    fn secret_request_en() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf
            .predict("don't tell your parents, it's our little secret")
            .unwrap();
        assert!(pred.request_secret >= 0.6);
        assert_eq!(pred.primary_intent, Some(IntentLabel::RequestSecret));
    }

    #[test]
    fn secret_request_ru() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf
            .predict("не говори родителям, только между нами")
            .unwrap();
        assert!(pred.request_secret >= 0.5);
    }

    #[test]
    fn media_request_en() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf.predict("send me a photo, turn on camera").unwrap();
        assert!(pred.request_media >= 0.6);
        assert_eq!(pred.primary_intent, Some(IntentLabel::RequestMedia));
    }

    #[test]
    fn media_request_uk() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf.predict("скинь фото, увімкни камеру").unwrap();
        assert!(pred.request_media >= 0.6);
    }

    #[test]
    fn combined_grooming_intents() {
        let mut clf = IntentClassifier::fallback_only();
        let pred = clf
            .predict("send me a photo, don't tell anyone, let's meet in secret")
            .unwrap();
        assert!(pred.request_media >= 0.5);
        assert!(pred.request_secret >= 0.5);
        assert!(pred.request_meeting >= 0.5);
    }
}
