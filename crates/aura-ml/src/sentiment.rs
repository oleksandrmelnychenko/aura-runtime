use aho_corasick::AhoCorasick;
use tracing::debug;

#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::types::SentimentPrediction;

#[derive(Debug, Clone, Copy, PartialEq)]
enum SentPolarity {
    Positive,
    Negative,
}

struct SentimentFallbackEntry {
    polarity: SentPolarity,
    weight: f32,
}

struct SentimentFallbackMatcher {
    automaton: AhoCorasick,
    entries: Vec<SentimentFallbackEntry>,
}

pub struct SentimentAnalyzer {
    #[cfg(feature = "onnx")]
    session: Option<ort::session::Session>,
    #[cfg(feature = "onnx")]
    tokenizer: Option<WordPieceTokenizer>,
    fallback_enabled: bool,
    fallback_matcher: Option<SentimentFallbackMatcher>,
}

impl SentimentAnalyzer {
    #[cfg(feature = "onnx")]
    pub fn with_model(
        model_path: &str,
        tokenizer: WordPieceTokenizer,
    ) -> Result<Self, SentimentError> {
        let session = ort::session::Session::builder()
            .map_err(|e| SentimentError::ModelLoadFailed(e.to_string()))?
            .with_intra_threads(1)
            .map_err(|e| SentimentError::ModelLoadFailed(e.to_string()))?
            .commit_from_file(model_path)
            .map_err(|e| SentimentError::ModelLoadFailed(e.to_string()))?;

        debug!("Sentiment ONNX model loaded from {model_path}");

        Ok(Self {
            session: Some(session),
            tokenizer: Some(tokenizer),
            fallback_enabled: true,
            fallback_matcher: Some(build_fallback_matcher()),
        })
    }

    pub fn fallback_only() -> Self {
        debug!("Sentiment analyzer using lexicon-based fallback");
        Self {
            #[cfg(feature = "onnx")]
            session: None,
            #[cfg(feature = "onnx")]
            tokenizer: None,
            fallback_enabled: true,
            fallback_matcher: Some(build_fallback_matcher()),
        }
    }

    pub fn predict(&mut self, text: &str) -> Option<SentimentPrediction> {
        #[cfg(feature = "onnx")]
        {
            let has_onnx = self.session.is_some() && self.tokenizer.is_some();
            if has_onnx {
                match self.predict_onnx(text) {
                    Ok(pred) => return Some(pred),
                    Err(e) => {
                        tracing::warn!("ONNX sentiment inference failed: {e}");
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
    fn predict_onnx(&mut self, text: &str) -> Result<SentimentPrediction, SentimentError> {
        let tokenizer = self
            .tokenizer
            .as_ref()
            .expect("predict_onnx only used when ONNX loaded");
        let encoded = tokenizer.encode(text);
        let seq_len = encoded.input_ids.len();

        let input_ids = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), encoded.input_ids)
                .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?;

        let attention_mask = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), encoded.attention_mask)
                .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?;

        let token_type_ids = ort::value::Tensor::from_array(
            ndarray::Array2::from_shape_vec((1, seq_len), encoded.token_type_ids)
                .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?,
        )
        .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?;

        let session = self
            .session
            .as_mut()
            .expect("predict_onnx only used when ONNX loaded");
        let outputs = session
            .run(ort::inputs![input_ids, attention_mask, token_type_ids])
            .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?;

        let (_shape, scores) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| SentimentError::InferenceFailed(e.to_string()))?;

        if scores.len() >= 3 {
            let max = scores[..3]
                .iter()
                .cloned()
                .fold(f32::NEG_INFINITY, f32::max);
            let exps: Vec<f32> = scores[..3].iter().map(|&s| (s - max).exp()).collect();
            let sum: f32 = exps.iter().sum();
            Ok(SentimentPrediction::from_scores(
                exps[2] / sum,
                exps[1] / sum,
                exps[0] / sum,
            ))
        } else if scores.len() >= 2 {
            let max = scores[0].max(scores[1]);
            let exp0 = (scores[0] - max).exp();
            let exp1 = (scores[1] - max).exp();
            let sum = exp0 + exp1;
            let neg_prob = exp0 / sum;
            let pos_prob = exp1 / sum;

            let margin = (pos_prob - neg_prob).abs();
            if margin < 0.3 {
                let neutral = 1.0 - margin;
                let pos_adj = pos_prob * margin;
                let neg_adj = neg_prob * margin;
                let total = pos_adj + neutral + neg_adj;
                Ok(SentimentPrediction::from_scores(
                    pos_adj / total,
                    neutral / total,
                    neg_adj / total,
                ))
            } else {
                let neutral = 0.05;
                let pos_adj = pos_prob * (1.0 - neutral);
                let neg_adj = neg_prob * (1.0 - neutral);
                Ok(SentimentPrediction::from_scores(pos_adj, neutral, neg_adj))
            }
        } else {
            Err(SentimentError::InferenceFailed(format!(
                "Expected 2 or 3 output scores, got {}",
                scores.len()
            )))
        }
    }

    fn predict_fallback(&self, text: &str) -> SentimentPrediction {
        let lower = text.to_lowercase();

        let mut pos_score = 0.0f32;
        let mut neg_score = 0.0f32;

        if let Some(ref matcher) = self.fallback_matcher {
            use crate::boundary::{aho_match_at_boundary, is_negated};

            for m in matcher.automaton.find_iter(&lower) {
                let start = m.start();
                let end = m.end();

                if !aho_match_at_boundary(&lower, start, end) {
                    continue;
                }

                let entry = &matcher.entries[m.pattern().as_usize()];

                match entry.polarity {
                    SentPolarity::Positive => {
                        if is_negated(&lower, start, 30) {
                            neg_score += entry.weight * 0.5;
                        } else {
                            pos_score += entry.weight;
                        }
                    }
                    SentPolarity::Negative => {
                        if is_negated(&lower, start, 30) {
                            pos_score += entry.weight * 0.3;
                        } else {
                            neg_score += entry.weight;
                        }
                    }
                }
            }
        }

        pos_score = pos_score.min(1.0);
        neg_score = neg_score.min(1.0);

        let total = pos_score + neg_score + 0.5;

        let positive = pos_score / total;
        let negative = neg_score / total;
        let neutral = 0.5 / total;

        SentimentPrediction::from_scores(positive, neutral, negative)
    }
}

fn build_fallback_matcher() -> SentimentFallbackMatcher {
    use SentPolarity::*;

    let all: &[(&str, f32, SentPolarity)] = &[
        ("love", 0.3, Positive),
        ("happy", 0.3, Positive),
        ("great", 0.3, Positive),
        ("amazing", 0.3, Positive),
        ("wonderful", 0.3, Positive),
        ("beautiful", 0.3, Positive),
        ("awesome", 0.3, Positive),
        ("good", 0.2, Positive),
        ("nice", 0.2, Positive),
        ("thanks", 0.2, Positive),
        ("thank you", 0.3, Positive),
        ("excellent", 0.3, Positive),
        ("perfect", 0.3, Positive),
        ("best", 0.2, Positive),
        ("excited", 0.3, Positive),
        ("glad", 0.2, Positive),
        ("joy", 0.3, Positive),
        ("fun", 0.2, Positive),
        ("cool", 0.2, Positive),
        ("fantastic", 0.3, Positive),
        ("brilliant", 0.3, Positive),
        ("lol", 0.1, Positive),
        ("haha", 0.1, Positive),
        ("😊", 0.2, Positive),
        ("❤️", 0.2, Positive),
        ("proud", 0.2, Positive),
        ("hopeful", 0.3, Positive),
        ("grateful", 0.3, Positive),
        ("thankful", 0.3, Positive),
        ("confident", 0.2, Positive),
        ("cheerful", 0.3, Positive),
        ("delighted", 0.3, Positive),
        ("pleased", 0.2, Positive),
        ("thrilled", 0.3, Positive),
        ("ecstatic", 0.3, Positive),
        ("blessed", 0.2, Positive),
        ("inspired", 0.2, Positive),
        ("optimistic", 0.2, Positive),
        ("peaceful", 0.2, Positive),
        ("relieved", 0.2, Positive),
        ("satisfied", 0.2, Positive),
        ("comfortable", 0.1, Positive),
        ("safe", 0.1, Positive),
        ("warm", 0.1, Positive),
        ("welcome", 0.2, Positive),
        ("supported", 0.2, Positive),
        ("valued", 0.2, Positive),
        ("appreciated", 0.2, Positive),
        ("accepted", 0.2, Positive),
        ("free", 0.1, Positive),
        ("strong", 0.2, Positive),
        ("brave", 0.2, Positive),
        ("courageous", 0.2, Positive),
        ("kind", 0.1, Positive),
        ("generous", 0.2, Positive),
        ("hate", 0.4, Negative),
        ("sad", 0.3, Negative),
        ("angry", 0.3, Negative),
        ("terrible", 0.4, Negative),
        ("awful", 0.4, Negative),
        ("horrible", 0.4, Negative),
        ("worst", 0.4, Negative),
        ("bad", 0.2, Negative),
        ("ugly", 0.3, Negative),
        ("disgusting", 0.4, Negative),
        ("annoying", 0.2, Negative),
        ("stupid", 0.3, Negative),
        ("boring", 0.2, Negative),
        ("depressed", 0.4, Negative),
        ("lonely", 0.3, Negative),
        ("scared", 0.3, Negative),
        ("worried", 0.2, Negative),
        ("upset", 0.3, Negative),
        ("cry", 0.3, Negative),
        ("crying", 0.3, Negative),
        ("hopeless", 0.4, Negative),
        ("worthless", 0.4, Negative),
        ("miserable", 0.4, Negative),
        ("anxious", 0.3, Negative),
        ("nervous", 0.2, Negative),
        ("afraid", 0.3, Negative),
        ("terrified", 0.4, Negative),
        ("furious", 0.4, Negative),
        ("frustrated", 0.3, Negative),
        ("devastated", 0.4, Negative),
        ("heartbroken", 0.4, Negative),
        ("ashamed", 0.3, Negative),
        ("embarrassed", 0.2, Negative),
        ("humiliated", 0.4, Negative),
        ("rejected", 0.3, Negative),
        ("abandoned", 0.4, Negative),
        ("betrayed", 0.4, Negative),
        ("trapped", 0.4, Negative),
        ("suffocated", 0.4, Negative),
        ("overwhelmed", 0.3, Negative),
        ("exhausted", 0.2, Negative),
        ("numb", 0.3, Negative),
        ("empty", 0.3, Negative),
        ("broken", 0.4, Negative),
        ("shattered", 0.4, Negative),
        ("crushed", 0.4, Negative),
        ("defeated", 0.3, Negative),
        ("helpless", 0.4, Negative),
        ("powerless", 0.4, Negative),
        ("useless", 0.4, Negative),
        ("invisible", 0.3, Negative),
        ("forgotten", 0.3, Negative),
        ("ignored", 0.3, Negative),
        ("alone", 0.3, Negative),
        ("isolated", 0.3, Negative),
        ("unwanted", 0.4, Negative),
        ("unloved", 0.4, Negative),
        ("unworthy", 0.4, Negative),
        ("кохаю", 0.3, Positive),
        ("люблю", 0.3, Positive),
        ("щасливий", 0.3, Positive),
        ("щаслива", 0.3, Positive),
        ("чудово", 0.3, Positive),
        ("прекрасно", 0.3, Positive),
        ("супер", 0.3, Positive),
        ("класно", 0.2, Positive),
        ("добре", 0.2, Positive),
        ("дякую", 0.3, Positive),
        ("файно", 0.2, Positive),
        ("красиво", 0.2, Positive),
        ("найкращий", 0.3, Positive),
        ("радий", 0.2, Positive),
        ("рада", 0.2, Positive),
        ("привіт", 0.1, Positive),
        ("весело", 0.2, Positive),
        ("гарний", 0.2, Positive),
        ("гарна", 0.2, Positive),
        ("горджуся", 0.2, Positive),
        ("надія", 0.3, Positive),
        ("вдячний", 0.3, Positive),
        ("вдячна", 0.3, Positive),
        ("задоволений", 0.2, Positive),
        ("задоволена", 0.2, Positive),
        ("натхненний", 0.2, Positive),
        ("натхненна", 0.2, Positive),
        ("спокійний", 0.2, Positive),
        ("спокійна", 0.2, Positive),
        ("впевнений", 0.2, Positive),
        ("впевнена", 0.2, Positive),
        ("сильний", 0.2, Positive),
        ("сильна", 0.2, Positive),
        ("щирий", 0.1, Positive),
        ("теплий", 0.1, Positive),
        ("тепла", 0.1, Positive),
        ("вільний", 0.1, Positive),
        ("сміливий", 0.2, Positive),
        ("сміливо", 0.2, Positive),
        ("ненавиджу", 0.4, Negative),
        ("сумно", 0.3, Negative),
        ("злий", 0.3, Negative),
        ("зла", 0.3, Negative),
        ("жахливо", 0.4, Negative),
        ("погано", 0.3, Negative),
        ("найгірший", 0.4, Negative),
        ("огидно", 0.4, Negative),
        ("противно", 0.3, Negative),
        ("тупо", 0.3, Negative),
        ("депресія", 0.4, Negative),
        ("самотній", 0.3, Negative),
        ("самотня", 0.3, Negative),
        ("боюся", 0.3, Negative),
        ("хвилююся", 0.2, Negative),
        ("плачу", 0.3, Negative),
        ("безнадійно", 0.4, Negative),
        ("нікчемний", 0.4, Negative),
        ("нещасний", 0.4, Negative),
        ("тривожний", 0.3, Negative),
        ("тривожна", 0.3, Negative),
        ("нервовий", 0.2, Negative),
        ("нервова", 0.2, Negative),
        ("розчарований", 0.3, Negative),
        ("розчарована", 0.3, Negative),
        ("принижений", 0.4, Negative),
        ("принижена", 0.4, Negative),
        ("відкинутий", 0.3, Negative),
        ("відкинута", 0.3, Negative),
        ("зраджений", 0.4, Negative),
        ("зраджена", 0.4, Negative),
        ("загнаний", 0.4, Negative),
        ("загнана", 0.4, Negative),
        ("знищений", 0.4, Negative),
        ("знищена", 0.4, Negative),
        ("зламаний", 0.4, Negative),
        ("зламана", 0.4, Negative),
        ("порожній", 0.3, Negative),
        ("порожня", 0.3, Negative),
        ("нечутний", 0.3, Negative),
        ("невидимий", 0.3, Negative),
        ("невидима", 0.3, Negative),
        ("покинутий", 0.4, Negative),
        ("покинута", 0.4, Negative),
        ("счастливый", 0.3, Positive),
        ("счастливая", 0.3, Positive),
        ("отлично", 0.3, Positive),
        ("классно", 0.2, Positive),
        ("хорошо", 0.2, Positive),
        ("спасибо", 0.3, Positive),
        ("радуюсь", 0.2, Positive),
        ("горжусь", 0.2, Positive),
        ("надежда", 0.3, Positive),
        ("благодарен", 0.3, Positive),
        ("доволен", 0.2, Positive),
        ("рад", 0.2, Positive),
        ("красивый", 0.2, Positive),
        ("красивая", 0.2, Positive),
        ("замечательно", 0.3, Positive),
        ("обожаю", 0.3, Positive),
        ("восхитительно", 0.3, Positive),
        ("великолепно", 0.3, Positive),
        ("потрясающе", 0.3, Positive),
        ("превосходно", 0.3, Positive),
        ("чудесно", 0.3, Positive),
        ("изумительно", 0.3, Positive),
        ("удивительно", 0.3, Positive),
        ("благодарна", 0.3, Positive),
        ("довольна", 0.2, Positive),
        ("радостный", 0.2, Positive),
        ("радостная", 0.2, Positive),
        ("веселый", 0.2, Positive),
        ("веселая", 0.2, Positive),
        ("вдохновлен", 0.2, Positive),
        ("вдохновлена", 0.2, Positive),
        ("восторг", 0.3, Positive),
        ("приятно", 0.2, Positive),
        ("прикольно", 0.2, Positive),
        ("милый", 0.2, Positive),
        ("милая", 0.2, Positive),
        ("уютно", 0.2, Positive),
        ("нежный", 0.1, Positive),
        ("ласковый", 0.1, Positive),
        ("улыбка", 0.2, Positive),
        ("мечта", 0.2, Positive),
        ("забота", 0.2, Positive),
        ("ненавижу", 0.4, Negative),
        ("грустно", 0.3, Negative),
        ("злой", 0.3, Negative),
        ("злая", 0.3, Negative),
        ("ужасно", 0.4, Negative),
        ("плохо", 0.3, Negative),
        ("отвратительно", 0.4, Negative),
        ("депрессия", 0.4, Negative),
        ("одинокий", 0.3, Negative),
        ("одинокая", 0.3, Negative),
        ("боюсь", 0.3, Negative),
        ("безнадежно", 0.4, Negative),
        ("ничтожный", 0.4, Negative),
        ("несчастный", 0.4, Negative),
        ("сломан", 0.4, Negative),
        ("пустота", 0.3, Negative),
        ("брошен", 0.4, Negative),
        ("брошена", 0.4, Negative),
        ("несчастная", 0.4, Negative),
        ("тоскливо", 0.3, Negative),
        ("печально", 0.3, Negative),
        ("подавлен", 0.4, Negative),
        ("подавлена", 0.4, Negative),
        ("тревога", 0.3, Negative),
        ("страх", 0.3, Negative),
        ("обида", 0.3, Negative),
        ("горе", 0.4, Negative),
        ("тоска", 0.3, Negative),
        ("страдание", 0.4, Negative),
        ("мучение", 0.4, Negative),
        ("безысходность", 0.4, Negative),
        ("бессилие", 0.4, Negative),
        ("отчаяние", 0.4, Negative),
        ("жалко", 0.3, Negative),
        ("обидно", 0.3, Negative),
        ("больно", 0.3, Negative),
        ("кошмар", 0.4, Negative),
        ("раздражает", 0.3, Negative),
        ("бесит", 0.3, Negative),
        ("разочарование", 0.3, Negative),
        ("паника", 0.3, Negative),
    ];

    let patterns: Vec<&str> = all.iter().map(|(w, _, _)| *w).collect();
    let entries: Vec<SentimentFallbackEntry> = all
        .iter()
        .map(|(_, weight, polarity)| SentimentFallbackEntry {
            polarity: *polarity,
            weight: *weight,
        })
        .collect();

    let automaton = AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(&patterns)
        .expect("sentiment AhoCorasick build");

    SentimentFallbackMatcher { automaton, entries }
}

#[derive(Debug, thiserror::Error)]
pub enum SentimentError {
    #[error("Failed to load sentiment model: {0}")]
    ModelLoadFailed(String),
    #[error("Sentiment inference failed: {0}")]
    InferenceFailed(String),
}

impl crate::backend::SentimentBackend for SentimentAnalyzer {
    fn predict(&self, text: &str) -> Option<SentimentPrediction> {
        Some(self.predict_fallback(text))
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
    use crate::types::SentimentLabel;

    #[test]
    fn fallback_positive_english() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("I'm so happy and excited! This is amazing!")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Positive);
        assert!(pred.positive > pred.negative);
    }

    #[test]
    fn fallback_negative_english() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("I hate everything, this is terrible and awful")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
        assert!(pred.negative > pred.positive);
    }

    #[test]
    fn fallback_positive_ukrainian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer.predict("Чудово! Я так щасливий, дякую!").unwrap();
        assert_eq!(pred.label, SentimentLabel::Positive);
    }

    #[test]
    fn fallback_negative_ukrainian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("Ненавиджу все, жахливо, мені сумно")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
    }

    #[test]
    fn fallback_neutral_message() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("The meeting is at 3pm in room 204")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Neutral);
    }

    #[test]
    fn fallback_mixed_signals() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("I love the weather but hate the traffic")
            .unwrap();

        assert!(pred.positive > 0.0);
        assert!(pred.negative > 0.0);
    }

    #[test]
    fn fallback_positive_russian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer.predict("Отлично! Я счастливый, спасибо!").unwrap();
        assert_eq!(pred.label, SentimentLabel::Positive);
        assert!(pred.positive > pred.negative);
    }

    #[test]
    fn fallback_negative_russian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("Ненавижу все, ужасно, мне грустно")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
        assert!(pred.negative > pred.positive);
    }

    #[test]
    fn fallback_hopelessness_english() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("I feel empty and broken inside, so helpless")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
        assert!(pred.negative > 0.3);
    }

    #[test]
    fn fallback_hopelessness_ukrainian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer.predict("Я зламана і порожня всередині").unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
        assert!(pred.negative > pred.positive);
    }

    #[test]
    fn fallback_anxiety_english() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("I'm terrified and overwhelmed, feeling so anxious")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
    }

    #[test]
    fn fallback_anxiety_ukrainian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("Я тривожна і загнана, мені нервово")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
    }

    #[test]
    fn fallback_rejection_words() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("I feel abandoned, rejected, unwanted by everyone")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
        assert!(pred.negative > 0.4);
    }

    #[test]
    fn fallback_positive_strength_words() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("I feel brave and strong, hopeful about the future")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Positive);
    }

    #[test]
    fn fallback_neutral_factual_russian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer.predict("Встреча в 15:00 в кабинете 204").unwrap();
        assert_eq!(pred.label, SentimentLabel::Neutral);
    }

    #[test]
    fn fallback_expanded_positive_russian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("Обожаю! Восхитительно и потрясающе!")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Positive);
        assert!(pred.positive > pred.negative);
    }

    #[test]
    fn fallback_expanded_negative_russian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("Отчаяние и безысходность, больно и тоскливо")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Negative);
        assert!(pred.negative > pred.positive);
    }

    #[test]
    fn fallback_gratitude_ukrainian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("Я вдячний за підтримку, горджуся нашою командою")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Positive);
    }

    #[test]
    fn no_false_positive_funeral() {
        let mut a = SentimentAnalyzer::fallback_only();
        let pred = a.predict("The funeral service was dignified").unwrap();
        assert_eq!(
            pred.label,
            SentimentLabel::Neutral,
            "funeral should not trigger fun"
        );
    }

    #[test]
    fn no_false_positive_crystal() {
        let mut a = SentimentAnalyzer::fallback_only();
        let pred = a.predict("The crystal was perfectly transparent").unwrap();
        assert_eq!(
            pred.label,
            SentimentLabel::Neutral,
            "crystal should not trigger cry"
        );
    }

    #[test]
    fn no_false_positive_saddle() {
        let mut a = SentimentAnalyzer::fallback_only();
        let pred = a.predict("Put the saddle on the horse").unwrap();
        assert_eq!(
            pred.label,
            SentimentLabel::Neutral,
            "saddle should not trigger sad"
        );
    }

    #[test]
    fn negation_not_happy_not_positive() {
        let mut a = SentimentAnalyzer::fallback_only();
        let pred = a.predict("I'm not happy about this").unwrap();
        assert_ne!(
            pred.label,
            SentimentLabel::Positive,
            "Negated positive should not be positive"
        );
    }

    #[test]
    fn negation_not_sad_not_strongly_negative() {
        let mut a = SentimentAnalyzer::fallback_only();
        let pred = a.predict("I'm not sad actually").unwrap();
        assert!(
            pred.negative < 0.4,
            "Negated negative should have low negative score: {}",
            pred.negative
        );
    }

    #[test]
    fn negation_ukrainian_not_positive() {
        let mut a = SentimentAnalyzer::fallback_only();
        let pred = a.predict("Я не щасливий сьогодні").unwrap();
        assert_ne!(
            pred.label,
            SentimentLabel::Positive,
            "Ukrainian negated positive should not be positive"
        );
    }

    #[test]
    fn no_negation_direct_positive() {
        let mut a = SentimentAnalyzer::fallback_only();
        let pred = a.predict("I'm so happy and excited!").unwrap();
        assert_eq!(
            pred.label,
            SentimentLabel::Positive,
            "Direct positive should stay positive"
        );
    }
}
