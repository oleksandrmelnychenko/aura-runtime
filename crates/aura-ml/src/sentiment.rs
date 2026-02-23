use tracing::debug;

#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::types::SentimentPrediction;

pub struct SentimentAnalyzer {
    #[cfg(feature = "onnx")]
    session: Option<ort::session::Session>,
    #[cfg(feature = "onnx")]
    tokenizer: Option<WordPieceTokenizer>,
    fallback_enabled: bool,
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
        let tokenizer = self.tokenizer.as_ref().unwrap();
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

        let session = self.session.as_mut().unwrap();
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

        let positive_en = [
            ("love", 0.3),
            ("happy", 0.3),
            ("great", 0.3),
            ("amazing", 0.3),
            ("wonderful", 0.3),
            ("beautiful", 0.3),
            ("awesome", 0.3),
            ("good", 0.2),
            ("nice", 0.2),
            ("thanks", 0.2),
            ("thank you", 0.3),
            ("excellent", 0.3),
            ("perfect", 0.3),
            ("best", 0.2),
            ("excited", 0.3),
            ("glad", 0.2),
            ("joy", 0.3),
            ("fun", 0.2),
            ("cool", 0.2),
            ("fantastic", 0.3),
            ("brilliant", 0.3),
            ("lol", 0.1),
            ("haha", 0.1),
            ("😊", 0.2),
            ("❤️", 0.2),
            ("proud", 0.2),
            ("hopeful", 0.3),
            ("grateful", 0.3),
            ("thankful", 0.3),
            ("confident", 0.2),
            ("cheerful", 0.3),
            ("delighted", 0.3),
            ("pleased", 0.2),
            ("thrilled", 0.3),
            ("ecstatic", 0.3),
            ("blessed", 0.2),
            ("inspired", 0.2),
            ("optimistic", 0.2),
            ("peaceful", 0.2),
            ("relieved", 0.2),
            ("satisfied", 0.2),
            ("comfortable", 0.1),
            ("safe", 0.1),
            ("warm", 0.1),
            ("welcome", 0.2),
            ("supported", 0.2),
            ("valued", 0.2),
            ("appreciated", 0.2),
            ("accepted", 0.2),
            ("free", 0.1),
            ("strong", 0.2),
            ("brave", 0.2),
            ("courageous", 0.2),
            ("kind", 0.1),
            ("generous", 0.2),
        ];

        let negative_en = [
            ("hate", 0.4),
            ("sad", 0.3),
            ("angry", 0.3),
            ("terrible", 0.4),
            ("awful", 0.4),
            ("horrible", 0.4),
            ("worst", 0.4),
            ("bad", 0.2),
            ("ugly", 0.3),
            ("disgusting", 0.4),
            ("annoying", 0.2),
            ("stupid", 0.3),
            ("boring", 0.2),
            ("depressed", 0.4),
            ("lonely", 0.3),
            ("scared", 0.3),
            ("worried", 0.2),
            ("upset", 0.3),
            ("cry", 0.3),
            ("crying", 0.3),
            ("hopeless", 0.4),
            ("worthless", 0.4),
            ("miserable", 0.4),
            ("anxious", 0.3),
            ("nervous", 0.2),
            ("afraid", 0.3),
            ("terrified", 0.4),
            ("furious", 0.4),
            ("frustrated", 0.3),
            ("devastated", 0.4),
            ("heartbroken", 0.4),
            ("ashamed", 0.3),
            ("embarrassed", 0.2),
            ("humiliated", 0.4),
            ("rejected", 0.3),
            ("abandoned", 0.4),
            ("betrayed", 0.4),
            ("trapped", 0.4),
            ("suffocated", 0.4),
            ("overwhelmed", 0.3),
            ("exhausted", 0.2),
            ("numb", 0.3),
            ("empty", 0.3),
            ("broken", 0.4),
            ("shattered", 0.4),
            ("crushed", 0.4),
            ("defeated", 0.3),
            ("helpless", 0.4),
            ("powerless", 0.4),
            ("useless", 0.4),
            ("invisible", 0.3),
            ("forgotten", 0.3),
            ("ignored", 0.3),
            ("alone", 0.3),
            ("isolated", 0.3),
            ("unwanted", 0.4),
            ("unloved", 0.4),
            ("unworthy", 0.4),
        ];

        let positive_uk = [
            ("кохаю", 0.3),
            ("люблю", 0.3),
            ("щасливий", 0.3),
            ("щаслива", 0.3),
            ("чудово", 0.3),
            ("прекрасно", 0.3),
            ("супер", 0.3),
            ("класно", 0.2),
            ("добре", 0.2),
            ("дякую", 0.3),
            ("файно", 0.2),
            ("красиво", 0.2),
            ("найкращий", 0.3),
            ("радий", 0.2),
            ("рада", 0.2),
            ("привіт", 0.1),
            ("весело", 0.2),
            ("гарний", 0.2),
            ("гарна", 0.2),
            ("горджуся", 0.2),
            ("надія", 0.3),
            ("вдячний", 0.3),
            ("вдячна", 0.3),
            ("задоволений", 0.2),
            ("задоволена", 0.2),
            ("натхненний", 0.2),
            ("натхненна", 0.2),
            ("спокійний", 0.2),
            ("спокійна", 0.2),
            ("впевнений", 0.2),
            ("впевнена", 0.2),
            ("сильний", 0.2),
            ("сильна", 0.2),
            ("щирий", 0.1),
            ("теплий", 0.1),
            ("тепла", 0.1),
            ("вільний", 0.1),
            ("сміливий", 0.2),
            ("сміливо", 0.2),
        ];

        let negative_uk = [
            ("ненавиджу", 0.4),
            ("сумно", 0.3),
            ("злий", 0.3),
            ("зла", 0.3),
            ("жахливо", 0.4),
            ("погано", 0.3),
            ("найгірший", 0.4),
            ("огидно", 0.4),
            ("противно", 0.3),
            ("тупо", 0.3),
            ("депресія", 0.4),
            ("самотній", 0.3),
            ("самотня", 0.3),
            ("боюся", 0.3),
            ("хвилююся", 0.2),
            ("плачу", 0.3),
            ("безнадійно", 0.4),
            ("нікчемний", 0.4),
            ("нещасний", 0.4),
            ("тривожний", 0.3),
            ("тривожна", 0.3),
            ("нервовий", 0.2),
            ("нервова", 0.2),
            ("розчарований", 0.3),
            ("розчарована", 0.3),
            ("принижений", 0.4),
            ("принижена", 0.4),
            ("відкинутий", 0.3),
            ("відкинута", 0.3),
            ("зраджений", 0.4),
            ("зраджена", 0.4),
            ("загнаний", 0.4),
            ("загнана", 0.4),
            ("знищений", 0.4),
            ("знищена", 0.4),
            ("зламаний", 0.4),
            ("зламана", 0.4),
            ("порожній", 0.3),
            ("порожня", 0.3),
            ("нечутний", 0.3),
            ("невидимий", 0.3),
            ("невидима", 0.3),
            ("покинутий", 0.4),
            ("покинута", 0.4),
        ];

        let positive_ru: &[(&str, f32)] = &[
            ("счастливый", 0.3),
            ("счастливая", 0.3),
            ("отлично", 0.3),
            ("прекрасно", 0.3),
            ("классно", 0.2),
            ("хорошо", 0.2),
            ("спасибо", 0.3),
            ("радуюсь", 0.2),
            ("горжусь", 0.2),
            ("надежда", 0.3),
            ("благодарен", 0.3),
            ("доволен", 0.2),
            ("рад", 0.2),
            ("весело", 0.2),
            ("красивый", 0.2),
            ("красивая", 0.2),
            ("замечательно", 0.3),
        ];

        let negative_ru: &[(&str, f32)] = &[
            ("ненавижу", 0.4),
            ("грустно", 0.3),
            ("злой", 0.3),
            ("злая", 0.3),
            ("ужасно", 0.4),
            ("плохо", 0.3),
            ("отвратительно", 0.4),
            ("тупо", 0.3),
            ("депрессия", 0.4),
            ("одинокий", 0.3),
            ("одинокая", 0.3),
            ("боюсь", 0.3),
            ("безнадежно", 0.4),
            ("ничтожный", 0.4),
            ("несчастный", 0.4),
            ("сломан", 0.4),
            ("пустота", 0.3),
            ("брошен", 0.4),
            ("брошена", 0.4),
        ];

        for (word, score) in positive_en
            .iter()
            .chain(positive_uk.iter())
            .chain(positive_ru.iter())
        {
            if lower.contains(word) {
                pos_score += score;
            }
        }

        for (word, score) in negative_en
            .iter()
            .chain(negative_uk.iter())
            .chain(negative_ru.iter())
        {
            if lower.contains(word) {
                neg_score += score;
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

#[derive(Debug, thiserror::Error)]
pub enum SentimentError {
    #[error("Failed to load sentiment model: {0}")]
    ModelLoadFailed(String),
    #[error("Sentiment inference failed: {0}")]
    InferenceFailed(String),
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
    fn fallback_gratitude_ukrainian() {
        let mut analyzer = SentimentAnalyzer::fallback_only();
        let pred = analyzer
            .predict("Я вдячний за підтримку, горджуся нашою командою")
            .unwrap();
        assert_eq!(pred.label, SentimentLabel::Positive);
    }
}
