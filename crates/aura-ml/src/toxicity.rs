use tracing::debug;
#[cfg(feature = "onnx")]
use tracing::warn;

#[cfg(feature = "onnx")]
use std::time::Instant;

#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::types::ToxicityPrediction;

pub struct ToxicityClassifier {
    #[cfg(feature = "onnx")]
    session: Option<ort::session::Session>,
    #[cfg(feature = "onnx")]
    tokenizer: Option<WordPieceTokenizer>,
    fallback_enabled: bool,
}

impl ToxicityClassifier {
    #[cfg(feature = "onnx")]
    pub fn with_model(model_path: &str, tokenizer: WordPieceTokenizer) -> Result<Self, MlError> {
        let session = ort::session::Session::builder()
            .map_err(|e| MlError::ModelLoadFailed(e.to_string()))?
            .with_intra_threads(1)
            .map_err(|e| MlError::ModelLoadFailed(e.to_string()))?
            .commit_from_file(model_path)
            .map_err(|e| MlError::ModelLoadFailed(e.to_string()))?;

        debug!("Toxicity ONNX model loaded from {model_path}");

        Ok(Self {
            session: Some(session),
            tokenizer: Some(tokenizer),
            fallback_enabled: true,
        })
    }

    pub fn fallback_only() -> Self {
        debug!("Toxicity classifier using rule-based fallback");
        Self {
            #[cfg(feature = "onnx")]
            session: None,
            #[cfg(feature = "onnx")]
            tokenizer: None,
            fallback_enabled: true,
        }
    }

    pub fn predict(&mut self, text: &str) -> Option<ToxicityPrediction> {
        #[cfg(feature = "onnx")]
        {
            let has_onnx = self.session.is_some() && self.tokenizer.is_some();
            if has_onnx {
                match self.predict_onnx(text) {
                    Ok(pred) => return Some(pred),
                    Err(e) => {
                        warn!("ONNX inference failed, falling back: {e}");
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
    fn predict_onnx(&mut self, text: &str) -> Result<ToxicityPrediction, MlError> {
        let start = Instant::now();

        let tokenizer = self.tokenizer.as_ref().unwrap();
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

        let session = self.session.as_mut().unwrap();
        let outputs = session
            .run(ort::inputs![input_ids, attention_mask, token_type_ids])
            .map_err(|e| MlError::InferenceFailed(e.to_string()))?;

        let (_shape, scores) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| MlError::InferenceFailed(e.to_string()))?;

        let elapsed = start.elapsed();
        debug!(elapsed_us = elapsed.as_micros(), "Toxicity ONNX inference");

        if scores.len() >= 6 {
            let mut pred = ToxicityPrediction {
                toxicity: sigmoid(scores[0]),

                severe_toxicity: sigmoid(scores[1]),

                sexual_explicit: sigmoid(scores[2]),

                threat: sigmoid(scores[3]),

                insult: sigmoid(scores[4]),

                identity_attack: sigmoid(scores[5]),

                primary_label: None,
            };
            pred.primary_label = pred.compute_primary_label(0.5);
            Ok(pred)
        } else {
            Err(MlError::InferenceFailed(format!(
                "Expected 6 output scores, got {}",
                scores.len()
            )))
        }
    }

    fn predict_fallback(&self, text: &str) -> ToxicityPrediction {
        let lower = text.to_lowercase();

        let mut insult = 0.0f32;
        let mut threat = 0.0f32;
        let mut sexual = 0.0f32;
        let mut profanity = 0.0f32;
        let mut drug = 0.0f32;
        let identity = 0.0f32;

        let insult_words_en = [
            ("stupid", 0.4),
            ("idiot", 0.5),
            ("moron", 0.5),
            ("loser", 0.4),
            ("pathetic", 0.4),
            ("worthless", 0.6),
            ("disgusting", 0.5),
            ("ugly", 0.4),
            ("fat", 0.3),
            ("dumb", 0.4),
            ("retard", 0.7),
            ("trash", 0.4),
            ("garbage", 0.3),
        ];

        let threat_words_en = [
            ("kill you", 0.9),
            ("hurt you", 0.7),
            ("beat you", 0.7),
            ("punch you", 0.6),
            ("i'll destroy you", 0.8),
            ("die", 0.3),
            ("murder", 0.8),
            ("stab", 0.8),
        ];

        let sexual_words_en = [
            ("nude", 0.6),
            ("naked", 0.5),
            ("porn", 0.7),
            ("boobs", 0.4),
            ("blowjob", 0.6),
            ("handjob", 0.6),
            ("cumshot", 0.7),
            ("orgasm", 0.4),
            ("sexting", 0.6),
            ("sext", 0.6),
            ("dick pic", 0.7),
            ("nudes", 0.6),
            ("strip", 0.5),
            ("twerk", 0.3),
            ("onlyfans", 0.5),
            ("webcam girl", 0.6),
            ("webcam show", 0.6),
            ("send pics", 0.4),
            ("show me more", 0.4),
            ("take it off", 0.5),
            ("what are you wearing", 0.4),
            ("hot body", 0.4),
            ("sexy photo", 0.5),
        ];

        let profanity_en = [
            ("fuck", 0.6),
            ("fucking", 0.6),
            ("fucker", 0.65),
            ("motherfucker", 0.7),
            ("shit", 0.5),
            ("shitty", 0.5),
            ("bullshit", 0.5),
            ("bitch", 0.55),
            ("bitches", 0.55),
            ("asshole", 0.55),
            ("dick", 0.5),
            ("dickhead", 0.55),
            ("cock", 0.5),
            ("cocksucker", 0.65),
            ("pussy", 0.5),
            ("cunt", 0.65),
            ("wanker", 0.5),
            ("twat", 0.5),
            ("whore", 0.6),
            ("slut", 0.6),
            ("bastard", 0.5),
            ("douchebag", 0.5),
            ("prick", 0.5),
            ("bellend", 0.5),
            ("tosser", 0.45),
            ("bollocks", 0.45),
            ("piss off", 0.45),
            ("scumbag", 0.55),
            ("son of a bitch", 0.6),
        ];

        let insult_words_uk = [
            ("дурний", 0.4),
            ("дура", 0.4),
            ("ідіот", 0.5),
            ("тупий", 0.5),
            ("тупа", 0.5),
            ("лузер", 0.4),
            ("потворний", 0.5),
            ("покидьок", 0.6),
            ("виродок", 0.6),
            ("нікчема", 0.5),
            ("дебіл", 0.6),
            ("придурок", 0.5),
            ("кретин", 0.5),
            ("жалюгідний", 0.4),
        ];

        let threat_words_uk = [
            ("вб'ю", 0.9),
            ("вбию", 0.9),
            ("уб'ю", 0.9),
            ("убию", 0.9),
            ("поб'ю", 0.7),
            ("побью", 0.7),
            ("зламаю тебе", 0.7),
            ("знищу", 0.7),
            ("покалічу", 0.8),
            ("здохни", 0.8),
        ];

        let sexual_words_uk = [
            ("голий", 0.4),
            ("гола", 0.4),
            ("секс", 0.4),
            ("порно", 0.7),
            ("секстинг", 0.6),
            ("голе фото", 0.6),
            ("інтимне фото", 0.6),
            ("роздягнись", 0.5),
            ("покажи тіло", 0.5),
            ("вебкам", 0.6),
            ("надішли фотку без одягу", 0.7),
            ("що на тобі наділо", 0.4),
            ("гаряче тіло", 0.4),
            ("сексуальне фото", 0.5),
        ];

        let profanity_uk = [
            ("хуй", 0.7),
            ("хуйня", 0.65),
            ("хуйло", 0.7),
            ("нахуй", 0.7),
            ("похуй", 0.65),
            ("охуїти", 0.65),
            ("охуєти", 0.65),
            ("охуєнно", 0.6),
            ("захуярити", 0.65),
            ("хуярити", 0.65),
            ("хуйовий", 0.6),
            ("хуйово", 0.6),
            ("хуєсос", 0.7),
            ("хуєплет", 0.65),
            ("пізда", 0.7),
            ("піздець", 0.65),
            ("піздатий", 0.5),
            ("піздюк", 0.65),
            ("піздюлі", 0.6),
            ("спіздити", 0.6),
            ("розпіздяй", 0.6),
            ("піздобол", 0.65),
            ("піздити", 0.6),
            ("блять", 0.6),
            ("бля", 0.5),
            ("блядь", 0.65),
            ("блядський", 0.6),
            ("блядство", 0.6),
            ("блядина", 0.65),
            ("блядюга", 0.65),
            ("бляха", 0.4),
            ("єбати", 0.7),
            ("їбати", 0.7),
            ("єбаний", 0.7),
            ("їбаний", 0.7),
            ("єбанутий", 0.65),
            ("їбанутий", 0.65),
            ("єбашити", 0.65),
            ("їбашити", 0.65),
            ("заєбали", 0.65),
            ("заїбали", 0.65),
            ("заєбись", 0.55),
            ("заїбись", 0.55),
            ("виїбати", 0.7),
            ("наїбати", 0.65),
            ("наїбалово", 0.6),
            ("підїбати", 0.6),
            ("доїбатись", 0.6),
            ("їбучий", 0.65),
            ("їбуча", 0.65),
            ("їбаний в рот", 0.75),
            ("їб твою мать", 0.75),
            ("сука", 0.6),
            ("сучка", 0.6),
            ("сучара", 0.65),
            ("падлюка", 0.6),
            ("падла", 0.55),
            ("падло", 0.55),
            ("стерва", 0.5),
            ("шльондра", 0.6),
            ("курва", 0.65),
            ("потаскуха", 0.6),
            ("шалава", 0.6),
            ("мудак", 0.65),
            ("мудила", 0.65),
            ("мудозвон", 0.6),
            ("гандон", 0.65),
            ("гондон", 0.65),
            ("підарас", 0.7),
            ("підар", 0.65),
            ("педик", 0.65),
            ("педрила", 0.65),
            ("гнида", 0.55),
            ("гнидота", 0.55),
            ("довбойоб", 0.65),
            ("довбоїб", 0.65),
            ("ублюдок", 0.6),
            ("виблядок", 0.65),
            ("дрочити", 0.5),
            ("задрот", 0.45),
            ("залупа", 0.55),
            ("засранець", 0.5),
            ("засрати", 0.5),
            ("пішов нахуй", 0.75),
            ("пішла нахуй", 0.75),
            ("іди нахуй", 0.75),
            ("йди нахуй", 0.75),
            ("їбись конем", 0.8),
            ("сука блять", 0.7),
        ];

        let profanity_ru = [
            ("хуй", 0.7),
            ("хуйня", 0.65),
            ("хуйло", 0.7),
            ("нахуй", 0.7),
            ("похуй", 0.65),
            ("охуеть", 0.65),
            ("охуенно", 0.6),
            ("хуярить", 0.65),
            ("хуесос", 0.7),
            ("пизда", 0.7),
            ("пиздец", 0.65),
            ("пиздюк", 0.65),
            ("спиздить", 0.6),
            ("распиздяй", 0.6),
            ("пиздобол", 0.65),
            ("блять", 0.6),
            ("бля", 0.5),
            ("блядь", 0.65),
            ("блядский", 0.6),
            ("блядина", 0.65),
            ("блядюга", 0.65),
            ("ебать", 0.7),
            ("ебаный", 0.7),
            ("ебанутый", 0.65),
            ("ебашить", 0.65),
            ("заебал", 0.65),
            ("заебали", 0.65),
            ("заебись", 0.55),
            ("выебать", 0.7),
            ("наебать", 0.65),
            ("наебалово", 0.6),
            ("ёбаный", 0.7),
            ("ёб твою мать", 0.75),
            ("сука", 0.6),
            ("сучка", 0.6),
            ("сучара", 0.65),
            ("падла", 0.55),
            ("падлюка", 0.6),
            ("стерва", 0.5),
            ("шалава", 0.6),
            ("шлюха", 0.6),
            ("курва", 0.65),
            ("мудак", 0.65),
            ("мудила", 0.65),
            ("мудозвон", 0.6),
            ("гандон", 0.65),
            ("гондон", 0.65),
            ("пидор", 0.7),
            ("пидорас", 0.7),
            ("педик", 0.65),
            ("педрила", 0.65),
            ("гнида", 0.55),
            ("долбоёб", 0.65),
            ("ублюдок", 0.6),
            ("выблядок", 0.65),
            ("дрочить", 0.5),
            ("задрот", 0.45),
            ("засранец", 0.5),
            ("говно", 0.5),
            ("говнюк", 0.55),
            ("херня", 0.45),
            ("херово", 0.45),
            ("иди нахуй", 0.75),
            ("пошёл нахуй", 0.75),
            ("пошла нахуй", 0.75),
        ];

        let drug_words_en: &[(&str, f32)] = &[
            ("cocaine", 0.6),
            ("heroin", 0.7),
            ("meth", 0.7),
            ("crack", 0.6),
            ("fentanyl", 0.7),
            ("overdose", 0.6),
            ("amphetamine", 0.6),
            ("ecstasy", 0.5),
            ("mdma", 0.5),
        ];
        let drug_words_uk: &[(&str, f32)] = &[
            ("кокаїн", 0.6),
            ("героїн", 0.7),
            ("метамфетамін", 0.7),
            ("передозування", 0.6),
            ("амфетамін", 0.6),
            ("екстазі", 0.5),
        ];

        for (word, score) in insult_words_en.iter().chain(insult_words_uk.iter()) {
            if lower.contains(word) {
                insult = insult.max(*score);
            }
        }

        for (word, score) in threat_words_en.iter().chain(threat_words_uk.iter()) {
            if lower.contains(word) {
                threat = threat.max(*score);
            }
        }

        for (word, score) in sexual_words_en.iter().chain(sexual_words_uk.iter()) {
            if lower.contains(word) {
                sexual = sexual.max(*score);
            }
        }

        for (word, score) in profanity_en
            .iter()
            .chain(profanity_uk.iter())
            .chain(profanity_ru.iter())
        {
            if lower.contains(word) {
                profanity = profanity.max(*score);
            }
        }

        for (word, score) in drug_words_en.iter().chain(drug_words_uk.iter()) {
            if lower.contains(word) {
                drug = drug.max(*score);
            }
        }

        let toxicity = insult
            .max(threat)
            .max(sexual)
            .max(identity)
            .max(profanity)
            .max(drug);

        let severe = if threat >= 0.7 || insult >= 0.7 || profanity >= 0.7 {
            (threat.max(profanity) + insult) / 2.0
        } else {
            0.0
        };

        let mut pred = ToxicityPrediction {
            toxicity,
            severe_toxicity: severe,
            identity_attack: identity,
            insult,
            sexual_explicit: sexual,
            threat,
            primary_label: None,
        };
        pred.primary_label = pred.compute_primary_label(0.4);
        pred
    }
}

#[allow(dead_code)]
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[derive(Debug, thiserror::Error)]
pub enum MlError {
    #[error("Failed to load model: {0}")]
    ModelLoadFailed(String),
    #[error("Inference failed: {0}")]
    InferenceFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_detects_english_insults() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier
            .predict("You're so stupid and worthless")
            .unwrap();
        assert!(pred.toxicity >= 0.4);
        assert!(pred.insult >= 0.4);
    }

    #[test]
    fn fallback_detects_english_threats() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("I will kill you").unwrap();
        assert!(pred.toxicity >= 0.8);
        assert!(pred.threat >= 0.8);
    }

    #[test]
    fn fallback_detects_ukrainian_insults() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("Ти тупий дебіл").unwrap();
        assert!(pred.toxicity >= 0.5);
        assert!(pred.insult >= 0.5);
    }

    #[test]
    fn fallback_detects_ukrainian_threats() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("Я тебе вб'ю, здохни").unwrap();
        assert!(pred.toxicity >= 0.8);
        assert!(pred.threat >= 0.8);
    }

    #[test]
    fn fallback_clean_message() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier
            .predict("Привіт, як справи? Гарний день!")
            .unwrap();
        assert!(
            pred.toxicity < 0.1,
            "Clean message should have low toxicity, got {}",
            pred.toxicity
        );
    }

    #[test]
    fn fallback_sexual_content() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("Send me nude photos").unwrap();
        assert!(pred.sexual_explicit >= 0.5);
    }

    #[test]
    fn primary_label_correct() {
        let mut classifier = ToxicityClassifier::fallback_only();

        let pred = classifier.predict("I will kill you").unwrap();
        assert_eq!(
            pred.primary_label,
            Some(crate::types::ToxicityLabel::Threat)
        );

        let pred = classifier.predict("You're a worthless idiot").unwrap();
        assert_eq!(
            pred.primary_label,
            Some(crate::types::ToxicityLabel::Insult)
        );
    }

    #[test]
    fn fallback_detects_sexting_english() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier
            .predict("send nudes, show me your sexy photo")
            .unwrap();
        assert!(
            pred.sexual_explicit >= 0.5,
            "Sexting should be detected: {}",
            pred.sexual_explicit
        );
    }

    #[test]
    fn fallback_detects_sexting_ukrainian() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("надішли голе фото, роздягнись").unwrap();
        assert!(
            pred.sexual_explicit >= 0.5,
            "UA sexting should be detected: {}",
            pred.sexual_explicit
        );
    }

    #[test]
    fn fallback_detects_drug_terminology_en() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier
            .predict("I have cocaine and heroin for sale")
            .unwrap();
        assert!(
            pred.toxicity >= 0.5,
            "Drug terminology should boost toxicity: {}",
            pred.toxicity
        );
    }

    #[test]
    fn fallback_detects_drug_terminology_uk() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("Є кокаїн та героїн").unwrap();
        assert!(
            pred.toxicity >= 0.5,
            "UA drug terminology should boost toxicity: {}",
            pred.toxicity
        );
    }

    #[test]
    fn fallback_clean_medical_text() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier
            .predict("Patient reported no history of issues")
            .unwrap();
        assert!(
            pred.toxicity < 0.2,
            "Clean medical text should have low toxicity: {}",
            pred.toxicity
        );
    }
}
