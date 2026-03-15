use aho_corasick::AhoCorasick;
use tracing::debug;
#[cfg(feature = "onnx")]
use tracing::warn;

#[cfg(feature = "onnx")]
use std::time::Instant;

#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::types::ToxicityPrediction;

#[derive(Clone, Copy)]
enum ToxCategory {
    Insult,
    Threat,
    Sexual,
    Profanity,
    Drug,
}

struct FallbackEntry {
    category: ToxCategory,
    score: f32,
}

struct FallbackMatcher {
    automaton: AhoCorasick,
    entries: Vec<FallbackEntry>,
}

pub struct ToxicityClassifier {
    #[cfg(feature = "onnx")]
    session: Option<ort::session::Session>,
    #[cfg(feature = "onnx")]
    tokenizer: Option<WordPieceTokenizer>,
    fallback_enabled: bool,
    fallback_matcher: Option<FallbackMatcher>,
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
            fallback_matcher: Some(Self::build_fallback_matcher()),
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
            fallback_matcher: Some(Self::build_fallback_matcher()),
        }
    }

    pub fn predict(&mut self, text: &str) -> Option<ToxicityPrediction> {
        self.predict_with_runtime(text)
    }

    fn predict_with_runtime(&mut self, text: &str) -> Option<ToxicityPrediction> {
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

        let tokenizer = self
            .tokenizer
            .as_ref()
            .expect("predict_onnx only used when ONNX loaded");
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
            .expect("predict_onnx only used when ONNX loaded");
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

    fn build_fallback_matcher() -> FallbackMatcher {
        use ToxCategory::*;

        let all_patterns: Vec<(&str, ToxCategory, f32)> = vec![
            ("stupid", Insult, 0.4),
            ("idiot", Insult, 0.5),
            ("moron", Insult, 0.5),
            ("loser", Insult, 0.4),
            ("pathetic", Insult, 0.4),
            ("worthless", Insult, 0.6),
            ("disgusting", Insult, 0.5),
            ("ugly", Insult, 0.4),
            ("fat", Insult, 0.3),
            ("dumb", Insult, 0.4),
            ("retard", Insult, 0.7),
            ("trash", Insult, 0.4),
            ("garbage", Insult, 0.3),
            ("дурний", Insult, 0.4),
            ("дура", Insult, 0.4),
            ("ідіот", Insult, 0.5),
            ("тупий", Insult, 0.5),
            ("тупа", Insult, 0.5),
            ("лузер", Insult, 0.4),
            ("потворний", Insult, 0.5),
            ("покидьок", Insult, 0.6),
            ("виродок", Insult, 0.6),
            ("нікчема", Insult, 0.5),
            ("дебіл", Insult, 0.6),
            ("придурок", Insult, 0.5),
            ("кретин", Insult, 0.5),
            ("жалюгідний", Insult, 0.4),
            ("дурак", Insult, 0.4),
            ("идиот", Insult, 0.5),
            ("идиотка", Insult, 0.5),
            ("тупой", Insult, 0.5),
            ("тупая", Insult, 0.5),
            ("ничтожество", Insult, 0.5),
            ("уродина", Insult, 0.5),
            ("урод", Insult, 0.5),
            ("дебил", Insult, 0.6),
            ("дебилка", Insult, 0.6),
            ("кретинка", Insult, 0.5),
            ("тварь", Insult, 0.6),
            ("быдло", Insult, 0.5),
            ("лох", Insult, 0.4),
            ("лохушка", Insult, 0.4),
            ("чмо", Insult, 0.6),
            ("чмошник", Insult, 0.6),
            ("отстой", Insult, 0.4),
            ("отброс", Insult, 0.5),
            ("ничтожный", Insult, 0.5),
            ("kill you", Threat, 0.9),
            ("hurt you", Threat, 0.7),
            ("beat you", Threat, 0.7),
            ("punch you", Threat, 0.6),
            ("i'll destroy you", Threat, 0.8),
            ("die", Threat, 0.3),
            ("murder", Threat, 0.8),
            ("stab", Threat, 0.8),
            ("вб'ю", Threat, 0.9),
            ("вбию", Threat, 0.9),
            ("уб'ю", Threat, 0.9),
            ("убию", Threat, 0.9),
            ("поб'ю", Threat, 0.7),
            ("побью", Threat, 0.7),
            ("зламаю тебе", Threat, 0.7),
            ("знищу", Threat, 0.7),
            ("покалічу", Threat, 0.8),
            ("здохни", Threat, 0.8),
            ("убью тебя", Threat, 0.9),
            ("убью", Threat, 0.8),
            ("прибью", Threat, 0.7),
            ("сдохни", Threat, 0.8),
            ("подохни", Threat, 0.8),
            ("зарежу", Threat, 0.8),
            ("задушу", Threat, 0.8),
            ("уничтожу", Threat, 0.7),
            ("изобью", Threat, 0.7),
            ("покалечу", Threat, 0.8),
            ("пристрелю", Threat, 0.8),
            ("башку оторву", Threat, 0.8),
            ("закопаю", Threat, 0.7),
            ("порву", Threat, 0.7),
            ("размажу", Threat, 0.7),
            ("nude", Sexual, 0.6),
            ("naked", Sexual, 0.5),
            ("porn", Sexual, 0.7),
            ("boobs", Sexual, 0.4),
            ("blowjob", Sexual, 0.6),
            ("handjob", Sexual, 0.6),
            ("cumshot", Sexual, 0.7),
            ("orgasm", Sexual, 0.4),
            ("sexting", Sexual, 0.6),
            ("sext", Sexual, 0.6),
            ("dick pic", Sexual, 0.7),
            ("nudes", Sexual, 0.6),
            ("strip", Sexual, 0.5),
            ("twerk", Sexual, 0.3),
            ("onlyfans", Sexual, 0.5),
            ("webcam girl", Sexual, 0.6),
            ("webcam show", Sexual, 0.6),
            ("send pics", Sexual, 0.4),
            ("show me more", Sexual, 0.4),
            ("take it off", Sexual, 0.5),
            ("what are you wearing", Sexual, 0.4),
            ("hot body", Sexual, 0.4),
            ("sexy photo", Sexual, 0.5),
            ("голий", Sexual, 0.4),
            ("гола", Sexual, 0.4),
            ("секс", Sexual, 0.4),
            ("порно", Sexual, 0.7),
            ("секстинг", Sexual, 0.6),
            ("голе фото", Sexual, 0.6),
            ("інтимне фото", Sexual, 0.6),
            ("роздягнись", Sexual, 0.5),
            ("покажи тіло", Sexual, 0.5),
            ("вебкам", Sexual, 0.6),
            ("надішли фотку без одягу", Sexual, 0.7),
            ("що на тобі наділо", Sexual, 0.4),
            ("гаряче тіло", Sexual, 0.4),
            ("сексуальне фото", Sexual, 0.5),
            ("голая", Sexual, 0.4),
            ("голый", Sexual, 0.4),
            ("секстинг", Sexual, 0.6),
            ("нюдсы", Sexual, 0.6),
            ("скинь фотку", Sexual, 0.4),
            ("покажи тело", Sexual, 0.5),
            ("интимное фото", Sexual, 0.6),
            ("разденься", Sexual, 0.5),
            ("что на тебе надето", Sexual, 0.4),
            ("горячее тело", Sexual, 0.4),
            ("fuck", Profanity, 0.6),
            ("fucking", Profanity, 0.6),
            ("fucker", Profanity, 0.65),
            ("motherfucker", Profanity, 0.7),
            ("shit", Profanity, 0.5),
            ("shitty", Profanity, 0.5),
            ("bullshit", Profanity, 0.5),
            ("bitch", Profanity, 0.55),
            ("bitches", Profanity, 0.55),
            ("asshole", Profanity, 0.55),
            ("dick", Profanity, 0.5),
            ("dickhead", Profanity, 0.55),
            ("cock", Profanity, 0.5),
            ("cocksucker", Profanity, 0.65),
            ("pussy", Profanity, 0.5),
            ("cunt", Profanity, 0.65),
            ("wanker", Profanity, 0.5),
            ("twat", Profanity, 0.5),
            ("whore", Profanity, 0.6),
            ("slut", Profanity, 0.6),
            ("bastard", Profanity, 0.5),
            ("douchebag", Profanity, 0.5),
            ("prick", Profanity, 0.5),
            ("bellend", Profanity, 0.5),
            ("tosser", Profanity, 0.45),
            ("bollocks", Profanity, 0.45),
            ("piss off", Profanity, 0.45),
            ("scumbag", Profanity, 0.55),
            ("son of a bitch", Profanity, 0.6),
            ("хуй", Profanity, 0.7),
            ("хуйня", Profanity, 0.65),
            ("хуйло", Profanity, 0.7),
            ("нахуй", Profanity, 0.7),
            ("похуй", Profanity, 0.65),
            ("охуїти", Profanity, 0.65),
            ("охуєти", Profanity, 0.65),
            ("охуєнно", Profanity, 0.6),
            ("захуярити", Profanity, 0.65),
            ("хуярити", Profanity, 0.65),
            ("хуйовий", Profanity, 0.6),
            ("хуйово", Profanity, 0.6),
            ("хуєсос", Profanity, 0.7),
            ("хуєплет", Profanity, 0.65),
            ("пізда", Profanity, 0.7),
            ("піздець", Profanity, 0.65),
            ("піздатий", Profanity, 0.5),
            ("піздюк", Profanity, 0.65),
            ("піздюлі", Profanity, 0.6),
            ("спіздити", Profanity, 0.6),
            ("розпіздяй", Profanity, 0.6),
            ("піздобол", Profanity, 0.65),
            ("піздити", Profanity, 0.6),
            ("блять", Profanity, 0.6),
            ("бля", Profanity, 0.5),
            ("блядь", Profanity, 0.65),
            ("блядський", Profanity, 0.6),
            ("блядство", Profanity, 0.6),
            ("блядина", Profanity, 0.65),
            ("блядюга", Profanity, 0.65),
            ("бляха", Profanity, 0.4),
            ("єбати", Profanity, 0.7),
            ("їбати", Profanity, 0.7),
            ("єбаний", Profanity, 0.7),
            ("їбаний", Profanity, 0.7),
            ("єбанутий", Profanity, 0.65),
            ("їбанутий", Profanity, 0.65),
            ("єбашити", Profanity, 0.65),
            ("їбашити", Profanity, 0.65),
            ("заєбали", Profanity, 0.65),
            ("заїбали", Profanity, 0.65),
            ("заєбись", Profanity, 0.55),
            ("заїбись", Profanity, 0.55),
            ("виїбати", Profanity, 0.7),
            ("наїбати", Profanity, 0.65),
            ("наїбалово", Profanity, 0.6),
            ("підїбати", Profanity, 0.6),
            ("доїбатись", Profanity, 0.6),
            ("їбучий", Profanity, 0.65),
            ("їбуча", Profanity, 0.65),
            ("їбаний в рот", Profanity, 0.75),
            ("їб твою мать", Profanity, 0.75),
            ("сука", Profanity, 0.6),
            ("сучка", Profanity, 0.6),
            ("сучара", Profanity, 0.65),
            ("падлюка", Profanity, 0.6),
            ("падла", Profanity, 0.55),
            ("падло", Profanity, 0.55),
            ("стерва", Profanity, 0.5),
            ("шльондра", Profanity, 0.6),
            ("курва", Profanity, 0.65),
            ("потаскуха", Profanity, 0.6),
            ("шалава", Profanity, 0.6),
            ("мудак", Profanity, 0.65),
            ("мудила", Profanity, 0.65),
            ("мудозвон", Profanity, 0.6),
            ("гандон", Profanity, 0.65),
            ("гондон", Profanity, 0.65),
            ("підарас", Profanity, 0.7),
            ("підар", Profanity, 0.65),
            ("педик", Profanity, 0.65),
            ("педрила", Profanity, 0.65),
            ("гнида", Profanity, 0.55),
            ("гнидота", Profanity, 0.55),
            ("довбойоб", Profanity, 0.65),
            ("довбоїб", Profanity, 0.65),
            ("ублюдок", Profanity, 0.6),
            ("виблядок", Profanity, 0.65),
            ("дрочити", Profanity, 0.5),
            ("задрот", Profanity, 0.45),
            ("залупа", Profanity, 0.55),
            ("засранець", Profanity, 0.5),
            ("засрати", Profanity, 0.5),
            ("пішов нахуй", Profanity, 0.75),
            ("пішла нахуй", Profanity, 0.75),
            ("іди нахуй", Profanity, 0.75),
            ("йди нахуй", Profanity, 0.75),
            ("їбись конем", Profanity, 0.8),
            ("сука блять", Profanity, 0.7),
            ("охуеть", Profanity, 0.65),
            ("охуенно", Profanity, 0.6),
            ("хуярить", Profanity, 0.65),
            ("хуесос", Profanity, 0.7),
            ("пизда", Profanity, 0.7),
            ("пиздец", Profanity, 0.65),
            ("пиздюк", Profanity, 0.65),
            ("спиздить", Profanity, 0.6),
            ("распиздяй", Profanity, 0.6),
            ("пиздобол", Profanity, 0.65),
            ("блядский", Profanity, 0.6),
            ("ебать", Profanity, 0.7),
            ("ебаный", Profanity, 0.7),
            ("ебанутый", Profanity, 0.65),
            ("ебашить", Profanity, 0.65),
            ("заебал", Profanity, 0.65),
            ("заебали", Profanity, 0.65),
            ("заебись", Profanity, 0.55),
            ("выебать", Profanity, 0.7),
            ("наебать", Profanity, 0.65),
            ("наебалово", Profanity, 0.6),
            ("ёбаный", Profanity, 0.7),
            ("ёб твою мать", Profanity, 0.75),
            ("сучара", Profanity, 0.65),
            ("шлюха", Profanity, 0.6),
            ("пидор", Profanity, 0.7),
            ("пидорас", Profanity, 0.7),
            ("долбоёб", Profanity, 0.65),
            ("выблядок", Profanity, 0.65),
            ("дрочить", Profanity, 0.5),
            ("засранец", Profanity, 0.5),
            ("говно", Profanity, 0.5),
            ("говнюк", Profanity, 0.55),
            ("херня", Profanity, 0.45),
            ("херово", Profanity, 0.45),
            ("иди нахуй", Profanity, 0.75),
            ("пошёл нахуй", Profanity, 0.75),
            ("пошла нахуй", Profanity, 0.75),
            ("cocaine", Drug, 0.6),
            ("heroin", Drug, 0.7),
            ("meth", Drug, 0.7),
            ("crack", Drug, 0.6),
            ("fentanyl", Drug, 0.7),
            ("overdose", Drug, 0.6),
            ("amphetamine", Drug, 0.6),
            ("ecstasy", Drug, 0.5),
            ("mdma", Drug, 0.5),
            ("кокаїн", Drug, 0.6),
            ("героїн", Drug, 0.7),
            ("метамфетамін", Drug, 0.7),
            ("передозування", Drug, 0.6),
            ("амфетамін", Drug, 0.6),
            ("екстазі", Drug, 0.5),
            ("кокаин", Drug, 0.6),
            ("героин", Drug, 0.7),
            ("метамфетамин", Drug, 0.7),
            ("передозировка", Drug, 0.6),
            ("амфетамин", Drug, 0.6),
            ("экстази", Drug, 0.5),
        ];

        let patterns: Vec<&str> = all_patterns.iter().map(|(p, _, _)| *p).collect();
        let entries: Vec<FallbackEntry> = all_patterns
            .iter()
            .map(|(_, cat, score)| FallbackEntry {
                category: *cat,
                score: *score,
            })
            .collect();

        let automaton = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("valid patterns");

        FallbackMatcher { automaton, entries }
    }

    fn predict_fallback(&self, text: &str) -> ToxicityPrediction {
        let matcher = self
            .fallback_matcher
            .as_ref()
            .expect("fallback matcher built");
        let lower = text.to_lowercase();

        let mut insult = 0.0f32;
        let mut threat = 0.0f32;
        let mut sexual = 0.0f32;
        let mut profanity = 0.0f32;
        let mut drug = 0.0f32;
        let identity = 0.0f32;

        use crate::boundary::{aho_match_at_boundary, is_negated};

        for m in matcher.automaton.find_iter(&lower) {
            let start = m.start();
            let end = m.end();
            if !aho_match_at_boundary(&lower, start, end) {
                continue;
            }
            let entry = &matcher.entries[m.pattern().as_usize()];
            let negated = is_negated(&lower, start, 30);

            match entry.category {
                ToxCategory::Insult => {
                    let eff = if negated {
                        entry.score * 0.3
                    } else {
                        entry.score
                    };
                    insult = insult.max(eff);
                }
                ToxCategory::Threat => {
                    let eff = if negated {
                        entry.score * 0.1
                    } else {
                        entry.score
                    };
                    threat = threat.max(eff);
                }
                ToxCategory::Sexual => {
                    let eff = if negated {
                        entry.score * 0.3
                    } else {
                        entry.score
                    };
                    sexual = sexual.max(eff);
                }
                ToxCategory::Profanity => {
                    profanity = profanity.max(entry.score);
                }
                ToxCategory::Drug => {
                    let eff = if negated {
                        entry.score * 0.3
                    } else {
                        entry.score
                    };
                    drug = drug.max(eff);
                }
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

impl crate::backend::ToxicityBackend for ToxicityClassifier {
    fn predict(&mut self, text: &str) -> Option<ToxicityPrediction> {
        self.predict_with_runtime(text)
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
    fn fallback_detects_russian_insults() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("Ты тупой дебил и ничтожество").unwrap();
        assert!(
            pred.toxicity >= 0.5,
            "RU insults should be detected: {}",
            pred.toxicity
        );
        assert!(pred.insult >= 0.5);
    }

    #[test]
    fn fallback_detects_russian_threats() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("Я тебя убью, сдохни").unwrap();
        assert!(pred.toxicity >= 0.8);
        assert!(pred.threat >= 0.8);
    }

    #[test]
    fn fallback_detects_russian_sexual() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("Скинь нюдсы, разденься").unwrap();
        assert!(
            pred.sexual_explicit >= 0.5,
            "RU sexual content should be detected: {}",
            pred.sexual_explicit
        );
    }

    #[test]
    fn fallback_detects_russian_drugs() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier.predict("У меня есть кокаин и героин").unwrap();
        assert!(
            pred.toxicity >= 0.5,
            "RU drug terms should boost toxicity: {}",
            pred.toxicity
        );
    }

    #[test]
    fn fallback_clean_russian_text() {
        let mut classifier = ToxicityClassifier::fallback_only();
        let pred = classifier
            .predict("Привет, как дела? Хорошая погода сегодня!")
            .unwrap();
        assert!(
            pred.toxicity < 0.1,
            "Clean RU message should have low toxicity: {}",
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

    #[test]
    fn no_false_positive_method() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("I use a scientific method for research").unwrap();
        assert!(
            pred.toxicity < 0.1,
            "method should not trigger meth: {}",
            pred.toxicity
        );
    }

    #[test]
    fn no_false_positive_cockpit() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("The cockpit was spacious and modern").unwrap();
        assert!(
            pred.toxicity < 0.1,
            "cockpit should not trigger cock: {}",
            pred.toxicity
        );
    }

    #[test]
    fn no_false_positive_establish() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c
            .predict("We need to establish a stable connection")
            .unwrap();
        assert!(
            pred.toxicity < 0.1,
            "establish/stable should not trigger stab: {}",
            pred.toxicity
        );
    }

    #[test]
    fn no_false_positive_scunthorpe() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("I live in Scunthorpe, England").unwrap();
        assert!(
            pred.toxicity < 0.1,
            "Scunthorpe should not trigger profanity: {}",
            pred.toxicity
        );
    }

    #[test]
    fn no_false_positive_dickens() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("I'm reading Dickens this semester").unwrap();
        assert!(
            pred.toxicity < 0.1,
            "Dickens should not trigger profanity: {}",
            pred.toxicity
        );
    }

    #[test]
    fn no_false_positive_shitake() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("Shitake mushrooms are delicious").unwrap();
        assert!(
            pred.toxicity < 0.1,
            "shitake should not trigger profanity: {}",
            pred.toxicity
        );
    }

    #[test]
    fn negation_wont_kill_low_threat() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("I won't kill you, don't worry").unwrap();
        assert!(
            pred.threat < 0.2,
            "Negated threat should be low: {}",
            pred.threat
        );
    }

    #[test]
    fn negation_not_stupid_low_insult() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("You're not stupid at all").unwrap();
        assert!(
            pred.insult < 0.2,
            "Negated insult should be low: {}",
            pred.insult
        );
    }

    #[test]
    fn negation_profanity_not_dampened() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("Don't say fuck in class").unwrap();
        assert!(
            pred.toxicity >= 0.4,
            "Profanity should stay even when negated: {}",
            pred.toxicity
        );
    }

    #[test]
    fn no_negation_direct_threat_high() {
        let mut c = ToxicityClassifier::fallback_only();
        let pred = c.predict("I will kill you").unwrap();
        assert!(
            pred.threat >= 0.8,
            "Direct threat should remain high: {}",
            pred.threat
        );
    }
}
