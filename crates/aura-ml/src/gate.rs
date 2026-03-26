//! Tier 1 gate model for cascade inference decisions.
//!
//! Runs on cheap lexicon features (<1ms) to determine whether the
//! expensive ONNX model (Tier 2) needs to run. Targets 60-70% skip
//! rate for benign messages, reducing average per-message latency.

use aho_corasick::AhoCorasick;

use crate::backend::GateModel;

/// Risk category weights for gate scoring.
#[derive(Debug, Clone, Copy)]
enum RiskCategory {
    /// Direct threats, violence.
    HighThreat,
    /// Sexual, grooming, self-harm indicators.
    HighSafety,
    /// Insults, bullying, hate speech.
    MediumToxicity,
    /// Manipulation, coercion, pressure.
    MediumManipulation,
    /// Secrecy, isolation, boundary violations.
    LowGrooming,
    /// Profanity without directed threat.
    LowProfanity,
}

impl RiskCategory {
    fn weight(self) -> f32 {
        match self {
            RiskCategory::HighThreat => 0.95,
            RiskCategory::HighSafety => 0.90,
            RiskCategory::MediumToxicity => 0.65,
            RiskCategory::MediumManipulation => 0.60,
            RiskCategory::LowGrooming => 0.50,
            RiskCategory::LowProfanity => 0.35,
        }
    }

    /// Returns a unique bit flag for tracking distinct categories.
    fn bit(self) -> u8 {
        match self {
            RiskCategory::HighThreat => 1 << 0,
            RiskCategory::HighSafety => 1 << 1,
            RiskCategory::MediumToxicity => 1 << 2,
            RiskCategory::MediumManipulation => 1 << 3,
            RiskCategory::LowGrooming => 1 << 4,
            RiskCategory::LowProfanity => 1 << 5,
        }
    }
}

struct GateEntry {
    category: RiskCategory,
}

/// Lexicon-based gate model that produces a risk score from keyword features.
pub struct LexiconGate {
    automaton: AhoCorasick,
    entries: Vec<GateEntry>,
}

impl LexiconGate {
    /// Creates a new gate model with the built-in multilingual risk lexicon.
    pub fn new() -> Self {
        let patterns = build_gate_patterns();
        let words: Vec<&str> = patterns.iter().map(|(w, _)| *w).collect();
        let entries: Vec<GateEntry> = patterns
            .iter()
            .map(|(_, cat)| GateEntry { category: *cat })
            .collect();

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&words)
            .expect("gate lexicon AhoCorasick build");

        Self { automaton, entries }
    }
}

impl Default for LexiconGate {
    fn default() -> Self {
        Self::new()
    }
}

impl GateModel for LexiconGate {
    fn gate_score(&self, text: &str) -> f32 {
        let lower = text.to_lowercase();
        let mut max_score: f32 = 0.0;
        let mut hit_count: u32 = 0;
        let mut category_mask: u8 = 0;

        for m in self.automaton.find_iter(&lower) {
            let start = m.start();
            let end = m.end();

            if !crate::boundary::aho_match_at_boundary(&lower, start, end) {
                continue;
            }

            if crate::boundary::is_negated(&lower, start, 30) {
                continue;
            }

            let entry = &self.entries[m.pattern().as_usize()];
            let weight = entry.category.weight();
            max_score = max_score.max(weight);
            hit_count += 1;
            category_mask |= entry.category.bit();
        }

        // Compound bonus reflects both volume and breadth of risk
        // indicators. Cross-category hits (e.g. profanity + threat)
        // receive a larger bonus than same-category repetition.
        let distinct_categories = category_mask.count_ones();
        let volume_bonus = match hit_count {
            0 => 0.0,
            1 => 0.0,
            2 => 0.05,
            3 => 0.10,
            _ => 0.15,
        };
        // Each additional risk category beyond the first adds 0.05.
        let breadth_bonus = if distinct_categories >= 2 {
            (distinct_categories - 1) as f32 * 0.05
        } else {
            0.0
        };
        let compound_bonus = (volume_bonus + breadth_bonus).min(0.25);

        (max_score + compound_bonus).min(1.0)
    }

    fn name(&self) -> &str {
        "lexicon_gate"
    }
}

fn build_gate_patterns() -> Vec<(&'static str, RiskCategory)> {
    use RiskCategory::*;

    vec![
        // === High Threat (EN/UK/RU) ===
        ("kill you", HighThreat),
        ("i will hurt you", HighThreat),
        ("i'll kill", HighThreat),
        ("die", HighThreat),
        ("stab", HighThreat),
        ("shoot", HighThreat),
        ("murder", HighThreat),
        ("strangle", HighThreat),
        ("i will find you", HighThreat),
        ("i know where you live", HighThreat),
        ("you're dead", HighThreat),
        // UK
        ("вб'ю", HighThreat),
        ("здохни", HighThreat),
        ("я тебе знайду", HighThreat),
        ("ти труп", HighThreat),
        ("я тебе вб'ю", HighThreat),
        // RU
        ("убью", HighThreat),
        ("сдохни", HighThreat),
        ("я тебя найду", HighThreat),
        ("ты труп", HighThreat),
        // === High Safety ===
        ("want to end it all", HighSafety),
        ("no reason to live", HighSafety),
        ("want to die", HighSafety),
        ("hurt myself", HighSafety),
        ("cutting myself", HighSafety),
        ("goodbye forever", HighSafety),
        ("send nudes", HighSafety),
        ("send me a photo", HighSafety),
        ("take off your", HighSafety),
        ("show me your body", HighSafety),
        ("don't tell your parents", HighSafety),
        ("our little secret", HighSafety),
        ("come to my place alone", HighSafety),
        // UK
        ("не хочу жити", HighSafety),
        ("хочу померти", HighSafety),
        ("ріжу себе", HighSafety),
        ("не кажи батькам", HighSafety),
        ("наш секрет", HighSafety),
        // RU
        ("не хочу жить", HighSafety),
        ("хочу умереть", HighSafety),
        ("режу себя", HighSafety),
        ("не говори родителям", HighSafety),
        // === Medium Toxicity ===
        ("idiot", MediumToxicity),
        ("stupid", MediumToxicity),
        ("worthless", MediumToxicity),
        ("retard", MediumToxicity),
        ("disgusting", MediumToxicity),
        ("ugly", MediumToxicity),
        ("nobody likes you", MediumToxicity),
        ("everyone hates you", MediumToxicity),
        ("дебіл", MediumToxicity),
        ("тупий", MediumToxicity),
        ("ідіот", MediumToxicity),
        ("покидьок", MediumToxicity),
        ("дебил", MediumToxicity),
        ("тупой", MediumToxicity),
        ("идиот", MediumToxicity),
        ("урод", MediumToxicity),
        // === Medium Manipulation ===
        ("you owe me", MediumManipulation),
        ("after everything i did", MediumManipulation),
        ("you're so ungrateful", MediumManipulation),
        ("if you loved me", MediumManipulation),
        ("i'll hurt myself if", MediumManipulation),
        ("everyone does it", MediumManipulation),
        ("prove you're not afraid", MediumManipulation),
        ("ти мені винна", MediumManipulation),
        ("ти мені винен", MediumManipulation),
        ("якщо ти мене любиш", MediumManipulation),
        ("ты мне должна", MediumManipulation),
        ("ты мне должен", MediumManipulation),
        // === Low Grooming ===
        ("how old are you", LowGrooming),
        ("are you home alone", LowGrooming),
        ("you're so mature", LowGrooming),
        ("just between us", LowGrooming),
        ("keep this between us", LowGrooming),
        ("let's meet in secret", LowGrooming),
        ("скільки тобі років", LowGrooming),
        ("ти одна вдома", LowGrooming),
        ("ти один вдома", LowGrooming),
        ("тільки між нами", LowGrooming),
        ("сколько тебе лет", LowGrooming),
        ("ты одна дома", LowGrooming),
        ("только между нами", LowGrooming),
        // === Low Profanity ===
        ("fuck", LowProfanity),
        ("shit", LowProfanity),
        ("ass", LowProfanity),
        ("bitch", LowProfanity),
        ("damn", LowProfanity),
        ("хуй", LowProfanity),
        ("блять", LowProfanity),
        ("сука", LowProfanity),
        ("пиздец", LowProfanity),
        ("нахуй", LowProfanity),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_message_scores_zero() {
        let gate = LexiconGate::new();
        assert_eq!(gate.gate_score("Hello! How are you today?"), 0.0);
        assert_eq!(gate.gate_score("Let's play Minecraft after school"), 0.0);
    }

    #[test]
    fn threat_scores_high() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("I will kill you");
        assert!(score >= 0.9, "Threat should score high, got {score}");
    }

    #[test]
    fn profanity_scores_low() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("oh shit I forgot my homework");
        assert!(
            score > 0.0 && score < 0.5,
            "Profanity should score low, got {score}"
        );
    }

    #[test]
    fn grooming_indicator_scores_medium() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("how old are you? are you home alone?");
        assert!(
            score >= 0.5,
            "Grooming indicators should score medium+, got {score}"
        );
    }

    #[test]
    fn ukrainian_threat_detected() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("Здохни, я тебе вб'ю");
        assert!(
            score >= 0.9,
            "Ukrainian threat should score high, got {score}"
        );
    }

    #[test]
    fn russian_threat_detected() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("Я тебя убью");
        assert!(
            score >= 0.9,
            "Russian threat should score high, got {score}"
        );
    }

    #[test]
    fn self_harm_scores_high() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("I want to end it all, no reason to live");
        assert!(score >= 0.9, "Self-harm should score high, got {score}");
    }

    #[test]
    fn multiple_hits_compound() {
        let gate = LexiconGate::new();
        let single = gate.gate_score("you're stupid");
        let compound = gate.gate_score("you're stupid and ugly and disgusting");
        assert!(
            compound > single,
            "Compound hits should score higher: single={single}, compound={compound}"
        );
    }

    #[test]
    fn mixed_language_detected() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("hey bro, тупий ідіот, go away");
        assert!(
            score >= 0.5,
            "Mixed language insults should be detected, got {score}"
        );
    }

    #[test]
    fn manipulation_detected() {
        let gate = LexiconGate::new();
        let score = gate.gate_score("after everything i did for you, you owe me");
        assert!(score >= 0.6, "Manipulation should be detected, got {score}");
    }

    #[test]
    fn boundary_safe_words_not_flagged() {
        let gate = LexiconGate::new();
        assert_eq!(gate.gate_score("the assessment was good"), 0.0);
        assert_eq!(gate.gate_score("a classic method"), 0.0);
    }
}
