#[derive(Debug, Clone)]
pub struct EmojiMatchResult {
    pub pattern_id: String,
    pub threat_type: String,
    pub score: f32,
    pub explanation: String,
    pub matched_emojis: String,
}

pub struct EmojiAnalyzer {
    patterns: Vec<EmojiPattern>,
}

struct EmojiPattern {
    id: String,
    threat_type: String,
    score: f32,
    explanation: String,

    sequences: Vec<Vec<&'static str>>,
}

impl EmojiAnalyzer {
    pub fn new() -> Self {
        let patterns = vec![
            EmojiPattern {
                id: "emoji_threat_weapon_person".into(),
                threat_type: "threat".into(),
                score: 0.7,
                explanation: "Threatening emoji combination: weapon + person".into(),
                sequences: vec![
                    vec!["🔪", "👧"],
                    vec!["🔪", "👦"],
                    vec!["🔪", "👩"],
                    vec!["🔪", "👨"],
                    vec!["🔪", "🧒"],
                    vec!["🔫", "👧"],
                    vec!["🔫", "👦"],
                    vec!["🔫", "👩"],
                    vec!["🔫", "👨"],
                    vec!["🔫", "🧒"],
                ],
            },
            EmojiPattern {
                id: "emoji_threat_death".into(),
                threat_type: "threat".into(),
                score: 0.65,
                explanation: "Death threat emoji combination".into(),
                sequences: vec![
                    vec!["💀", "🔫"],
                    vec!["💀", "🔪"],
                    vec!["☠️", "🔪"],
                    vec!["☠️", "🔫"],
                    vec!["💣", "🏠"],
                    vec!["💣", "🏫"],
                ],
            },
            EmojiPattern {
                id: "emoji_threat_fire".into(),
                threat_type: "threat".into(),
                score: 0.6,
                explanation: "Arson/fire threat emoji".into(),
                sequences: vec![vec!["🔥", "🏠"], vec!["🔥", "🏫"]],
            },
            EmojiPattern {
                id: "emoji_sexual_explicit".into(),
                threat_type: "explicit".into(),
                score: 0.7,
                explanation: "Sexually explicit emoji combination".into(),
                sequences: vec![
                    vec!["🍆", "🍑"],
                    vec!["🍆", "👄"],
                    vec!["🍆", "💦"],
                    vec!["🍆", "😮"],
                    vec!["🍑", "💦"],
                ],
            },
            EmojiPattern {
                id: "emoji_sexual_suggestive".into(),
                threat_type: "explicit".into(),
                score: 0.55,
                explanation: "Sexually suggestive emoji combination".into(),
                sequences: vec![
                    vec!["💦", "👅"],
                    vec!["👅", "🍑"],
                    vec!["😈", "🍆"],
                    vec!["😏", "🍆"],
                ],
            },
            EmojiPattern {
                id: "emoji_selfharm".into(),
                threat_type: "self_harm".into(),
                score: 0.6,
                explanation: "Self-harm related emoji combination".into(),
                sequences: vec![
                    vec!["💀", "💔"],
                    vec!["⚰️", "👼"],
                    vec!["🪦", "💔"],
                    vec!["🪦", "😢"],
                    vec!["💊", "💀"],
                ],
            },
            EmojiPattern {
                id: "emoji_bullying_animal".into(),
                threat_type: "bullying".into(),
                score: 0.5,
                explanation: "Dehumanizing emoji combination (animal + person)".into(),
                sequences: vec![
                    vec!["🐷", "👧"],
                    vec!["🐷", "👦"],
                    vec!["🐷", "👩"],
                    vec!["🐵", "👧"],
                    vec!["🐵", "👦"],
                    vec!["🐵", "👩"],
                    vec!["🤡", "👉"],
                    vec!["🤡", "👈"],
                ],
            },
            EmojiPattern {
                id: "emoji_bullying_mockery".into(),
                threat_type: "bullying".into(),
                score: 0.45,
                explanation: "Mocking emoji combination".into(),
                sequences: vec![
                    vec!["🤣", "👉"],
                    vec!["😂", "👉"],
                    vec!["🤮", "👉"],
                    vec!["💩", "👉"],
                ],
            },
            EmojiPattern {
                id: "emoji_sextortion".into(),
                threat_type: "manipulation".into(),
                score: 0.75,
                explanation: "Sextortion-related emoji combination".into(),
                sequences: vec![
                    vec!["📸", "💰"],
                    vec!["💵", "📷"],
                    vec!["🤫", "📸"],
                    vec!["🔒", "💰"],
                ],
            },
            EmojiPattern {
                id: "emoji_drug".into(),
                threat_type: "scam".into(),
                score: 0.6,
                explanation: "Drug-related emoji combination".into(),
                sequences: vec![
                    vec!["💊", "💰"],
                    vec!["🍃", "🔥"],
                    vec!["💉", "💀"],
                    vec!["🍄", "🌈"],
                ],
            },
            EmojiPattern {
                id: "emoji_isolation".into(),
                threat_type: "bullying".into(),
                score: 0.5,
                explanation: "Isolation/exclusion emoji combination".into(),
                sequences: vec![vec!["🚫", "👧"], vec!["🚫", "👦"], vec!["👋", "🚪"]],
            },
        ];

        Self { patterns }
    }

    pub fn scan(&self, text: &str) -> Vec<EmojiMatchResult> {
        let emojis: Vec<&str> = extract_emojis(text);
        if emojis.len() < 2 {
            return Vec::new();
        }

        let mut results = Vec::new();

        for pattern in &self.patterns {
            for seq in &pattern.sequences {
                if contains_emoji_sequence(&emojis, seq) {
                    results.push(EmojiMatchResult {
                        pattern_id: pattern.id.clone(),
                        threat_type: pattern.threat_type.clone(),
                        score: pattern.score,
                        explanation: pattern.explanation.clone(),
                        matched_emojis: seq.join(""),
                    });
                    break;
                }
            }
        }

        results
    }
}

impl Default for EmojiAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_emojis(text: &str) -> Vec<&str> {
    use unicode_segmentation::UnicodeSegmentation;

    text.graphemes(true)
        .filter(|g| {
            let first_char = g.chars().next().unwrap_or(' ');
            is_emoji_char(first_char)
        })
        .collect()
}

fn is_emoji_char(c: char) -> bool {
    let cp = c as u32;

    (0x1F300..=0x1F9FF).contains(&cp)
        || (0x1FA00..=0x1FAFF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || cp == 0x200D
        || (0xFE00..=0xFE0F).contains(&cp)
        || (0x2702..=0x27B0).contains(&cp)
}

fn contains_emoji_sequence(emojis: &[&str], sequence: &[&str]) -> bool {
    if sequence.is_empty() {
        return false;
    }

    let mut seq_idx = 0;
    for emoji in emojis {
        if *emoji == sequence[seq_idx] {
            seq_idx += 1;
            if seq_idx >= sequence.len() {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer() -> EmojiAnalyzer {
        EmojiAnalyzer::new()
    }

    #[test]
    fn detects_knife_girl_threat() {
        let a = analyzer();
        let results = a.scan("🔪👧");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "threat");
    }

    #[test]
    fn detects_gun_boy_threat() {
        let a = analyzer();
        let results = a.scan("🔫👦");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "threat");
    }

    #[test]
    fn detects_death_threat_emojis() {
        let a = analyzer();
        let results = a.scan("💀🔫");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "threat");
    }

    #[test]
    fn detects_bomb_school_threat() {
        let a = analyzer();
        let results = a.scan("💣🏫");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "threat");
    }

    #[test]
    fn detects_sexual_emojis() {
        let a = analyzer();
        let results = a.scan("🍆🍑");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "explicit");
    }

    #[test]
    fn detects_suggestive_emojis() {
        let a = analyzer();
        let results = a.scan("💦👅");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "explicit");
    }

    #[test]
    fn detects_selfharm_emojis() {
        let a = analyzer();
        let results = a.scan("💀💔");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "self_harm");
    }

    #[test]
    fn detects_bullying_pig_girl() {
        let a = analyzer();
        let results = a.scan("🐷👧");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "bullying");
    }

    #[test]
    fn detects_emojis_with_text_between() {
        let a = analyzer();

        let results = a.scan("hey 🔪 look at this 👧 haha");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "threat");
    }

    #[test]
    fn safe_emojis_no_match() {
        let a = analyzer();
        let results = a.scan("👋😊🎉");
        assert!(results.is_empty());
    }

    #[test]
    fn single_emoji_no_match() {
        let a = analyzer();
        let results = a.scan("🔪");
        assert!(results.is_empty());
    }

    #[test]
    fn no_emojis_no_match() {
        let a = analyzer();
        let results = a.scan("hello world");
        assert!(results.is_empty());
    }

    #[test]
    fn multiple_patterns_detected() {
        let a = analyzer();

        let results = a.scan("🔪👧 🍆🍑");
        assert!(results.len() >= 2);
        let types: Vec<&str> = results.iter().map(|r| r.threat_type.as_str()).collect();
        assert!(types.contains(&"threat"));
        assert!(types.contains(&"explicit"));
    }

    #[test]
    fn detects_sextortion_emojis() {
        let a = analyzer();
        let results = a.scan("📸💰");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "manipulation");
        assert_eq!(results[0].pattern_id, "emoji_sextortion");
    }

    #[test]
    fn detects_drug_emojis() {
        let a = analyzer();
        let results = a.scan("💊💰");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "scam");
        assert_eq!(results[0].pattern_id, "emoji_drug");
    }

    #[test]
    fn detects_isolation_emojis() {
        let a = analyzer();
        let results = a.scan("🚫👧");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "bullying");
    }

    #[test]
    fn detects_ransom_emoji() {
        let a = analyzer();
        let results = a.scan("🔒💰");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "manipulation");
    }

    #[test]
    fn detects_drug_needle_emoji() {
        let a = analyzer();
        let results = a.scan("💉💀");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "scam");
    }
}
