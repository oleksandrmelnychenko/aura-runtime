use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use regex::Regex;
use tracing::debug;

use crate::database::{PatternDatabase, PatternKind};
use crate::normalizer::TextNormalizer;

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub rule_id: String,
    pub threat_type: String,
    pub score: f32,
    pub explanation: String,
    pub matched_text: Option<String>,
}

pub struct PatternMatcher {
    keyword_matchers: Vec<KeywordMatcher>,
    regex_matchers: Vec<RegexMatcher>,
    normalizer: TextNormalizer,
}

struct KeywordMatcher {
    rule_id: String,
    threat_type: String,
    score: f32,
    explanation: String,
    automaton: AhoCorasick,
    words: Vec<String>,
}

struct RegexMatcher {
    rule_id: String,
    threat_type: String,
    score: f32,
    explanation: String,
    regex: Regex,
}

impl PatternMatcher {
    pub fn from_database(db: &PatternDatabase, language: &str) -> Self {
        let rules = db.rules_for_language(language);
        let mut keyword_matchers = Vec::new();
        let mut regex_matchers = Vec::new();

        for rule in rules {
            match &rule.kind {
                PatternKind::Keyword { words } => {
                    if words.is_empty() {
                        continue;
                    }
                    let lower_words: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
                    if let Ok(automaton) = AhoCorasick::builder()
                        .ascii_case_insensitive(true)
                        .build(&lower_words)
                    {
                        keyword_matchers.push(KeywordMatcher {
                            rule_id: rule.id.clone(),
                            threat_type: rule.threat_type.clone(),
                            score: rule.score,
                            explanation: rule.explanation.clone(),
                            automaton,
                            words: lower_words,
                        });
                    }
                }
                PatternKind::Regex { pattern } => match Regex::new(pattern) {
                    Ok(regex) => {
                        regex_matchers.push(RegexMatcher {
                            rule_id: rule.id.clone(),
                            threat_type: rule.threat_type.clone(),
                            score: rule.score,
                            explanation: rule.explanation.clone(),
                            regex,
                        });
                    }
                    Err(e) => {
                        debug!(rule_id = %rule.id, error = %e, "skipping invalid regex pattern");
                    }
                },
                PatternKind::UrlDomain { .. } => {}
            }
        }

        Self {
            keyword_matchers,
            regex_matchers,
            normalizer: TextNormalizer::new(),
        }
    }

    pub fn scan(&self, text: &str) -> Vec<MatchResult> {
        let mut results = Vec::new();
        let mut matched_rules: HashSet<String> = HashSet::new();
        let lower_text = text.to_lowercase();

        self.scan_text(&lower_text, &mut results, &mut matched_rules);

        let normalized = self.normalizer.normalize(text);
        if normalized != lower_text {
            self.scan_text(&normalized, &mut results, &mut matched_rules);
        }

        results
    }

    fn scan_text(
        &self,
        text: &str,
        results: &mut Vec<MatchResult>,
        matched_rules: &mut HashSet<String>,
    ) {
        for km in &self.keyword_matchers {
            if matched_rules.contains(&km.rule_id) {
                continue;
            }
            if let Some(mat) = km.automaton.find(text) {
                let matched = &km.words[mat.pattern().as_usize()];
                matched_rules.insert(km.rule_id.clone());
                results.push(MatchResult {
                    rule_id: km.rule_id.clone(),
                    threat_type: km.threat_type.clone(),
                    score: km.score,
                    explanation: km.explanation.clone(),
                    matched_text: Some(matched.clone()),
                });
            }
        }

        for rm in &self.regex_matchers {
            if matched_rules.contains(&rm.rule_id) {
                continue;
            }
            if let Some(mat) = rm.regex.find(text) {
                matched_rules.insert(rm.rule_id.clone());
                results.push(MatchResult {
                    rule_id: rm.rule_id.clone(),
                    threat_type: rm.threat_type.clone(),
                    score: rm.score,
                    explanation: rm.explanation.clone(),
                    matched_text: Some(mat.as_str().to_string()),
                });
            }
        }
    }

    pub fn has_threat(&self, text: &str) -> bool {
        let lower = text.to_lowercase();

        if self.has_threat_in(&lower) {
            return true;
        }

        let normalized = self.normalizer.normalize(text);
        if normalized != lower {
            return self.has_threat_in(&normalized);
        }

        false
    }

    fn has_threat_in(&self, text: &str) -> bool {
        for km in &self.keyword_matchers {
            if km.automaton.find(text).is_some() {
                return true;
            }
        }
        for rm in &self.regex_matchers {
            if rm.regex.is_match(text) {
                return true;
            }
        }
        false
    }

    pub fn rule_count(&self) -> usize {
        self.keyword_matchers.len() + self.regex_matchers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::PatternDatabase;

    fn test_db() -> PatternDatabase {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "threat_direct_001",
                    "threat_type": "threat",
                    "kind": { "type": "keyword", "words": ["kill you", "i will hurt you"] },
                    "score": 0.9,
                    "languages": ["en"],
                    "explanation": "Direct threat detected"
                },
                {
                    "id": "threat_uk_001",
                    "threat_type": "threat",
                    "kind": { "type": "keyword", "words": ["\u0443\u0431'\u044e \u0442\u0435\u0431\u0435", "\u043f\u0440\u0438\u0431'\u044e"] },
                    "score": 0.85,
                    "languages": ["uk", "ru"],
                    "explanation": "\u0412\u0438\u044f\u0432\u043b\u0435\u043d\u043e \u043f\u0440\u044f\u043c\u0443 \u0437\u0430\u0433\u0440\u043e\u0437\u0443"
                },
                {
                    "id": "phishing_url_001",
                    "threat_type": "phishing",
                    "kind": { "type": "regex", "pattern": "https?://[\\w.-]*(?:free-?gift|claim-?prize|verify-?account)[\\w./-]*" },
                    "score": 0.8,
                    "languages": [],
                    "explanation": "Suspicious phishing URL pattern"
                },
                {
                    "id": "grooming_secrecy_001",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["don't tell your parents", "our little secret", "just between us"] },
                    "score": 0.7,
                    "languages": ["en"],
                    "explanation": "Secrecy request detected (potential grooming)"
                },
                {
                    "id": "grooming_secrecy_uk_001",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["\u043d\u0435 \u043a\u0430\u0436\u0438 \u0431\u0430\u0442\u044c\u043a\u0430\u043c", "\u043d\u0435 \u0433\u043e\u0432\u043e\u0440\u0438 \u043d\u0456\u043a\u043e\u043c\u0443", "\u0446\u0435 \u043d\u0430\u0448 \u0441\u0435\u043a\u0440\u0435\u0442"] },
                    "score": 0.7,
                    "languages": ["uk"],
                    "explanation": "\u0412\u0438\u044f\u0432\u043b\u0435\u043d\u043e \u043f\u0440\u043e\u0445\u0430\u043d\u043d\u044f \u0437\u0431\u0435\u0440\u0456\u0433\u0430\u0442\u0438 \u0442\u0430\u0454\u043c\u043d\u0438\u0446\u044e (\u043c\u043e\u0436\u043b\u0438\u0432\u0438\u0439 \u0433\u0440\u0443\u043c\u0456\u043d\u0433)"
                },
                {
                    "id": "selfharm_001",
                    "threat_type": "self_harm",
                    "kind": { "type": "keyword", "words": ["want to end it all", "no reason to live", "better off without me"] },
                    "score": 0.75,
                    "languages": ["en"],
                    "explanation": "Self-harm language detected. Resources available."
                }
            ]
        }"#;
        PatternDatabase::from_json(json).unwrap()
    }

    #[test]
    fn detects_direct_threat_en() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");
        let results = matcher.scan("I will kill you");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_type, "threat");
        assert!(results[0].score >= 0.9);
    }

    #[test]
    fn detects_threat_ukrainian() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "uk");
        let results = matcher.scan("\u{042f} \u{0442}\u{0435}\u{0431}\u{0435} \u{0443}\u{0431}'\u{044e} \u{0442}\u{0435}\u{0431}\u{0435}");
        assert!(!results.is_empty());
        assert_eq!(results[0].threat_type, "threat");
    }

    #[test]
    fn detects_grooming_secrecy() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");
        let results = matcher.scan("Hey, don't tell your parents about this okay?");
        assert!(!results.is_empty());
        assert_eq!(results[0].threat_type, "grooming");
    }

    #[test]
    fn detects_grooming_secrecy_ukrainian() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "uk");
        let results = matcher.scan("\u{041d}\u{0435} \u{043a}\u{0430}\u{0436}\u{0438} \u{0431}\u{0430}\u{0442}\u{044c}\u{043a}\u{0430}\u{043c} \u{043f}\u{0440}\u{043e} \u{0446}\u{0435}");
        assert!(!results.is_empty());
        assert_eq!(results[0].threat_type, "grooming");
    }

    #[test]
    fn detects_phishing_url() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");
        let results = matcher.scan("Click here: https://free-gift-cards.example.com/claim");
        assert!(!results.is_empty());
        assert_eq!(results[0].threat_type, "phishing");
    }

    #[test]
    fn detects_self_harm() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");
        let results = matcher.scan("I feel like there's no reason to live anymore");
        assert!(!results.is_empty());
        assert_eq!(results[0].threat_type, "self_harm");
    }

    #[test]
    fn clean_message_no_matches() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");
        let results = matcher.scan("Hey, want to grab coffee tomorrow?");
        assert!(results.is_empty());
    }

    #[test]
    fn case_insensitive() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");
        assert!(matcher.has_threat("I WILL KILL YOU"));
        assert!(matcher.has_threat("Don't Tell Your Parents"));
    }

    #[test]
    fn language_filtering_works() {
        let db = test_db();

        let en_matcher = PatternMatcher::from_database(&db, "en");
        let uk_matcher = PatternMatcher::from_database(&db, "uk");

        assert!(en_matcher.has_threat("https://free-gift.example.com"));
        assert!(uk_matcher.has_threat("https://free-gift.example.com"));
    }
}
