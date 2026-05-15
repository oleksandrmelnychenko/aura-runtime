use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use regex::Regex;
use thiserror::Error;

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
    language: String,
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

#[derive(Debug, Error)]
pub enum PatternMatcherBuildError {
    #[error("failed to build keyword matcher for rule '{0}': {1}")]
    InvalidKeywordMatcher(String, String),

    #[error("invalid regex in rule '{0}': {1}")]
    InvalidRegex(String, String),
}

impl PatternMatcher {
    pub fn from_database(db: &PatternDatabase, language: &str) -> Self {
        Self::try_from_database(db, language)
            .expect("pattern database must be validated before building matchers")
    }

    pub fn try_from_database(
        db: &PatternDatabase,
        language: &str,
    ) -> Result<Self, PatternMatcherBuildError> {
        let rules = db.rules_for_language(language);
        let mut keyword_matchers = Vec::new();
        let mut regex_matchers = Vec::new();
        let normalizer = TextNormalizer::new();

        for rule in rules {
            match &rule.kind {
                PatternKind::Keyword { words } => {
                    if words.is_empty() {
                        continue;
                    }
                    let mut lower_words = Vec::new();
                    let mut seen_words = HashSet::new();
                    for word in words {
                        let lower = word.to_lowercase();
                        if seen_words.insert(lower.clone()) {
                            lower_words.push(lower.clone());
                        }

                        let normalized = normalizer.normalize(word);
                        if !normalized.is_empty() && seen_words.insert(normalized.clone()) {
                            lower_words.push(normalized);
                        }
                    }
                    let automaton = AhoCorasick::builder()
                        .ascii_case_insensitive(true)
                        .build(&lower_words)
                        .map_err(|error| {
                            PatternMatcherBuildError::InvalidKeywordMatcher(
                                rule.id.clone(),
                                error.to_string(),
                            )
                        })?;
                    keyword_matchers.push(KeywordMatcher {
                        rule_id: rule.id.clone(),
                        threat_type: rule.threat_type.clone(),
                        score: rule.score,
                        explanation: rule.explanation.clone(),
                        automaton,
                        words: lower_words,
                    });
                }
                PatternKind::Regex { pattern } => {
                    let regex = Regex::new(pattern).map_err(|error| {
                        PatternMatcherBuildError::InvalidRegex(rule.id.clone(), error.to_string())
                    })?;
                    regex_matchers.push(RegexMatcher {
                        rule_id: rule.id.clone(),
                        threat_type: rule.threat_type.clone(),
                        score: rule.score,
                        explanation: rule.explanation.clone(),
                        regex,
                    });
                }
                PatternKind::UrlDomain { .. } => {}
            }
        }

        Ok(Self {
            keyword_matchers,
            regex_matchers,
            normalizer,
            language: language.to_string(),
        })
    }

    pub fn scan(&self, text: &str) -> Vec<MatchResult> {
        let mut results = Vec::new();
        let mut matched_rules: HashSet<String> = HashSet::new();
        let lower_text = text.to_lowercase();

        self.scan_text(&lower_text, &mut results, &mut matched_rules);

        let light = self.normalizer.normalize_light_obfuscation(text);
        if light != lower_text {
            self.scan_text(&light, &mut results, &mut matched_rules);

            let typo_repaired = self.normalizer.normalize_known_typos(&light);
            if typo_repaired != light && typo_repaired != lower_text {
                self.scan_text(&typo_repaired, &mut results, &mut matched_rules);
            }

            let leet_words = self.normalizer.normalize_known_leet_words(&light);
            if leet_words != light && leet_words != lower_text {
                self.scan_text(&leet_words, &mut results, &mut matched_rules);
            }
        }

        let mixed_script_latin = self.normalizer.normalize_mixed_script_latin_tokens(text);
        if mixed_script_latin != lower_text && mixed_script_latin != light {
            self.scan_text(&mixed_script_latin, &mut results, &mut matched_rules);

            let typo_repaired = self.normalizer.normalize_known_typos(&mixed_script_latin);
            if typo_repaired != mixed_script_latin
                && typo_repaired != light
                && typo_repaired != lower_text
            {
                self.scan_text(&typo_repaired, &mut results, &mut matched_rules);
            }

            let leet_words = self
                .normalizer
                .normalize_known_leet_words(&mixed_script_latin);
            if leet_words != mixed_script_latin && leet_words != light && leet_words != lower_text {
                self.scan_text(&leet_words, &mut results, &mut matched_rules);
            }
        }

        let lower_typo_repaired = self.normalizer.normalize_known_typos(&lower_text);
        if lower_typo_repaired != lower_text {
            self.scan_text(&lower_typo_repaired, &mut results, &mut matched_rules);

            let leet_words = self
                .normalizer
                .normalize_known_leet_words(&lower_typo_repaired);
            if leet_words != lower_typo_repaired && leet_words != lower_text {
                self.scan_text(&leet_words, &mut results, &mut matched_rules);
            }
        }

        let lower_leet_words = self.normalizer.normalize_known_leet_words(&lower_text);
        if lower_leet_words != lower_text {
            self.scan_text(&lower_leet_words, &mut results, &mut matched_rules);

            let typo_repaired = self.normalizer.normalize_known_typos(&lower_leet_words);
            if typo_repaired != lower_leet_words && typo_repaired != lower_text {
                self.scan_text(&typo_repaired, &mut results, &mut matched_rules);
            }
        }

        let normalized = self.normalizer.normalize(text);
        if normalized != lower_text {
            self.scan_text(&normalized, &mut results, &mut matched_rules);
        }

        let leet_words = self.normalizer.normalize_known_leet_words(&normalized);
        if leet_words != normalized && leet_words != lower_text {
            self.scan_text(&leet_words, &mut results, &mut matched_rules);
        }

        let typo_repaired = self.normalizer.normalize_known_typos(&normalized);
        if typo_repaired != normalized && typo_repaired != lower_text {
            self.scan_text(&typo_repaired, &mut results, &mut matched_rules);
        }

        let typo_repaired_leet_words = self.normalizer.normalize_known_leet_words(&typo_repaired);
        if typo_repaired_leet_words != typo_repaired
            && typo_repaired_leet_words != normalized
            && typo_repaired_leet_words != lower_text
        {
            self.scan_text(&typo_repaired_leet_words, &mut results, &mut matched_rules);
        }

        if contains_cyrillic(text) {
            let cyrillic_light = self.normalizer.normalize_light_preserving_cyrillic(text);
            if cyrillic_light != lower_text
                && cyrillic_light != light
                && cyrillic_light != mixed_script_latin
                && cyrillic_light != normalized
            {
                self.scan_text(&cyrillic_light, &mut results, &mut matched_rules);
            }

            let typo_repaired = self.normalizer.normalize_known_typos(&cyrillic_light);
            if typo_repaired != cyrillic_light
                && typo_repaired != light
                && typo_repaired != mixed_script_latin
                && typo_repaired != normalized
                && typo_repaired != lower_text
            {
                self.scan_text(&typo_repaired, &mut results, &mut matched_rules);
            }

            let cyrillic_normalized = self.normalizer.normalize_preserving_cyrillic(text);
            if cyrillic_normalized != lower_text && cyrillic_normalized != normalized {
                self.scan_text(&cyrillic_normalized, &mut results, &mut matched_rules);
            }

            let typo_repaired = self.normalizer.normalize_known_typos(&cyrillic_normalized);
            if typo_repaired != cyrillic_normalized
                && typo_repaired != normalized
                && typo_repaired != lower_text
            {
                self.scan_text(&typo_repaired, &mut results, &mut matched_rules);
            }

            for cyrillic_leet in self
                .normalizer
                .normalize_cyrillic_leet_variants(text, &self.language)
            {
                if cyrillic_leet == lower_text
                    || cyrillic_leet == light
                    || cyrillic_leet == mixed_script_latin
                    || cyrillic_leet == normalized
                    || cyrillic_leet == cyrillic_light
                    || cyrillic_leet == cyrillic_normalized
                {
                    continue;
                }

                self.scan_text(&cyrillic_leet, &mut results, &mut matched_rules);

                let typo_repaired = self.normalizer.normalize_known_typos(&cyrillic_leet);
                if typo_repaired != cyrillic_leet
                    && typo_repaired != cyrillic_normalized
                    && typo_repaired != normalized
                    && typo_repaired != lower_text
                {
                    self.scan_text(&typo_repaired, &mut results, &mut matched_rules);
                }
            }
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
            if let Some(mat) = km
                .automaton
                .find_iter(text)
                .find(|mat| aho_match_at_boundary(text, mat.start(), mat.end()))
            {
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

        let light = self.normalizer.normalize_light_obfuscation(text);
        if light != lower {
            if self.has_threat_in(&light) {
                return true;
            }

            let typo_repaired = self.normalizer.normalize_known_typos(&light);
            if typo_repaired != light && self.has_threat_in(&typo_repaired) {
                return true;
            }

            let leet_words = self.normalizer.normalize_known_leet_words(&light);
            if leet_words != light && self.has_threat_in(&leet_words) {
                return true;
            }
        }

        let mixed_script_latin = self.normalizer.normalize_mixed_script_latin_tokens(text);
        if mixed_script_latin != lower && mixed_script_latin != light {
            if self.has_threat_in(&mixed_script_latin) {
                return true;
            }

            let typo_repaired = self.normalizer.normalize_known_typos(&mixed_script_latin);
            if typo_repaired != mixed_script_latin && self.has_threat_in(&typo_repaired) {
                return true;
            }

            let leet_words = self
                .normalizer
                .normalize_known_leet_words(&mixed_script_latin);
            if leet_words != mixed_script_latin && self.has_threat_in(&leet_words) {
                return true;
            }
        }

        let lower_typo_repaired = self.normalizer.normalize_known_typos(&lower);
        if lower_typo_repaired != lower {
            if self.has_threat_in(&lower_typo_repaired) {
                return true;
            }

            let leet_words = self
                .normalizer
                .normalize_known_leet_words(&lower_typo_repaired);
            if leet_words != lower_typo_repaired && self.has_threat_in(&leet_words) {
                return true;
            }
        }

        let lower_leet_words = self.normalizer.normalize_known_leet_words(&lower);
        if lower_leet_words != lower {
            if self.has_threat_in(&lower_leet_words) {
                return true;
            }

            let typo_repaired = self.normalizer.normalize_known_typos(&lower_leet_words);
            if typo_repaired != lower_leet_words && self.has_threat_in(&typo_repaired) {
                return true;
            }
        }

        let normalized = self.normalizer.normalize(text);
        if normalized != lower {
            if self.has_threat_in(&normalized) {
                return true;
            }
        }

        let leet_words = self.normalizer.normalize_known_leet_words(&normalized);
        if leet_words != normalized && self.has_threat_in(&leet_words) {
            return true;
        }

        let typo_repaired = self.normalizer.normalize_known_typos(&normalized);
        if typo_repaired != normalized && self.has_threat_in(&typo_repaired) {
            return true;
        }

        let typo_repaired_leet_words = self.normalizer.normalize_known_leet_words(&typo_repaired);
        if typo_repaired_leet_words != typo_repaired
            && self.has_threat_in(&typo_repaired_leet_words)
        {
            return true;
        }

        if contains_cyrillic(text) {
            let cyrillic_light = self.normalizer.normalize_light_preserving_cyrillic(text);
            if cyrillic_light != lower
                && cyrillic_light != light
                && cyrillic_light != mixed_script_latin
                && cyrillic_light != normalized
                && self.has_threat_in(&cyrillic_light)
            {
                return true;
            }

            let typo_repaired = self.normalizer.normalize_known_typos(&cyrillic_light);
            if typo_repaired != cyrillic_light && self.has_threat_in(&typo_repaired) {
                return true;
            }

            let cyrillic_normalized = self.normalizer.normalize_preserving_cyrillic(text);
            if cyrillic_normalized != lower
                && cyrillic_normalized != normalized
                && self.has_threat_in(&cyrillic_normalized)
            {
                return true;
            }

            let typo_repaired = self.normalizer.normalize_known_typos(&cyrillic_normalized);
            if typo_repaired != cyrillic_normalized && self.has_threat_in(&typo_repaired) {
                return true;
            }

            for cyrillic_leet in self
                .normalizer
                .normalize_cyrillic_leet_variants(text, &self.language)
            {
                if cyrillic_leet == lower
                    || cyrillic_leet == light
                    || cyrillic_leet == mixed_script_latin
                    || cyrillic_leet == normalized
                    || cyrillic_leet == cyrillic_light
                    || cyrillic_leet == cyrillic_normalized
                {
                    continue;
                }

                if self.has_threat_in(&cyrillic_leet) {
                    return true;
                }

                let typo_repaired = self.normalizer.normalize_known_typos(&cyrillic_leet);
                if typo_repaired != cyrillic_leet && self.has_threat_in(&typo_repaired) {
                    return true;
                }
            }
        }

        false
    }

    fn has_threat_in(&self, text: &str) -> bool {
        for km in &self.keyword_matchers {
            if km
                .automaton
                .find_iter(text)
                .any(|mat| aho_match_at_boundary(text, mat.start(), mat.end()))
            {
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

fn aho_match_at_boundary(text: &str, match_start: usize, match_end: usize) -> bool {
    let before_ok = match_start == 0
        || text[..match_start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
    let after_ok = match_end >= text.len()
        || text[match_end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
    before_ok && after_ok
}

fn contains_cyrillic(text: &str) -> bool {
    text.chars().any(|c| {
        matches!(
            c,
            '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}' | '\u{2DE0}'..='\u{2DFF}' | '\u{A640}'..='\u{A69F}'
        )
    })
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
                },
                {
                    "id": "explicit_ass_001",
                    "threat_type": "explicit",
                    "kind": { "type": "keyword", "words": ["ass"] },
                    "score": 0.55,
                    "languages": ["en"],
                    "explanation": "Profanity detected"
                }
            ]
        }"#;
        PatternDatabase::from_json_validated(json).unwrap()
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

    #[test]
    fn keyword_boundary_blocks_embedded_profanity_false_positive() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results = matcher.scan("let's meet by the gym after class tomorrow");
        assert!(
            results
                .iter()
                .all(|result| result.rule_id != "explicit_ass_001"),
            "Embedded profanity substring should not match: {results:?}"
        );
    }

    #[test]
    fn keyword_boundary_still_matches_standalone_profanity() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results = matcher.scan("you are such an ass");
        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "explicit_ass_001"),
            "Standalone profanity should still match: {results:?}"
        );
    }

    #[test]
    fn default_mvp_obfuscation_regex_does_not_match_class() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results = matcher.scan("let's meet by the gym after class tomorrow");
        assert!(
            results
                .iter()
                .all(|result| result.rule_id != "profanity_en_obfuscation"),
            "Obfuscation regex should not fire on 'class': {results:?}"
        );
    }

    #[test]
    fn invalid_regex_is_rejected_during_build() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "bad_regex",
                    "threat_type": "threat",
                    "kind": { "type": "regex", "pattern": "(unclosed" },
                    "score": 0.9,
                    "languages": ["en"],
                    "explanation": "Broken regex"
                }
            ]
        }"#;
        let db = PatternDatabase::from_json(json).unwrap();
        let err = match PatternMatcher::try_from_database(&db, "en") {
            Ok(_) => panic!("invalid regex should fail matcher build"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("bad_regex"));
    }

    #[test]
    fn normalized_keyword_variants_are_scanned() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "drug_offer_en",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["wanna try some weed"] },
                    "score": 0.8,
                    "languages": ["en"],
                    "explanation": "drug offer"
                }
            ]
        }"#;
        let db = PatternDatabase::from_json_validated(json).unwrap();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results = matcher.scan("wanna try some w33d");
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].rule_id, "drug_offer_en");
    }

    #[test]
    fn emoji_padded_keyword_variants_are_scanned() {
        let db = test_db();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results = matcher.scan("He said I will k🔥i🔥l🔥l you");

        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].rule_id, "threat_direct_001");
    }

    #[test]
    fn emoji_padded_ukrainian_threat_regex_is_scanned() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "uk");
        let normalizer = TextNormalizer::new();

        assert_eq!(
            normalizer.normalize_preserving_cyrillic("я 💀 тебе задушу"),
            "я тебе задушу"
        );
        let results = matcher.scan("я 💀 тебе задушу");

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "threat_uk_kill_001"),
            "expected emoji-padded Ukrainian threat to match, got {results:?}"
        );
    }

    #[test]
    fn mixed_script_cyrillic_regex_uses_preserving_normalization() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "uk_threat_test",
                    "threat_type": "threat",
                    "kind": { "type": "regex", "pattern": "(?i)я\\s+тебе\\s+задушу" },
                    "score": 0.8,
                    "languages": ["uk"],
                    "explanation": "test"
                }
            ]
        }"#;
        let db = PatternDatabase::from_json_validated(json).unwrap();
        let matcher = PatternMatcher::from_database(&db, "uk");

        let results = matcher.scan("ID 47: я 💯 тебе 🔥 задушу");

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "uk_threat_test"),
            "expected mixed-script Cyrillic regex to match after normalization, got {results:?}"
        );
    }

    #[test]
    fn coordinate_spelled_out_ukrainian_variants_are_scanned() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "uk");

        for text in [
            "Сорко вісім крапка п'ять дев'ять два вісім, тридцять вісім крапка нуль нуль шість один.",
            "Сорок 🔥 вісім 🔥 крапка 👀 п'ять 👀 дев'ять 💀 два 😂 вісім, тридцять 👀 вісім крапка 💯 нуль нуль шість один.",
            "Сорок вісім крапка п ять дев ять два вісім тридцять вісім крапка нуль нуль шість один",
        ] {
            let results = matcher.scan(text);
            assert!(
                results
                    .iter()
                    .any(|result| result.rule_id == "coord_spelled_out_uk_001"),
                "expected spoken coordinate pattern to match {text:?}, got {results:?}"
            );
        }
    }

    #[test]
    fn mvp_patterns_scan_known_typo_repaired_text() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results =
            matcher.scan("Wire it to checking: routing 021000021 accuont 5571980134 Chase.");

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "pii_routing_account_001"),
            "expected typo-repaired bank routing/account pattern, got {results:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_bullying_typo_repaired_text() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "en");
        let normalizer = TextNormalizer::new();
        let text = "eveyrone is lauhging at your video";

        let results = matcher.scan(text);

        assert!(
            results
                .iter()
                .any(|result| result.threat_type == "bullying"),
            "expected typo-repaired bullying pattern, repaired={:?}, got {results:?}",
            normalizer.normalize_known_typos(text)
        );
    }

    #[test]
    fn mvp_patterns_scan_whitelisted_leet_word_variants() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results = matcher.scan(
            "FR33 573M 5K1N5!!! cl41m n0w h77p5://5734mg1f75-cl41m.3x4mpl3.c0m/c52-p4ck l0g1n w17h 5734m",
        );

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "phishing_steam_giveaway_leet_001"),
            "expected leet-word Steam giveaway to match, got {results:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_community_surface_child_safety_anchors() {
        let db = PatternDatabase::default_mvp();
        let en = PatternMatcher::from_database(&db, "en");
        let uk = PatternMatcher::from_database(&db, "uk");

        let en_selfie = en.scan("send a selfie there so i know its really you");
        assert!(
            en_selfie
                .iter()
                .any(|result| result.rule_id == "grooming_photo_en"),
            "expected EN selfie request to match grooming_photo_en, got {en_selfie:?}"
        );

        let uk_selfie = uk.scan("скинь селфі там, щоб я знав що це точно ти");
        assert!(
            uk_selfie
                .iter()
                .any(|result| result.rule_id == "grooming_photo_uk"),
            "expected UK selfie request to match grooming_photo_uk, got {uk_selfie:?}"
        );

        let uk_leet_selfie = uk.scan("5к1нь 53лф1 74м, щ0б я зн4в щ0 ц3 70чн0 71");
        assert!(
            uk_leet_selfie
                .iter()
                .any(|result| result.rule_id == "grooming_photo_uk"),
            "expected UK leet selfie request to match grooming_photo_uk, got {uk_leet_selfie:?}"
        );

        let uk_leet_delete = uk.scan("в1д4л1 ц3й ч47 п15ля, кр4щ3 щ0б н1х70 н3 б4ч1в");
        assert!(
            uk_leet_delete
                .iter()
                .any(|result| result.rule_id == "platform_switch_teen_uk"),
            "expected UK leet delete-chat request to match platform_switch_teen_uk, got {uk_leet_delete:?}"
        );

        let media_humiliation = en.scan("everyone is laughing at your video");
        assert!(
            media_humiliation
                .iter()
                .any(|result| result.rule_id == "bullying_en_media_humiliation_001"),
            "expected media humiliation to match bullying rule, got {media_humiliation:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_leet_passport_without_destroying_id() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "en");

        let results = matcher.scan("p45p0r7 U48821449 issued 2021-04-12");

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "pii_passport_obfuscated_value_001"),
            "expected leet passport token with preserved ID to match, got {results:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_fullwidth_medical_pii() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "uk");

        let results = matcher.scan("діагноз Ｆ３３．１, призначення в файлі");

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "pii_diagnosis_icd_001"),
            "expected fullwidth ICD diagnosis to match, got {results:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_mixed_script_dog_whistle() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "uk");

        let results = matcher.scan("уou know які люди cоntrоl evеrуthing");

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "hate_dog_whistle_001"),
            "expected mixed-script dog whistle to match, got {results:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_mixed_script_reuters_psyops() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "uk");

        let results =
            matcher.scan("Скріншот з Reutеrs: 'ЗСУ відступають по всьому фронту' - ймовірно фейк");

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "psyops_false_news_framing_001"),
            "expected mixed-script Reuters psyops framing to match, got {results:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_interstitial_what3words() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "uk");

        let results =
            matcher.scan("what3words ///s·h·e·l·v·e·s.cliff.amazed - саме там наша точка.");

        assert!(
            results.iter().any(|result| {
                result.rule_id == "coord_w3w_lenient_001"
                    || result.rule_id == "opsec_coordinates_w3w_001"
            }),
            "expected interstitial What3Words coordinate to match, got {results:?}"
        );
    }

    #[test]
    fn mvp_patterns_scan_known_cyrillic_typo_repaired_text() {
        let db = PatternDatabase::default_mvp();
        let matcher = PatternMatcher::from_database(&db, "uk");

        let results = matcher.scan(
            "Сорок вісім крапка п'ять дев'ять два вісім, трдицять вісім крапка нуль нуль шість один.",
        );

        assert!(
            results
                .iter()
                .any(|result| result.rule_id == "coord_spelled_out_uk_001"),
            "expected typo-repaired spoken coordinate pattern, got {results:?}"
        );
    }
}
