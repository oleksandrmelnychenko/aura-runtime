use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::url_checker::normalize_domain;

#[derive(Debug, Error)]
pub enum PatternLoadError {
    #[error("failed to read pattern file '{0}': {1}")]
    IoError(String, String),

    #[error("failed to parse pattern JSON from '{0}': {1}")]
    ParseError(String, String),

    #[error("pattern file '{0}' contains no rules")]
    EmptyRuleset(String),

    #[error("pattern source '{0}' has invalid regex in rule '{1}': {2}")]
    InvalidRegex(String, String, String),

    #[error("pattern source '{0}' has invalid domain '{2}' in rule '{1}'")]
    InvalidUrlDomain(String, String, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRule {
    pub id: String,

    pub threat_type: String,

    pub kind: PatternKind,

    pub score: f32,

    pub languages: Vec<String>,

    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PatternKind {
    Keyword { words: Vec<String> },

    Regex { pattern: String },

    UrlDomain { domains: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDatabase {
    pub version: String,
    pub updated_at: String,
    pub rules: Vec<PatternRule>,
}

impl PatternDatabase {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn from_json_validated(json: &str) -> Result<Self, PatternLoadError> {
        let db: Self = serde_json::from_str(json)
            .map_err(|e| PatternLoadError::ParseError("<inline>".to_string(), e.to_string()))?;
        db.validate("<inline>")?;
        Ok(db)
    }

    pub fn rules_for_language(&self, lang: &str) -> Vec<&PatternRule> {
        self.rules
            .iter()
            .filter(|r| r.languages.is_empty() || r.languages.iter().any(|l| l == lang))
            .collect()
    }

    pub fn rules_by_threat(&self) -> HashMap<&str, Vec<&PatternRule>> {
        let mut map: HashMap<&str, Vec<&PatternRule>> = HashMap::new();
        for rule in &self.rules {
            map.entry(&rule.threat_type).or_default().push(rule);
        }
        map
    }

    pub fn empty() -> Self {
        Self {
            version: "0.0.0".to_string(),
            updated_at: String::new(),
            rules: Vec::new(),
        }
    }

    pub fn default_mvp() -> Self {
        let json = include_str!("../data/patterns_mvp.json");
        Self::from_json_validated(json).expect("built-in MVP patterns must be valid")
    }

    pub fn from_file(path: &str) -> Result<Self, PatternLoadError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PatternLoadError::IoError(path.to_string(), e.to_string()))?;
        let db: Self = serde_json::from_str(&content)
            .map_err(|e| PatternLoadError::ParseError(path.to_string(), e.to_string()))?;
        if db.rules.is_empty() {
            return Err(PatternLoadError::EmptyRuleset(path.to_string()));
        }
        db.validate(path)?;
        Ok(db)
    }

    pub fn validate(&self, source: &str) -> Result<(), PatternLoadError> {
        for rule in &self.rules {
            match &rule.kind {
                PatternKind::Regex { pattern } => {
                    regex::Regex::new(pattern).map_err(|error| {
                        PatternLoadError::InvalidRegex(
                            source.to_string(),
                            rule.id.clone(),
                            error.to_string(),
                        )
                    })?;
                }
                PatternKind::UrlDomain { domains } => {
                    for domain in domains {
                        if normalize_domain(domain).is_none() {
                            return Err(PatternLoadError::InvalidUrlDomain(
                                source.to_string(),
                                rule.id.clone(),
                                domain.clone(),
                            ));
                        }
                    }
                }
                PatternKind::Keyword { .. } => {}
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_json_rejects_invalid_regex() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "broken_regex",
                    "threat_type": "threat",
                    "kind": { "type": "regex", "pattern": "(unclosed" },
                    "score": 0.9,
                    "languages": [],
                    "explanation": "Broken regex"
                }
            ]
        }"#;

        let err = PatternDatabase::from_json_validated(json).unwrap_err();
        assert!(err.to_string().contains("broken_regex"));
    }

    #[test]
    fn validated_json_rejects_invalid_url_domain() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "broken_domain",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["not a domain"] },
                    "score": 0.9,
                    "languages": [],
                    "explanation": "Broken domain"
                }
            ]
        }"#;

        let err = PatternDatabase::from_json_validated(json).unwrap_err();
        assert!(err.to_string().contains("broken_domain"));
    }
}
