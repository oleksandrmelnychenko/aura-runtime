use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        Self::from_json(json).expect("built-in MVP patterns must be valid JSON")
    }
}
