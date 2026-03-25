use serde::Deserialize;

use crate::{DomainAction, DomainSignal};

pub const LEXICON_SCHEMA_VERSION: u32 = 1;

pub struct PhraseRule {
    pub threat_key: &'static str,
    pub reason_code: &'static str,
    pub score: f32,
    pub all_of: &'static [&'static str],
    pub any_of: &'static [&'static str],
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalRuleRecord {
    pub threat_key: String,
    pub reason_code: String,
    pub score: f32,
    #[serde(default)]
    pub threat_type: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub priority: Option<u8>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub all_of: Vec<String>,
    #[serde(default)]
    pub any_of: Vec<String>,
    #[serde(default)]
    pub any_groups: Vec<Vec<String>>,
}

impl PhraseRule {
    fn matches(&self, text: &str) -> bool {
        for needle in self.all_of {
            if !text.contains(needle) {
                return false;
            }
        }
        if self.any_of.is_empty() {
            return true;
        }
        for needle in self.any_of {
            if text.contains(needle) {
                return true;
            }
        }
        false
    }
}

pub fn match_phrase_rules(text: &str, rules: &[PhraseRule]) -> Option<DomainSignal> {
    if text.is_empty() {
        return None;
    }
    let text = text.to_lowercase();
    for rule in rules {
        if rule.matches(&text) {
            return Some(DomainSignal {
                threat_key: rule.threat_key.to_string(),
                score: rule.score,
                reason_code: rule.reason_code.to_string(),
                threat_type: None,
                severity: None,
                priority: None,
                action: None,
            });
        }
    }
    None
}

pub fn signal_from_rule(rule: &PhraseRule) -> DomainSignal {
    DomainSignal {
        threat_key: rule.threat_key.to_string(),
        score: rule.score,
        reason_code: rule.reason_code.to_string(),
        threat_type: None,
        severity: None,
        priority: None,
        action: None,
    }
}

pub fn contains_any(text: &str, phrases: &[&str]) -> bool {
    for phrase in phrases {
        if text.contains(phrase) {
            return true;
        }
    }
    false
}

pub fn match_lexical_rules(text: &str, rules: &[LexicalRuleRecord]) -> Option<DomainSignal> {
    if text.is_empty() {
        return None;
    }
    let text = text.to_lowercase();
    for rule in rules {
        if lexical_rule_matches(rule, &text) {
            return Some(DomainSignal {
                threat_key: rule.threat_key.clone(),
                score: rule.score,
                reason_code: rule.reason_code.clone(),
                threat_type: rule.threat_type.clone(),
                severity: rule.severity.clone(),
                priority: rule.priority,
                action: parse_action_hint(rule.action.as_deref()),
            });
        }
    }
    None
}

fn lexical_rule_matches(rule: &LexicalRuleRecord, text: &str) -> bool {
    for needle in &rule.all_of {
        if !text.contains(needle) {
            return false;
        }
    }
    for group in &rule.any_groups {
        let mut group_matched = false;
        for needle in group {
            if text.contains(needle) {
                group_matched = true;
                break;
            }
        }
        if !group_matched {
            return false;
        }
    }
    if rule.any_of.is_empty() {
        return true;
    }
    for needle in &rule.any_of {
        if text.contains(needle) {
            return true;
        }
    }
    false
}

pub fn validate_lexical_rules(rules: &[LexicalRuleRecord]) -> Result<(), String> {
    for (idx, rule) in rules.iter().enumerate() {
        if rule.threat_key.trim().is_empty() {
            return Err(format!("rule[{idx}] has empty threat_key"));
        }
        if rule.reason_code.trim().is_empty() {
            return Err(format!("rule[{idx}] has empty reason_code"));
        }
        if !(0.0..=1.0).contains(&rule.score) {
            return Err(format!(
                "rule[{idx}] score must be within 0..=1, got {}",
                rule.score
            ));
        }
        let Some(ref threat_type) = rule.threat_type else {
            return Err(format!("rule[{idx}] must define threat_type"));
        };
        let valid_threat_type = match threat_type.as_str() {
            "none"
            | "bullying"
            | "grooming"
            | "explicit"
            | "threat"
            | "self_harm"
            | "spam"
            | "scam"
            | "phishing"
            | "manipulation"
            | "nsfw"
            | "hate_speech"
            | "doxxing"
            | "pii_leakage"
            | "propaganda"
            | "opsec_violation"
            | "psyops"
            | "military_social_eng"
            | "coordinate_leak" => true,
            _ => false,
        };
        if !valid_threat_type {
            return Err(format!("rule[{idx}] has invalid threat_type `{threat_type}`"));
        }

        let Some(ref severity) = rule.severity else {
            return Err(format!("rule[{idx}] must define severity"));
        };
        let valid_severity = match severity.as_str() {
            "low" | "medium" | "high" | "critical" => true,
            _ => false,
        };
        if !valid_severity {
            return Err(format!("rule[{idx}] has invalid severity `{severity}`"));
        }

        let Some(priority) = rule.priority else {
            return Err(format!("rule[{idx}] must define priority"));
        };
        if priority == 0 {
            return Err(format!("rule[{idx}] priority must be >= 1"));
        }
        if let Some(ref action) = rule.action {
            let valid_action = match action.as_str() {
                "allow" | "mark" | "warn" | "block" => true,
                _ => false,
            };
            if !valid_action {
                return Err(format!("rule[{idx}] has invalid action `{action}`"));
            }
        }
        let has_matchers =
            !rule.all_of.is_empty() || !rule.any_of.is_empty() || !rule.any_groups.is_empty();
        if !has_matchers {
            return Err(format!(
                "rule[{idx}] must define all_of, any_of, or any_groups"
            ));
        }
        for needle in &rule.all_of {
            if needle.trim().is_empty() {
                return Err(format!("rule[{idx}] has empty all_of phrase"));
            }
        }
        for needle in &rule.any_of {
            if needle.trim().is_empty() {
                return Err(format!("rule[{idx}] has empty any_of phrase"));
            }
        }
        for (group_idx, group) in rule.any_groups.iter().enumerate() {
            if group.is_empty() {
                return Err(format!("rule[{idx}] has empty any_groups[{group_idx}]"));
            }
            for needle in group {
                if needle.trim().is_empty() {
                    return Err(format!(
                        "rule[{idx}] has empty phrase in any_groups[{group_idx}]"
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn validate_schema_version(actual: u32, pack_name: &str) -> Result<(), String> {
    if actual != LEXICON_SCHEMA_VERSION {
        return Err(format!(
            "{pack_name} schema_version mismatch: expected {}, got {}",
            LEXICON_SCHEMA_VERSION, actual
        ));
    }
    Ok(())
}

fn parse_action_hint(action: Option<&str>) -> Option<DomainAction> {
    match action {
        Some("allow") => Some(DomainAction::Allow),
        Some("mark") => Some(DomainAction::Mark),
        Some("warn") => Some(DomainAction::Warn),
        Some("block") => Some(DomainAction::Block),
        Some(_) | None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        match_lexical_rules, validate_lexical_rules, validate_schema_version, LexicalRuleRecord,
    };

    #[test]
    fn matches_when_any_groups_all_satisfied() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            all_of: vec![],
            any_of: vec![],
            any_groups: vec![
                vec!["hello".to_string(), "hi".to_string()],
                vec!["world".to_string(), "earth".to_string()],
            ],
        }];
        let hit = match_lexical_rules("hi there world", &rules);
        assert!(hit.is_some());
    }

    #[test]
    fn does_not_match_when_any_group_missing() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            all_of: vec![],
            any_of: vec![],
            any_groups: vec![
                vec!["hello".to_string(), "hi".to_string()],
                vec!["world".to_string(), "earth".to_string()],
            ],
        }];
        let hit = match_lexical_rules("hi there", &rules);
        assert!(hit.is_none());
    }

    #[test]
    fn validation_rejects_missing_matchers() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            all_of: vec![],
            any_of: vec![],
            any_groups: vec![],
        }];
        let error = validate_lexical_rules(&rules).expect_err("must fail");
        assert!(error.contains("must define all_of, any_of, or any_groups"));
    }

    #[test]
    fn validation_rejects_missing_metadata() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: None,
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            all_of: vec!["x".to_string()],
            any_of: vec![],
            any_groups: vec![],
        }];
        let error = validate_lexical_rules(&rules).expect_err("must fail");
        assert!(error.contains("must define threat_type"));
    }

    #[test]
    fn schema_version_mismatch_fails() {
        let error = validate_schema_version(99, "test-pack").expect_err("must fail");
        assert!(error.contains("schema_version mismatch"));
    }
}
