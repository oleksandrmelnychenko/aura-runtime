use std::collections::HashSet;

use serde::Deserialize;

use crate::{DomainAction, DomainSignal};

/// Supported schema version for embedded lexical rule packs.
pub const LEXICON_SCHEMA_VERSION: u32 = 1;

/// Static phrase rule retained for small compile-time detector tables.
pub struct PhraseRule {
    /// Stable detector identity.
    pub threat_key: &'static str,
    /// Stable explainability identity.
    pub reason_code: &'static str,
    /// Normalized detector score.
    pub score: f32,
    /// Phrases that must all be present.
    pub all_of: &'static [&'static str],
    /// Alternative phrases of which at least one must be present.
    pub any_of: &'static [&'static str],
}

/// Deserialized lexical rule with policy and taxonomy metadata.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalRuleRecord {
    /// Stable detector identity.
    pub threat_key: String,
    /// Stable explainability identity.
    pub reason_code: String,
    /// Normalized detector score in `0..=1`.
    pub score: f32,
    /// Domain-neutral threat taxonomy label.
    #[serde(default)]
    pub threat_type: Option<String>,
    /// Severity label used by shared policy.
    #[serde(default)]
    pub severity: Option<String>,
    /// Rule priority used by shared policy.
    #[serde(default)]
    pub priority: Option<u8>,
    /// Optional serialized action hint.
    #[serde(default)]
    pub action: Option<String>,
    /// Phrases that must all match.
    #[serde(default)]
    pub all_of: Vec<String>,
    /// Alternative phrases of which at least one must match.
    #[serde(default)]
    pub any_of: Vec<String>,
    /// Conjunctive groups, each containing alternative phrases.
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

/// Returns the first matching static phrase rule.
#[must_use]
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

/// Converts a static phrase rule to a normalized domain signal.
#[must_use]
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

/// Returns whether any phrase is contained in the already-normalized text.
#[must_use]
pub fn contains_any(text: &str, phrases: &[&str]) -> bool {
    for phrase in phrases {
        if text.contains(phrase) {
            return true;
        }
    }
    false
}

/// Returns the first matching lexical rule in pack order.
#[must_use]
pub fn match_lexical_rules(text: &str, rules: &[LexicalRuleRecord]) -> Option<DomainSignal> {
    let hits = match_all_lexical_rules(text, rules);
    if hits.is_empty() {
        return None;
    }
    Some(hits[0].clone())
}

/// Returns every matching lexical rule in deterministic pack order.
#[must_use]
pub fn match_all_lexical_rules(text: &str, rules: &[LexicalRuleRecord]) -> Vec<DomainSignal> {
    if text.is_empty() {
        return Vec::new();
    }
    let text = text.to_lowercase();
    let compact_text = compact_for_lexical_match(&text);
    let mut hits = Vec::new();
    for rule in rules {
        if lexical_rule_matches(rule, &text, &compact_text) {
            hits.push(DomainSignal {
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
    hits
}

fn lexical_rule_matches(rule: &LexicalRuleRecord, text: &str, compact_text: &str) -> bool {
    for needle in &rule.all_of {
        if !contains_needle(text, compact_text, needle) {
            return false;
        }
    }
    for group in &rule.any_groups {
        let mut group_matched = false;
        for needle in group {
            if contains_needle(text, compact_text, needle) {
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
        if contains_needle(text, compact_text, needle) {
            return true;
        }
    }
    false
}

fn contains_needle(text: &str, compact_text: &str, needle: &str) -> bool {
    let needle = needle.to_lowercase();
    if text.contains(&needle) {
        return true;
    }
    let compact_needle = compact_for_lexical_match(&needle);
    if compact_needle.is_empty() {
        return false;
    }
    compact_text.contains(&compact_needle)
}

fn compact_for_lexical_match(text: &str) -> String {
    let mut compact = String::new();
    for ch in text.chars() {
        let mapped = match ch {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            _ => ch,
        };
        if mapped.is_alphanumeric() {
            compact.push(mapped);
        }
    }
    compact
}

/// Validates the metadata and match expressions in one lexical rule family.
///
/// # Errors
///
/// Returns a descriptive error for malformed metadata, invalid numeric bounds,
/// empty match expressions, or duplicate threat and reason identities.
pub fn validate_lexical_rules(rules: &[LexicalRuleRecord]) -> Result<(), String> {
    let mut threat_keys = HashSet::with_capacity(rules.len());
    let mut reason_codes = HashSet::with_capacity(rules.len());
    for (idx, rule) in rules.iter().enumerate() {
        if rule.threat_key.trim().is_empty() {
            return Err(format!("rule[{idx}] has empty threat_key"));
        }
        if rule.reason_code.trim().is_empty() {
            return Err(format!("rule[{idx}] has empty reason_code"));
        }
        if !threat_keys.insert(rule.threat_key.as_str()) {
            return Err(format!(
                "rule[{idx}] duplicates threat_key `{}`",
                rule.threat_key
            ));
        }
        if !reason_codes.insert(rule.reason_code.as_str()) {
            return Err(format!(
                "rule[{idx}] duplicates reason_code `{}`",
                rule.reason_code
            ));
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
        let valid_threat_type = matches!(
            threat_type.as_str(),
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
                | "coordinate_leak"
        );
        if !valid_threat_type {
            return Err(format!(
                "rule[{idx}] has invalid threat_type `{threat_type}`"
            ));
        }

        let Some(ref severity) = rule.severity else {
            return Err(format!("rule[{idx}] must define severity"));
        };
        let valid_severity = matches!(severity.as_str(), "low" | "medium" | "high" | "critical");
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
            let valid_action = matches!(action.as_str(), "allow" | "mark" | "warn" | "block");
            if !valid_action {
                return Err(format!("rule[{idx}] has invalid action `{action}`"));
            }
        }
        validate_matchers(idx, rule)?;
    }
    Ok(())
}

fn validate_matchers(idx: usize, rule: &LexicalRuleRecord) -> Result<(), String> {
    let has_matchers =
        !rule.all_of.is_empty() || !rule.any_of.is_empty() || !rule.any_groups.is_empty();
    if !has_matchers {
        return Err(format!(
            "rule[{idx}] must define all_of, any_of, or any_groups"
        ));
    }
    if rule.all_of.iter().any(|needle| needle.trim().is_empty()) {
        return Err(format!("rule[{idx}] has empty all_of phrase"));
    }
    if rule.any_of.iter().any(|needle| needle.trim().is_empty()) {
        return Err(format!("rule[{idx}] has empty any_of phrase"));
    }
    for (group_idx, group) in rule.any_groups.iter().enumerate() {
        if group.is_empty() {
            return Err(format!("rule[{idx}] has empty any_groups[{group_idx}]"));
        }
        if group.iter().any(|needle| needle.trim().is_empty()) {
            return Err(format!(
                "rule[{idx}] has empty phrase in any_groups[{group_idx}]"
            ));
        }
    }
    Ok(())
}

/// Verifies that a rule pack uses the only schema understood by this crate.
///
/// # Errors
///
/// Returns an error when `actual` differs from [`LEXICON_SCHEMA_VERSION`].
pub fn validate_schema_version(actual: u32, pack_name: &str) -> Result<(), String> {
    if actual != LEXICON_SCHEMA_VERSION {
        return Err(format!(
            "{pack_name} schema_version mismatch: expected {LEXICON_SCHEMA_VERSION}, got {actual}"
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
        match_all_lexical_rules, match_lexical_rules, validate_lexical_rules,
        validate_schema_version, LexicalRuleRecord,
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
    fn matches_obfuscated_spacing_and_symbols() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            all_of: vec![],
            any_of: vec!["dont tell your parents".to_string()],
            any_groups: vec![],
        }];
        let hit = match_lexical_rules("d.o.n.t t3ll your parents", &rules);
        assert!(hit.is_some());
    }

    #[test]
    fn matches_obfuscated_group_requirement() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("manipulation".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            all_of: vec![],
            any_of: vec![],
            any_groups: vec![
                vec!["i have your photo".to_string()],
                vec!["do what i say or i post it".to_string()],
            ],
        }];
        let hit = match_lexical_rules(
            "i h@ve your ph0to. d o w h a t i s a y or i p0st it",
            &rules,
        );
        assert!(hit.is_some());
    }

    #[test]
    fn returns_all_matching_rules_in_order() {
        let rules = vec![
            LexicalRuleRecord {
                threat_key: "first".to_string(),
                reason_code: "x.first".to_string(),
                score: 0.8,
                threat_type: Some("grooming".to_string()),
                severity: Some("high".to_string()),
                priority: Some(90),
                action: None,
                all_of: vec![],
                any_of: vec!["hello".to_string()],
                any_groups: vec![],
            },
            LexicalRuleRecord {
                threat_key: "second".to_string(),
                reason_code: "x.second".to_string(),
                score: 0.7,
                threat_type: Some("grooming".to_string()),
                severity: Some("medium".to_string()),
                priority: Some(70),
                action: None,
                all_of: vec![],
                any_of: vec!["world".to_string()],
                any_groups: vec![],
            },
        ];
        let hits = match_all_lexical_rules("hello world", &rules);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].reason_code, "x.first");
        assert_eq!(hits[1].reason_code, "x.second");
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
    fn validation_rejects_duplicate_rule_identity() {
        let rule = LexicalRuleRecord {
            threat_key: "duplicate".to_string(),
            reason_code: "x.duplicate".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            all_of: vec!["x".to_string()],
            any_of: vec![],
            any_groups: vec![],
        };

        let error = validate_lexical_rules(&[rule.clone(), rule]).expect_err("must fail");

        assert!(error.contains("duplicates threat_key"));
    }

    #[test]
    fn schema_version_mismatch_fails() {
        let error = validate_schema_version(99, "test-pack").expect_err("must fail");
        assert!(error.contains("schema_version mismatch"));
    }
}
