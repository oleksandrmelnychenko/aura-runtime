use std::collections::HashSet;

use serde::Deserialize;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

use crate::{DomainAction, DomainSignal, LanguageEvidence, LanguageScript, LanguageTag};

/// Legacy schema version for embedded lexical rule packs and closed v1 policies.
pub const LEXICON_SCHEMA_VERSION: u32 = 1;
/// Latest schema version for multilingual lexical rule packs.
pub const LATEST_LEXICON_SCHEMA_VERSION: u32 = 2;

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
    /// Optional BCP-47-style language scopes. Empty means language-universal.
    #[serde(default)]
    pub languages: Vec<String>,
    /// Optional Unicode script scopes. Empty means script-universal.
    #[serde(default)]
    pub scripts: Vec<LanguageScript>,
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

/// Message text normalized once for repeated lexical detector evaluation.
///
/// The visible channel preserves word boundaries. The compact channel closes
/// spacing, punctuation, leetspeak, compatibility-character, combining-mark,
/// and mixed-script confusable evasions.
#[derive(Debug)]
pub struct PreparedLexicalText {
    visible: String,
    visible_chars: Vec<char>,
    compact: String,
    confusable_skeleton: String,
    /// Index into `visible_chars` for every char of the compact channels.
    compact_origin: Vec<usize>,
    mixed_script: bool,
}

/// Compact needles at least this long are distinctive enough to match even
/// when glued into surrounding noise; shorter needles must align with word
/// boundaries of the visible text so `spend it all` cannot hit `end it all`.
const LONG_COMPACT_NEEDLE_CHARS: usize = 12;

impl PreparedLexicalText {
    /// Normalizes attacker-controlled text into reusable matching channels.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let visible = normalize_visible(text);
        let visible_chars = visible.chars().collect();
        let (compact, confusable_skeleton, mixed_script, compact_origin) =
            compact_channels(&visible);
        Self {
            visible,
            visible_chars,
            compact,
            confusable_skeleton,
            compact_origin,
            mixed_script,
        }
    }

    fn contains(&self, needle: &PreparedNeedle) -> bool {
        if contains_at_word_boundary(&self.visible, &needle.visible) {
            return true;
        }
        if needle.compact.is_empty() {
            return false;
        }
        let long_needle = needle.compact.chars().count() >= LONG_COMPACT_NEEDLE_CHARS;
        self.compact_contains_aligned(&self.compact, &needle.compact, long_needle)
            || (self.mixed_script
                && self.compact_contains_aligned(
                    &self.confusable_skeleton,
                    &needle.confusable_skeleton,
                    long_needle,
                ))
    }

    /// Finds `needle` in a compact channel and, unless the needle is long
    /// enough to be distinctive on its own, requires the match to start and
    /// end at word boundaries of the visible text it was derived from.
    fn compact_contains_aligned(&self, haystack: &str, needle: &str, long_needle: bool) -> bool {
        if needle.is_empty() {
            return false;
        }
        let needle_chars = needle.chars().count();
        for (byte_offset, _) in haystack.match_indices(needle) {
            if long_needle {
                return true;
            }
            let start_char = haystack[..byte_offset].chars().count();
            let end_char = start_char + needle_chars;
            let Some(&first_origin) = self.compact_origin.get(start_char) else {
                continue;
            };
            let Some(&last_origin) = self.compact_origin.get(end_char.saturating_sub(1)) else {
                continue;
            };
            let before_ok =
                first_origin == 0 || !self.visible_chars[first_origin - 1].is_alphanumeric();
            let after_ok = last_origin + 1 >= self.visible_chars.len()
                || !self.visible_chars[last_origin + 1].is_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
        }
        false
    }
}

/// Substring search that only accepts matches delimited by non-alphanumeric
/// characters (or the ends of the text) on both sides.
fn contains_at_word_boundary(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.match_indices(needle).any(|(start, matched)| {
        let end = start + matched.len();
        let before_ok = haystack[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_ok = haystack[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        before_ok && after_ok
    })
}

#[derive(Debug)]
struct PreparedNeedle {
    visible: String,
    compact: String,
    confusable_skeleton: String,
}

impl PreparedNeedle {
    fn new(needle: &str) -> Self {
        let visible = normalize_visible(needle);
        let (compact, confusable_skeleton, _, _) = compact_channels(&visible);
        Self {
            visible,
            compact,
            confusable_skeleton,
        }
    }
}

#[derive(Debug)]
struct CompiledLexicalRule {
    signal: DomainSignal,
    languages: Vec<String>,
    scripts: Vec<LanguageScript>,
    all_of: Vec<PreparedNeedle>,
    any_of: Vec<PreparedNeedle>,
    any_groups: Vec<Vec<PreparedNeedle>>,
}

impl CompiledLexicalRule {
    fn from_record(rule: &LexicalRuleRecord) -> Self {
        Self {
            signal: signal_from_lexical_record(rule),
            languages: rule.languages.clone(),
            scripts: rule.scripts.clone(),
            all_of: rule
                .all_of
                .iter()
                .map(|needle| PreparedNeedle::new(needle))
                .collect(),
            any_of: rule
                .any_of
                .iter()
                .map(|needle| PreparedNeedle::new(needle))
                .collect(),
            any_groups: rule
                .any_groups
                .iter()
                .map(|group| {
                    group
                        .iter()
                        .map(|needle| PreparedNeedle::new(needle))
                        .collect()
                })
                .collect(),
        }
    }

    fn matches(&self, text: &PreparedLexicalText) -> bool {
        self.all_of.iter().all(|needle| text.contains(needle))
            && self
                .any_groups
                .iter()
                .all(|group| group.iter().any(|needle| text.contains(needle)))
            && (self.any_of.is_empty() || self.any_of.iter().any(|needle| text.contains(needle)))
    }

    fn applies_to(&self, evidence: Option<&LanguageEvidence>) -> bool {
        if self.languages.is_empty() && self.scripts.is_empty() {
            return true;
        }
        let Some(evidence) = evidence else {
            return false;
        };
        let language_matches = self.languages.is_empty()
            || evidence.candidates().iter().any(|candidate| {
                self.languages.iter().any(|language| {
                    language == candidate.tag().as_str()
                        || (!language.contains('-') && language == candidate.tag().primary())
                })
            });
        let script_matches = self.scripts.is_empty()
            || evidence
                .scripts()
                .iter()
                .any(|item| self.scripts.contains(&item.script()));
        language_matches && script_matches
    }
}

/// Pre-normalized lexical rule family for allocation-efficient repeated scans.
#[derive(Debug)]
pub struct CompiledLexicalRules {
    rules: Vec<CompiledLexicalRule>,
}

impl CompiledLexicalRules {
    /// Compiles normalized needles and immutable signal metadata once.
    #[must_use]
    pub fn new(rules: &[LexicalRuleRecord]) -> Self {
        Self {
            rules: rules.iter().map(CompiledLexicalRule::from_record).collect(),
        }
    }

    /// Returns the first match for raw message text.
    #[must_use]
    pub fn first_match(&self, text: &str) -> Option<DomainSignal> {
        let evidence = LanguageEvidence::from_text_and_hints(text, None, None);
        self.first_match_prepared_with_language(&PreparedLexicalText::new(text), &evidence)
    }

    /// Returns the first match using a message normalized by the caller.
    #[must_use]
    pub fn first_match_prepared(&self, text: &PreparedLexicalText) -> Option<DomainSignal> {
        self.first_match_prepared_inner(text, None)
    }

    /// Returns the first match using normalized text and bounded language evidence.
    #[must_use]
    pub fn first_match_prepared_with_language(
        &self,
        text: &PreparedLexicalText,
        evidence: &LanguageEvidence,
    ) -> Option<DomainSignal> {
        self.first_match_prepared_inner(text, Some(evidence))
    }

    fn first_match_prepared_inner(
        &self,
        text: &PreparedLexicalText,
        evidence: Option<&LanguageEvidence>,
    ) -> Option<DomainSignal> {
        self.rules
            .iter()
            .find(|rule| rule.applies_to(evidence) && rule.matches(text))
            .map(|rule| rule.signal.clone())
    }

    /// Returns every match for raw message text in deterministic pack order.
    #[must_use]
    pub fn all_matches(&self, text: &str) -> Vec<DomainSignal> {
        let evidence = LanguageEvidence::from_text_and_hints(text, None, None);
        self.all_matches_prepared_with_language(&PreparedLexicalText::new(text), &evidence)
    }

    /// Returns every match using a message normalized by the caller.
    #[must_use]
    pub fn all_matches_prepared(&self, text: &PreparedLexicalText) -> Vec<DomainSignal> {
        self.all_matches_prepared_inner(text, None)
    }

    /// Returns every match using normalized text and bounded language evidence.
    #[must_use]
    pub fn all_matches_prepared_with_language(
        &self,
        text: &PreparedLexicalText,
        evidence: &LanguageEvidence,
    ) -> Vec<DomainSignal> {
        self.all_matches_prepared_inner(text, Some(evidence))
    }

    fn all_matches_prepared_inner(
        &self,
        text: &PreparedLexicalText,
        evidence: Option<&LanguageEvidence>,
    ) -> Vec<DomainSignal> {
        self.rules
            .iter()
            .filter(|rule| rule.applies_to(evidence) && rule.matches(text))
            .map(|rule| rule.signal.clone())
            .collect()
    }
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
    let text = PreparedLexicalText::new(text);
    let mut hits = Vec::new();
    for rule in rules {
        if lexical_rule_matches(rule, &text) {
            hits.push(signal_from_lexical_record(rule));
        }
    }
    hits
}

fn lexical_rule_matches(rule: &LexicalRuleRecord, text: &PreparedLexicalText) -> bool {
    for needle in &rule.all_of {
        if !text.contains(&PreparedNeedle::new(needle)) {
            return false;
        }
    }
    for group in &rule.any_groups {
        let mut group_matched = false;
        for needle in group {
            if text.contains(&PreparedNeedle::new(needle)) {
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
        if text.contains(&PreparedNeedle::new(needle)) {
            return true;
        }
    }
    false
}

fn normalize_visible(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut previous_was_space = false;
    for ch in text.nfkd().flat_map(char::to_lowercase) {
        if is_combining_mark(ch) || is_default_ignorable(ch) || ch.is_control() {
            continue;
        }
        if ch.is_whitespace() {
            if !previous_was_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            previous_was_space = true;
            continue;
        }
        normalized.push(ch);
        previous_was_space = false;
    }
    if normalized.ends_with(' ') {
        normalized.pop();
    }
    normalized
}

fn compact_channels(text: &str) -> (String, String, bool, Vec<usize>) {
    let mut compact = String::new();
    let mut confusable_skeleton = String::new();
    let mut origin = Vec::new();
    let mut scripts = 0u8;
    for (index, ch) in text.chars().enumerate() {
        let leet = match ch {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            _ => ch,
        };
        if leet.is_alphanumeric() {
            compact.push(leet);
            confusable_skeleton.push(confusable_to_latin(leet).unwrap_or(leet));
            origin.push(index);
            scripts |= script_mask(leet);
        }
    }
    (
        compact,
        confusable_skeleton,
        scripts.count_ones() > 1,
        origin,
    )
}

fn script_mask(ch: char) -> u8 {
    if ch.is_ascii_alphabetic() || matches!(ch as u32, 0x00C0..=0x024F) {
        0b001
    } else if matches!(ch as u32, 0x0400..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F) {
        0b010
    } else if matches!(ch as u32, 0x0370..=0x03FF | 0x1F00..=0x1FFF) {
        0b100
    } else {
        0
    }
}

fn confusable_to_latin(ch: char) -> Option<char> {
    match ch {
        'а' | 'α' => Some('a'),
        'β' => Some('b'),
        'с' => Some('c'),
        'ԁ' => Some('d'),
        'е' | 'ε' => Some('e'),
        'һ' => Some('h'),
        'і' | 'ι' => Some('i'),
        'ј' => Some('j'),
        'к' | 'κ' => Some('k'),
        'ӏ' => Some('l'),
        'м' => Some('m'),
        'о' | 'ο' => Some('o'),
        'р' | 'ρ' => Some('p'),
        'ԛ' => Some('q'),
        'ѕ' => Some('s'),
        'т' | 'τ' => Some('t'),
        'у' | 'υ' => Some('y'),
        'х' | 'χ' => Some('x'),
        _ => None,
    }
}

fn is_default_ignorable(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

fn signal_from_lexical_record(rule: &LexicalRuleRecord) -> DomainSignal {
    DomainSignal {
        threat_key: rule.threat_key.clone(),
        score: rule.score,
        reason_code: rule.reason_code.clone(),
        threat_type: rule.threat_type.clone(),
        severity: rule.severity.clone(),
        priority: rule.priority,
        action: parse_action_hint(rule.action.as_deref()),
    }
}

/// Validates the metadata and match expressions in one lexical rule family.
///
/// # Errors
///
/// Returns a descriptive error for malformed metadata, invalid numeric bounds,
/// empty match expressions, or duplicate threat and reason identities.
pub fn validate_lexical_rules(rules: &[LexicalRuleRecord]) -> Result<(), String> {
    validate_lexical_rules_for_schema(LEXICON_SCHEMA_VERSION, rules)
}

/// Validates lexical rules against an explicit pack schema version.
///
/// # Errors
///
/// Returns an error for an unsupported schema, malformed rule metadata, or
/// multilingual scopes that are invalid for the selected schema.
pub fn validate_lexical_rules_for_schema(
    schema_version: u32,
    rules: &[LexicalRuleRecord],
) -> Result<(), String> {
    validate_lexicon_schema_version(schema_version, "lexical rules")?;
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
        validate_language_scope(schema_version, idx, rule)?;
        validate_matchers(idx, rule)?;
    }
    Ok(())
}

fn validate_language_scope(
    schema_version: u32,
    idx: usize,
    rule: &LexicalRuleRecord,
) -> Result<(), String> {
    if schema_version == LEXICON_SCHEMA_VERSION
        && (!rule.languages.is_empty() || !rule.scripts.is_empty())
    {
        return Err(format!(
            "rule[{idx}] language/script scopes require lexicon schema_version 2"
        ));
    }

    let mut previous_language: Option<&str> = None;
    for language in &rule.languages {
        LanguageTag::try_from(language.as_str())
            .map_err(|error| format!("rule[{idx}] has invalid language `{language}`: {error}"))?;
        if previous_language.is_some_and(|previous| previous >= language.as_str()) {
            return Err(format!("rule[{idx}] languages must be sorted and unique"));
        }
        previous_language = Some(language.as_str());
    }
    if rule.scripts.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("rule[{idx}] scripts must be sorted and unique"));
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

/// Verifies that a lexical pack uses a supported v1 or multilingual v2 schema.
///
/// # Errors
///
/// Returns an error when `actual` is outside the supported closed range.
pub fn validate_lexicon_schema_version(actual: u32, pack_name: &str) -> Result<(), String> {
    if !(LEXICON_SCHEMA_VERSION..=LATEST_LEXICON_SCHEMA_VERSION).contains(&actual) {
        return Err(format!(
            "{pack_name} schema_version mismatch: expected {}..={}, got {actual}",
            LEXICON_SCHEMA_VERSION, LATEST_LEXICON_SCHEMA_VERSION
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
        validate_lexical_rules_for_schema, validate_schema_version, CompiledLexicalRules,
        LexicalRuleRecord,
    };
    use crate::{LanguageEvidence, LanguageScript, PreparedLexicalText};

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
            languages: vec![],
            scripts: vec![],
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
            languages: vec![],
            scripts: vec![],
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
            languages: vec![],
            scripts: vec![],
            all_of: vec![],
            any_of: vec!["dont tell your parents".to_string()],
            any_groups: vec![],
        }];
        let hit = match_lexical_rules("d.o.n.t t3ll your parents", &rules);
        assert!(hit.is_some());
    }

    #[test]
    fn matches_unicode_compatibility_and_default_ignorable_evasion() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            languages: vec![],
            scripts: vec![],
            all_of: vec![],
            any_of: vec!["dont tell your parents".to_string()],
            any_groups: vec![],
        }];

        let hit = match_lexical_rules("ｄｏｎｔ\u{2060} ｔｅｌｌ ｙｏｕｒ ｐａｒｅｎｔｓ", &rules);

        assert!(hit.is_some());
    }

    #[test]
    fn matches_mixed_latin_cyrillic_and_greek_confusables() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            languages: vec![],
            scripts: vec![],
            all_of: vec![],
            any_of: vec!["dont tell your parents".to_string()],
            any_groups: vec![],
        }];

        let hit = match_lexical_rules("dоnt tεll yоur pаrents", &rules);

        assert!(hit.is_some());
    }

    #[test]
    fn confusable_skeleton_is_not_used_for_pure_cyrillic_text() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            languages: vec![],
            scripts: vec![],
            all_of: vec![],
            any_of: vec!["pace".to_string()],
            any_groups: vec![],
        }];

        assert!(match_lexical_rules("расе", &rules).is_none());
    }

    fn any_of_rule(phrase: &str) -> LexicalRuleRecord {
        LexicalRuleRecord {
            threat_key: "x".to_string(),
            reason_code: "x.reason".to_string(),
            score: 0.8,
            threat_type: Some("self_harm".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            languages: vec![],
            scripts: vec![],
            all_of: vec![],
            any_of: vec![phrase.to_string()],
            any_groups: vec![],
        }
    }

    #[test]
    fn end_it_all_requires_word_boundary() {
        let rules = vec![any_of_rule("end it all")];

        for text in [
            "I'll spend it all tomorrow",
            "friend it all the way",
            "we attend it all the time",
        ] {
            assert!(
                match_lexical_rules(text, &rules).is_none(),
                "{text} must not match a phrase embedded in a longer word"
            );
        }

        for text in [
            "i want to end it all",
            "END IT ALL!!",
            "e n d i t a l l",
            "end.it.all",
            "3nd it @ll",
        ] {
            assert!(
                match_lexical_rules(text, &rules).is_some(),
                "{text} must still match at word boundaries"
            );
        }
    }

    #[test]
    fn long_compact_needles_tolerate_glued_noise() {
        let long = vec![any_of_rule("dont tell your parents")];
        assert!(match_lexical_rules("xxdonttellyourparentsxx", &long).is_some());

        let short = vec![any_of_rule("end it all")];
        assert!(match_lexical_rules("xxenditallxx", &short).is_none());
    }

    #[test]
    fn compiled_rules_preserve_pack_order_and_unicode_matching() {
        let rules = vec![
            LexicalRuleRecord {
                threat_key: "first".to_string(),
                reason_code: "x.first".to_string(),
                score: 0.8,
                threat_type: Some("grooming".to_string()),
                severity: Some("high".to_string()),
                priority: Some(90),
                action: None,
                languages: vec![],
                scripts: vec![],
                all_of: vec![],
                any_of: vec!["dont tell your parents".to_string()],
                any_groups: vec![],
            },
            LexicalRuleRecord {
                threat_key: "second".to_string(),
                reason_code: "x.second".to_string(),
                score: 0.7,
                threat_type: Some("manipulation".to_string()),
                severity: Some("medium".to_string()),
                priority: Some(70),
                action: None,
                languages: vec![],
                scripts: vec![],
                all_of: vec![],
                any_of: vec!["our little secret".to_string()],
                any_groups: vec![],
            },
        ];
        let compiled = CompiledLexicalRules::new(&rules);

        let hits = compiled.all_matches("dоnt tell your parents, our little secret");

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].reason_code, "x.first");
        assert_eq!(hits[1].reason_code, "x.second");
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
            languages: vec![],
            scripts: vec![],
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
                languages: vec![],
                scripts: vec![],
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
                languages: vec![],
                scripts: vec![],
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
            languages: vec![],
            scripts: vec![],
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
            languages: vec![],
            scripts: vec![],
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
            languages: vec![],
            scripts: vec![],
            all_of: vec!["x".to_string()],
            any_of: vec![],
            any_groups: vec![],
        };

        let error = validate_lexical_rules(&[rule.clone(), rule]).expect_err("must fail");

        assert!(error.contains("duplicates threat_key"));
    }

    #[test]
    fn schema_v1_rejects_multilingual_rule_scope() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "scoped".to_string(),
            reason_code: "x.scoped".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            languages: vec!["en".to_string()],
            scripts: vec![LanguageScript::Latin],
            all_of: vec![],
            any_of: vec!["secret".to_string()],
            any_groups: vec![],
        }];

        let error = validate_lexical_rules(&rules).expect_err("v1 scope must fail");

        assert!(error.contains("require lexicon schema_version 2"));
    }

    #[test]
    fn schema_v2_scoped_rule_matches_only_corresponding_language() {
        let rules = vec![LexicalRuleRecord {
            threat_key: "scoped".to_string(),
            reason_code: "x.scoped".to_string(),
            score: 0.8,
            threat_type: Some("grooming".to_string()),
            severity: Some("high".to_string()),
            priority: Some(90),
            action: None,
            languages: vec!["en".to_string()],
            scripts: vec![LanguageScript::Latin],
            all_of: vec![],
            any_of: vec!["secret".to_string()],
            any_groups: vec![],
        }];
        validate_lexical_rules_for_schema(2, &rules).expect("valid v2 rules");
        let compiled = CompiledLexicalRules::new(&rules);
        let prepared = PreparedLexicalText::new("secret");
        let english = LanguageEvidence::from_text_and_hints("secret", Some("en-US"), None);
        let ukrainian = LanguageEvidence::from_text_and_hints("secret", Some("uk"), None);

        assert_eq!(
            compiled
                .all_matches_prepared_with_language(&prepared, &english)
                .len(),
            1
        );
        assert!(compiled
            .all_matches_prepared_with_language(&prepared, &ukrainian)
            .is_empty());
    }

    #[test]
    fn schema_version_mismatch_fails() {
        let error = validate_schema_version(99, "test-pack").expect_err("must fail");
        assert!(error.contains("schema_version mismatch"));
    }
}
