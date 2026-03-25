use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use idna::domain_to_ascii;

use crate::database::{PatternDatabase, PatternKind};

const MAX_URL_TOKENS_PER_TEXT: usize = 256;
const MAX_URL_TOKEN_LEN: usize = 4096;
const MAX_URL_HOST_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct SuspiciousUrl {
    pub url: String,
    pub score: f32,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockedUrlMatch {
    pub url: String,
    pub domain: String,
    pub matched_domain: String,
    pub rule_id: String,
    pub threat_type: String,
    pub score: f32,
    pub explanation: String,
}

#[derive(Debug, Clone)]
struct BlockedDomainRule {
    domain: String,
    rule_id: String,
    threat_type: String,
    score: f32,
    explanation: String,
}

struct ParsedUrl {
    domain: String,
    host: String,
    host_lower: String,
    token_starts_http: bool,
}

#[derive(Default)]
struct BlockedDomainTrieNode {
    children: HashMap<String, BlockedDomainTrieNode>,
    rules: Vec<BlockedDomainRule>,
}

pub struct UrlChecker {
    blocked_domain_trie: BlockedDomainTrieNode,
    blocked_count: usize,
}

impl UrlChecker {
    pub fn from_database(db: &PatternDatabase) -> Self {
        let mut blocked_unique = HashSet::new();
        let mut blocked_domain_trie = BlockedDomainTrieNode::default();
        for rule in &db.rules {
            if let PatternKind::UrlDomain { domains } = &rule.kind {
                for domain in domains {
                    if let Some(normalized) = normalize_domain(domain) {
                        blocked_unique.insert(normalized.clone());
                        let mut node = &mut blocked_domain_trie;
                        for label in normalized.rsplit('.') {
                            node = node.children.entry(label.to_string()).or_default();
                        }
                        node.rules.push(BlockedDomainRule {
                            domain: normalized,
                            rule_id: rule.id.clone(),
                            threat_type: rule.threat_type.clone(),
                            score: rule.score,
                            explanation: rule.explanation.clone(),
                        });
                    }
                }
            }
        }
        Self {
            blocked_domain_trie,
            blocked_count: blocked_unique.len(),
        }
    }

    pub fn is_blocked(&self, url: &str) -> bool {
        let Some(parsed) = Self::parse_url(url) else {
            return false;
        };
        self.has_blocked_domain_match(&parsed.domain)
    }

    pub fn find_blocked_matches(&self, text: &str) -> Vec<BlockedUrlMatch> {
        let mut matches = Vec::new();
        for_each_url_token(text, |url| {
            let Some(parsed) = Self::parse_url(url) else {
                return;
            };
            if let Some(hit) = self.blocked_match_for_domain(url, &parsed.domain) {
                matches.push(hit);
            }
        });
        matches
    }

    pub fn find_blocked_urls(&self, text: &str) -> Vec<String> {
        self.find_blocked_matches(text)
            .into_iter()
            .map(|blocked| blocked.url)
            .collect()
    }

    pub fn find_suspicious_urls(&self, text: &str) -> Vec<SuspiciousUrl> {
        let mut merged: HashMap<String, SuspiciousUrl> = HashMap::new();

        for_each_url_token(text, |url| {
            let Some(parsed) = Self::parse_url(url) else {
                return;
            };
            if self.has_blocked_domain_match(&parsed.domain) {
                return;
            }
            if let Some(hit) = self.assess_suspicious_url_parsed(url, &parsed) {
                upsert_suspicious_hit(&mut merged, hit);
            }
            if let Some(hit) = self.detect_doppelganger_domain(url, &parsed.domain) {
                upsert_suspicious_hit(&mut merged, hit);
            }
            if let Some(hit) = self.detect_homoglyph_host(url, &parsed.host, &parsed.host_lower) {
                upsert_suspicious_hit(&mut merged, hit);
            }
        });

        merged.into_values().collect()
    }

    fn extract_domain(url: &str) -> Option<String> {
        let host = Self::extract_host(url)?;
        normalize_domain(host)
    }

    fn blocked_match_for_domain(&self, url: &str, domain: &str) -> Option<BlockedUrlMatch> {
        let mut best: Option<(BlockedDomainRule, bool)> = None;

        self.for_each_blocked_match(domain, |rule, exact_match| {
            let should_replace = match &best {
                Some((current, current_exact)) => {
                    if exact_match != *current_exact {
                        exact_match
                    } else if rule.domain.len() != current.domain.len() {
                        rule.domain.len() > current.domain.len()
                    } else {
                        rule.score > current.score
                    }
                }
                None => true,
            };

            if should_replace {
                best = Some((rule.clone(), exact_match));
            }
            false
        });

        best.map(|(rule, _)| BlockedUrlMatch {
            url: url.to_string(),
            domain: domain.to_string(),
            matched_domain: rule.domain,
            rule_id: rule.rule_id,
            threat_type: rule.threat_type,
            score: rule.score,
            explanation: rule.explanation,
        })
    }

    fn assess_suspicious_url_parsed(&self, url: &str, parsed: &ParsedUrl) -> Option<SuspiciousUrl> {
        let normalized = normalize_obfuscated_token(&parsed.host_lower);
        let tld = parsed.domain.rsplit('.').next().unwrap_or_default();
        let suspicious_tld = matches!(tld, "xyz" | "top" | "win" | "club" | "cc");
        let digit_count = parsed.domain.chars().filter(|c| c.is_ascii_digit()).count();
        let hyphen_count = parsed.domain.matches('-').count();
        let keyword_hits: Vec<&str> = suspicious_keywords()
            .iter()
            .copied()
            .filter(|keyword| parsed.host_lower.contains(keyword) || normalized.contains(keyword))
            .collect();

        let keyword_count = keyword_hits.len();
        let looks_suspicious = keyword_count >= 2
            || (suspicious_tld && keyword_count >= 1)
            || (digit_count >= 2 && keyword_count >= 1);
        if !looks_suspicious {
            return None;
        }

        let mut features = Vec::new();
        if suspicious_tld {
            features.push(format!("tld={tld}"));
        }
        if parsed.token_starts_http {
            features.push("scheme=http".to_string());
        }
        if digit_count >= 2 {
            features.push("digit_obfuscation".to_string());
        }
        if hyphen_count >= 2 {
            features.push("hyphenated_domain".to_string());
        }
        if !keyword_hits.is_empty() {
            features.push(format!("keywords={}", keyword_hits.join("+")));
        }

        let score = if suspicious_tld && keyword_count >= 1 {
            0.82
        } else if keyword_count >= 3 {
            0.80
        } else {
            0.75
        };

        Some(SuspiciousUrl {
            url: url.to_string(),
            score,
            explanation: format!("Heuristic suspicious host ({})", features.join(", ")),
        })
    }

    pub fn detect_doppelganger(&self, url: &str) -> Option<SuspiciousUrl> {
        let parsed = Self::parse_url(url)?;
        self.detect_doppelganger_domain(url, &parsed.domain)
    }

    fn detect_doppelganger_domain(&self, url: &str, domain: &str) -> Option<SuspiciousUrl> {
        const LEGITIMATE_MEDIA: &[&str] = &[
            "bild",
            "lemonde",
            "spiegel",
            "guardian",
            "bbc",
            "reuters",
            "washingtonpost",
            "nytimes",
            "cnn",
            "foxnews",
            "dw",
            "france24",
            "euronews",
            "politico",
            "economist",
            "telegraph",
        ];
        const DOPPELGANGER_TLDS: &[&str] = &[
            ".ltd", ".live", ".news", ".online", ".info", ".top", ".site", ".click",
        ];
        let dot_pos = domain.rfind('.')?;
        let tld_with_dot = &domain[dot_pos..];
        let base = &domain[..dot_pos];

        let base_clean = base.rsplit('.').next().unwrap_or(base);

        let is_media = LEGITIMATE_MEDIA.iter().any(|m| *m == base_clean);
        let is_suspect_tld = DOPPELGANGER_TLDS.iter().any(|t| *t == tld_with_dot);

        if is_media && is_suspect_tld {
            Some(SuspiciousUrl {
                url: url.to_string(),
                score: 0.90,
                explanation: format!(
                    "Doppelganger campaign: domain '{}' mimics legitimate media '{}' with suspicious TLD '{}'",
                    domain, base_clean, tld_with_dot,
                ),
            })
        } else {
            None
        }
    }

    pub fn detect_homoglyph_domain(&self, url: &str) -> Option<SuspiciousUrl> {
        let parsed = Self::parse_url(url)?;
        self.detect_homoglyph_host(url, &parsed.host, &parsed.host_lower)
    }

    fn detect_homoglyph_host(
        &self,
        url: &str,
        host: &str,
        host_lower: &str,
    ) -> Option<SuspiciousUrl> {
        let has_cyrillic = host_lower.chars().any(|c| {
            matches!(c,
                '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}'
            )
        });
        if !has_cyrillic {
            return None;
        }

        let normalized: String = host_lower
            .chars()
            .map(|c| match c {
                '\u{0430}' => 'a', // а→a
                '\u{0435}' => 'e', // е→e
                '\u{043E}' => 'o', // о→o
                '\u{0440}' => 'p', // р→p
                '\u{0441}' => 'c', // с→c
                '\u{0443}' => 'y', // у→y
                '\u{0445}' => 'x', // х→x
                '\u{0456}' => 'i', // і→i
                '\u{0457}' => 'i', // ї→i
                '\u{0454}' => 'e', // є→e
                '\u{043D}' => 'h', // н→h (lookalike)
                '\u{043A}' => 'k', // к→k
                '\u{0442}' => 't', // т→t
                '\u{0412}' => 'b', // В→B (lowercased)
                '\u{0432}' => 'b', // в (lowercase of В)
                '\u{041C}' => 'm', // М→M (lowercased)
                '\u{043C}' => 'm', // м (lowercase of М)
                '\u{041D}' => 'h', // Н→H (lowercased)
                other => other,
            })
            .collect();

        if self.has_blocked_domain_match(&normalized) {
            return Some(SuspiciousUrl {
                url: url.to_string(),
                score: 0.92,
                explanation: format!(
                    "Homoglyph attack: domain '{}' uses mixed Cyrillic/Latin characters to mimic '{}'",
                    host, normalized,
                ),
            });
        }

        None
    }

    fn has_blocked_domain_match(&self, domain: &str) -> bool {
        let mut matched = false;
        self.for_each_blocked_match(domain, |_, _| {
            matched = true;
            true
        });
        matched
    }

    fn for_each_blocked_match<F>(&self, domain: &str, mut on_match: F)
    where
        F: FnMut(&BlockedDomainRule, bool) -> bool,
    {
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.is_empty() {
            return;
        }

        let mut node = &self.blocked_domain_trie;
        for (idx, label) in labels.iter().rev().enumerate() {
            let Some(next) = node.children.get(*label) else {
                return;
            };
            node = next;
            if node.rules.is_empty() {
                continue;
            }
            let exact_match = idx + 1 == labels.len();
            for rule in &node.rules {
                if on_match(rule, exact_match) {
                    return;
                }
            }
        }
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked_count
    }

    fn extract_host(url: &str) -> Option<&str> {
        let token = trim_url_token(url);
        if token.is_empty() || token.len() > MAX_URL_TOKEN_LEN {
            return None;
        }
        let without_scheme = token
            .strip_prefix("https://")
            .or_else(|| token.strip_prefix("http://"))
            .or_else(|| token.strip_prefix("www."))
            .unwrap_or(token);
        let authority = without_scheme.split(['/', '?', '#']).next()?;
        let host = extract_host_from_authority(authority)?;
        if host.is_empty() || host.len() > MAX_URL_HOST_LEN {
            return None;
        }
        Some(host)
    }

    fn parse_url(url: &str) -> Option<ParsedUrl> {
        let token = trim_url_token(url);
        let host = Self::extract_host(url)?;
        let domain = normalize_domain(host)?;
        let host_lower: String = host.chars().flat_map(|c| c.to_lowercase()).collect();
        Some(ParsedUrl {
            domain,
            host: host.to_string(),
            host_lower,
            token_starts_http: token.starts_with("http://"),
        })
    }
}

fn suspicious_keywords() -> &'static [&'static str] {
    &[
        "robux", "bonus", "gift", "claim", "prize", "verify", "security", "login", "reward",
        "free", "spin", "account", "profile", "support", "update",
    ]
}

fn normalize_obfuscated_token(token: &str) -> String {
    token
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            _ => c,
        })
        .collect()
}

fn upsert_suspicious_hit(merged: &mut HashMap<String, SuspiciousUrl>, incoming: SuspiciousUrl) {
    if let Some(existing) = merged.get_mut(&incoming.url) {
        if incoming.score > existing.score {
            existing.score = incoming.score;
        }
        existing.explanation =
            merge_reason_explanations(&existing.explanation, &incoming.explanation);
        return;
    }
    merged.insert(incoming.url.clone(), incoming);
}

fn merge_reason_explanations(existing: &str, incoming: &str) -> String {
    let mut reasons: Vec<String> = Vec::new();
    for reason in existing.split(" | ") {
        let reason = reason.trim();
        if !reason.is_empty() && !reasons.iter().any(|r| r == reason) {
            reasons.push(reason.to_string());
        }
    }
    let incoming = incoming.trim();
    if !incoming.is_empty() && !reasons.iter().any(|r| r == incoming) {
        reasons.push(incoming.to_string());
    }
    reasons.sort_by(|a, b| {
        reason_priority(a)
            .cmp(&reason_priority(b))
            .then_with(|| a.cmp(b))
    });
    if reasons.len() > 3 {
        reasons.truncate(3);
    }
    reasons.join(" | ")
}

fn reason_priority(reason: &str) -> u8 {
    if reason.starts_with("Homoglyph attack:") {
        0
    } else if reason.starts_with("Doppelganger campaign:") {
        1
    } else if reason.starts_with("Heuristic suspicious host") {
        2
    } else {
        3
    }
}

pub(crate) fn normalize_domain(domain: &str) -> Option<String> {
    let trimmed = domain.trim().trim_matches('.');
    if trimmed.is_empty() || trimmed.contains('@') {
        return None;
    }
    if let Ok(ipv4) = trimmed.parse::<Ipv4Addr>() {
        return Some(ipv4.to_string());
    }
    if let Ok(ipv6) = trimmed.parse::<Ipv6Addr>() {
        return Some(ipv6.to_string());
    }
    if !trimmed.contains('.') {
        return None;
    }

    let ascii = domain_to_ascii(trimmed).ok()?.to_lowercase();
    let ascii = ascii.trim_end_matches('.').to_string();
    let labels = ascii.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return None;
    }
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) {
        return None;
    }

    let tld = *labels.last()?;
    if !(tld.starts_with("xn--") || tld.chars().any(|c| c.is_ascii_alphabetic())) {
        return None;
    }

    Some(ascii)
}

fn extract_host_from_authority(authority: &str) -> Option<&str> {
    let authority = authority.rsplit('@').next()?;
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(&authority[1..end]);
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if !host.contains(':') && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Some(host);
        }
    }
    Some(authority)
}

fn trim_url_token(token: &str) -> &str {
    token.trim_matches(|c: char| {
        matches!(
            c,
            ',' | '.' | ';' | ':' | '!' | '?' | ')' | '(' | ']' | '[' | '}' | '{' | '"' | '\''
        )
    })
}

fn for_each_url_token<F>(text: &str, mut f: F)
where
    F: FnMut(&str),
{
    let mut processed = 0usize;
    for token in text.split_whitespace() {
        if processed >= MAX_URL_TOKENS_PER_TEXT {
            break;
        }
        let token = trim_url_token(token);
        if is_url_like(token) {
            f(token);
            processed += 1;
        }
    }
}

fn is_url_like(token: &str) -> bool {
    let has_scheme = token.starts_with("http://") || token.starts_with("https://");
    let starts_with_www = token.starts_with("www.");
    let contains_path = token.contains('/');
    let looks_like_bare_domain = token.contains('.') && !token.contains('@');

    (has_scheme || starts_with_www || contains_path || looks_like_bare_domain)
        && UrlChecker::extract_domain(token).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::PatternDatabase;
    use std::collections::HashMap;
    use std::time::Instant;

    fn test_db() -> PatternDatabase {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "url_block_001",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["malware-site.com", "phishing-example.net", "fake-bank.org"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Known malicious domain"
                }
            ]
        }"#;
        PatternDatabase::from_json_validated(json).unwrap()
    }

    #[test]
    fn blocks_exact_domain() {
        let checker = UrlChecker::from_database(&test_db());
        assert!(checker.is_blocked("https://malware-site.com/payload"));
        assert!(checker.is_blocked("http://phishing-example.net"));
    }

    #[test]
    fn blocks_subdomain() {
        let checker = UrlChecker::from_database(&test_db());
        assert!(checker.is_blocked("https://login.fake-bank.org/verify"));
    }

    #[test]
    fn does_not_block_suffix_without_domain_boundary() {
        let checker = UrlChecker::from_database(&test_db());
        assert!(!checker.is_blocked("https://notfake-bank.org/login"));
    }

    #[test]
    fn allows_safe_domain() {
        let checker = UrlChecker::from_database(&test_db());
        assert!(!checker.is_blocked("https://google.com"));
        assert!(!checker.is_blocked("https://github.com"));
    }

    #[test]
    fn finds_blocked_urls_in_text() {
        let checker = UrlChecker::from_database(&test_db());
        let text = "Check this out: https://malware-site.com/free and also https://google.com";
        let blocked = checker.find_blocked_urls(text);
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].contains("malware-site.com"));
    }

    #[test]
    fn blocked_matches_preserve_rule_metadata() {
        let checker = UrlChecker::from_database(&test_db());
        let blocked = checker.find_blocked_matches("https://phishing-example.net/reset");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].rule_id, "url_block_001");
        assert_eq!(blocked[0].threat_type, "phishing");
        assert_eq!(blocked[0].matched_domain, "phishing-example.net");
    }

    #[test]
    fn extracts_domain_correctly() {
        assert_eq!(
            UrlChecker::extract_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            UrlChecker::extract_domain("https://sub.example.com:8080/path"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(
            UrlChecker::extract_domain("http://203.0.113.7/admin"),
            Some("203.0.113.7".to_string())
        );
        assert_eq!(
            UrlChecker::extract_domain("https://[2001:db8::1]:8443/path"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn normalizes_punycode_and_unicode_domains() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "url_block_idn",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["bücher.example"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Known malicious IDN domain"
                }
            ]
        }"#;
        let db = PatternDatabase::from_json_validated(json).unwrap();
        let checker = UrlChecker::from_database(&db);

        assert!(checker.is_blocked("https://bücher.example/path"));
        assert!(checker.is_blocked("https://xn--bcher-kva.example/path"));
    }

    #[test]
    fn blocks_ipv4_literal_domains() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "url_block_ip",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["203.0.113.7"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Known malicious IP host"
                }
            ]
        }"#;
        let db = PatternDatabase::from_json_validated(json).unwrap();
        let checker = UrlChecker::from_database(&db);

        assert!(checker.is_blocked("http://203.0.113.7/login"));
    }

    #[test]
    fn does_not_treat_email_as_url() {
        let checker = UrlChecker::from_database(&test_db());
        let blocked = checker.find_blocked_urls("email me at help@malware-site.com please");
        assert!(blocked.is_empty());
    }

    #[test]
    fn rejects_non_url_dot_slash_tokens() {
        let checker = UrlChecker::from_database(&test_db());
        let blocked = checker.find_blocked_urls("release-1.2/notes is not a link");
        assert!(blocked.is_empty());
    }

    #[test]
    fn flags_suspicious_reward_link_by_heuristic() {
        let checker = UrlChecker::from_database(&test_db());
        let hits = checker
            .find_suspicious_urls("grab this now http://fr33-r0bux.xyz/claim before it expires");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].explanation.contains("keywords="));
        assert!(hits[0].explanation.contains("robux"));
        assert!(hits[0].score >= 0.75);
    }

    #[test]
    fn does_not_flag_normal_product_link() {
        let checker = UrlChecker::from_database(&test_db());
        let hits = checker.find_suspicious_urls("docs: https://support.apple.com/en-us/guide");
        assert!(hits.is_empty());
    }

    #[test]
    fn does_not_flag_keywords_only_in_path_for_safe_host() {
        let checker = UrlChecker::from_database(&test_db());
        let hits = checker.find_suspicious_urls(
            "read this https://example.com/free-account-login-update-guide for docs",
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn test_doppelganger_detection() {
        let checker = UrlChecker::from_database(&test_db());
        let result = checker.detect_doppelganger("https://bild.ltd/article");
        assert!(result.is_some());
        let hit = result.unwrap();
        assert!((hit.score - 0.90).abs() < f32::EPSILON);
        assert!(hit.explanation.contains("Doppelganger"));
    }

    #[test]
    fn test_doppelganger_legitimate_domain() {
        let checker = UrlChecker::from_database(&test_db());
        let result = checker.detect_doppelganger("https://bild.de/news");
        assert!(result.is_none());
    }

    #[test]
    fn test_homoglyph_cyrillic_domain() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "url_block_gov",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["gov.ua"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Government domain"
                }
            ]
        }"#;
        let db = PatternDatabase::from_json_validated(json).unwrap();
        let checker = UrlChecker::from_database(&db);

        let spoofed_url = "https://g\u{043E}v.ua/login";
        let result = checker.detect_homoglyph_domain(spoofed_url);
        assert!(result.is_some());
        let hit = result.unwrap();
        assert!((hit.score - 0.92).abs() < f32::EPSILON);
        assert!(hit.explanation.contains("Homoglyph"));
    }

    #[test]
    fn test_no_homoglyph_in_clean_domain() {
        let checker = UrlChecker::from_database(&test_db());
        let result = checker.detect_homoglyph_domain("https://google.com");
        assert!(result.is_none());
    }

    #[test]
    fn blocked_matches_prefer_more_specific_domain() {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "broad_domain",
                    "threat_type": "propaganda",
                    "kind": { "type": "url_domain", "domains": ["example.com"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Broad domain"
                },
                {
                    "id": "specific_domain",
                    "threat_type": "propaganda",
                    "kind": { "type": "url_domain", "domains": ["secure.example.com"] },
                    "score": 0.75,
                    "languages": [],
                    "explanation": "Specific domain"
                }
            ]
        }"#;
        let db = PatternDatabase::from_json_validated(json).unwrap();
        let checker = UrlChecker::from_database(&db);
        let blocked = checker.find_blocked_matches("https://secure.example.com/login");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].rule_id, "specific_domain");
        assert_eq!(blocked[0].matched_domain, "secure.example.com");
    }

    #[test]
    fn suspicious_urls_are_deduplicated_per_url() {
        let checker = UrlChecker::from_database(&test_db());
        let text = "watch http://fr33-r0bux.xyz/claim and again http://fr33-r0bux.xyz/claim";
        let hits = checker.find_suspicious_urls(text);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn merge_suspicious_hit_keeps_max_score_and_reasons() {
        let mut merged = HashMap::new();
        upsert_suspicious_hit(
            &mut merged,
            SuspiciousUrl {
                url: "https://x.example".to_string(),
                score: 0.75,
                explanation: "reason-a".to_string(),
            },
        );
        upsert_suspicious_hit(
            &mut merged,
            SuspiciousUrl {
                url: "https://x.example".to_string(),
                score: 0.92,
                explanation: "reason-b".to_string(),
            },
        );

        let hit = merged.get("https://x.example").unwrap();
        assert!((hit.score - 0.92).abs() < f32::EPSILON);
        assert!(hit.explanation.contains("reason-a"));
        assert!(hit.explanation.contains("reason-b"));
    }

    #[test]
    fn merge_suspicious_hit_orders_reasons_by_priority() {
        let mut merged = HashMap::new();
        upsert_suspicious_hit(
            &mut merged,
            SuspiciousUrl {
                url: "https://x.example".to_string(),
                score: 0.75,
                explanation: "Heuristic suspicious host (keywords=login)".to_string(),
            },
        );
        upsert_suspicious_hit(
            &mut merged,
            SuspiciousUrl {
                url: "https://x.example".to_string(),
                score: 0.90,
                explanation: "Doppelganger campaign: domain 'bild.ltd' mimics legitimate media 'bild' with suspicious TLD '.ltd'".to_string(),
            },
        );
        upsert_suspicious_hit(
            &mut merged,
            SuspiciousUrl {
                url: "https://x.example".to_string(),
                score: 0.92,
                explanation: "Homoglyph attack: domain 'gоv.ua' uses mixed Cyrillic/Latin characters to mimic 'gov.ua'".to_string(),
            },
        );

        let hit = merged.get("https://x.example").unwrap();
        let parts: Vec<&str> = hit.explanation.split(" | ").collect();
        assert!(parts[0].starts_with("Homoglyph attack:"));
        assert!(parts[1].starts_with("Doppelganger campaign:"));
        assert!(parts[2].starts_with("Heuristic suspicious host"));
    }

    #[test]
    fn caps_number_of_url_tokens_processed() {
        let checker = UrlChecker::from_database(&test_db());
        let mut text = String::new();
        for _ in 0..(MAX_URL_TOKENS_PER_TEXT + 40) {
            text.push_str(" https://malware-site.com/path");
        }
        let blocked = checker.find_blocked_urls(&text);
        assert_eq!(blocked.len(), MAX_URL_TOKENS_PER_TEXT);
    }

    #[test]
    fn rejects_oversized_url_token() {
        let checker = UrlChecker::from_database(&test_db());
        let oversized = format!("https://{}", "a".repeat(MAX_URL_TOKEN_LEN + 10));
        assert!(!checker.is_blocked(&oversized));
    }

    #[test]
    #[ignore]
    fn perf_trie_lookup_matches_naive_scan() {
        let mut domains = Vec::new();
        for i in 0..5000 {
            domains.push(format!("malicious-{i}.example.com"));
        }
        domains.push("secure.example.com".to_string());

        let domain_json = domains
            .iter()
            .map(|domain| format!("\"{domain}\""))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {{
                    "id": "url_block_perf",
                    "threat_type": "phishing",
                    "kind": {{ "type": "url_domain", "domains": [{domain_json}] }},
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Perf test domain set"
                }}
            ]
        }}"#
        );

        let db = PatternDatabase::from_json_validated(&json).unwrap();
        let checker = UrlChecker::from_database(&db);
        let mut blocked_domains = Vec::new();
        for rule in &db.rules {
            if let PatternKind::UrlDomain { domains } = &rule.kind {
                for domain in domains {
                    if let Some(normalized) = normalize_domain(domain) {
                        blocked_domains.push(normalized);
                    }
                }
            }
        }

        let mut urls = Vec::new();
        for i in 0..1000 {
            urls.push(format!("https://safe-{i}.example.org/login"));
            urls.push(format!("https://malicious-{i}.example.com/phish"));
        }
        urls.push("https://x.secure.example.com/session".to_string());

        let mut trie_hits = 0usize;
        let start_trie = Instant::now();
        for _ in 0..30 {
            for url in &urls {
                if checker.is_blocked(url) {
                    trie_hits += 1;
                }
            }
        }
        let trie_elapsed = start_trie.elapsed();

        let mut naive_hits = 0usize;
        let start_naive = Instant::now();
        for _ in 0..30 {
            for url in &urls {
                let Some(domain) = UrlChecker::extract_domain(url) else {
                    continue;
                };
                if blocked_domains
                    .iter()
                    .any(|blocked| domain == *blocked || domain.ends_with(&format!(".{blocked}")))
                {
                    naive_hits += 1;
                }
            }
        }
        let naive_elapsed = start_naive.elapsed();

        assert_eq!(trie_hits, naive_hits);
        println!(
            "trie_elapsed_ms={} naive_elapsed_ms={}",
            trie_elapsed.as_millis(),
            naive_elapsed.as_millis()
        );
    }
}
