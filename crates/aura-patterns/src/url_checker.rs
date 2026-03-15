use std::collections::HashSet;

use idna::domain_to_ascii;

use crate::database::{PatternDatabase, PatternKind};

pub struct UrlChecker {
    blocked_domains: HashSet<String>,
}

impl UrlChecker {
    pub fn from_database(db: &PatternDatabase) -> Self {
        let mut blocked = HashSet::new();
        for rule in &db.rules {
            if let PatternKind::UrlDomain { domains } = &rule.kind {
                for domain in domains {
                    if let Some(normalized) = normalize_domain(domain) {
                        blocked.insert(normalized);
                    }
                }
            }
        }
        Self {
            blocked_domains: blocked,
        }
    }

    pub fn is_blocked(&self, url: &str) -> bool {
        if let Some(domain) = Self::extract_domain(url) {
            if self.blocked_domains.contains(&domain) {
                return true;
            }

            for blocked in &self.blocked_domains {
                if domain.ends_with(&format!(".{blocked}")) {
                    return true;
                }
            }
        }
        false
    }

    pub fn find_blocked_urls(&self, text: &str) -> Vec<String> {
        Self::extract_urls(text)
            .into_iter()
            .filter(|url| self.is_blocked(url))
            .collect()
    }

    fn extract_domain(url: &str) -> Option<String> {
        let token = trim_url_token(url);
        let without_scheme = token
            .strip_prefix("https://")
            .or_else(|| token.strip_prefix("http://"))
            .or_else(|| token.strip_prefix("www."))
            .unwrap_or(token);

        let authority = without_scheme
            .split(['/', '?', '#'])
            .next()?
            .split('@')
            .next_back()?;
        let host = authority.split(':').next()?;

        normalize_domain(host)
    }

    fn extract_urls(text: &str) -> Vec<String> {
        text.split_whitespace()
            .map(trim_url_token)
            .filter(|word| is_url_like(word))
            .map(String::from)
            .collect()
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked_domains.len()
    }
}

pub(crate) fn normalize_domain(domain: &str) -> Option<String> {
    let trimmed = domain.trim().trim_matches('.');
    if trimmed.is_empty() || trimmed.contains('@') || !trimmed.contains('.') {
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

fn trim_url_token(token: &str) -> &str {
    token.trim_matches(|c: char| {
        matches!(
            c,
            ',' | '.' | ';' | ':' | '!' | '?' | ')' | '(' | ']' | '[' | '}' | '{' | '"' | '\''
        )
    })
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
    fn extracts_domain_correctly() {
        assert_eq!(
            UrlChecker::extract_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            UrlChecker::extract_domain("https://sub.example.com:8080/path"),
            Some("sub.example.com".to_string())
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
}
