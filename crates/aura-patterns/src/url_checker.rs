use std::collections::HashSet;

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
                    blocked.insert(domain.to_lowercase());
                }
            }
        }
        Self {
            blocked_domains: blocked,
        }
    }

    pub fn is_blocked(&self, url: &str) -> bool {
        if let Some(domain) = Self::extract_domain(url) {
            let lower = domain.to_lowercase();

            if self.blocked_domains.contains(&lower) {
                return true;
            }

            for blocked in &self.blocked_domains {
                if lower.ends_with(&format!(".{blocked}")) {
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

    fn extract_domain(url: &str) -> Option<&str> {
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        let domain = without_scheme.split('/').next()?;
        let domain = domain.split(':').next()?;

        let domain = domain.split('?').next()?;

        if domain.contains('.') {
            Some(domain)
        } else {
            None
        }
    }

    fn extract_urls(text: &str) -> Vec<String> {
        text.split_whitespace()
            .filter(|word| {
                word.starts_with("http://")
                    || word.starts_with("https://")
                    || (word.contains('.') && word.contains('/'))
            })
            .map(|w| w.trim_matches(|c: char| c == ',' || c == '.' || c == ')' || c == ']'))
            .map(String::from)
            .collect()
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked_domains.len()
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
                    "id": "url_block_001",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["malware-site.com", "phishing-example.net", "fake-bank.org"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Known malicious domain"
                }
            ]
        }"#;
        PatternDatabase::from_json(json).unwrap()
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
            Some("example.com")
        );
        assert_eq!(
            UrlChecker::extract_domain("https://sub.example.com:8080/path"),
            Some("sub.example.com")
        );
    }
}
