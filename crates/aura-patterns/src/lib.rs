//! Pattern matching library for AURA threat detection.
//!
//! Provides Aho-Corasick and regex-based pattern matching, text normalization,
//! emoji analysis, and suspicious URL detection.

pub mod database;
pub mod emoji;
pub mod matcher;
pub mod normalizer;
pub mod url_checker;

pub use database::{PatternDatabase, PatternLoadError};
pub use emoji::{EmojiAnalyzer, EmojiMatchResult};
pub use matcher::{MatchResult, PatternMatcher, PatternMatcherBuildError};
pub use normalizer::TextNormalizer;
pub use url_checker::{SuspiciousUrl, UrlChecker};
