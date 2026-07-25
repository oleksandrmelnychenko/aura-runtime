//! Pattern matching library for AURA threat detection.
//!
//! Provides Aho-Corasick and regex-based pattern matching, text normalization,
//! emoji analysis, and suspicious URL detection.

pub mod coordinates;
pub mod database;
pub mod emoji;
pub mod matcher;
pub mod normalizer;
mod routing;
pub mod url_checker;

pub use coordinates::{validate_ukraine_coordinates, CoordinateFormat, CoordinateMatch};
pub use database::{PatternDatabase, PatternLoadError};
pub use emoji::{EmojiAnalyzer, EmojiMatchResult};
pub use matcher::{MatchResult, PatternMatcher, PatternMatcherBuildError};
pub use normalizer::TextNormalizer;
pub use routing::{
    event_kind_for_rule, is_shadowed_generic_coordinate_rule, military_threat_subtype,
    requires_ukraine_coordinate_validation, MilitaryPatternFamily, PatternEventKind,
};
pub use url_checker::{BlockedUrlMatch, SuspiciousUrl, UrlChecker};
