//! Typed, content-minimizing language evidence for multilingual detector routing.

use std::collections::BTreeMap;
use std::fmt;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Maximum accepted length of a normalized BCP-47-style language tag.
pub const MAX_LANGUAGE_TAG_BYTES: usize = 35;
/// Maximum message-level language candidates accepted at a trust boundary.
pub const MAX_LANGUAGE_CANDIDATES: usize = 4;
/// Maximum non-overlapping language spans accepted for one message.
pub const MAX_LANGUAGE_SPANS: usize = 32;

/// A validated, lowercase BCP-47-style language tag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LanguageTag(String);

impl LanguageTag {
    /// Returns the normalized tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the primary language subtag without region or variant suffixes.
    #[must_use]
    pub fn primary(&self) -> &str {
        self.0.split('-').next().unwrap_or(self.0.as_str())
    }
}

impl fmt::Display for LanguageTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for LanguageTag {
    type Error = LanguageEvidenceError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX_LANGUAGE_TAG_BYTES
            || value.contains('_')
            || !value.is_ascii()
        {
            return Err(LanguageEvidenceError::InvalidLanguageTag);
        }

        let normalized = value.to_ascii_lowercase();
        let mut components = normalized.split('-');
        let language = components
            .next()
            .ok_or(LanguageEvidenceError::InvalidLanguageTag)?;
        if !(2..=8).contains(&language.len())
            || !language.bytes().all(|byte| byte.is_ascii_lowercase())
        {
            return Err(LanguageEvidenceError::InvalidLanguageTag);
        }
        if !components.all(|component| {
            (1..=8).contains(&component.len())
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        }) {
            return Err(LanguageEvidenceError::InvalidLanguageTag);
        }

        Ok(Self(normalized))
    }
}

impl Serialize for LanguageTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LanguageTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw.as_str()).map_err(D::Error::custom)
    }
}

/// Unicode script families used to route language-specific detector packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageScript {
    /// Latin-derived alphabets.
    Latin,
    /// Cyrillic-derived alphabets.
    Cyrillic,
    /// Greek alphabet.
    Greek,
    /// Arabic-derived alphabets.
    Arabic,
    /// Hebrew alphabet.
    Hebrew,
    /// Devanagari-derived alphabets.
    Devanagari,
    /// Han ideographs.
    Han,
    /// Japanese hiragana.
    Hiragana,
    /// Japanese katakana.
    Katakana,
    /// Korean hangul.
    Hangul,
    /// An alphabetic script not yet mapped to a dedicated route.
    Other,
}

impl LanguageScript {
    /// Returns conservative language routes suggested by this script.
    ///
    /// Script evidence is intentionally broader than language identification:
    /// Cyrillic alone cannot safely distinguish Ukrainian from Russian, for
    /// example, so both currently supported packs are returned.
    #[must_use]
    pub fn conservative_language_routes(self) -> &'static [&'static str] {
        match self {
            Self::Latin => &["en"],
            Self::Cyrillic => &["uk", "ru"],
            Self::Greek => &["el"],
            Self::Arabic => &["ar"],
            Self::Hebrew => &["he"],
            Self::Devanagari => &["hi"],
            Self::Han => &["zh"],
            Self::Hiragana | Self::Katakana => &["ja"],
            Self::Hangul => &["ko"],
            Self::Other => &[],
        }
    }
}

/// Origin of one language candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageEvidenceSource {
    /// Per-message hint supplied by the client boundary.
    MessageHint,
    /// Language classification performed locally on the message content.
    OnDeviceClassifier,
    /// Default language configured for the local runtime.
    RuntimeDefault,
}

/// One validated language candidate without retaining message content.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LanguageCandidate {
    /// Normalized language tag.
    tag: LanguageTag,
    /// Confidence assigned by the evidence source in `0..=1`.
    confidence: f32,
    /// Source of the candidate.
    source: LanguageEvidenceSource,
}

impl LanguageCandidate {
    /// Creates a validated candidate.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed language tag or non-finite/out-of-range
    /// confidence.
    pub fn try_new(
        tag: &str,
        confidence: f32,
        source: LanguageEvidenceSource,
    ) -> Result<Self, LanguageEvidenceError> {
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err(LanguageEvidenceError::InvalidConfidence);
        }
        Ok(Self {
            tag: LanguageTag::try_from(tag)?,
            confidence,
            source,
        })
    }

    /// Returns the validated language tag.
    #[must_use]
    pub fn tag(&self) -> &LanguageTag {
        &self.tag
    }

    /// Returns the bounded source confidence.
    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.confidence
    }

    /// Returns the evidence source.
    #[must_use]
    pub fn source(&self) -> LanguageEvidenceSource {
        self.source
    }
}

/// Count of alphabetic scalars observed for one script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScriptEvidence {
    /// Observed script family.
    script: LanguageScript,
    /// Saturating count of alphabetic Unicode scalars in the message.
    scalar_count: u32,
}

impl ScriptEvidence {
    /// Returns the observed script family.
    #[must_use]
    pub fn script(self) -> LanguageScript {
        self.script
    }

    /// Returns the saturating alphabetic scalar count.
    #[must_use]
    pub fn scalar_count(self) -> u32 {
        self.scalar_count
    }
}

/// One validated, non-overlapping UTF-8 language span without plaintext.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LanguageSpan {
    tag: LanguageTag,
    script: LanguageScript,
    confidence: f32,
    source: LanguageEvidenceSource,
    start_utf8: u32,
    end_utf8: u32,
}

impl LanguageSpan {
    /// Creates a span after checking UTF-8 boundaries and declared script.
    ///
    /// # Errors
    ///
    /// Returns an error when the tag/confidence is invalid, the byte range is
    /// empty or outside `text`, or the declared script is absent from the span.
    pub fn try_new(
        tag: &str,
        script: LanguageScript,
        confidence: f32,
        source: LanguageEvidenceSource,
        start_utf8: u32,
        end_utf8: u32,
        text: &str,
    ) -> Result<Self, LanguageEvidenceError> {
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err(LanguageEvidenceError::InvalidConfidence);
        }
        let start =
            usize::try_from(start_utf8).map_err(|_| LanguageEvidenceError::InvalidSpanBoundary)?;
        let end =
            usize::try_from(end_utf8).map_err(|_| LanguageEvidenceError::InvalidSpanBoundary)?;
        if start >= end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return Err(LanguageEvidenceError::InvalidSpanBoundary);
        }
        if !text[start..end]
            .chars()
            .filter(|character| character.is_alphabetic())
            .any(|character| classify_script(character) == script)
        {
            return Err(LanguageEvidenceError::SpanScriptMismatch);
        }

        Ok(Self {
            tag: LanguageTag::try_from(tag)?,
            script,
            confidence,
            source,
            start_utf8,
            end_utf8,
        })
    }

    /// Returns the classified language tag.
    #[must_use]
    pub fn tag(&self) -> &LanguageTag {
        &self.tag
    }

    /// Returns the declared Unicode script.
    #[must_use]
    pub fn script(&self) -> LanguageScript {
        self.script
    }

    /// Returns the classifier confidence.
    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.confidence
    }

    /// Returns the evidence source.
    #[must_use]
    pub fn source(&self) -> LanguageEvidenceSource {
        self.source
    }

    /// Returns the inclusive UTF-8 byte offset.
    #[must_use]
    pub fn start_utf8(&self) -> u32 {
        self.start_utf8
    }

    /// Returns the exclusive UTF-8 byte offset.
    #[must_use]
    pub fn end_utf8(&self) -> u32 {
        self.end_utf8
    }
}

/// Bounded language and script evidence derived without retaining plaintext.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LanguageEvidence {
    /// Validated candidates in precedence order.
    candidates: Vec<LanguageCandidate>,
    /// Observed scripts in deterministic enum order.
    scripts: Vec<ScriptEvidence>,
    /// Validated language spans in ascending byte order.
    spans: Vec<LanguageSpan>,
    /// Number of malformed hints discarded at the untrusted boundary.
    discarded_hint_count: u8,
}

impl LanguageEvidence {
    /// Creates bounded evidence from already typed candidates and spans.
    ///
    /// # Errors
    ///
    /// Returns an error for excessive or duplicate candidates, excessive,
    /// unsorted, or overlapping spans, or span tags missing from candidates.
    pub fn try_new(
        candidates: Vec<LanguageCandidate>,
        spans: Vec<LanguageSpan>,
        text: &str,
    ) -> Result<Self, LanguageEvidenceError> {
        if candidates.len() > MAX_LANGUAGE_CANDIDATES {
            return Err(LanguageEvidenceError::TooManyCandidates);
        }
        if spans.len() > MAX_LANGUAGE_SPANS {
            return Err(LanguageEvidenceError::TooManySpans);
        }
        for (index, candidate) in candidates.iter().enumerate() {
            if candidates[..index]
                .iter()
                .any(|previous| previous.tag == candidate.tag)
            {
                return Err(LanguageEvidenceError::DuplicateCandidate);
            }
        }
        let mut previous_end = 0_u32;
        for span in &spans {
            if span.start_utf8 < previous_end {
                return Err(LanguageEvidenceError::OverlappingSpans);
            }
            if !candidates.iter().any(|candidate| candidate.tag == span.tag) {
                return Err(LanguageEvidenceError::SpanCandidateMissing);
            }
            previous_end = span.end_utf8;
        }

        Ok(Self {
            candidates,
            scripts: script_evidence(text),
            spans,
            discarded_hint_count: 0,
        })
    }

    /// Derives bounded evidence from plaintext and legacy single-language hints.
    ///
    /// Invalid hints are excluded rather than disabling analysis. The returned
    /// structure never contains the original message text.
    #[must_use]
    pub fn from_text_and_hints(
        text: &str,
        message_hint: Option<&str>,
        runtime_default: Option<&str>,
    ) -> Self {
        Self::for_analysis(text, message_hint, runtime_default, None)
    }

    /// Combines locally derived script evidence with optional validated wire evidence.
    ///
    /// Local script classification is always recomputed, so supplied evidence
    /// cannot suppress a script that is present in the analyzed text.
    #[must_use]
    pub fn for_analysis(
        text: &str,
        message_hint: Option<&str>,
        runtime_default: Option<&str>,
        supplied: Option<&Self>,
    ) -> Self {
        let mut evidence = Self {
            candidates: Vec::with_capacity(MAX_LANGUAGE_CANDIDATES),
            scripts: script_evidence(text),
            spans: Vec::new(),
            discarded_hint_count: supplied.map_or(0, |item| item.discarded_hint_count),
        };
        evidence.push_hint(message_hint, 1.0, LanguageEvidenceSource::MessageHint);
        if let Some(supplied) = supplied {
            let mut candidates = supplied.candidates.iter().collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                candidate_source_rank(left.source)
                    .cmp(&candidate_source_rank(right.source))
                    .then_with(|| right.confidence.total_cmp(&left.confidence))
                    .then_with(|| left.tag.cmp(&right.tag))
            });
            for candidate in candidates {
                evidence.push_candidate(candidate.clone());
            }
            evidence.spans = supplied
                .spans
                .iter()
                .filter(|span| {
                    evidence
                        .candidates
                        .iter()
                        .any(|candidate| candidate.tag == span.tag)
                })
                .cloned()
                .collect();
        }
        evidence.push_hint(
            runtime_default,
            0.25,
            LanguageEvidenceSource::RuntimeDefault,
        );
        evidence
    }

    /// Returns whether the text contained at least one scalar from `script`.
    #[must_use]
    pub fn contains_script(&self, script: LanguageScript) -> bool {
        self.scripts.iter().any(|item| item.script == script)
    }

    /// Returns validated candidates in precedence order.
    #[must_use]
    pub fn candidates(&self) -> &[LanguageCandidate] {
        &self.candidates
    }

    /// Returns deterministic script counts.
    #[must_use]
    pub fn scripts(&self) -> &[ScriptEvidence] {
        &self.scripts
    }

    /// Returns validated non-overlapping language spans.
    #[must_use]
    pub fn spans(&self) -> &[LanguageSpan] {
        &self.spans
    }

    /// Returns the number of malformed hints discarded during derivation.
    #[must_use]
    pub fn discarded_hint_count(&self) -> u8 {
        self.discarded_hint_count
    }

    fn push_hint(&mut self, raw: Option<&str>, confidence: f32, source: LanguageEvidenceSource) {
        let Some(raw) = raw else {
            return;
        };
        let Ok(candidate) = LanguageCandidate::try_new(raw, confidence, source) else {
            self.discarded_hint_count = self.discarded_hint_count.saturating_add(1);
            return;
        };

        self.push_candidate(candidate);
    }

    fn push_candidate(&mut self, candidate: LanguageCandidate) {
        if let Some(existing) = self
            .candidates
            .iter_mut()
            .find(|existing| existing.tag == candidate.tag)
        {
            if candidate.confidence > existing.confidence {
                *existing = candidate;
            }
            return;
        }
        if self.candidates.len() < MAX_LANGUAGE_CANDIDATES {
            self.candidates.push(candidate);
        }
    }
}

fn candidate_source_rank(source: LanguageEvidenceSource) -> u8 {
    match source {
        LanguageEvidenceSource::MessageHint => 0,
        LanguageEvidenceSource::OnDeviceClassifier => 1,
        LanguageEvidenceSource::RuntimeDefault => 2,
    }
}

/// Validation failures for typed language evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LanguageEvidenceError {
    /// Language tag is not a bounded BCP-47-style identifier.
    #[error("invalid language tag")]
    InvalidLanguageTag,
    /// Confidence is non-finite or outside `0..=1`.
    #[error("language confidence must be finite and within 0..=1")]
    InvalidConfidence,
    /// Candidate collection exceeds the boundary limit.
    #[error("language evidence exceeds the candidate limit")]
    TooManyCandidates,
    /// Span collection exceeds the boundary limit.
    #[error("language evidence exceeds the span limit")]
    TooManySpans,
    /// The same normalized candidate occurs more than once.
    #[error("language evidence contains a duplicate candidate")]
    DuplicateCandidate,
    /// A UTF-8 span is empty, out of bounds, or not aligned to scalar boundaries.
    #[error("language span has invalid UTF-8 boundaries")]
    InvalidSpanBoundary,
    /// A declared script is not present in its text span.
    #[error("language span script does not match its text")]
    SpanScriptMismatch,
    /// Language spans are not sorted or overlap.
    #[error("language spans must be sorted and non-overlapping")]
    OverlappingSpans,
    /// A span references a language absent from message-level candidates.
    #[error("language span tag is missing from message-level candidates")]
    SpanCandidateMissing,
}

fn script_evidence(text: &str) -> Vec<ScriptEvidence> {
    let mut counts = BTreeMap::<LanguageScript, u32>::new();
    for character in text.chars().filter(|character| character.is_alphabetic()) {
        let script = classify_script(character);
        let count = counts.entry(script).or_default();
        *count = count.saturating_add(1);
    }
    counts
        .into_iter()
        .map(|(script, scalar_count)| ScriptEvidence {
            script,
            scalar_count,
        })
        .collect()
}

fn classify_script(character: char) -> LanguageScript {
    match character as u32 {
        0x0041..=0x024F | 0x1E00..=0x1EFF => LanguageScript::Latin,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => LanguageScript::Greek,
        0x0400..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => LanguageScript::Cyrillic,
        0x0590..=0x05FF => LanguageScript::Hebrew,
        0x0600..=0x06FF | 0x0750..=0x077F | 0x08A0..=0x08FF => LanguageScript::Arabic,
        0x0900..=0x097F => LanguageScript::Devanagari,
        0x3040..=0x309F => LanguageScript::Hiragana,
        0x30A0..=0x30FF | 0x31F0..=0x31FF => LanguageScript::Katakana,
        0x1100..=0x11FF | 0x3130..=0x318F | 0xAC00..=0xD7AF => LanguageScript::Hangul,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF => LanguageScript::Han,
        _ => LanguageScript::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LanguageCandidate, LanguageEvidence, LanguageEvidenceError, LanguageEvidenceSource,
        LanguageScript, LanguageSpan, LanguageTag, MAX_LANGUAGE_CANDIDATES,
    };

    #[test]
    fn language_tag_normalizes_ascii_case_and_preserves_region() {
        let tag = LanguageTag::try_from("EN-us").expect("valid tag");

        assert_eq!(tag.as_str(), "en-us");
    }

    #[test]
    fn language_tag_rejects_underscore_form() {
        let error = LanguageTag::try_from("en_US").expect_err("underscore must fail");

        assert_eq!(error, LanguageEvidenceError::InvalidLanguageTag);
    }

    #[test]
    fn language_candidate_rejects_nonfinite_confidence() {
        let error = LanguageCandidate::try_new("en", f32::NAN, LanguageEvidenceSource::MessageHint)
            .expect_err("NaN must fail");

        assert_eq!(error, LanguageEvidenceError::InvalidConfidence);
    }

    #[test]
    fn evidence_detects_mixed_latin_cyrillic_and_han_scripts() {
        let evidence = LanguageEvidence::from_text_and_hints("hello привіт 世界", None, None);

        assert_eq!(
            evidence
                .scripts()
                .iter()
                .map(|item| item.script())
                .collect::<Vec<_>>(),
            vec![
                LanguageScript::Latin,
                LanguageScript::Cyrillic,
                LanguageScript::Han,
            ]
        );
    }

    #[test]
    fn message_hint_overrides_duplicate_runtime_default() {
        let evidence = LanguageEvidence::from_text_and_hints("hello", Some("EN"), Some("en"));

        assert_eq!(evidence.candidates().len(), 1);
        assert_eq!(
            evidence.candidates()[0].source(),
            LanguageEvidenceSource::MessageHint
        );
    }

    #[test]
    fn invalid_hint_is_discarded_without_losing_script_evidence() {
        let evidence = LanguageEvidence::from_text_and_hints("привіт", Some("uk_UA"), None);

        assert_eq!(evidence.discarded_hint_count(), 1);
        assert!(evidence.contains_script(LanguageScript::Cyrillic));
    }

    #[test]
    fn language_span_rejects_non_utf8_scalar_boundary() {
        let error = LanguageSpan::try_new(
            "fr",
            LanguageScript::Latin,
            0.9,
            LanguageEvidenceSource::OnDeviceClassifier,
            1,
            2,
            "é",
        )
        .expect_err("middle of UTF-8 scalar must fail");

        assert_eq!(error, LanguageEvidenceError::InvalidSpanBoundary);
    }

    #[test]
    fn language_evidence_rejects_overlapping_spans() {
        let text = "hello world";
        let candidate =
            LanguageCandidate::try_new("en", 0.9, LanguageEvidenceSource::OnDeviceClassifier)
                .expect("valid candidate");
        let first = LanguageSpan::try_new(
            "en",
            LanguageScript::Latin,
            0.9,
            LanguageEvidenceSource::OnDeviceClassifier,
            0,
            5,
            text,
        )
        .expect("valid first span");
        let overlapping = LanguageSpan::try_new(
            "en",
            LanguageScript::Latin,
            0.8,
            LanguageEvidenceSource::OnDeviceClassifier,
            4,
            11,
            text,
        )
        .expect("individually valid second span");

        let error = LanguageEvidence::try_new(vec![candidate], vec![first, overlapping], text)
            .expect_err("overlap must fail");

        assert_eq!(error, LanguageEvidenceError::OverlappingSpans);
    }

    #[test]
    fn analysis_combines_classifier_candidate_with_locally_derived_scripts() {
        let text = "hello привіт";
        let candidate =
            LanguageCandidate::try_new("uk", 0.9, LanguageEvidenceSource::OnDeviceClassifier)
                .expect("valid candidate");
        let supplied = LanguageEvidence::try_new(vec![candidate], Vec::new(), text)
            .expect("valid supplied evidence");

        let combined = LanguageEvidence::for_analysis(text, None, Some("en"), Some(&supplied));

        assert!(combined
            .candidates()
            .iter()
            .any(|item| item.tag().as_str() == "uk"));
        assert!(combined.contains_script(LanguageScript::Latin));
        assert!(combined.contains_script(LanguageScript::Cyrillic));
    }

    #[test]
    fn legacy_hint_cannot_be_displaced_by_full_classifier_candidate_set() {
        let candidates = ["fr", "de", "es", "it"]
            .into_iter()
            .map(|tag| {
                LanguageCandidate::try_new(tag, 0.9, LanguageEvidenceSource::OnDeviceClassifier)
                    .expect("valid classifier candidate")
            })
            .collect();
        let supplied =
            LanguageEvidence::try_new(candidates, Vec::new(), "hello").expect("valid evidence");

        let combined = LanguageEvidence::for_analysis("hello", Some("en"), None, Some(&supplied));

        assert_eq!(combined.candidates()[0].tag().as_str(), "en");
        assert_eq!(combined.candidates().len(), MAX_LANGUAGE_CANDIDATES);
    }
}
