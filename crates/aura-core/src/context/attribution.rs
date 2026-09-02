//! Attribution analysis for context suppression.
//!
//! Context suppression (reports, lessons, refusals, protective negation,
//! crisis support) used to be decided from phrase lists over the whole
//! message, so an attacker could disarm the detector by appending a reporting
//! cue to a live threat. This module separates the message into:
//!
//! - **attributed spans**: closed quotations, reported-speech clauses
//!   introduced by an explicit cue, and protective negations that quote the
//!   abusive claim in order to deny it;
//! - **stance cues**: the author's own reporting, educational, refusing,
//!   protective, counter-speech, supportive or crisis wording;
//! - **unattributed text**: everything else, which is rescanned by the same
//!   detectors (pattern layer and kids composition) through an
//!   [`ActiveRiskProbe`] plus a small phrase floor.
//!
//! Suppression of a family is only permitted when that family is *not* active
//! in the unattributed text and, for pattern and composition signals, the same
//! detector finds the family inside the attributed content. Any structural
//! ambiguity (unclosed or mismatched quotes, semantic capacity errors) fails
//! closed: no spans are produced and every family counts as active.

use aura_domain::{PreparedSemanticText, QuoteClosure};
use aura_patterns::PatternMatcher;

use super::interpretation::{
    contains_any, is_self_referential_distress, looks_like_counter_context,
    looks_like_crisis_support_response, looks_like_educational_safety_context,
    looks_like_protective_action_context, looks_like_report_context, looks_like_support_context,
};
use crate::domain_runtime::{parse_threat_type_label, should_skip_pattern_match};
use crate::types::ThreatType;

/// Upper bound on the number of tokens a reported-speech clause may attribute.
const MAX_REPORTED_SPEECH_TOKENS: usize = 32;
/// Minimum number of tokens for a reported-speech clause to count.
const MIN_REPORTED_SPEECH_TOKENS: usize = 2;
/// Minimum number of tokens for a span to count as substantive attribution.
const MIN_SUBSTANTIVE_SPAN_TOKENS: usize = 3;
/// Discourse tokens that may precede a reported-speech cue at clause start.
const DISCOURSE_TOKENS: &[&str] = &[
    "ok",
    "okay",
    "so",
    "btw",
    "well",
    "and",
    "but",
    "also",
    "look",
    "ну",
    "ось",
    "вот",
    "також",
    "також,",
    "также",
    "і",
    "и",
    "але",
    "но",
    "от",
    "дивись",
    "смотри",
];

/// A bit set over [`ThreatType`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FamilySet(u32);

impl FamilySet {
    pub(crate) const ALL: Self = Self(!1_u32);

    pub(crate) fn insert(&mut self, family: ThreatType) {
        if family != ThreatType::None {
            self.0 |= family_bit(family);
        }
    }

    pub(crate) fn contains(self, family: ThreatType) -> bool {
        family != ThreatType::None && self.0 & family_bit(family) != 0
    }

    pub(crate) fn remove(&mut self, family: ThreatType) {
        self.0 &= !family_bit(family);
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn from_families(families: &[ThreatType]) -> Self {
        let mut set = Self::default();
        for family in families {
            set.insert(*family);
        }
        set
    }
}

fn family_bit(family: ThreatType) -> u32 {
    1_u32 << (family as u32)
}

/// Families whose suppression is never allowed while the author's own text is
/// targeting someone.
pub(crate) fn targeted_families() -> FamilySet {
    FamilySet::from_families(&[
        ThreatType::Threat,
        ThreatType::Bullying,
        ThreatType::Grooming,
        ThreatType::Manipulation,
        ThreatType::Explicit,
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpanKind {
    ClosedQuote,
    ReportedSpeech,
    ProtectiveNegation,
    StanceCue,
}

/// A character range of the normalized message that is not the author's own
/// assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NeutralizedSpan {
    pub(crate) kind: SpanKind,
    /// Start offset in characters.
    pub(crate) start: usize,
    /// End offset in characters (exclusive).
    pub(crate) end: usize,
    /// Families the span explicitly attributes (protective negations only).
    pub(crate) families: FamilySet,
}

impl NeutralizedSpan {
    fn token_count(&self, chars: &[char]) -> usize {
        chars[self.start..self.end]
            .iter()
            .collect::<String>()
            .split_whitespace()
            .count()
    }
}

/// The author's own stance cues, detected on the unattributed text only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StanceCues {
    pub(crate) report: bool,
    pub(crate) education: bool,
    pub(crate) refusal: bool,
    pub(crate) protective_action: bool,
    pub(crate) negation: bool,
    pub(crate) counter: bool,
    pub(crate) support: bool,
    pub(crate) crisis: bool,
    /// Generic protective wording built from token classes (report,
    /// opposition, protection, education) in the combinations a report,
    /// refusal or lesson uses.
    pub(crate) structured: bool,
}

impl StanceCues {
    /// Whether the author takes a stance that could justify treating
    /// attributed risk as a report rather than an assertion.
    pub(crate) fn is_protective(self) -> bool {
        self.report
            || self.education
            || self.refusal
            || self.protective_action
            || self.negation
            || self.structured
    }
}

/// Result of rescanning a text fragment with the risk detectors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProbeResult {
    pub(crate) families: FamilySet,
    /// Families found by the semantic composition layer only.
    pub(crate) semantic_families: FamilySet,
    pub(crate) compliance_directive: bool,
    pub(crate) capacity_failed: bool,
}

/// Rescans a text fragment with the live detectors.
///
/// Implementations must be side-effect free: the probe runs on attacker
/// controlled fragments and must not touch memory or policy state.
pub(crate) trait ActiveRiskProbe {
    fn scan_families(&self, text: &str) -> ProbeResult;
}

/// Kids composition only. Used when no pattern matchers are available; it
/// suppresses less than [`PatternRiskProbe`] because pattern-only families
/// inside a quotation cannot be attributed.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DefaultRiskProbe;

#[cfg(test)]
impl ActiveRiskProbe for DefaultRiskProbe {
    fn scan_families(&self, text: &str) -> ProbeResult {
        composition_probe(text)
    }
}

/// Pattern matchers of the routed languages plus kids composition.
pub(crate) struct PatternRiskProbe<'a> {
    matchers: Vec<&'a PatternMatcher>,
}

impl<'a> PatternRiskProbe<'a> {
    pub(crate) fn new(matchers: Vec<&'a PatternMatcher>) -> Self {
        Self { matchers }
    }
}

impl ActiveRiskProbe for PatternRiskProbe<'_> {
    fn scan_families(&self, text: &str) -> ProbeResult {
        let mut result = composition_probe(text);
        if text.trim().is_empty() {
            return result;
        }
        for matcher in &self.matchers {
            for hit in matcher.scan(text) {
                let family = parse_threat_type_label(&hit.threat_type);
                if family == ThreatType::None
                    || should_skip_pattern_match(
                        text,
                        family,
                        &hit.rule_id,
                        hit.matched_text.as_deref(),
                    )
                {
                    continue;
                }
                result.families.insert(family);
            }
        }
        result
    }
}

fn composition_probe(text: &str) -> ProbeResult {
    let mut result = ProbeResult::default();
    if text.trim().is_empty() {
        return result;
    }
    match aura_kids::probe::probe_clauses(text) {
        Ok(clauses) => {
            for clause in clauses {
                for family in clause.families {
                    let family = parse_threat_type_label(family);
                    // Composition self-harm is only the author's own risk when
                    // the clause speaks in the first person about itself.
                    if family == ThreatType::SelfHarm
                        && (!clause.first_person || clause.second_person)
                    {
                        continue;
                    }
                    result.families.insert(family);
                    result.semantic_families.insert(family);
                }
                result.compliance_directive |= clause.compliance_directive;
            }
        }
        Err(_) => result.capacity_failed = true,
    }
    result
}

/// Attribution analysis of one normalized message.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AttributionAnalysis {
    pub(crate) spans: Vec<NeutralizedSpan>,
    pub(crate) ambiguous_quotes: bool,
    pub(crate) stance: StanceCues,
    /// Normalized text with attributed and stance spans blanked out.
    pub(crate) unattributed: String,
    /// Concatenated attributed content.
    pub(crate) attributed_content: String,
    pub(crate) attributed_families: FamilySet,
    /// Composition families found inside the attributed content.
    pub(crate) attributed_semantic: FamilySet,
    /// Families active in the author's own text by any detector.
    pub(crate) active_unattributed: FamilySet,
    /// Families active in the author's own text by intent-bearing evidence
    /// (composition and the phrase floor), used for support stance decisions.
    pub(crate) active_semantic: FamilySet,
    /// The author's own unattributed text expresses self-directed distress
    /// (first-person composition self-harm or the self-referential floor),
    /// as opposed to coercing someone else.
    pub(crate) author_self_distress: bool,
    pub(crate) compliance_directive: bool,
    pub(crate) capacity_failed: bool,
    substantive: bool,
}

impl AttributionAnalysis {
    /// Analysis for a message without any quotation, reporting or stance cue.
    /// Only the phrase floor runs, so cue-free messages pay nothing for the
    /// probe.
    pub(crate) fn cue_free(cue_lower: &str) -> Self {
        Self {
            spans: Vec::new(),
            ambiguous_quotes: false,
            stance: StanceCues::default(),
            unattributed: cue_lower.to_string(),
            attributed_content: String::new(),
            attributed_families: FamilySet::default(),
            attributed_semantic: FamilySet::default(),
            active_unattributed: phrase_floor_families(cue_lower),
            active_semantic: phrase_floor_families(cue_lower),
            author_self_distress: self_directed_distress_floor(cue_lower),
            compliance_directive: false,
            capacity_failed: false,
            substantive: false,
        }
    }

    /// Returns whether `cue_lower` carries any cue that could enable
    /// suppression.
    pub(crate) fn has_cues(cue_lower: &str) -> bool {
        contains_quote_mark(cue_lower)
            || reported_speech_cue_present(cue_lower)
            || stance_present(cue_lower)
    }

    pub(crate) fn analyze(cue_lower: &str, probe: &dyn ActiveRiskProbe) -> Self {
        if !Self::has_cues(cue_lower) {
            return Self::cue_free(cue_lower);
        }

        let chars: Vec<char> = cue_lower.chars().collect();
        let byte_to_char = byte_to_char_map(cue_lower);

        let semantic = match PreparedSemanticText::new(cue_lower) {
            Ok(semantic) => semantic,
            Err(_) => return Self::fail_closed(cue_lower, true),
        };
        let ambiguous_quotes = semantic.has_ambiguous_quote_structure();
        if ambiguous_quotes {
            return Self::fail_closed(cue_lower, false);
        }

        let mut spans = Vec::new();
        {
            // Outermost closed quotations.
            let closed: Vec<_> = semantic
                .quotes()
                .iter()
                .filter(|quote| quote.closure() == QuoteClosure::Closed)
                .collect();
            for quote in &closed {
                let span = quote.span();
                let nested = closed.iter().any(|other| {
                    other.span() != span
                        && other.span().start() <= span.start()
                        && other.span().end() >= span.end()
                });
                if nested {
                    continue;
                }
                let content = quote.content_span();
                spans.push(NeutralizedSpan {
                    kind: SpanKind::ClosedQuote,
                    start: byte_to_char[content.start()],
                    end: byte_to_char[content.end()],
                    families: FamilySet::default(),
                });
            }

            // Reported speech introduced by an explicit cue.
            let clauses = semantic.clauses();
            for (index, clause) in clauses.iter().enumerate() {
                let clause_span = clause.span();
                let clause_text = &cue_lower[clause_span.start()..clause_span.end()];
                let range = reported_speech_range(clause_text).or_else(|| {
                    // "quote:" / "he said:" alone in a clause attributes the
                    // following clause.
                    let bare = clause_text.trim().trim_end_matches(':').trim_end();
                    if !REPORTED_SPEECH_CUES
                        .iter()
                        .any(|cue| cue.trim_end_matches(':') == bare)
                    {
                        return None;
                    }
                    let next = clauses.get(index + 1)?;
                    let next_text = &cue_lower[next.span().start()..next.span().end()];
                    if contains_quote_mark(next_text) {
                        return None;
                    }
                    let tokens: Vec<&str> = next_text.split_whitespace().collect();
                    if tokens.len() < MIN_REPORTED_SPEECH_TOKENS {
                        return None;
                    }
                    let end = if tokens.len() > MAX_REPORTED_SPEECH_TOKENS {
                        next_text.find(tokens[MAX_REPORTED_SPEECH_TOKENS])?
                    } else {
                        next_text
                            .trim_end_matches(|c: char| !c.is_alphanumeric())
                            .len()
                    };
                    let offset = next.span().start() - clause_span.start();
                    Some((offset, offset + end))
                });
                if let Some((start, end)) = range {
                    let start = byte_to_char[clause_span.start() + start];
                    let end = byte_to_char[clause_span.start() + end];
                    if spans
                        .iter()
                        .any(|span| span.start < end && start < span.end)
                    {
                        continue;
                    }
                    spans.push(NeutralizedSpan {
                        kind: SpanKind::ReportedSpeech,
                        start,
                        end,
                        families: FamilySet::default(),
                    });
                }
            }
        }

        // Protective negations quote the abusive claim in order to deny it.
        for (phrase, families) in PROTECTIVE_NEGATIONS {
            let mut search = 0;
            while let Some(found) = cue_lower[search..].find(phrase) {
                let start = search + found;
                let end = start + phrase.len();
                spans.push(NeutralizedSpan {
                    kind: SpanKind::ProtectiveNegation,
                    start: byte_to_char[start],
                    end: byte_to_char[end],
                    families: FamilySet::from_families(families),
                });
                search = end;
            }
        }

        let attributed_content = join_spans(&chars, &spans, |span| {
            matches!(span.kind, SpanKind::ClosedQuote | SpanKind::ReportedSpeech)
        });
        let mut unattributed = mask_spans(&chars, &spans);
        let stance = StanceCues {
            report: looks_like_report_context(&unattributed),
            education: looks_like_educational_safety_context(&unattributed),
            refusal: looks_like_refusal_context(&unattributed),
            protective_action: looks_like_protective_action_context(&unattributed),
            negation: spans
                .iter()
                .any(|span| span.kind == SpanKind::ProtectiveNegation),
            counter: looks_like_counter_context(&unattributed),
            support: looks_like_support_context(&unattributed),
            crisis: looks_like_crisis_support_response(&unattributed),
            structured: structured_protective_stance(&unattributed),
        };
        // Stance phrases are the author's protective wording, not attacker
        // text, so they are blanked before the rescan.
        blank_stance_phrases(&mut unattributed, &mut spans, &chars);

        let substantive = spans.iter().any(|span| {
            matches!(
                span.kind,
                SpanKind::ClosedQuote | SpanKind::ReportedSpeech | SpanKind::ProtectiveNegation
            ) && span.token_count(&chars) >= MIN_SUBSTANTIVE_SPAN_TOKENS
        });

        let attributed_probe = probe.scan_families(&attributed_content);
        let unattributed_probe = probe.scan_families(&unattributed);
        if attributed_probe.capacity_failed || unattributed_probe.capacity_failed {
            return Self::fail_closed(cue_lower, true);
        }

        let mut attributed_families = attributed_probe
            .families
            .union(phrase_floor_families(&attributed_content));
        for span in &spans {
            attributed_families = attributed_families.union(span.families);
        }
        let attributed_semantic = attributed_probe.semantic_families;
        let floor = phrase_floor_families(&unattributed);
        let floor_self_directed = self_directed_distress_floor(&unattributed);
        let floor_coercion = coercion_floor(&unattributed);
        // A supporter answering a crisis repeats the victim's words in the
        // first person ("I'm sorry it feels like there is no reason to
        // live"); composition self-harm is then not the author's own risk
        // unless the phrase floor says so.
        let support_crisis = stance.support && stance.crisis;
        let semantic_self_harm = unattributed_probe
            .semantic_families
            .contains(ThreatType::SelfHarm)
            && !(support_crisis && !floor_self_directed && !floor_coercion);
        let author_self_distress = floor_self_directed || semantic_self_harm;
        let mut active_unattributed = unattributed_probe.families.union(floor);
        let mut active_semantic = unattributed_probe.semantic_families.union(floor);
        if !semantic_self_harm && !floor_self_directed && !floor_coercion {
            active_semantic.remove(ThreatType::SelfHarm);
            active_unattributed.remove(ThreatType::SelfHarm);
        }
        let compliance_directive = unattributed_probe.compliance_directive
            || contains_any(&unattributed, COMPLIANCE_DIRECTIVES);
        if compliance_directive {
            // A quoted request that the author orders the child to obey is the
            // author's own request.
            active_unattributed = active_unattributed.union(attributed_families);
            active_semantic = active_semantic.union(attributed_families);
        }

        Self {
            spans,
            ambiguous_quotes,
            stance,
            unattributed,
            attributed_content,
            attributed_families,
            attributed_semantic,
            active_unattributed,
            active_semantic,
            author_self_distress,
            compliance_directive,
            capacity_failed: false,
            substantive,
        }
    }

    fn fail_closed(cue_lower: &str, capacity_failed: bool) -> Self {
        Self {
            spans: Vec::new(),
            ambiguous_quotes: true,
            stance: StanceCues::default(),
            unattributed: cue_lower.to_string(),
            attributed_content: String::new(),
            attributed_families: FamilySet::default(),
            attributed_semantic: FamilySet::default(),
            active_unattributed: FamilySet::ALL,
            active_semantic: FamilySet::ALL,
            author_self_distress: self_directed_distress_floor(cue_lower),
            compliance_directive: false,
            capacity_failed,
            substantive: false,
        }
    }

    /// Whether at least one attributed span is long enough to carry a claim.
    pub(crate) fn has_substantive_attribution(&self) -> bool {
        self.substantive
    }
}

/// Where a signal came from, which decides how strict attribution must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalOrigin {
    Pattern,
    Composition,
    Other,
}

pub(crate) fn signal_origin(reason_code: &str) -> SignalOrigin {
    if reason_code.starts_with("pattern.") {
        SignalOrigin::Pattern
    } else if reason_code.contains("kids.composition.") {
        SignalOrigin::Composition
    } else {
        SignalOrigin::Other
    }
}

/// Whether suppression of `family` is permitted by the attribution evidence.
pub(crate) fn attribution_permits(
    analysis: &AttributionAnalysis,
    family: ThreatType,
    origin: SignalOrigin,
) -> bool {
    if analysis.active_unattributed.contains(family) {
        return false;
    }
    match origin {
        SignalOrigin::Pattern => analysis.attributed_families.contains(family),
        // The kids composition runs over the whole message, so words from a
        // quotation and from the author's stance can combine into a family
        // that exists in neither fragment. Such a family is attributable when
        // the quotation itself composes and the family is not active in the
        // author's own text.
        SignalOrigin::Composition => {
            analysis.attributed_families.contains(family)
                || !analysis.attributed_semantic.is_empty()
        }
        SignalOrigin::Other => analysis.has_substantive_attribution(),
    }
}

/// Whether `text` contains a quotation mark, ignoring apostrophes inside
/// words such as `i'm` or `don't`.
fn contains_quote_mark(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    chars.iter().enumerate().any(|(index, c)| {
        if !is_quote_char(*c) {
            return false;
        }
        if matches!(c, '\'' | '’') {
            let before = index.checked_sub(1).and_then(|i| chars.get(i));
            let after = chars.get(index + 1);
            let in_word = before.is_some_and(|c| c.is_alphanumeric())
                && after.is_some_and(|c| c.is_alphanumeric());
            return !in_word;
        }
        true
    })
}

fn is_quote_char(c: char) -> bool {
    matches!(
        c,
        '"' | '\'' | '«' | '»' | '“' | '”' | '„' | '‘' | '’' | '‹' | '›'
    )
}

fn byte_to_char_map(text: &str) -> Vec<usize> {
    let mut map = vec![0; text.len() + 1];
    let mut char_index = 0;
    for (byte_index, character) in text.char_indices() {
        for offset in 0..character.len_utf8() {
            map[byte_index + offset] = char_index;
        }
        char_index += 1;
    }
    map[text.len()] = char_index;
    map
}

fn join_spans(
    chars: &[char],
    spans: &[NeutralizedSpan],
    select: impl Fn(&NeutralizedSpan) -> bool,
) -> String {
    let mut joined = String::new();
    for span in spans.iter().filter(|span| select(span)) {
        if !joined.is_empty() {
            joined.push_str(". ");
        }
        joined.extend(chars[span.start..span.end].iter());
    }
    joined
}

fn mask_spans(chars: &[char], spans: &[NeutralizedSpan]) -> String {
    let mut masked: Vec<char> = chars.to_vec();
    for span in spans {
        for character in &mut masked[span.start..span.end] {
            if !character.is_whitespace() {
                *character = ' ';
            }
        }
    }
    masked.into_iter().collect()
}

fn blank_stance_phrases(
    unattributed: &mut String,
    spans: &mut Vec<NeutralizedSpan>,
    chars: &[char],
) {
    let byte_to_char = byte_to_char_map(unattributed);
    let mut stance_spans = Vec::new();
    for phrase in STANCE_PHRASES_TO_BLANK {
        let mut search = 0;
        while let Some(found) = unattributed[search..].find(phrase) {
            let start = search + found;
            let end = start + phrase.len();
            stance_spans.push(NeutralizedSpan {
                kind: SpanKind::StanceCue,
                start: byte_to_char[start],
                end: byte_to_char[end],
                families: FamilySet::default(),
            });
            search = end;
        }
    }
    // Single stance-class tokens ("harmful", "unsafe", "evidence") are the
    // author's wording about the quoted material, never attacker text.
    for (start, end) in stance_token_ranges(unattributed) {
        stance_spans.push(NeutralizedSpan {
            kind: SpanKind::StanceCue,
            start: byte_to_char[start],
            end: byte_to_char[end],
            families: FamilySet::default(),
        });
    }
    if stance_spans.is_empty() {
        return;
    }
    let mut masked: Vec<char> = unattributed.chars().collect();
    for span in &stance_spans {
        for character in &mut masked[span.start..span.end] {
            if !character.is_whitespace() {
                *character = ' ';
            }
        }
    }
    debug_assert_eq!(masked.len(), chars.len());
    *unattributed = masked.into_iter().collect();
    spans.extend(stance_spans);
}

const STANCE_REPORT_STEMS: &[&str] = &[
    "report",
    "quot",
    "evidence",
    "document",
    "sharing",
    "forward",
    "screenshot",
    "instruction",
    "цитат",
    "доказ",
    "скарг",
    "документ",
    "вказів",
    "скріншот",
    "поскарж",
    "повідомля",
    "жалоб",
    "указан",
    "скриншот",
    "сообща",
    "сообщу",
    "задокумент",
    "процитов",
    "процитир",
    "cited",
];
const STANCE_OPPOSITION_STEMS: &[&str] = &[
    "refus",
    "reject",
    "unaccept",
    "unsafe",
    "harmful",
    "dangerous",
    "abusive",
    "bullying",
    "blackmail",
    "manipulat",
    "grooming",
    "wrong",
    "відмов",
    "відкид",
    "неприйнят",
    "небезпеч",
    "шкідлив",
    "цькуван",
    "шантаж",
    "маніпуляц",
    "відверт",
    "отказ",
    "отверг",
    "неприемл",
    "опасн",
    "вредн",
    "травл",
    "буллинг",
    "манипуляц",
    "нельзя",
];
const STANCE_PROTECTION_STEMS: &[&str] = &[
    "help",
    "adult",
    "support",
    "protect",
    "safety",
    "warning",
    "trusted",
    "counsel",
    "teacher",
    "staff",
    "moderator",
    "допомог",
    "доросл",
    "підтрим",
    "захист",
    "безпек",
    "довір",
    "вчител",
    "психолог",
    "модератор",
    "помощ",
    "взросл",
    "поддерж",
    "защит",
    "безопас",
    "довер",
    "учител",
];
const STANCE_EDUCATION_STEMS: &[&str] = &[
    "example",
    "lesson",
    "teach",
    "приклад",
    "урок",
    "ознак",
    "пример",
    "признак",
    "тревожн",
];

fn token_ranges(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, character) in text.char_indices() {
        let is_word = character.is_alphanumeric() || matches!(character, '\'' | '’');
        match (start, is_word) {
            (None, true) => start = Some(index),
            (Some(begin), false) => {
                ranges.push((begin, index));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        ranges.push((begin, text.len()));
    }
    ranges.into_iter()
}

fn any_token_with_prefix(text: &str, stems: &[&str]) -> bool {
    token_ranges(text).any(|(start, end)| {
        let token = &text[start..end];
        stems.iter().any(|stem| token.starts_with(stem))
    })
}

/// Generic protective wording: the combinations of report, opposition,
/// protection and education vocabulary that a report, refusal or lesson uses
/// ("this is an example of unsafe language", "I am sharing the quote with
/// support staff"). Single words never count on their own.
fn structured_protective_stance(unattributed: &str) -> bool {
    let report = any_token_with_prefix(unattributed, STANCE_REPORT_STEMS);
    let opposition = any_token_with_prefix(unattributed, STANCE_OPPOSITION_STEMS)
        || contains_any(unattributed, &["не можна", "should not", "must not"]);
    let protection = any_token_with_prefix(unattributed, STANCE_PROTECTION_STEMS);
    let education = any_token_with_prefix(unattributed, STANCE_EDUCATION_STEMS);
    (report && (opposition || protection))
        || (opposition && protection)
        || (education && (opposition || protection))
}

fn stance_token_ranges(text: &str) -> Vec<(usize, usize)> {
    token_ranges(text)
        .filter(|(start, end)| {
            let token = &text[*start..*end];
            [
                STANCE_REPORT_STEMS,
                STANCE_OPPOSITION_STEMS,
                STANCE_PROTECTION_STEMS,
                STANCE_EDUCATION_STEMS,
            ]
            .iter()
            .any(|stems| stems.iter().any(|stem| token.starts_with(stem)))
        })
        .collect()
}

fn reported_speech_cue_present(cue_lower: &str) -> bool {
    contains_any(cue_lower, REPORTED_SPEECH_CUES)
}

fn stance_present(cue_lower: &str) -> bool {
    looks_like_report_context(cue_lower)
        || looks_like_educational_safety_context(cue_lower)
        || looks_like_refusal_context(cue_lower)
        || looks_like_protective_action_context(cue_lower)
        || PROTECTIVE_NEGATIONS
            .iter()
            .any(|(phrase, _)| cue_lower.contains(phrase))
        || looks_like_counter_context(cue_lower)
        || looks_like_support_context(cue_lower)
}

/// Returns the byte range of reported content inside one clause, if the clause
/// starts with a reported-speech cue.
fn reported_speech_range(clause_text: &str) -> Option<(usize, usize)> {
    let mut cursor = 0;
    let bytes = clause_text;
    // Skip up to two discourse tokens.
    for _ in 0..2 {
        let rest = &bytes[cursor..];
        let trimmed = rest.trim_start();
        let leading = rest.len() - trimmed.len();
        let token_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
        let token = trimmed[..token_end].trim_matches(|c: char| !c.is_alphanumeric());
        if token.is_empty() || !DISCOURSE_TOKENS.contains(&token) {
            break;
        }
        cursor += leading + token_end;
    }
    let rest = &bytes[cursor..];
    let trimmed = rest.trim_start();
    let leading = rest.len() - trimmed.len();
    let cue_len = REPORTED_SPEECH_CUES
        .iter()
        .filter(|cue| trimmed.starts_with(*cue))
        .map(|cue| cue.len())
        .max()
        .or_else(|| possessive_reported_speech_cue_len(trimmed))?;
    let mut content_start = cursor + leading + cue_len;
    let after_cue = &bytes[content_start..];
    let after_trimmed = after_cue.trim_start_matches(|c: char| {
        c.is_whitespace() || matches!(c, ':' | ',' | '-' | '—' | '–')
    });
    content_start += after_cue.len() - after_trimmed.len();
    let mut content_end = bytes.len();
    let content = &bytes[content_start..];
    if contains_quote_mark(content) {
        // Quoted speech is handled by the closed-quote path.
        return None;
    }
    for separator in [" - ", " — ", " – "] {
        if let Some(found) = content.find(separator) {
            content_end = content_end.min(content_start + found);
        }
    }
    for phrase in STANCE_PHRASES_TO_BLANK {
        if let Some(found) = content.find(phrase) {
            content_end = content_end.min(content_start + found);
        }
    }
    let selected = bytes[content_start..content_end]
        .trim_end()
        .trim_end_matches(|c: char| !c.is_alphanumeric() && !matches!(c, ')' | '»' | '”'));
    let content_end = content_start + selected.len();
    let tokens: Vec<&str> = selected.split_whitespace().collect();
    if tokens.len() < MIN_REPORTED_SPEECH_TOKENS {
        return None;
    }
    if tokens.len() > MAX_REPORTED_SPEECH_TOKENS {
        let capped = tokens[..MAX_REPORTED_SPEECH_TOKENS].join(" ");
        let capped_end = selected
            .find(tokens[MAX_REPORTED_SPEECH_TOKENS])
            .unwrap_or(capped.len());
        return Some((content_start, content_start + capped_end));
    }
    Some((content_start, content_end))
}

/// Matches `my <noun> said` style cues ("my friend texted", "мій брат
/// написав") and returns the cue length in bytes.
fn possessive_reported_speech_cue_len(text: &str) -> Option<usize> {
    const POSSESSIVES: &[&str] = &["my", "мій", "моя", "мої", "мой", "мои"];
    const VERBS: &[&str] = &[
        "said",
        "says",
        "texted",
        "wrote",
        "messaged",
        "sent",
        "сказав",
        "сказала",
        "сказали",
        "написав",
        "написала",
        "написали",
        "скинув",
        "скинула",
        "сказал",
        "сказала",
        "сказали",
        "написал",
        "написала",
        "написали",
        "скинул",
        "скинула",
    ];
    let mut tokens = text.split_whitespace();
    let possessive = tokens.next()?;
    if !POSSESSIVES.contains(&possessive) {
        return None;
    }
    let noun = tokens.next()?;
    if !noun.chars().all(char::is_alphanumeric) {
        return None;
    }
    let verb = tokens.next()?;
    let verb_clean = verb.trim_end_matches(|c: char| !c.is_alphanumeric());
    if !VERBS.contains(&verb_clean) {
        return None;
    }
    let verb_offset = text.find(verb)?;
    Some(verb_offset + verb_clean.len())
}

const REPORTED_SPEECH_CUES: &[&str] = &[
    "he said",
    "she said",
    "they said",
    "someone said",
    "he texted",
    "she texted",
    "they texted",
    "someone texted",
    "he wrote",
    "she wrote",
    "they wrote",
    "someone wrote",
    "he messaged",
    "she messaged",
    "they messaged",
    "he sent me",
    "she sent me",
    "they sent me",
    "someone sent me",
    "the message said",
    "the text said",
    "message read",
    "court read",
    "quote:",
    "quoted:",
    "він сказав",
    "вона сказала",
    "вони сказали",
    "хтось сказав",
    "він написав",
    "вона написала",
    "вони написали",
    "хтось написав",
    "мені написали",
    "мені скинули",
    "мені надіслали",
    "цитата:",
    "цитую:",
    "он сказал",
    "она сказала",
    "они сказали",
    "кто-то сказал",
    "он написал",
    "она написала",
    "они написали",
    "кто-то написал",
    "мне написали",
    "мне скинули",
    "мне прислали",
    "цитирую:",
];

const PROTECTIVE_NEGATIONS: &[(&str, &[ThreatType])] = &[
    ("you are not imagining things", &[ThreatType::Manipulation]),
    ("it is not all in your head", &[ThreatType::Manipulation]),
    (
        "you are not worthless",
        &[ThreatType::Bullying, ThreatType::Manipulation],
    ),
    (
        "i will not tell your parents i am your classmate",
        &[ThreatType::Grooming, ThreatType::Manipulation],
    ),
    ("ти не вигадуєш", &[ThreatType::Manipulation]),
    ("це не лише в твоїй голові", &[ThreatType::Manipulation]),
    (
        "ти потрібен нам",
        &[ThreatType::Bullying, ThreatType::Manipulation],
    ),
    (
        "ти потрібна нам",
        &[ThreatType::Bullying, ThreatType::Manipulation],
    ),
    (
        "не кажи батькам, що я однокласник: розкажи їм правду",
        &[ThreatType::Grooming, ThreatType::Manipulation],
    ),
    ("ты не выдумываешь", &[ThreatType::Manipulation]),
    ("это не только в твоей голове", &[ThreatType::Manipulation]),
    (
        "ты нужен нам",
        &[ThreatType::Bullying, ThreatType::Manipulation],
    ),
    (
        "ты нужна нам",
        &[ThreatType::Bullying, ThreatType::Manipulation],
    ),
    (
        "не говори родителям, что незнакомец одноклассник",
        &[ThreatType::Grooming, ThreatType::Manipulation],
    ),
];

/// Author-stance phrases that must not be rescanned as attacker text.
const STANCE_PHRASES_TO_BLANK: &[&str] = &[
    "refuse and tell",
    "tell a trusted adult",
    "tell them the truth",
    "should know who i really am",
    "i believe you",
    "is blackmail",
    "were bullying you",
    "was bullying you",
    "dangerous pressure",
    "not responsible for someone else's threats",
    "not responsible for their threats",
    "teacher recorded",
    "contact crisis support",
    "requires immediate support",
    "require immediate support",
    "safety lesson",
    "lesson says",
    "warning sign",
    "protective guidance",
    "i'm reporting",
    "im reporting",
    "reporting this",
    "reported this",
    "report it",
    "report this",
    "will report",
    "forwarding this",
    "forwarding it",
    "forwarding the screenshot",
    "i m forwarding",
    "for context",
    "for the report",
    "should be reported",
    "saved the evidence",
    "i reject",
    "i refuse",
    "відмовся та звернися",
    "звернися до дорослого",
    "розкажи їм правду",
    "я вірю тобі",
    "є шантажем",
    "були цькуванням",
    "небезпечний тиск",
    "не відповідаєш за чужі погрози",
    "передали вчителю",
    "знайдемо допомогу",
    "урок безпеки",
    "на уроці пояснили",
    "ознака небезпеки",
    "небезпечний приклад",
    "показати дорослому",
    "поскаржуся",
    "скаржуся",
    "для контексту",
    "для звіту",
    "слід повідомити",
    "збережи доказ",
    "це мені скинули",
    "це переслали",
    "я відмовляюся",
    "я відмовляюсь",
    "звернуся по допомогу",
    "откажись и расскажи",
    "расскажи взрослому",
    "расскажи им правду",
    "я верю тебе",
    "является шантажом",
    "были травлей",
    "опасное давление",
    "не отвечаешь за чужие угрозы",
    "передали учителю",
    "найдём помощь",
    "найдем помощь",
    "урок безопасности",
    "на уроке объяснили",
    "признак опасности",
    "опасный пример",
    "показать взрослому",
    "я жалуюсь",
    "я пожалуюсь",
    "для отчёта",
    "для отчета",
    "нужно сообщить",
    "сохрани доказательство",
    "мне это скинули",
    "это переслали",
    "я отказываюсь",
    "обращусь за помощью",
];

const COMPLIANCE_DIRECTIVES: &[&str] = &[
    "do it now",
    "do what i say",
    "do what they say",
    "send it now",
    "send it to them",
    "just send it",
    "or else",
    "зроби це",
    "зроби як сказано",
    "просто надішли",
    "сделай это",
    "сделай как сказано",
    "просто отправь",
];

pub(crate) fn looks_like_refusal_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "i refuse",
            "i reject",
            "refuse this",
            "reject this",
            "i will not do",
            "i won't do",
            "i wont do",
            "this is unacceptable",
            "not my intent",
            "not my intention",
            "not what i intend",
            "will not comply",
            "won't comply",
            "wont comply",
            "не буду його виконувати",
            "не виконуватиму",
            "не буду его выполнять",
            "не буду это выполнять",
            "не моим намерением",
            "не моїм наміром",
            "не мій намір",
            "не мое намерение",
            "не моё намерение",
            "не моя цель",
            "я відмовляюся",
            "я відмовляюсь",
            "відмовляюся від",
            "не буду цього робити",
            "це неприйнятно",
            "я отказываюсь",
            "отказываюсь от",
            "не буду этого делать",
            "это неприемлемо",
        ],
    )
}

/// Phrase floor for the author's own risk, applied to unattributed text.
pub(crate) fn phrase_floor_families(outside: &str) -> FamilySet {
    let mut families = FamilySet::default();
    let truth_correction = contains_any(
        outside,
        &[
            "know who i really am",
            "tell them the truth",
            "розкажи їм правду",
            "правду про незнайомця",
            "расскажи им правду",
            "правду о незнакомце",
        ],
    );
    if !truth_correction
        && contains_any(
            outside,
            &[
                "don't tell your parents",
                "dont tell your parents",
                "keep this between us",
                "нікому не кажи",
                "не розповідай батькам",
                "не кажи батькам",
                "никому не говори",
                "не говори родителям",
                "tell your parents i am your classmate",
                "кажи, що я однокласник",
                "скажи родителям, что я твой одноклассник",
            ],
        )
    {
        families.insert(ThreatType::Grooming);
    }
    if contains_any(
        outside,
        &[
            "send me a photo",
            "send me your photo",
            "send your photo",
            "send me a selfie",
            "надішли мені фото",
            "надішли фото",
            "скинь мені фото",
            "пришли мне фото",
            "пришли фото",
            "скинь мне фото",
        ],
    ) {
        families.insert(ThreatType::Grooming);
    }
    if contains_any(
        outside,
        &[
            "i'll share your private photo",
            "ill share your private photo",
            "i will share your private photo",
            "я всім покажу твоє приватне фото",
            "я разошлю всем твоё личное фото",
            "я разошлю всем твое личное фото",
            "if you leave me",
            "it'll be on you",
            "itll be on you",
            "it will be on you",
            "якщо ти підеш",
            "если ты уйдёшь",
            "если ты уйдешь",
        ],
    ) {
        families.insert(ThreatType::Manipulation);
    }
    if contains_any(
        outside,
        &[
            "you're worthless",
            "you are worthless",
            "everyone hates you",
            "ти нікому не потрібен",
            "ти нікому не потрібна",
            "тебе всі ненавидять",
            "тебе все ненавидят",
        ],
    ) {
        families.insert(ThreatType::Bullying);
    }
    if contains_any(
        outside,
        &[
            "we will beat you",
            "після школи тебе поб'ємо",
            "после школы мы тебя побьём",
            "после школы мы тебя побьем",
        ],
    ) {
        families.insert(ThreatType::Bullying);
        families.insert(ThreatType::Threat);
    }
    if coercion_floor(outside) {
        families.insert(ThreatType::SelfHarm);
        families.insert(ThreatType::Manipulation);
    }
    if self_directed_distress_floor(outside) {
        families.insert(ThreatType::SelfHarm);
    }
    families
}

/// Suicide coercion aimed at the reader: self-harm family for policy, but
/// never the author's own distress.
fn coercion_floor(outside: &str) -> bool {
    contains_any(
        outside,
        &[
            "kill yourself",
            "go die",
            "вбий себе",
            "убей себя",
            "покінчи з собою",
            "покончи с собой",
            "повісься",
            "повесься",
        ],
    )
}

/// The author's own first-person distress or farewell.
fn self_directed_distress_floor(outside: &str) -> bool {
    is_self_referential_distress(outside)
        || contains_any(
            outside,
            &[
                "hurt myself",
                "end everything",
                "i want to disappear",
                "goodbye forever",
                "this is my last message",
                "my last message",
                "прощавайте назавжди",
                "це моє останнє повідомлення",
                "моє останнє повідомлення",
                "прощайте навсегда",
                "это моё последнее сообщение",
                "это мое последнее сообщение",
                "моё последнее сообщение",
                "я помру",
                "хочу зникнути",
                "хочу исчезнуть",
            ],
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoProbe;

    impl ActiveRiskProbe for NoProbe {
        fn scan_families(&self, _text: &str) -> ProbeResult {
            ProbeResult::default()
        }
    }

    fn analyze(text: &str) -> AttributionAnalysis {
        AttributionAnalysis::analyze(&text.to_lowercase(), &DefaultRiskProbe)
    }

    fn span_texts(analysis: &AttributionAnalysis, text: &str, kind: SpanKind) -> Vec<String> {
        let chars: Vec<char> = text.to_lowercase().chars().collect();
        analysis
            .spans
            .iter()
            .filter(|span| span.kind == kind)
            .map(|span| chars[span.start..span.end].iter().collect::<String>())
            .collect()
    }

    #[test]
    fn closed_quote_is_attributed_and_masked() {
        let text = r#"He said "I will kill you", and I'm reporting it."#;
        let analysis = analyze(text);
        assert_eq!(
            span_texts(&analysis, text, SpanKind::ClosedQuote),
            vec!["i will kill you".to_string()]
        );
        assert!(analysis.has_substantive_attribution());
        assert!(analysis.stance.report);
        assert!(!analysis.unattributed.contains("kill"));
    }

    #[test]
    fn reported_speech_cue_attributes_rest_of_clause() {
        let text = "He texted I will hurt you tomorrow I m forwarding the screenshot";
        let analysis = analyze(text);
        let spans = span_texts(&analysis, text, SpanKind::ReportedSpeech);
        assert_eq!(spans, vec!["i will hurt you tomorrow".to_string()]);
        assert!(analysis.stance.report);
        assert!(analysis.has_substantive_attribution());
    }

    #[test]
    fn reported_speech_stops_at_dash_separator() {
        let text = "she wrote you are worthless - this is bullying and i saved the evidence";
        let analysis = analyze(text);
        assert_eq!(
            span_texts(&analysis, text, SpanKind::ReportedSpeech),
            vec!["you are worthless".to_string()]
        );
        assert!(analysis.attributed_families.contains(ThreatType::Bullying));
        assert!(!analysis.active_unattributed.contains(ThreatType::Bullying));
    }

    #[test]
    fn reported_speech_cue_cannot_attribute_author_threat_outside_it() {
        let text = "he said hi. i will kill you tomorrow, for context";
        let analysis = analyze(text);
        assert!(
            analysis.active_unattributed.contains(ThreatType::Threat)
                || !analysis.attributed_families.contains(ThreatType::Threat)
        );
    }

    #[test]
    fn possessive_reported_speech_cue_attributes_friend_words() {
        let text = "My friend said there is no reason to live. I'm here with u, let's tell ur parents together";
        let analysis = analyze(text);
        assert_eq!(
            span_texts(&analysis, text, SpanKind::ReportedSpeech),
            vec!["there is no reason to live".to_string()]
        );
        assert!(!analysis.active_semantic.contains(ThreatType::SelfHarm));
    }

    #[test]
    fn semantic_activity_ignores_pattern_only_hits() {
        // A supportive author may repeat the victim's words; only intent-bearing
        // composition or floor phrases count as the author's own risk here.
        let analysis = analyze("мені шкода, що тобі здається, ніби немає сенсу жити; залишайся зі мною, ми знайдемо допомогу");
        assert!(!analysis.active_semantic.contains(ThreatType::SelfHarm));
        assert!(!analysis.active_semantic.contains(ThreatType::Manipulation));
    }

    #[test]
    fn colon_reported_speech_uses_next_clause() {
        let text = "quote: i will hurt you tomorrow. i'm reporting this";
        let analysis = analyze(text);
        assert_eq!(
            span_texts(&analysis, text, SpanKind::ReportedSpeech),
            vec!["i will hurt you tomorrow".to_string()]
        );
    }

    #[test]
    fn suicide_coercion_floor_marks_author_risk() {
        let analysis = analyze(
            "you should just kill yourself already, stay with me and contact crisis support",
        );
        assert!(analysis.active_semantic.contains(ThreatType::SelfHarm));
        assert!(analysis.active_semantic.contains(ThreatType::Manipulation));
        assert!(
            !analysis.author_self_distress,
            "coercion is not the author's own distress"
        );
        assert!(!analyze("you're pathetic, kill yourself loser").author_self_distress);
        assert!(analyze("i want to die, goodbye forever").author_self_distress);
    }

    #[test]
    fn structured_stance_recognizes_generic_report_and_lesson_wording() {
        for text in [
            "“You will regret this when I find you.” — This is an example of unsafe language that people should not use.",
            "“I feel like everyone would be better without me.” — I am sharing the quote with support staff so they can protect someone.",
            "«Перейди в таємний чат, де дорослі нас не побачать.» — Це приклад небезпечних слів, які не можна використовувати.",
            "«Если бы ты правда обо мне заботился, ты бы это сделал.» — Я сообщаю об этом вредном сообщении, а не соглашаюсь с ним.",
        ] {
            let analysis = analyze(text);
            assert!(analysis.stance.is_protective(), "{text}: {:?}", analysis.stance);
            assert!(analysis.active_unattributed.is_empty(), "{text}: {analysis:?}");
        }
        for text in [
            "this is not a joke, i got your message",
            "help me with the homework and send the report card",
        ] {
            assert!(!analyze(text).stance.structured, "{text}");
        }
    }

    #[test]
    fn crisis_support_repeating_victim_words_is_not_author_distress() {
        let analysis = analyze("I'm sorry it feels like there is no reason to live; stay with me while we contact crisis support.");
        assert!(!analysis.author_self_distress, "{analysis:?}");
        assert!(!analysis.active_semantic.contains(ThreatType::SelfHarm));
        let attacker =
            analyze("I want to die tonight; stay with me while we contact crisis support.");
        assert!(attacker.author_self_distress);
    }

    #[test]
    fn cross_boundary_composition_family_is_attributable() {
        let analysis = analyze("If anyone says 'don't tell your parents and send me a photo', refuse and tell a trusted adult.");
        assert!(!analysis.attributed_semantic.is_empty());
        assert!(attribution_permits(
            &analysis,
            ThreatType::Nsfw,
            SignalOrigin::Composition
        ));
        assert!(!attribution_permits(
            &analysis,
            ThreatType::Nsfw,
            SignalOrigin::Pattern
        ));
    }

    #[test]
    fn unclosed_quote_fails_closed() {
        let analysis = analyze("Court read the defendant's text 'I will kill you tomorrow");
        assert!(analysis.ambiguous_quotes);
        assert!(analysis.spans.is_empty());
        assert!(!analysis.has_substantive_attribution());
        assert_eq!(analysis.active_unattributed, FamilySet::ALL);
    }

    #[test]
    fn nested_quotes_use_outermost_span() {
        let text = r#"she said "he told me 'send a photo' yesterday" and i refuse"#;
        let analysis = analyze(text);
        let quotes = span_texts(&analysis, text, SpanKind::ClosedQuote);
        assert_eq!(quotes.len(), 1, "{quotes:?}");
        assert!(quotes[0].contains("send a photo"));
    }

    #[test]
    fn negation_spans_only_neutralize_tagged_families() {
        let analysis = analyze("You are not worthless, I believe you.");
        assert!(analysis.stance.negation);
        assert!(analysis.attributed_families.contains(ThreatType::Bullying));
        assert!(analysis
            .attributed_families
            .contains(ThreatType::Manipulation));
        assert!(!analysis.attributed_families.contains(ThreatType::Grooming));
        assert!(!attribution_permits(
            &analysis,
            ThreatType::Grooming,
            SignalOrigin::Pattern
        ));
        assert!(attribution_permits(
            &analysis,
            ThreatType::Bullying,
            SignalOrigin::Pattern
        ));
    }

    #[test]
    fn stance_phrases_are_whole_phrases_not_prefixes() {
        let analysis = analyze("nothing happened, i got your message");
        assert!(!analysis.stance.is_protective());
        assert!(!analysis.stance.report);
    }

    #[test]
    fn compliance_directive_reactivates_quoted_request() {
        let text = r#"they said "send me a nude photo tonight" so do it now"#;
        let analysis = AttributionAnalysis::analyze(&text.to_lowercase(), &DefaultRiskProbe);
        assert!(analysis.compliance_directive);
        assert!(
            analysis.active_unattributed.contains(ThreatType::Explicit)
                || analysis.active_unattributed.contains(ThreatType::Grooming),
            "{analysis:?}"
        );
    }

    #[test]
    fn author_farewell_is_active_even_with_support_words() {
        let analysis = analyze("goodbye everyone, i want to die. i care about you all");
        assert!(analysis.active_unattributed.contains(ThreatType::SelfHarm));
    }

    #[test]
    fn capacity_failure_marks_every_family_active() {
        let text = "«".repeat(17) + " hi, he said something";
        let analysis = analyze(&text);
        assert!(analysis.capacity_failed || analysis.ambiguous_quotes);
        assert_eq!(analysis.active_unattributed, FamilySet::ALL);
    }

    #[test]
    fn cue_free_message_uses_only_the_phrase_floor() {
        let analysis = analyze("did you finish the math homework");
        assert!(analysis.spans.is_empty());
        assert!(analysis.active_unattributed.is_empty());
        let distress = analyze("i want to die");
        assert!(distress.active_unattributed.contains(ThreatType::SelfHarm));
    }

    #[test]
    fn family_set_round_trips() {
        let set = FamilySet::from_families(&[ThreatType::Threat, ThreatType::SelfHarm]);
        assert!(set.contains(ThreatType::Threat));
        assert!(!set.contains(ThreatType::Grooming));
        assert!(set.intersects(targeted_families()));
        assert!(!FamilySet::default().contains(ThreatType::None));
        let _ = NoProbe.scan_families("x");
    }
}
