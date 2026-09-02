//! Bounded, content-free structural evidence for compositional interpretation.
//!
//! This module deliberately stops before assigning a final speech act, stance,
//! directionality, or reciprocity. It exposes only byte spans and raw cues for a
//! higher-level interpreter to confirm.

use std::fmt;

use thiserror::Error;

use crate::truncate_domain_text;

/// Maximum number of tokens retained from one bounded message.
pub const MAX_SEMANTIC_TOKENS: usize = 2_048;
/// Maximum number of clauses retained from one bounded message.
pub const MAX_SEMANTIC_CLAUSES: usize = 512;
/// Maximum number of quote structures retained from one bounded message.
pub const MAX_SEMANTIC_QUOTES: usize = 128;
/// Maximum supported quote nesting depth.
pub const MAX_SEMANTIC_QUOTE_DEPTH: usize = 16;
/// Maximum number of raw semantic cues retained from one bounded message.
pub const MAX_SEMANTIC_ATOMS: usize = 512;
/// Maximum number of content-free diagnostics retained from one bounded message.
pub const MAX_SEMANTIC_DIAGNOSTICS: usize = 256;

/// A half-open UTF-8 byte range into the caller-provided source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSpan {
    start: u32,
    end: u32,
}

impl ByteSpan {
    /// Creates a span after validating ordering and UTF-8 boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`SpanError`] when the bounds are reversed, outside `source`, or
    /// split a UTF-8 scalar value.
    pub fn new(source: &str, start: usize, end: usize) -> Result<Self, SpanError> {
        if start > end {
            return Err(SpanError::Reversed { start, end });
        }
        if end > source.len() {
            return Err(SpanError::OutOfBounds {
                end,
                source_len: source.len(),
            });
        }
        if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
            return Err(SpanError::NotCharBoundary { start, end });
        }
        let start = u32::try_from(start).map_err(|_| SpanError::IndexTooLarge { index: start })?;
        let end = u32::try_from(end).map_err(|_| SpanError::IndexTooLarge { index: end })?;
        Ok(Self { start, end })
    }

    /// Returns the inclusive start byte offset.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start as usize
    }

    /// Returns the exclusive end byte offset.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end as usize
    }

    /// Returns the span length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end() - self.start()
    }

    /// Returns whether this span is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Returns whether this span fully contains `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Borrows the source segment selected by this span.
    ///
    /// # Errors
    ///
    /// Returns [`SpanError`] if the span does not belong to `source`.
    pub fn slice(self, source: &str) -> Result<&str, SpanError> {
        source.get(self.start()..self.end()).ok_or_else(|| {
            if self.end() > source.len() {
                SpanError::OutOfBounds {
                    end: self.end(),
                    source_len: source.len(),
                }
            } else {
                SpanError::NotCharBoundary {
                    start: self.start(),
                    end: self.end(),
                }
            }
        })
    }
}

/// Validation failure for a byte span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SpanError {
    /// The start offset is after the end offset.
    #[error("span start {start} is after end {end}")]
    Reversed {
        /// Requested start byte.
        start: usize,
        /// Requested end byte.
        end: usize,
    },
    /// The end offset exceeds the source length.
    #[error("span end {end} exceeds source length {source_len}")]
    OutOfBounds {
        /// Requested end byte.
        end: usize,
        /// Available source bytes.
        source_len: usize,
    },
    /// At least one offset splits a UTF-8 scalar value.
    #[error("span {start}..{end} is not aligned to UTF-8 boundaries")]
    NotCharBoundary {
        /// Requested start byte.
        start: usize,
        /// Requested end byte.
        end: usize,
    },
    /// An offset cannot be represented by the compact span type.
    #[error("span index {index} exceeds the supported range")]
    IndexTooLarge {
        /// Unrepresentable byte index.
        index: usize,
    },
}

/// Resource whose configured bound was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticCapacity {
    /// Token capacity.
    Tokens,
    /// Clause capacity.
    Clauses,
    /// Quote structure capacity.
    Quotes,
    /// Quote nesting capacity.
    QuoteDepth,
    /// Raw semantic cue capacity.
    Atoms,
    /// Diagnostic capacity.
    Diagnostics,
}

/// Failure to prepare bounded semantic structure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SemanticPrepareError {
    /// Attacker-controlled structure exceeded a fixed capacity.
    #[error("semantic {capacity:?} capacity exceeded (limit {limit})")]
    CapacityExceeded {
        /// Exhausted resource.
        capacity: SemanticCapacity,
        /// Configured maximum count.
        limit: usize,
    },
    /// A bounded allocation could not be reserved.
    #[error("failed to reserve bounded semantic {capacity:?} storage")]
    AllocationFailed {
        /// Resource whose storage could not be reserved.
        capacity: SemanticCapacity,
    },
    /// Internal construction produced an invalid UTF-8 span.
    #[error(transparent)]
    InvalidSpan(#[from] SpanError),
}

/// Coarse lexical token type without retaining token plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Alphabetic word, optionally containing an in-word apostrophe.
    Word,
    /// Decimal number.
    Number,
    /// Token containing both alphabetic and numeric scalars.
    Alphanumeric,
}

/// Structural relationship between evidence and recognized quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteContext {
    /// Evidence is outside all recognized quotes.
    Outside,
    /// Evidence is inside one or more fully closed quotes.
    Closed {
        /// Number of containing closed quote structures.
        depth: u8,
    },
    /// Evidence is inside at least one structurally ambiguous quote.
    Ambiguous {
        /// Total number of containing quote structures.
        depth: u8,
    },
}

/// One plaintext-free token projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    span: ByteSpan,
    kind: TokenKind,
    clause_index: u16,
    quote_context: QuoteContext,
}

impl Token {
    /// Returns the token byte span.
    #[must_use]
    pub const fn span(self) -> ByteSpan {
        self.span
    }

    /// Returns the coarse token kind.
    #[must_use]
    pub const fn kind(self) -> TokenKind {
        self.kind
    }

    /// Returns the containing clause index.
    #[must_use]
    pub const fn clause_index(self) -> usize {
        self.clause_index as usize
    }

    /// Returns the raw quote containment state.
    #[must_use]
    pub const fn quote_context(self) -> QuoteContext {
        self.quote_context
    }
}

/// Punctuation that terminated a structural clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClauseTerminator {
    /// Full stop.
    FullStop,
    /// Question mark.
    Question,
    /// Exclamation mark.
    Exclamation,
    /// Semicolon.
    Semicolon,
    /// Colon.
    Colon,
    /// Ellipsis scalar.
    Ellipsis,
    /// Line break.
    LineBreak,
    /// The bounded input ended without terminal punctuation.
    EndOfInput,
}

/// One raw punctuation-delimited clause span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clause {
    span: ByteSpan,
    terminator: ClauseTerminator,
}

impl Clause {
    /// Returns the clause byte span, including terminal punctuation when present.
    #[must_use]
    pub const fn span(self) -> ByteSpan {
        self.span
    }

    /// Returns how the clause ended.
    #[must_use]
    pub const fn terminator(self) -> ClauseTerminator {
        self.terminator
    }
}

/// Recognized quote delimiter family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteDelimiter {
    /// Straight ASCII double quotation mark.
    AsciiDouble,
    /// Straight ASCII single quotation mark outside a word.
    AsciiSingle,
    /// Curly double quotation marks, including low opening form.
    CurlyDouble,
    /// Curly single quotation marks outside a word.
    CurlySingle,
    /// Double angle quotation marks.
    Guillemets,
    /// Single angle quotation marks.
    SingleGuillemets,
    /// Low-9 opener (`„`) closed by `“` or `”`, as in Ukrainian and German
    /// typography.
    LowDouble,
}

/// Structural closure state of a quote span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteClosure {
    /// Opener and closer form a recognized pair.
    Closed,
    /// No matching closer appeared before the bounded input ended.
    AmbiguousUnclosed,
    /// A conflicting closer appeared; suppression must not treat this as closed.
    AmbiguousMismatched,
}

/// One recognized quote structure without retained plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteSpan {
    span: ByteSpan,
    content_span: ByteSpan,
    delimiter: QuoteDelimiter,
    closure: QuoteClosure,
    depth: u8,
}

impl QuoteSpan {
    /// Returns the full span including the opener and any observed closer.
    #[must_use]
    pub const fn span(self) -> ByteSpan {
        self.span
    }

    /// Returns the content span between structural delimiters.
    #[must_use]
    pub const fn content_span(self) -> ByteSpan {
        self.content_span
    }

    /// Returns the opener delimiter family.
    #[must_use]
    pub const fn delimiter(self) -> QuoteDelimiter {
        self.delimiter
    }

    /// Returns whether the structure is closed or ambiguous.
    #[must_use]
    pub const fn closure(self) -> QuoteClosure {
        self.closure
    }

    /// Returns the opener nesting depth, starting at one.
    #[must_use]
    pub const fn depth(self) -> usize {
        self.depth as usize
    }
}

/// Raw actor-reference category requiring interpreter confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorReferenceCandidate {
    /// First-person lexical reference.
    FirstPerson,
    /// Second-person lexical reference.
    SecondPerson,
    /// Third-person lexical reference.
    ThirdPerson,
}

/// Raw cue category; none of these values is a final interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticAtomKind {
    /// Lexical negation candidate.
    NegationCue,
    /// Lexical modality or intent candidate.
    ModalCue,
    /// Candidate actor reference.
    ActorReference(ActorReferenceCandidate),
}

/// One raw, span-backed semantic cue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticAtom {
    kind: SemanticAtomKind,
    evidence_span: ByteSpan,
    clause_index: u16,
    quote_context: QuoteContext,
}

impl SemanticAtom {
    /// Returns the raw cue category.
    #[must_use]
    pub const fn kind(self) -> SemanticAtomKind {
        self.kind
    }

    /// Returns the source evidence span.
    #[must_use]
    pub const fn evidence_span(self) -> ByteSpan {
        self.evidence_span
    }

    /// Returns the containing clause index.
    #[must_use]
    pub const fn clause_index(self) -> usize {
        self.clause_index as usize
    }

    /// Returns raw quote containment for interpreter-side handling.
    #[must_use]
    pub const fn quote_context(self) -> QuoteContext {
        self.quote_context
    }
}

/// Content-free structural diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticDiagnostic {
    /// Input exceeded the domain byte limit and was truncated at a UTF-8 boundary.
    InputTruncated {
        /// Original source byte count.
        original_bytes: usize,
        /// Retained source byte count.
        retained_bytes: usize,
    },
    /// A quote opener had no matching closer.
    UnclosedQuote {
        /// Opener byte span.
        opener: ByteSpan,
        /// Delimiter family that remained open.
        delimiter: QuoteDelimiter,
    },
    /// A closer conflicted with the active opener.
    MismatchedQuote {
        /// Active opener byte span.
        opener: ByteSpan,
        /// Observed closer byte span.
        closer: ByteSpan,
        /// Active opener family.
        expected: QuoteDelimiter,
        /// Observed closer family.
        observed: QuoteDelimiter,
    },
    /// A closing delimiter appeared without an active opener.
    UnmatchedClosingQuote {
        /// Closing delimiter byte span.
        closer: ByteSpan,
        /// Observed closer family.
        observed: QuoteDelimiter,
    },
}

/// Bounded structural preparation borrowing the original source text.
///
/// The type does not implement serialization, and its `Debug` representation
/// reports only lengths and counts. Callers may borrow a span explicitly for
/// ephemeral detector work, but diagnostics and atoms never retain plaintext.
pub struct PreparedSemanticText<'a> {
    source: &'a str,
    original_bytes: usize,
    tokens: Vec<Token>,
    clauses: Vec<Clause>,
    quotes: Vec<QuoteSpan>,
    atoms: Vec<SemanticAtom>,
    diagnostics: Vec<SemanticDiagnostic>,
}

impl fmt::Debug for PreparedSemanticText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSemanticText")
            .field("original_bytes", &self.original_bytes)
            .field("retained_bytes", &self.source.len())
            .field("token_count", &self.tokens.len())
            .field("clause_count", &self.clauses.len())
            .field("quote_count", &self.quotes.len())
            .field("atom_count", &self.atoms.len())
            .field("diagnostic_count", &self.diagnostics.len())
            .finish()
    }
}

impl<'a> PreparedSemanticText<'a> {
    /// Prepares bounded structural evidence from attacker-controlled UTF-8 text.
    ///
    /// Text beyond [`crate::MAX_DOMAIN_TEXT_BYTES`] is truncated at a valid UTF-8
    /// boundary and reported through [`SemanticDiagnostic::InputTruncated`].
    ///
    /// # Errors
    ///
    /// Returns [`SemanticPrepareError`] when a fixed structural capacity is
    /// exceeded or its bounded storage cannot be reserved. Callers must treat
    /// either outcome as unavailable semantic evidence, not as a safe verdict.
    pub fn new(source: &'a str) -> Result<Self, SemanticPrepareError> {
        let original_bytes = source.len();
        let source = truncate_domain_text(source);
        let mut diagnostics = bounded_vec(MAX_SEMANTIC_DIAGNOSTICS, SemanticCapacity::Diagnostics)?;
        if source.len() != original_bytes {
            push_bounded(
                &mut diagnostics,
                SemanticDiagnostic::InputTruncated {
                    original_bytes,
                    retained_bytes: source.len(),
                },
                MAX_SEMANTIC_DIAGNOSTICS,
                SemanticCapacity::Diagnostics,
            )?;
        }

        let quotes = scan_quotes(source, &mut diagnostics)?;
        let clauses = scan_clauses(source)?;
        let tokens = scan_tokens(source, &clauses, &quotes)?;
        let atoms = scan_atoms(source, &tokens)?;

        Ok(Self {
            source,
            original_bytes,
            tokens,
            clauses,
            quotes,
            atoms,
            diagnostics,
        })
    }

    /// Returns the original byte count before bounded truncation.
    #[must_use]
    pub const fn original_bytes(&self) -> usize {
        self.original_bytes
    }

    /// Returns the retained UTF-8 byte count.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.source.len()
    }

    /// Returns whether the input was truncated.
    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.original_bytes != self.source.len()
    }

    /// Returns the bounded token projections.
    #[must_use]
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    /// Returns the bounded structural clauses.
    #[must_use]
    pub fn clauses(&self) -> &[Clause] {
        &self.clauses
    }

    /// Returns recognized closed and ambiguous quote structures.
    #[must_use]
    pub fn quotes(&self) -> &[QuoteSpan] {
        &self.quotes
    }

    /// Returns raw cues awaiting interpreter confirmation.
    #[must_use]
    pub fn atoms(&self) -> &[SemanticAtom] {
        &self.atoms
    }

    /// Returns content-free structural diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[SemanticDiagnostic] {
        &self.diagnostics
    }

    /// Returns whether quote structure is ambiguous and must not enable safe suppression.
    #[must_use]
    pub fn has_ambiguous_quote_structure(&self) -> bool {
        self.quotes
            .iter()
            .any(|quote| quote.closure != QuoteClosure::Closed)
            || self.diagnostics.iter().any(|diagnostic| {
                matches!(diagnostic, SemanticDiagnostic::UnmatchedClosingQuote { .. })
            })
    }

    /// Borrows the retained source segment selected by `span`.
    ///
    /// # Errors
    ///
    /// Returns [`SpanError`] when the span is not valid for the retained source.
    pub fn slice(&self, span: ByteSpan) -> Result<&'a str, SpanError> {
        span.slice(self.source)
    }
}

#[derive(Debug, Clone, Copy)]
struct OpenQuote {
    opener: ByteSpan,
    delimiter: QuoteDelimiter,
    depth: u8,
}

#[derive(Debug, Clone, Copy)]
enum QuoteMark {
    Open(QuoteDelimiter),
    Close(QuoteDelimiter),
    Symmetric(QuoteDelimiter),
}

fn bounded_vec<T>(
    limit: usize,
    capacity: SemanticCapacity,
) -> Result<Vec<T>, SemanticPrepareError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(limit)
        .map_err(|_| SemanticPrepareError::AllocationFailed { capacity })?;
    Ok(values)
}

fn push_bounded<T>(
    values: &mut Vec<T>,
    value: T,
    limit: usize,
    capacity: SemanticCapacity,
) -> Result<(), SemanticPrepareError> {
    if values.len() >= limit {
        return Err(SemanticPrepareError::CapacityExceeded { capacity, limit });
    }
    values.push(value);
    Ok(())
}

fn span(source: &str, start: usize, end: usize) -> Result<ByteSpan, SemanticPrepareError> {
    Ok(ByteSpan::new(source, start, end)?)
}

fn scan_quotes(
    source: &str,
    diagnostics: &mut Vec<SemanticDiagnostic>,
) -> Result<Vec<QuoteSpan>, SemanticPrepareError> {
    let mut quotes = bounded_vec(MAX_SEMANTIC_QUOTES, SemanticCapacity::Quotes)?;
    let mut stack: Vec<OpenQuote> =
        bounded_vec(MAX_SEMANTIC_QUOTE_DEPTH, SemanticCapacity::QuoteDepth)?;
    let mut opened_count = 0usize;
    let mut characters = source.char_indices().peekable();
    let mut previous = None;

    while let Some((offset, character)) = characters.next() {
        let next = characters.peek().map(|(_, value)| *value);
        let Some(mark) = quote_mark(character, previous, next) else {
            previous = Some(character);
            continue;
        };
        let delimiter_span = span(source, offset, offset + character.len_utf8())?;
        // A low-9 quotation is closed by either curly double mark.
        let mark = match mark {
            QuoteMark::Open(QuoteDelimiter::CurlyDouble)
            | QuoteMark::Close(QuoteDelimiter::CurlyDouble)
                if stack
                    .last()
                    .is_some_and(|open| open.delimiter == QuoteDelimiter::LowDouble) =>
            {
                QuoteMark::Close(QuoteDelimiter::LowDouble)
            }
            other => other,
        };
        match mark {
            QuoteMark::Open(delimiter) | QuoteMark::Symmetric(delimiter) => {
                if matches!(mark, QuoteMark::Symmetric(_))
                    && stack.last().is_some_and(|open| open.delimiter == delimiter)
                {
                    close_quote(
                        source,
                        &mut quotes,
                        &mut stack,
                        delimiter_span,
                        delimiter,
                        diagnostics,
                    )?;
                } else {
                    if opened_count >= MAX_SEMANTIC_QUOTES {
                        return Err(SemanticPrepareError::CapacityExceeded {
                            capacity: SemanticCapacity::Quotes,
                            limit: MAX_SEMANTIC_QUOTES,
                        });
                    }
                    if stack.len() >= MAX_SEMANTIC_QUOTE_DEPTH {
                        return Err(SemanticPrepareError::CapacityExceeded {
                            capacity: SemanticCapacity::QuoteDepth,
                            limit: MAX_SEMANTIC_QUOTE_DEPTH,
                        });
                    }
                    let depth = u8::try_from(stack.len() + 1).map_err(|_| {
                        SemanticPrepareError::CapacityExceeded {
                            capacity: SemanticCapacity::QuoteDepth,
                            limit: MAX_SEMANTIC_QUOTE_DEPTH,
                        }
                    })?;
                    stack.push(OpenQuote {
                        opener: delimiter_span,
                        delimiter,
                        depth,
                    });
                    opened_count += 1;
                }
            }
            QuoteMark::Close(delimiter) => close_quote(
                source,
                &mut quotes,
                &mut stack,
                delimiter_span,
                delimiter,
                diagnostics,
            )?,
        }
        previous = Some(character);
    }

    while let Some(open) = stack.pop() {
        let full_span = span(source, open.opener.start(), source.len())?;
        let content_span = span(source, open.opener.end(), source.len())?;
        push_bounded(
            &mut quotes,
            QuoteSpan {
                span: full_span,
                content_span,
                delimiter: open.delimiter,
                closure: QuoteClosure::AmbiguousUnclosed,
                depth: open.depth,
            },
            MAX_SEMANTIC_QUOTES,
            SemanticCapacity::Quotes,
        )?;
        push_bounded(
            diagnostics,
            SemanticDiagnostic::UnclosedQuote {
                opener: open.opener,
                delimiter: open.delimiter,
            },
            MAX_SEMANTIC_DIAGNOSTICS,
            SemanticCapacity::Diagnostics,
        )?;
    }

    quotes.sort_unstable_by_key(|quote| (quote.span.start(), quote.span.end(), quote.depth));
    Ok(quotes)
}

fn close_quote(
    source: &str,
    quotes: &mut Vec<QuoteSpan>,
    stack: &mut Vec<OpenQuote>,
    closer: ByteSpan,
    observed: QuoteDelimiter,
    diagnostics: &mut Vec<SemanticDiagnostic>,
) -> Result<(), SemanticPrepareError> {
    let Some(open) = stack.pop() else {
        return push_bounded(
            diagnostics,
            SemanticDiagnostic::UnmatchedClosingQuote { closer, observed },
            MAX_SEMANTIC_DIAGNOSTICS,
            SemanticCapacity::Diagnostics,
        );
    };
    let closure = if open.delimiter == observed {
        QuoteClosure::Closed
    } else {
        push_bounded(
            diagnostics,
            SemanticDiagnostic::MismatchedQuote {
                opener: open.opener,
                closer,
                expected: open.delimiter,
                observed,
            },
            MAX_SEMANTIC_DIAGNOSTICS,
            SemanticCapacity::Diagnostics,
        )?;
        QuoteClosure::AmbiguousMismatched
    };
    push_bounded(
        quotes,
        QuoteSpan {
            span: span(source, open.opener.start(), closer.end())?,
            content_span: span(source, open.opener.end(), closer.start())?,
            delimiter: open.delimiter,
            closure,
            depth: open.depth,
        },
        MAX_SEMANTIC_QUOTES,
        SemanticCapacity::Quotes,
    )
}

fn quote_mark(character: char, previous: Option<char>, next: Option<char>) -> Option<QuoteMark> {
    let in_word =
        previous.is_some_and(char::is_alphanumeric) && next.is_some_and(char::is_alphanumeric);
    match character {
        '"' => Some(QuoteMark::Symmetric(QuoteDelimiter::AsciiDouble)),
        '\'' if !in_word => Some(QuoteMark::Symmetric(QuoteDelimiter::AsciiSingle)),
        '“' => Some(QuoteMark::Open(QuoteDelimiter::CurlyDouble)),
        '„' => Some(QuoteMark::Open(QuoteDelimiter::LowDouble)),
        '”' => Some(QuoteMark::Close(QuoteDelimiter::CurlyDouble)),
        '‘' if !in_word => Some(QuoteMark::Open(QuoteDelimiter::CurlySingle)),
        '’' if !in_word => Some(QuoteMark::Close(QuoteDelimiter::CurlySingle)),
        '«' => Some(QuoteMark::Open(QuoteDelimiter::Guillemets)),
        '»' => Some(QuoteMark::Close(QuoteDelimiter::Guillemets)),
        '‹' => Some(QuoteMark::Open(QuoteDelimiter::SingleGuillemets)),
        '›' => Some(QuoteMark::Close(QuoteDelimiter::SingleGuillemets)),
        _ => None,
    }
}

fn scan_clauses(source: &str) -> Result<Vec<Clause>, SemanticPrepareError> {
    let mut clauses = bounded_vec(MAX_SEMANTIC_CLAUSES, SemanticCapacity::Clauses)?;
    let mut clause_start = None;
    let mut last_non_whitespace_end = 0usize;

    for (offset, character) in source.char_indices() {
        let character_end = offset + character.len_utf8();
        if clause_start.is_none() && !character.is_whitespace() {
            clause_start = Some(offset);
        }
        if !character.is_whitespace() {
            last_non_whitespace_end = character_end;
        }
        let Some(terminator) = clause_terminator(character) else {
            continue;
        };
        if let Some(start) = clause_start.take() {
            push_bounded(
                &mut clauses,
                Clause {
                    span: span(source, start, character_end)?,
                    terminator,
                },
                MAX_SEMANTIC_CLAUSES,
                SemanticCapacity::Clauses,
            )?;
        }
        last_non_whitespace_end = character_end;
    }

    if let Some(start) = clause_start {
        push_bounded(
            &mut clauses,
            Clause {
                span: span(source, start, last_non_whitespace_end)?,
                terminator: ClauseTerminator::EndOfInput,
            },
            MAX_SEMANTIC_CLAUSES,
            SemanticCapacity::Clauses,
        )?;
    }
    Ok(clauses)
}

fn clause_terminator(character: char) -> Option<ClauseTerminator> {
    match character {
        '.' => Some(ClauseTerminator::FullStop),
        '?' => Some(ClauseTerminator::Question),
        '!' => Some(ClauseTerminator::Exclamation),
        ';' => Some(ClauseTerminator::Semicolon),
        ':' => Some(ClauseTerminator::Colon),
        '…' => Some(ClauseTerminator::Ellipsis),
        '\n' | '\r' => Some(ClauseTerminator::LineBreak),
        _ => None,
    }
}

fn scan_tokens(
    source: &str,
    clauses: &[Clause],
    quotes: &[QuoteSpan],
) -> Result<Vec<Token>, SemanticPrepareError> {
    let mut tokens = bounded_vec(MAX_SEMANTIC_TOKENS, SemanticCapacity::Tokens)?;
    let mut characters = source.char_indices().peekable();
    let mut previous = None;
    let mut token_start = None;
    let mut has_alphabetic = false;
    let mut has_numeric = false;
    let mut clause_cursor = 0usize;

    while let Some((offset, character)) = characters.next() {
        let next = characters.peek().map(|(_, value)| *value);
        if is_token_character(character, previous, next) {
            token_start.get_or_insert(offset);
            has_alphabetic |= character.is_alphabetic();
            has_numeric |= character.is_numeric();
        } else if let Some(start) = token_start.take() {
            push_token(
                source,
                &mut tokens,
                clauses,
                quotes,
                &mut clause_cursor,
                start,
                offset,
                has_alphabetic,
                has_numeric,
            )?;
            has_alphabetic = false;
            has_numeric = false;
        }
        previous = Some(character);
    }
    if let Some(start) = token_start {
        push_token(
            source,
            &mut tokens,
            clauses,
            quotes,
            &mut clause_cursor,
            start,
            source.len(),
            has_alphabetic,
            has_numeric,
        )?;
    }
    Ok(tokens)
}

#[expect(
    clippy::too_many_arguments,
    reason = "token finalization keeps scan state explicit"
)]
fn push_token(
    source: &str,
    tokens: &mut Vec<Token>,
    clauses: &[Clause],
    quotes: &[QuoteSpan],
    clause_cursor: &mut usize,
    start: usize,
    end: usize,
    has_alphabetic: bool,
    has_numeric: bool,
) -> Result<(), SemanticPrepareError> {
    let token_span = span(source, start, end)?;
    while clauses
        .get(*clause_cursor)
        .is_some_and(|clause| token_span.start() >= clause.span.end())
    {
        *clause_cursor += 1;
    }
    let Some(clause) = clauses.get(*clause_cursor) else {
        return Ok(());
    };
    if !clause.span.contains(token_span) {
        return Ok(());
    }
    let clause_index =
        u16::try_from(*clause_cursor).map_err(|_| SemanticPrepareError::CapacityExceeded {
            capacity: SemanticCapacity::Clauses,
            limit: MAX_SEMANTIC_CLAUSES,
        })?;
    let kind = match (has_alphabetic, has_numeric) {
        (true, true) => TokenKind::Alphanumeric,
        (false, true) => TokenKind::Number,
        _ => TokenKind::Word,
    };
    push_bounded(
        tokens,
        Token {
            span: token_span,
            kind,
            clause_index,
            quote_context: quote_context(token_span, quotes),
        },
        MAX_SEMANTIC_TOKENS,
        SemanticCapacity::Tokens,
    )
}

fn is_token_character(character: char, previous: Option<char>, next: Option<char>) -> bool {
    character.is_alphanumeric()
        || character == '_'
        || is_combining_mark(character)
        || (matches!(character, '\'' | '’')
            && previous.is_some_and(char::is_alphanumeric)
            && next.is_some_and(char::is_alphanumeric))
}

fn is_combining_mark(character: char) -> bool {
    matches!(
        character as u32,
        0x0300..=0x036F
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x20D0..=0x20FF
            | 0xFE20..=0xFE2F
    )
}

fn quote_context(evidence: ByteSpan, quotes: &[QuoteSpan]) -> QuoteContext {
    let mut closed = 0u8;
    let mut ambiguous = 0u8;
    for quote in quotes {
        if !quote.content_span.contains(evidence) {
            continue;
        }
        match quote.closure {
            QuoteClosure::Closed => closed = closed.saturating_add(1),
            QuoteClosure::AmbiguousUnclosed | QuoteClosure::AmbiguousMismatched => {
                ambiguous = ambiguous.saturating_add(1);
            }
        }
    }
    if ambiguous > 0 {
        QuoteContext::Ambiguous {
            depth: ambiguous.saturating_add(closed),
        }
    } else if closed > 0 {
        QuoteContext::Closed { depth: closed }
    } else {
        QuoteContext::Outside
    }
}

fn scan_atoms(source: &str, tokens: &[Token]) -> Result<Vec<SemanticAtom>, SemanticPrepareError> {
    let mut atoms = bounded_vec(MAX_SEMANTIC_ATOMS, SemanticCapacity::Atoms)?;
    for token in tokens {
        let text = token.span.slice(source)?;
        if matches_any(text, NEGATION_CUES) {
            push_atom(&mut atoms, *token, SemanticAtomKind::NegationCue)?;
        }
        if matches_any(text, MODAL_CUES) {
            push_atom(&mut atoms, *token, SemanticAtomKind::ModalCue)?;
        }
        if let Some(actor) = actor_reference(text) {
            push_atom(&mut atoms, *token, SemanticAtomKind::ActorReference(actor))?;
        }
    }
    Ok(atoms)
}

fn push_atom(
    atoms: &mut Vec<SemanticAtom>,
    token: Token,
    kind: SemanticAtomKind,
) -> Result<(), SemanticPrepareError> {
    push_bounded(
        atoms,
        SemanticAtom {
            kind,
            evidence_span: token.span,
            clause_index: token.clause_index,
            quote_context: token.quote_context,
        },
        MAX_SEMANTIC_ATOMS,
        SemanticCapacity::Atoms,
    )
}

fn matches_any(text: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|candidate| {
        text.chars()
            .flat_map(char::to_lowercase)
            .eq(candidate.chars())
    })
}

fn actor_reference(text: &str) -> Option<ActorReferenceCandidate> {
    if matches_any(text, FIRST_PERSON_REFERENCES) {
        Some(ActorReferenceCandidate::FirstPerson)
    } else if matches_any(text, SECOND_PERSON_REFERENCES) {
        Some(ActorReferenceCandidate::SecondPerson)
    } else if matches_any(text, THIRD_PERSON_REFERENCES) {
        Some(ActorReferenceCandidate::ThirdPerson)
    } else {
        None
    }
}

const NEGATION_CUES: &[&str] = &[
    "no",
    "not",
    "never",
    "without",
    "не",
    "ні",
    "ніколи",
    "без",
    "нет",
    "никогда",
];
const MODAL_CUES: &[&str] = &[
    "can",
    "could",
    "may",
    "might",
    "must",
    "should",
    "will",
    "would",
    "need",
    "want",
    "plan",
    "intend",
    "можу",
    "можна",
    "може",
    "мусиш",
    "треба",
    "буду",
    "хочу",
    "планую",
    "могу",
    "может",
    "должен",
    "надо",
    "планирую",
];
const FIRST_PERSON_REFERENCES: &[&str] = &[
    "i", "im", "i'm", "i’m", "i'll", "i’ll", "me", "my", "mine", "we", "us", "our", "ours", "я",
    "мене", "мені", "мій", "ми", "нас", "наш", "мне", "мой",
];
const SECOND_PERSON_REFERENCES: &[&str] = &[
    "you", "your", "yours", "ти", "тебе", "тобі", "твій", "ви", "вас", "вам", "ваш", "ты", "тебя",
    "тебе", "твой",
];
const THIRD_PERSON_REFERENCES: &[&str] = &[
    "he", "him", "his", "she", "her", "hers", "they", "them", "their", "він", "вона", "вони",
    "його", "її", "їм", "он", "она", "они", "его", "ее", "им",
];

#[cfg(test)]
mod tests {
    use super::{
        ActorReferenceCandidate, ByteSpan, PreparedSemanticText, QuoteClosure, QuoteContext,
        QuoteDelimiter, SemanticAtomKind, SemanticCapacity, SemanticDiagnostic,
        SemanticPrepareError, SpanError, MAX_SEMANTIC_ATOMS, MAX_SEMANTIC_CLAUSES,
        MAX_SEMANTIC_DIAGNOSTICS, MAX_SEMANTIC_QUOTES, MAX_SEMANTIC_QUOTE_DEPTH,
        MAX_SEMANTIC_TOKENS,
    };
    use crate::MAX_DOMAIN_TEXT_BYTES;

    #[test]
    fn byte_span_rejects_utf8_split() {
        let error = ByteSpan::new("🙂", 0, 1).expect_err("split scalar must fail");

        assert_eq!(error, SpanError::NotCharBoundary { start: 0, end: 1 });
    }

    #[test]
    fn preparation_truncates_at_utf8_boundary() {
        let source = format!("{}🙂tail", "a".repeat(MAX_DOMAIN_TEXT_BYTES - 1));
        let prepared = PreparedSemanticText::new(&source).expect("bounded preparation");

        assert!(prepared.retained_bytes() <= MAX_DOMAIN_TEXT_BYTES);
        assert!(prepared.was_truncated());
        assert!(matches!(
            prepared.diagnostics().first(),
            Some(SemanticDiagnostic::InputTruncated { .. })
        ));
    }

    #[test]
    fn preparation_accepts_exact_maximum_input() {
        let source = "я".repeat(MAX_DOMAIN_TEXT_BYTES / "я".len());
        let prepared = PreparedSemanticText::new(&source).expect("exact bound must prepare");

        assert_eq!(prepared.retained_bytes(), MAX_DOMAIN_TEXT_BYTES);
        assert!(!prepared.was_truncated());
    }

    #[test]
    fn nested_unicode_quotes_are_closed_deterministically() {
        let source = "Вона сказала: “не кажи «це» нікому”.";
        let prepared = PreparedSemanticText::new(source).expect("valid structure");
        let observed: Vec<_> = prepared
            .quotes()
            .iter()
            .map(|quote| {
                (
                    quote.delimiter(),
                    quote.closure(),
                    prepared.slice(quote.content_span()).expect("valid span"),
                )
            })
            .collect();

        assert_eq!(
            observed,
            vec![
                (
                    QuoteDelimiter::CurlyDouble,
                    QuoteClosure::Closed,
                    "не кажи «це» нікому"
                ),
                (QuoteDelimiter::Guillemets, QuoteClosure::Closed, "це"),
            ]
        );
    }

    #[test]
    fn in_word_apostrophes_are_not_quotes() {
        let prepared = PreparedSemanticText::new("don't і п’ять").expect("valid structure");

        assert!(prepared.quotes().is_empty());
    }

    #[test]
    fn unclosed_quote_is_explicitly_ambiguous() {
        let prepared = PreparedSemanticText::new("Він сказав: «не йди").expect("valid structure");

        assert_eq!(
            prepared.quotes()[0].closure(),
            QuoteClosure::AmbiguousUnclosed
        );
        assert!(prepared.tokens().iter().any(|token| {
            prepared.slice(token.span()).ok() == Some("не")
                && matches!(token.quote_context(), QuoteContext::Ambiguous { .. })
        }));
    }

    #[test]
    fn mismatched_quote_is_explicitly_ambiguous() {
        let prepared = PreparedSemanticText::new("“текст»").expect("valid structure");

        assert_eq!(
            prepared.quotes()[0].closure(),
            QuoteClosure::AmbiguousMismatched
        );
        assert!(matches!(
            prepared.diagnostics()[0],
            SemanticDiagnostic::MismatchedQuote { .. }
        ));
    }

    #[test]
    fn unmatched_closer_marks_whole_quote_structure_ambiguous() {
        let prepared = PreparedSemanticText::new("reported text»").expect("valid structure");

        assert!(prepared.has_ambiguous_quote_structure());
    }

    #[test]
    fn excess_tokens_return_typed_capacity_error() {
        let source = "a ".repeat(MAX_SEMANTIC_TOKENS + 1);
        let error = PreparedSemanticText::new(&source).expect_err("token bound must fail");

        assert_eq!(
            error,
            SemanticPrepareError::CapacityExceeded {
                capacity: SemanticCapacity::Tokens,
                limit: MAX_SEMANTIC_TOKENS,
            }
        );
    }

    #[test]
    fn excess_quote_depth_returns_typed_capacity_error() {
        let source = "«".repeat(MAX_SEMANTIC_QUOTE_DEPTH + 1);
        let error = PreparedSemanticText::new(&source).expect_err("depth bound must fail");

        assert_eq!(
            error,
            SemanticPrepareError::CapacityExceeded {
                capacity: SemanticCapacity::QuoteDepth,
                limit: MAX_SEMANTIC_QUOTE_DEPTH,
            }
        );
    }

    #[test]
    fn excess_clauses_return_typed_capacity_error() {
        let source = "a.".repeat(MAX_SEMANTIC_CLAUSES + 1);
        let error = PreparedSemanticText::new(&source).expect_err("clause bound must fail");

        assert_eq!(
            error,
            SemanticPrepareError::CapacityExceeded {
                capacity: SemanticCapacity::Clauses,
                limit: MAX_SEMANTIC_CLAUSES,
            }
        );
    }

    #[test]
    fn excess_quote_count_returns_typed_capacity_error() {
        let source = "\"x\"".repeat(MAX_SEMANTIC_QUOTES + 1);
        let error = PreparedSemanticText::new(&source).expect_err("quote bound must fail");

        assert_eq!(
            error,
            SemanticPrepareError::CapacityExceeded {
                capacity: SemanticCapacity::Quotes,
                limit: MAX_SEMANTIC_QUOTES,
            }
        );
    }

    #[test]
    fn excess_atoms_return_typed_capacity_error() {
        let source = "не ".repeat(MAX_SEMANTIC_ATOMS + 1);
        let error = PreparedSemanticText::new(&source).expect_err("atom bound must fail");

        assert_eq!(
            error,
            SemanticPrepareError::CapacityExceeded {
                capacity: SemanticCapacity::Atoms,
                limit: MAX_SEMANTIC_ATOMS,
            }
        );
    }

    #[test]
    fn excess_diagnostics_return_typed_capacity_error() {
        let source = "»".repeat(MAX_SEMANTIC_DIAGNOSTICS + 1);
        let error = PreparedSemanticText::new(&source).expect_err("diagnostic bound must fail");

        assert_eq!(
            error,
            SemanticPrepareError::CapacityExceeded {
                capacity: SemanticCapacity::Diagnostics,
                limit: MAX_SEMANTIC_DIAGNOSTICS,
            }
        );
    }

    #[test]
    fn raw_atoms_cover_multilingual_negation_modal_and_actor_references() {
        let prepared =
            PreparedSemanticText::new("Я не хочу. You should.").expect("valid structure");
        let kinds: Vec<_> = prepared.atoms().iter().map(|atom| atom.kind()).collect();

        assert_eq!(
            kinds,
            vec![
                SemanticAtomKind::ActorReference(ActorReferenceCandidate::FirstPerson),
                SemanticAtomKind::NegationCue,
                SemanticAtomKind::ModalCue,
                SemanticAtomKind::ActorReference(ActorReferenceCandidate::SecondPerson),
                SemanticAtomKind::ModalCue,
            ]
        );
    }

    #[test]
    fn first_person_contractions_remain_actor_references() {
        for text in [
            "im done",
            "I'm done",
            "I’m done",
            "I'll do it",
            "I’ll do it",
        ] {
            let prepared = PreparedSemanticText::new(text).expect("valid structure");
            assert!(
                prepared.atoms().iter().any(|atom| {
                    atom.kind()
                        == SemanticAtomKind::ActorReference(ActorReferenceCandidate::FirstPerson)
                }),
                "{text}"
            );
        }
    }

    #[test]
    fn repeated_preparation_produces_identical_spans() {
        let source = "He said: «не роби цього»!";
        let first = PreparedSemanticText::new(source).expect("first preparation");
        let second = PreparedSemanticText::new(source).expect("second preparation");

        assert_eq!(first.tokens(), second.tokens());
        assert_eq!(first.clauses(), second.clauses());
        assert_eq!(first.quotes(), second.quotes());
        assert_eq!(first.atoms(), second.atoms());
        assert_eq!(first.diagnostics(), second.diagnostics());
    }

    #[test]
    fn debug_output_does_not_contain_plaintext() {
        let prepared = PreparedSemanticText::new("private message").expect("valid structure");
        let debug = format!("{prepared:?}");

        assert!(!debug.contains("private message"));
    }

    #[test]
    fn low_nine_quotation_closes_with_either_curly_mark() {
        for text in ["„Надішли фото“ — це шантаж", "„Надішли фото” — це шантаж"]
        {
            let prepared = PreparedSemanticText::new(text).expect("prepare");
            assert!(!prepared.has_ambiguous_quote_structure(), "{text}");
            let quote = prepared.quotes().first().expect("one quote");
            assert_eq!(quote.closure(), QuoteClosure::Closed);
            assert_eq!(quote.delimiter(), QuoteDelimiter::LowDouble);
            assert_eq!(
                prepared.slice(quote.content_span()).unwrap(),
                "Надішли фото"
            );
        }
        let nested = PreparedSemanticText::new("“outer “inner” text”").expect("prepare");
        assert!(!nested.has_ambiguous_quote_structure());
    }

    #[test]
    fn hostile_unicode_samples_never_panic() {
        let samples = [
            "",
            "\0\0\0",
            "🙂🙂🙂",
            "\u{0301}\u{0301}",
            "«“„'\"»”",
            "а\u{200d}б\u{2060}в",
            "\r\n\n...!!!???",
        ];

        assert!(samples
            .iter()
            .all(|sample| PreparedSemanticText::new(sample).is_ok()));
    }

    #[test]
    fn every_unicode_prefix_produces_sliceable_spans_or_typed_error() {
        let source = "Я не скажу: “don’t «роби» це” 🙂\nНіколи!";
        let mut boundaries: Vec<_> = source.char_indices().map(|(index, _)| index).collect();
        boundaries.push(source.len());

        for end in boundaries {
            let prepared = PreparedSemanticText::new(&source[..end]).expect("bounded prefix");
            assert!(prepared
                .tokens()
                .iter()
                .all(|token| prepared.slice(token.span()).is_ok()));
            assert!(prepared
                .clauses()
                .iter()
                .all(|clause| prepared.slice(clause.span()).is_ok()));
            assert!(prepared
                .quotes()
                .iter()
                .all(|quote| prepared.slice(quote.span()).is_ok()
                    && prepared.slice(quote.content_span()).is_ok()));
        }
    }
}
