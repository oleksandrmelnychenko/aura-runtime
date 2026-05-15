//! Volume-scaling engine for detector simulation packs.
//!
//! Takes a `DetectorPack`, applies a set of language-agnostic perturbations
//! to each scenario, and emits N variants per case. This multiplies a
//! 25-case pack into ~150-300 case variants without writing them by hand.
//!
//! Perturbations are deterministic given a seed — re-running the volume
//! suite produces the same variants every time, so CI reports are stable.

use crate::ScenarioCase;

/// A single character-level perturbation profile that applies to ANY language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PerturbationKind {
    /// Drop a single character mid-word (typo).
    TypoDrop,
    /// Swap two adjacent characters (typo).
    TypoSwap,
    /// Substitute select latin letters with leet digits (a→4, e→3, i→1, o→0, s→5).
    Leetspeak,
    /// Sprinkle fire/100/eyes emojis between words.
    EmojiPadding,
    /// Strip ASCII punctuation and collapse whitespace.
    PunctuationStrip,
    /// Insert zero-width space between every other character of the longest word.
    ZwspInsert,
    /// Random uppercase flip on word starts.
    SponBob,
    /// Append/prepend ellipsis blocks ("... ... ...").
    EllipsisFlood,
}

impl PerturbationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::TypoDrop => "typo_drop",
            Self::TypoSwap => "typo_swap",
            Self::Leetspeak => "leetspeak",
            Self::EmojiPadding => "emoji_pad",
            Self::PunctuationStrip => "punct_strip",
            Self::ZwspInsert => "zwsp",
            Self::SponBob => "spongebob",
            Self::EllipsisFlood => "ellipsis",
        }
    }

    pub fn default_set() -> &'static [PerturbationKind] {
        &[
            Self::TypoDrop,
            Self::TypoSwap,
            Self::Leetspeak,
            Self::EmojiPadding,
            Self::PunctuationStrip,
            Self::ZwspInsert,
            Self::SponBob,
            Self::EllipsisFlood,
        ]
    }
}

/// Ordered perturbation chain used for adversarial combo stress.
///
/// Single perturbations are good for attribution ("which mutator hurts us?").
/// Combo sequences are closer to real evasion: kids and bad actors rarely use
/// just one trick when they are trying to slip through moderation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PerturbationSequence {
    kinds: Vec<PerturbationKind>,
}

impl PerturbationSequence {
    pub fn new(kinds: Vec<PerturbationKind>) -> Self {
        assert!(!kinds.is_empty(), "perturbation sequence cannot be empty");
        Self { kinds }
    }

    pub fn kinds(&self) -> &[PerturbationKind] {
        &self.kinds
    }

    pub fn label(&self) -> String {
        self.kinds
            .iter()
            .map(|kind| kind.label())
            .collect::<Vec<_>>()
            .join("+")
    }
}

pub fn default_combo_set() -> Vec<PerturbationSequence> {
    use PerturbationKind::{
        EllipsisFlood, EmojiPadding, Leetspeak, PunctuationStrip, SponBob, TypoDrop, TypoSwap,
        ZwspInsert,
    };

    vec![
        PerturbationSequence::new(vec![Leetspeak, EmojiPadding]),
        PerturbationSequence::new(vec![Leetspeak, PunctuationStrip]),
        PerturbationSequence::new(vec![Leetspeak, ZwspInsert]),
        PerturbationSequence::new(vec![TypoDrop, EmojiPadding]),
        PerturbationSequence::new(vec![TypoDrop, Leetspeak]),
        PerturbationSequence::new(vec![TypoSwap, EmojiPadding]),
        PerturbationSequence::new(vec![TypoSwap, PunctuationStrip]),
        PerturbationSequence::new(vec![EmojiPadding, PunctuationStrip]),
        PerturbationSequence::new(vec![PunctuationStrip, ZwspInsert]),
        PerturbationSequence::new(vec![ZwspInsert, EmojiPadding]),
        PerturbationSequence::new(vec![SponBob, EmojiPadding]),
        PerturbationSequence::new(vec![EllipsisFlood, Leetspeak]),
    ]
}

/// Held-out perturbations used to test generalization beyond the tuned volume
/// and combo suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoldoutPerturbationKind {
    /// Convert ASCII letters/digits/punctuation into Unicode fullwidth forms.
    FullwidthAscii,
    /// Replace selected Latin letters with Cyrillic lookalikes.
    MixedScriptHomoglyph,
    /// Add combining marks after Latin letters.
    CombiningMarkFlood,
    /// Insert middle-dot separators inside the longest word.
    InterstitialDot,
    /// Replace ordinary spaces with newlines, tabs and NBSP.
    WhitespaceNoise,
}

impl HoldoutPerturbationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::FullwidthAscii => "fullwidth_ascii",
            Self::MixedScriptHomoglyph => "mixed_script_homoglyph",
            Self::CombiningMarkFlood => "combining_mark_flood",
            Self::InterstitialDot => "interstitial_dot",
            Self::WhitespaceNoise => "whitespace_noise",
        }
    }

    pub fn default_set() -> &'static [HoldoutPerturbationKind] {
        &[
            Self::FullwidthAscii,
            Self::MixedScriptHomoglyph,
            Self::CombiningMarkFlood,
            Self::InterstitialDot,
            Self::WhitespaceNoise,
        ]
    }
}

/// Tiny deterministic PRNG (xorshift64).
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x & 0xFFFF_FFFF) as u32
    }
    fn range(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u32() as usize) % n
    }
}

pub fn perturb_text(text: &str, kind: PerturbationKind, seed: u64) -> String {
    let mut rng = Lcg::new(seed);
    match kind {
        PerturbationKind::TypoDrop => typo_drop(text, &mut rng),
        PerturbationKind::TypoSwap => typo_swap(text, &mut rng),
        PerturbationKind::Leetspeak => leetspeak(text),
        PerturbationKind::EmojiPadding => emoji_padding(text, &mut rng),
        PerturbationKind::PunctuationStrip => punct_strip(text),
        PerturbationKind::ZwspInsert => zwsp_insert(text),
        PerturbationKind::SponBob => spongebob(text, &mut rng),
        PerturbationKind::EllipsisFlood => ellipsis_flood(text),
    }
}

pub fn perturb_text_sequence(text: &str, kinds: &[PerturbationKind], seed: u64) -> String {
    let mut out = text.to_string();
    for (idx, kind) in kinds.iter().enumerate() {
        let step_seed = seed.wrapping_add((idx as u64 + 1).wrapping_mul(0xA24B_AED4_963E_E407));
        out = perturb_text(&out, *kind, step_seed);
    }
    out
}

pub fn perturb_text_holdout(text: &str, kind: HoldoutPerturbationKind, seed: u64) -> String {
    let mut rng = Lcg::new(seed);
    match kind {
        HoldoutPerturbationKind::FullwidthAscii => fullwidth_ascii(text),
        HoldoutPerturbationKind::MixedScriptHomoglyph => mixed_script_homoglyph(text, &mut rng),
        HoldoutPerturbationKind::CombiningMarkFlood => combining_mark_flood(text, &mut rng),
        HoldoutPerturbationKind::InterstitialDot => interstitial_dot(text),
        HoldoutPerturbationKind::WhitespaceNoise => whitespace_noise(text, &mut rng),
    }
}

fn typo_drop(text: &str, rng: &mut Lcg) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < 4 {
        return text.to_string();
    }
    let mut drop_at = None;
    for _ in 0..16 {
        let idx = rng.range(chars.len());
        if chars[idx].is_alphabetic() {
            drop_at = Some(idx);
            break;
        }
    }
    let Some(drop_at) = drop_at else {
        return text.to_string();
    };
    chars
        .into_iter()
        .enumerate()
        .filter_map(|(i, c)| if i == drop_at { None } else { Some(c) })
        .collect()
}

fn typo_swap(text: &str, rng: &mut Lcg) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    if chars.len() < 4 {
        return text.to_string();
    }
    for _ in 0..16 {
        let start = rng.range(chars.len().saturating_sub(2));
        if chars[start].is_alphabetic()
            && chars[start + 1].is_alphabetic()
            && chars[start] != chars[start + 1]
        {
            chars.swap(start, start + 1);
            return chars.into_iter().collect();
        }
    }
    chars.into_iter().collect()
}

fn leetspeak(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a' => '4',
            'A' => '4',
            'e' => '3',
            'E' => '3',
            'i' => '1',
            'I' => '1',
            'o' => '0',
            'O' => '0',
            's' => '5',
            'S' => '5',
            't' => '7',
            'T' => '7',
            other => other,
        })
        .collect()
}

fn emoji_padding(text: &str, rng: &mut Lcg) -> String {
    let emojis = ["🔥", "💯", "👀", "😂", "💀"];
    let mut out = String::with_capacity(text.len() + 32);
    for (idx, word) in text.split_whitespace().enumerate() {
        if idx > 0 {
            out.push(' ');
            if rng.range(3) == 0 {
                out.push_str(emojis[rng.range(emojis.len())]);
                out.push(' ');
            }
        }
        out.push_str(word);
    }
    out
}

fn punct_strip(text: &str) -> String {
    let stripped: String = text
        .chars()
        .map(|c| match c {
            '.' | ',' | ';' | ':' | '!' | '?' | '"' | '\'' | '(' | ')' | '[' | ']' | '-' | '—'
            | '–' => ' ',
            other => other,
        })
        .collect();
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn zwsp_insert(text: &str) -> String {
    // Find the longest alphabetic run and pepper it with U+200B between every other char.
    let chars: Vec<char> = text.chars().collect();
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut cur_start, mut cur_len) = (0usize, 0usize);
    for (i, c) in chars.iter().enumerate() {
        if c.is_alphabetic() {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    if best_len < 5 {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + best_len);
    for (i, c) in chars.iter().enumerate() {
        out.push(*c);
        if i >= best_start && i < best_start + best_len - 1 && (i - best_start) % 2 == 0 {
            out.push('\u{200B}');
        }
    }
    out
}

fn spongebob(text: &str, rng: &mut Lcg) -> String {
    text.chars()
        .map(|c| {
            if c.is_alphabetic() && rng.range(2) == 0 {
                c.to_uppercase().next().unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

fn ellipsis_flood(text: &str) -> String {
    format!("... {} ...", text)
}

fn fullwidth_ascii(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            ' ' => '\u{3000}',
            '!'..='~' => char::from_u32(c as u32 + 0xFEE0).unwrap_or(c),
            other => other,
        })
        .collect()
}

fn mixed_script_homoglyph(text: &str, rng: &mut Lcg) -> String {
    text.chars()
        .map(|c| {
            if rng.range(3) != 0 {
                return c;
            }
            match c {
                'a' => 'а',
                'A' => 'А',
                'e' => 'е',
                'E' => 'Е',
                'o' => 'о',
                'O' => 'О',
                'p' => 'р',
                'P' => 'Р',
                'c' => 'с',
                'C' => 'С',
                'x' => 'х',
                'X' => 'Х',
                'y' => 'у',
                'Y' => 'У',
                'i' => 'і',
                'I' => 'І',
                other => other,
            }
        })
        .collect()
}

fn combining_mark_flood(text: &str, rng: &mut Lcg) -> String {
    let marks = ['\u{0301}', '\u{0307}', '\u{0323}'];
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        out.push(c);
        if c.is_ascii_alphabetic() && rng.range(4) == 0 {
            out.push(marks[rng.range(marks.len())]);
        }
    }
    out
}

fn interstitial_dot(text: &str) -> String {
    interstitial_insert(text, '·')
}

fn interstitial_insert(text: &str, separator: char) -> String {
    let chars: Vec<char> = text.chars().collect();
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut cur_start, mut cur_len) = (0usize, 0usize);
    for (i, c) in chars.iter().enumerate() {
        if c.is_alphabetic() {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    if best_len < 5 {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len() + best_len);
    for (i, c) in chars.iter().enumerate() {
        out.push(*c);
        if i >= best_start && i < best_start + best_len - 1 {
            out.push(separator);
        }
    }
    out
}

fn whitespace_noise(text: &str, rng: &mut Lcg) -> String {
    let spaces = ["\n", "\t", "\u{00A0}", "  "];
    text.split_whitespace().enumerate().fold(
        String::with_capacity(text.len() + 12),
        |mut out, (idx, word)| {
            if idx > 0 {
                out.push_str(spaces[rng.range(spaces.len())]);
            }
            out.push_str(word);
            out
        },
    )
}

/// Build N perturbed variants of a scenario case.
///
/// `case_seed` should be derived from the original case name so different
/// cases get reproducible-but-different mutations.
pub fn perturb_case(case: &ScenarioCase, kind: PerturbationKind, seed: u64) -> ScenarioCase {
    let mut perturbed = case.clone();
    perturbed.name = format!("{}__{}", case.name, kind.label());
    for (idx, step) in perturbed.steps.iter_mut().enumerate() {
        if let Some(text) = &step.input.text {
            let step_seed = seed
                .wrapping_add(idx as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            step.input.text = Some(perturb_text(text, kind, step_seed));
        }
    }
    perturbed
}

pub fn perturb_case_sequence(
    case: &ScenarioCase,
    sequence: &PerturbationSequence,
    seed: u64,
) -> ScenarioCase {
    let mut perturbed = case.clone();
    perturbed.name = format!("{}__{}", case.name, sequence.label());
    for (idx, step) in perturbed.steps.iter_mut().enumerate() {
        if let Some(text) = &step.input.text {
            let step_seed = seed
                .wrapping_add(idx as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            step.input.text = Some(perturb_text_sequence(text, sequence.kinds(), step_seed));
        }
    }
    perturbed
}

pub fn perturb_case_holdout(
    case: &ScenarioCase,
    kind: HoldoutPerturbationKind,
    seed: u64,
) -> ScenarioCase {
    let mut perturbed = case.clone();
    perturbed.name = format!("{}__{}", case.name, kind.label());
    for (idx, step) in perturbed.steps.iter_mut().enumerate() {
        if let Some(text) = &step.input.text {
            let step_seed = seed
                .wrapping_add(idx as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            step.input.text = Some(perturb_text_holdout(text, kind, step_seed));
        }
    }
    perturbed
}

/// Default volume amplification: each case → 1 variant per perturbation kind
/// (8 variants by default). 25 cases × 8 = 200 variants per pack.
pub fn perturb_pack(pack: &[ScenarioCase], kinds: &[PerturbationKind]) -> Vec<ScenarioCase> {
    let mut variants = Vec::with_capacity(pack.len() * kinds.len());
    for case in pack {
        let case_seed = hash_name(&case.name);
        for kind in kinds {
            variants.push(perturb_case(case, *kind, case_seed));
        }
    }
    variants
}

/// Combo volume amplification: each case -> 1 variant per perturbation sequence.
pub fn perturb_pack_sequences(
    pack: &[ScenarioCase],
    sequences: &[PerturbationSequence],
) -> Vec<ScenarioCase> {
    let mut variants = Vec::with_capacity(pack.len() * sequences.len());
    for case in pack {
        let case_seed = hash_name(&case.name);
        for sequence in sequences {
            variants.push(perturb_case_sequence(case, sequence, case_seed));
        }
    }
    variants
}

pub fn perturb_pack_holdout(
    pack: &[ScenarioCase],
    kinds: &[HoldoutPerturbationKind],
) -> Vec<ScenarioCase> {
    let mut variants = Vec::with_capacity(pack.len() * kinds.len());
    for case in pack {
        let case_seed = hash_name(&case.name);
        for kind in kinds {
            variants.push(perturb_case_holdout(case, *kind, case_seed));
        }
    }
    variants
}

fn hash_name(name: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

#[derive(Debug, Clone, PartialEq)]
pub struct VolumeReport {
    pub pack_name: &'static str,
    pub base_case_count: usize,
    pub variant_count: usize,
    pub per_kind: Vec<KindOutcome>,
    pub aggregate: VolumeOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KindOutcome {
    pub kind: PerturbationKind,
    pub outcome: VolumeOutcome,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct VolumeOutcome {
    pub total: usize,
    pub positives: usize,
    pub negatives: usize,
    pub positives_detected: usize,
    pub negatives_fired: usize,
}

impl VolumeOutcome {
    pub fn pos_rate(&self) -> f32 {
        if self.positives == 0 {
            0.0
        } else {
            self.positives_detected as f32 / self.positives as f32
        }
    }
    pub fn fp_rate(&self) -> f32 {
        if self.negatives == 0 {
            0.0
        } else {
            self.negatives_fired as f32 / self.negatives as f32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario_packs::hate_speech::canonical_hate_speech_scenarios;
    use crate::{run_scenario_case, ThreatType};
    use aura_patterns::PatternDatabase;

    #[test]
    fn perturb_pack_multiplies_cases() {
        let base = canonical_hate_speech_scenarios();
        let kinds = PerturbationKind::default_set();
        let variants = perturb_pack(&base, kinds);
        assert_eq!(variants.len(), base.len() * kinds.len());
    }

    #[test]
    fn perturbations_change_text() {
        let s = "Those people are cockroaches, infesting our streets.";
        for kind in PerturbationKind::default_set() {
            let mutated = perturb_text(s, *kind, 42);
            assert_ne!(
                mutated,
                s,
                "perturbation {} should change text",
                kind.label()
            );
        }
    }

    #[test]
    fn perturbed_pack_runs_through_harness() {
        let db = PatternDatabase::default_mvp();
        let base: Vec<_> = canonical_hate_speech_scenarios()
            .into_iter()
            .take(3)
            .collect();
        let variants = perturb_pack(&base, &[PerturbationKind::PunctuationStrip]);
        for case in &variants {
            let run = run_scenario_case(&db, case);
            assert_eq!(run.step_results.len(), case.steps.len());
            assert!(matches!(
                case.primary_threat,
                Some(ThreatType::HateSpeech) | None
            ));
        }
    }

    #[test]
    fn perturb_pack_sequences_multiplies_cases() {
        let base = canonical_hate_speech_scenarios();
        let sequences = default_combo_set();
        let variants = perturb_pack_sequences(&base, &sequences);
        assert_eq!(variants.len(), base.len() * sequences.len());
    }

    #[test]
    fn combined_perturbations_apply_in_order() {
        let s = "claim the secret access code today";
        let sequence = PerturbationSequence::new(vec![
            PerturbationKind::Leetspeak,
            PerturbationKind::EmojiPadding,
        ]);

        let mutated = perturb_text_sequence(s, sequence.kinds(), 42);

        assert_ne!(mutated, s);
        assert!(mutated.contains('4') || mutated.contains('3') || mutated.contains('0'));
        assert!(mutated.contains("🔥") || mutated.contains("💯") || mutated.contains("👀"));
    }

    #[test]
    fn holdout_perturb_pack_multiplies_cases() {
        let base = canonical_hate_speech_scenarios();
        let kinds = HoldoutPerturbationKind::default_set();
        let variants = perturb_pack_holdout(&base, kinds);
        assert_eq!(variants.len(), base.len() * kinds.len());
    }

    #[test]
    fn holdout_perturbations_change_text() {
        let text = "FREE Steam skins claim now https://example.com";
        for kind in HoldoutPerturbationKind::default_set() {
            let mutated = perturb_text_holdout(text, *kind, 42);
            assert_ne!(
                mutated,
                text,
                "holdout perturbation {} should change text",
                kind.label()
            );
        }
    }
}
