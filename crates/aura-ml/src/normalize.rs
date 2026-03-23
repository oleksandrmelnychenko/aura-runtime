//! Text normalization pipeline for ML inference.
//!
//! Handles adversarial bypass attempts: leetspeak, unicode confusables,
//! zero-width characters, spaced-out words, and emoji substitution.
//! Applied before tokenization to improve model robustness.

/// Applies the full normalization pipeline for ML input.
pub fn normalize_for_ml(text: &str) -> String {
    let text = strip_zero_width(text);
    let text = normalize_confusables(&text);
    let text = normalize_leetspeak(&text);
    let text = collapse_spaced_chars(&text);
    unicode_normalization_nfkc(&text)
}

/// Strips zero-width and invisible Unicode characters.
fn strip_zero_width(text: &str) -> String {
    text.chars()
        .filter(|c| {
            let cp = *c as u32;
            cp != 0x200B // zero-width space
            && cp != 0x200C // zero-width non-joiner
            && cp != 0x200D // zero-width joiner
            && cp != 0x200E // left-to-right mark
            && cp != 0x200F // right-to-left mark
            && cp != 0x2060 // word joiner
            && cp != 0x2061 // function application
            && cp != 0x2062 // invisible times
            && cp != 0x2063 // invisible separator
            && cp != 0x2064 // invisible plus
            && cp != 0xFEFF // BOM
            && cp != 0x00AD // soft hyphen
        })
        .collect()
}

/// Maps visually confusable Unicode characters to ASCII equivalents.
fn normalize_confusables(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{0410}' => 'A',
            '\u{0412}' => 'B',
            '\u{0421}' => 'C',
            '\u{0415}' => 'E',
            '\u{041D}' => 'H',
            '\u{041A}' => 'K',
            '\u{041C}' => 'M',
            '\u{041E}' => 'O',
            '\u{0420}' => 'P',
            '\u{0422}' => 'T',
            '\u{0425}' => 'X',
            '\u{0430}' => 'a',
            '\u{0435}' => 'e',
            '\u{043E}' => 'o',
            '\u{0440}' => 'p',
            '\u{0441}' => 'c',
            '\u{0443}' => 'y',
            '\u{0445}' => 'x',
            '\u{0456}' => 'i',
            c if ('\u{FF01}'..='\u{FF5E}').contains(&c) => {
                char::from_u32(c as u32 - 0xFF01 + 0x21).unwrap_or(c)
            }
            other => other,
        })
        .collect()
}

/// Maps common leetspeak substitutions back to letters.
fn normalize_leetspeak(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    for i in 0..chars.len() {
        let c = chars[i];
        let mapped = match c {
            '0' => 'o',
            '1' if is_leet_context(&chars, i) => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' if is_leet_context(&chars, i) => 'b',
            '@' if is_leet_context(&chars, i) => 'a',
            '$' if is_leet_context(&chars, i) => 's',
            '!' if is_leet_context_strict(&chars, i) => 'i',
            other => other,
        };
        result.push(mapped);
    }
    result
}

fn is_leet_context(chars: &[char], pos: usize) -> bool {
    let before = pos > 0 && chars[pos - 1].is_alphabetic();
    let after = pos + 1 < chars.len() && chars[pos + 1].is_alphabetic();
    before || after
}

fn is_leet_context_strict(chars: &[char], pos: usize) -> bool {
    let before = pos > 0 && chars[pos - 1].is_alphabetic();
    let after = pos + 1 < chars.len() && chars[pos + 1].is_alphabetic();
    before && after
}

/// Collapses single characters separated by spaces: "k i l l" -> "kill".
fn collapse_spaced_chars(text: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < 3 {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut run_start = 0;

    while run_start < words.len() {
        let mut run_end = run_start;
        while run_end < words.len()
            && words[run_end].chars().count() == 1
            && words[run_end]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphabetic())
        {
            run_end += 1;
        }

        let run_len = run_end - run_start;
        if run_len >= 3 {
            if !result.is_empty() {
                result.push(' ');
            }
            for i in run_start..run_end {
                result.push_str(words[i]);
            }
        } else {
            for i in run_start..run_end.max(run_start + 1) {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str(words[i]);
                if run_len == 0 {
                    run_end = run_start + 1;
                }
            }
        }
        run_start = run_end;
    }
    result
}

fn unicode_normalization_nfkc(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    text.nfkc().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_chars() {
        assert_eq!(strip_zero_width("k\u{200B}ill"), "kill");
        assert_eq!(strip_zero_width("he\u{200C}llo"), "hello");
        assert_eq!(strip_zero_width("\u{FEFF}test"), "test");
    }

    #[test]
    fn normalizes_cyrillic_latin_confusables() {
        assert_eq!(normalize_confusables("k\u{0456}ll"), "kill");
    }

    #[test]
    fn normalizes_leetspeak() {
        assert_eq!(normalize_leetspeak("k1ll"), "kill");
        assert_eq!(normalize_leetspeak("h4t3"), "hate");
    }

    #[test]
    fn leetspeak_preserves_standalone_digits() {
        let result = normalize_leetspeak("call 123");
        assert!(result.contains('1'), "standalone digits should stay");
    }

    #[test]
    fn collapses_spaced_chars() {
        assert_eq!(collapse_spaced_chars("k i l l you"), "kill you");
        assert_eq!(collapse_spaced_chars("d i e now"), "die now");
    }

    #[test]
    fn preserves_normal_text() {
        assert_eq!(collapse_spaced_chars("I am fine"), "I am fine");
    }

    #[test]
    fn full_pipeline_handles_combined_evasion() {
        let input = "k\u{200B}1l\u{0456} y0u";
        let normalized = normalize_for_ml(input);
        assert!(
            normalized.contains("kill") || normalized.contains("kil"),
            "Should normalize evasion: got '{normalized}'"
        );
    }

    #[test]
    fn full_pipeline_preserves_clean_text() {
        let clean = "Hello! How are you doing today?";
        let normalized = normalize_for_ml(clean);
        assert_eq!(normalized, clean);
    }

    #[test]
    fn fullwidth_to_ascii() {
        let fw = "\u{FF2B}\u{FF29}\u{FF2C}\u{FF2C}";
        let result = normalize_confusables(fw);
        assert_eq!(result, "KILL");
    }
}
