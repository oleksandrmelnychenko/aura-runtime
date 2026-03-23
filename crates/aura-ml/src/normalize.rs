pub fn normalize_for_ml(text: &str) -> String {
    let text = strip_zero_width(text);
    let text = normalize_confusables(&text);
    let text = normalize_leetspeak(&text);
    let text = collapse_spaced_chars(&text);
    unicode_normalization_nfkc(&text)
}

fn strip_zero_width(text: &str) -> String {
    text.chars()
        .filter(|c| {
            let cp = *c as u32;
            cp != 0x200B
                && cp != 0x200C
                && cp != 0x200D
                && cp != 0x200E
                && cp != 0x200F
                && cp != 0x2060
                && cp != 0x2061
                && cp != 0x2062
                && cp != 0x2063
                && cp != 0x2064
                && cp != 0xFEFF
                && cp != 0x00AD
        })
        .collect()
}

fn is_cyrillic(c: char) -> bool {
    let cp = c as u32;
    (0x0400..=0x04FF).contains(&cp) || (0x0500..=0x052F).contains(&cp)
}

fn is_latin(c: char) -> bool {
    c.is_ascii_alphabetic() || (c as u32 >= 0x00C0 && c as u32 <= 0x024F)
}

fn has_latin_neighbor(chars: &[char], pos: usize) -> bool {
    let before = pos > 0 && is_latin(chars[pos - 1]);
    let after = pos + 1 < chars.len() && is_latin(chars[pos + 1]);
    before || after
}

fn confusable_target(c: char) -> Option<char> {
    match c {
        '\u{0410}' => Some('A'),
        '\u{0412}' => Some('B'),
        '\u{0421}' => Some('C'),
        '\u{0415}' => Some('E'),
        '\u{041D}' => Some('H'),
        '\u{041A}' => Some('K'),
        '\u{041C}' => Some('M'),
        '\u{041E}' => Some('O'),
        '\u{0420}' => Some('P'),
        '\u{0422}' => Some('T'),
        '\u{0425}' => Some('X'),
        '\u{0430}' => Some('a'),
        '\u{0435}' => Some('e'),
        '\u{043E}' => Some('o'),
        '\u{0440}' => Some('p'),
        '\u{0441}' => Some('c'),
        '\u{0443}' => Some('y'),
        '\u{0445}' => Some('x'),
        '\u{0456}' => Some('i'),
        _ => None,
    }
}

fn normalize_confusables(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut result = String::with_capacity(text.len());

    for i in 0..chars.len() {
        let c = chars[i];
        if let Some(target) = confusable_target(c) {
            if has_latin_neighbor(&chars, i) {
                result.push(target);
                continue;
            }
        }
        if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
            result.push(char::from_u32(c as u32 - 0xFF01 + 0x21).unwrap_or(c));
            continue;
        }
        result.push(c);
    }
    result
}

fn normalize_leetspeak(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    for i in 0..chars.len() {
        let c = chars[i];
        let mapped = match c {
            '0' if is_leet_context(&chars, i) => 'o',
            '1' if is_leet_context(&chars, i) => 'i',
            '3' if is_leet_context(&chars, i) => 'e',
            '4' if is_leet_context(&chars, i) => 'a',
            '5' if is_leet_context(&chars, i) => 's',
            '7' if is_leet_context(&chars, i) => 't',
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
    fn confusable_maps_cyrillic_in_latin_context() {
        assert_eq!(normalize_confusables("k\u{0456}ll"), "kill");
        assert_eq!(normalize_confusables("h\u{0435}llo"), "hello");
    }

    #[test]
    fn confusable_preserves_pure_cyrillic() {
        let ukr = "\u{043F}\u{0440}\u{0438}\u{0432}\u{0456}\u{0442}";
        assert_eq!(normalize_confusables(ukr), ukr);
    }

    #[test]
    fn confusable_preserves_cyrillic_sentence() {
        let text = "\u{0422}\u{0438} \u{0442}\u{0443}\u{043F}\u{0438}\u{0439} \u{0434}\u{0435}\u{0431}\u{0456}\u{043B}";
        let result = normalize_confusables(text);
        assert_eq!(result, text);
    }

    #[test]
    fn confusable_preserves_russian() {
        let text = "\u{041F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442} \u{043C}\u{0438}\u{0440}";
        let result = normalize_confusables(text);
        assert_eq!(result, text);
    }

    #[test]
    fn confusable_maps_mixed_script_evasion() {
        let evasion = "k\u{0456}ll y\u{043E}u";
        let result = normalize_confusables(evasion);
        assert_eq!(result, "kill you");
    }

    #[test]
    fn leetspeak_context_aware() {
        assert_eq!(normalize_leetspeak("k1ll"), "kill");
        assert_eq!(normalize_leetspeak("h4t3"), "hate");
        assert_eq!(normalize_leetspeak("call 123"), "call 123");
    }

    #[test]
    fn leetspeak_preserves_standalone_digits() {
        assert_eq!(normalize_leetspeak("room 101"), "room 101");
        assert_eq!(normalize_leetspeak("2 + 2 = 4"), "2 + 2 = 4");
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
    fn full_pipeline_evasion() {
        let input = "k\u{200B}\u{0456}ll y0u";
        let result = normalize_for_ml(input);
        assert!(result.contains("kill"), "got '{result}'");
    }

    #[test]
    fn full_pipeline_leetspeak_evasion() {
        assert!(normalize_for_ml("k1ll y0u").contains("kill"));
        assert!(normalize_for_ml("5tup1d").contains("stupid"));
    }

    #[test]
    fn full_pipeline_preserves_clean() {
        assert_eq!(
            normalize_for_ml("Hello! How are you?"),
            "Hello! How are you?"
        );
    }

    #[test]
    fn full_pipeline_preserves_ukrainian() {
        let ukr = "\u{041F}\u{0440}\u{0438}\u{0432}\u{0456}\u{0442}, \u{044F}\u{043A} \u{0441}\u{043F}\u{0440}\u{0430}\u{0432}\u{0438}?";
        let result = normalize_for_ml(ukr);
        assert_eq!(result, ukr);
    }

    #[test]
    fn full_pipeline_preserves_russian() {
        let rus = "\u{041F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}, \u{043A}\u{0430}\u{043A} \u{0434}\u{0435}\u{043B}\u{0430}?";
        let result = normalize_for_ml(rus);
        assert_eq!(result, rus);
    }

    #[test]
    fn fullwidth_to_ascii() {
        let fw = "\u{FF2B}\u{FF29}\u{FF2C}\u{FF2C}";
        assert_eq!(normalize_confusables(fw), "KILL");
    }

    #[test]
    fn mixed_cyrillic_latin_sentence_preserved() {
        let mixed = "hey bro, \u{044F}\u{043A} \u{0441}\u{043F}\u{0440}\u{0430}\u{0432}\u{0438}?";
        let result = normalize_for_ml(mixed);
        assert!(
            result.contains("\u{044F}\u{043A}"),
            "Cyrillic words should survive: '{result}'"
        );
    }
}
