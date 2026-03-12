use std::collections::HashMap;

pub struct TextNormalizer {
    leet_map: HashMap<char, char>,

    latin_mat_to_cyrillic: Vec<(&'static str, &'static str)>,

    homoglyph_to_latin: HashMap<char, char>,

    interstitial_symbols: Vec<char>,
}

impl TextNormalizer {
    pub fn new() -> Self {
        let mut leet_map = HashMap::new();
        leet_map.insert('4', 'a');
        leet_map.insert('@', 'a');
        leet_map.insert('3', 'e');
        leet_map.insert('€', 'e');
        leet_map.insert('0', 'o');
        leet_map.insert('1', 'i');
        leet_map.insert('!', 'i');
        leet_map.insert('$', 's');
        leet_map.insert('5', 's');
        leet_map.insert('7', 't');
        leet_map.insert('8', 'b');
        leet_map.insert('9', 'g');
        leet_map.insert('+', 't');

        let latin_mat_to_cyrillic: Vec<(&str, &str)> = vec![
            ("pizdec", "піздець"),
            ("pizdet", "піздєт"),
            ("pizdec", "піздец"),
            ("pizda", "пізда"),
            ("pidar", "підар"),
            ("pidor", "підор"),
            ("pidoras", "підорас"),
            ("mudak", "мудак"),
            ("mudilo", "мудило"),
            ("blyad", "блядь"),
            ("blyat", "блять"),
            ("svoloch", "сволоч"),
            ("nahui", "нахуй"),
            ("nahuy", "нахуй"),
            ("zasranec", "засранець"),
            ("debil", "дебіл"),
            ("durak", "дурак"),
            ("ebal", "їбав"),
            ("ebat", "їбать"),
            ("ebanat", "їбанат"),
            ("gandon", "гандон"),
            ("zalupa", "залупа"),
            ("shmara", "шмара"),
            ("shlyuha", "шлюха"),
            ("shliuha", "шлюха"),
            ("padla", "падла"),
            ("tvar", "твар"),
            ("suka", "сука"),
            ("suki", "сукі"),
            ("huynya", "хуйня"),
            ("huilo", "хуйло"),
            ("hui", "хуй"),
            ("huy", "хуй"),
            ("pizd", "пізд"),
            ("blya", "бля"),
            ("xyj", "хуй"),
            ("xui", "хуй"),
        ];

        let mut homoglyph_to_latin = HashMap::new();
        homoglyph_to_latin.insert('а', 'a');

        homoglyph_to_latin.insert('о', 'o');
        homoglyph_to_latin.insert('е', 'e');
        homoglyph_to_latin.insert('с', 'c');
        homoglyph_to_latin.insert('р', 'p');
        homoglyph_to_latin.insert('х', 'x');
        homoglyph_to_latin.insert('у', 'y');
        homoglyph_to_latin.insert('і', 'i');
        homoglyph_to_latin.insert('і', 'i');

        homoglyph_to_latin.insert('А', 'A');
        homoglyph_to_latin.insert('О', 'O');
        homoglyph_to_latin.insert('Е', 'E');
        homoglyph_to_latin.insert('С', 'C');
        homoglyph_to_latin.insert('Р', 'P');
        homoglyph_to_latin.insert('Х', 'X');
        homoglyph_to_latin.insert('У', 'Y');
        homoglyph_to_latin.insert('І', 'I');

        let interstitial_symbols = vec![
            '*', '.', '-', '_', '~', '`', '|', '/', '\\', '#', '^', '&', '=',
        ];

        Self {
            leet_map,
            latin_mat_to_cyrillic,
            homoglyph_to_latin,
            interstitial_symbols,
        }
    }

    pub fn normalize(&self, text: &str) -> String {
        let mut s = text.to_string();

        s = self.strip_zero_width(&s);

        s = self.strip_diacritics(&s);

        s = self.collapse_repeats(&s);

        s = self.strip_interstitial(&s);

        s = self.collapse_spacing(&s);

        s = s.to_lowercase();

        s = self.decode_leet(&s);

        s = self.transliterate_mat(&s);

        s = self.unify_homoglyphs(&s);

        s
    }

    pub fn normalize_semantic(&self, text: &str) -> String {
        let mut s = text.to_string();

        s = self.strip_zero_width(&s);
        s = self.strip_diacritics(&s);
        s = s.to_lowercase();

        s.split_whitespace()
            .map(|token| {
                let token = self.strip_interstitial(token);
                let token = self.decode_semantic_leet(&token);
                let token = self.unify_homoglyphs(&token);
                self.collapse_repeats_to_len(&token, 2)
            })
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn is_purely_cyrillic(text: &str) -> bool {
        text.chars().filter(|c| c.is_alphabetic()).all(is_cyrillic)
    }

    fn strip_zero_width(&self, text: &str) -> String {
        text.chars()
            .filter(|c| {
                !matches!(
                    c,
                    '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{FEFF}'
                        | '\u{00AD}'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{2060}'
                        | '\u{2061}'
                        | '\u{2062}'
                        | '\u{2063}'
                        | '\u{2064}'
                        | '\u{034F}'
                )
            })
            .collect()
    }

    fn strip_diacritics(&self, text: &str) -> String {
        use unicode_normalization::UnicodeNormalization;

        let nfd: Vec<char> = text.nfd().collect();
        let mut result = String::with_capacity(nfd.len());
        let mut last_base_is_cyrillic = false;

        for c in nfd {
            if is_combining_mark(c) {
                if last_base_is_cyrillic {
                    result.push(c);
                }
            } else {
                last_base_is_cyrillic = is_cyrillic(c);
                result.push(c);
            }
        }

        result.nfc().collect()
    }

    fn collapse_repeats(&self, text: &str) -> String {
        self.collapse_repeats_to_len(text, 1)
    }

    fn collapse_repeats_to_len(&self, text: &str, collapsed_len: usize) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.is_empty() {
            return String::new();
        }

        let mut runs: Vec<(char, usize)> = Vec::new();
        let mut current = chars[0];
        let mut count = 1usize;

        for &ch in &chars[1..] {
            if ch == current {
                count += 1;
            } else {
                runs.push((current, count));
                current = ch;
                count = 1;
            }
        }
        runs.push((current, count));

        let mut result = String::with_capacity(chars.len());
        for (ch, len) in runs {
            if len >= 3 {
                for _ in 0..collapsed_len {
                    result.push(ch);
                }
            } else {
                for _ in 0..len {
                    result.push(ch);
                }
            }
        }

        result
    }

    fn strip_interstitial(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() < 3 {
            return text.to_string();
        }

        let mut result = String::with_capacity(chars.len());

        for i in 0..chars.len() {
            if self.interstitial_symbols.contains(&chars[i]) {
                let prev_letter = i > 0 && chars[i - 1].is_alphabetic();
                let next_letter = i + 1 < chars.len() && chars[i + 1].is_alphabetic();
                if prev_letter && next_letter {
                    continue;
                }
            }
            result.push(chars[i]);
        }

        result
    }

    fn collapse_spacing(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() < 3 {
            return text.to_string();
        }

        let mut result = String::with_capacity(chars.len());
        let mut i = 0;

        while i < chars.len() {
            if chars[i].is_alphanumeric()
                && i + 2 < chars.len()
                && chars[i + 1] == ' '
                && chars[i + 2].is_alphanumeric()
            {
                let start = i;
                let mut end = i;
                let mut char_count = 1;

                let mut j = i + 1;
                while j < chars.len() {
                    if chars[j] == ' ' && j + 1 < chars.len() && chars[j + 1].is_alphanumeric() {
                        if j + 2 >= chars.len()
                            || chars[j + 2] == ' '
                            || !chars[j + 2].is_alphanumeric()
                        {
                            char_count += 1;
                            end = j + 1;
                            j += 2;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if char_count >= 3 {
                    let mut k = start;
                    while k <= end {
                        if chars[k] != ' ' {
                            result.push(chars[k]);
                        }
                        k += 1;
                    }
                    i = end + 1;
                } else {
                    result.push(chars[i]);
                    i += 1;
                }
            } else {
                result.push(chars[i]);
                i += 1;
            }
        }

        result
    }

    fn decode_leet(&self, text: &str) -> String {
        text.chars()
            .map(|c| *self.leet_map.get(&c).unwrap_or(&c))
            .collect()
    }

    fn decode_semantic_leet(&self, text: &str) -> String {
        text.chars()
            .map(|c| {
                if c == '!' {
                    c
                } else {
                    *self.leet_map.get(&c).unwrap_or(&c)
                }
            })
            .collect()
    }

    fn transliterate_mat(&self, text: &str) -> String {
        if Self::is_purely_cyrillic(text) {
            return text.to_string();
        }

        let mut s = text.to_string();
        for (latin, cyrillic) in &self.latin_mat_to_cyrillic {
            if s.contains(latin) {
                s = s.replace(latin, cyrillic);
            }
        }
        s
    }

    fn unify_homoglyphs(&self, text: &str) -> String {
        text.chars()
            .map(|c| *self.homoglyph_to_latin.get(&c).unwrap_or(&c))
            .collect()
    }
}

impl Default for TextNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

fn is_combining_mark(c: char) -> bool {
    let cp = c as u32;

    (0x0300..=0x036F).contains(&cp)
        || (0x1AB0..=0x1AFF).contains(&cp)
        || (0x1DC0..=0x1DFF).contains(&cp)
        || (0xFE20..=0xFE2F).contains(&cp)
}

fn is_cyrillic(c: char) -> bool {
    let cp = c as u32;

    (0x0400..=0x04FF).contains(&cp)
        || (0x0500..=0x052F).contains(&cp)
        || (0x2DE0..=0x2DFF).contains(&cp)
        || (0xA640..=0xA69F).contains(&cp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm() -> TextNormalizer {
        TextNormalizer::new()
    }

    #[test]
    fn strips_zero_width_chars() {
        let n = norm();
        let input = "su\u{200B}ka\u{200D}!";
        assert_eq!(n.strip_zero_width(input), "suka!");
    }

    #[test]
    fn strips_soft_hyphen() {
        let n = norm();
        let input = "su\u{00AD}ka";
        assert_eq!(n.strip_zero_width(input), "suka");
    }

    #[test]
    fn strips_latin_diacritics() {
        let n = norm();
        assert_eq!(n.strip_diacritics("café"), "cafe");
        assert_eq!(n.strip_diacritics("naïve"), "naive");
        assert_eq!(n.strip_diacritics("résumé"), "resume");
    }

    #[test]
    fn collapses_repeated_chars() {
        let n = norm();
        assert_eq!(n.collapse_repeats("suuuuka"), "suka");
        assert_eq!(n.collapse_repeats("ааааааа"), "а");
        assert_eq!(n.collapse_repeats("heeelp"), "help");
    }

    #[test]
    fn preserves_normal_doubles() {
        let n = norm();
        assert_eq!(n.collapse_repeats("hello"), "hello");
        assert_eq!(n.collapse_repeats("good"), "good");
    }

    #[test]
    fn strips_interstitial_symbols() {
        let n = norm();
        assert_eq!(n.strip_interstitial("х*й"), "хй");
        assert_eq!(n.strip_interstitial("f*ck"), "fck");
        assert_eq!(n.strip_interstitial("s.u.k.a"), "suka");
    }

    #[test]
    fn preserves_symbols_at_boundaries() {
        let n = norm();
        assert_eq!(n.strip_interstitial("*hello"), "*hello");
        assert_eq!(n.strip_interstitial("hello*"), "hello*");
        assert_eq!(n.strip_interstitial("a * b"), "a * b");
    }

    #[test]
    fn collapses_spaced_out_words() {
        let n = norm();
        assert_eq!(n.collapse_spacing("с у к а"), "сука");
        assert_eq!(n.collapse_spacing("f u c k"), "fuck");
        assert_eq!(n.collapse_spacing("h u i"), "hui");
    }

    #[test]
    fn preserves_normal_words() {
        let n = norm();
        assert_eq!(n.collapse_spacing("hello world"), "hello world");
        assert_eq!(n.collapse_spacing("I am fine"), "I am fine");
    }

    #[test]
    fn preserves_two_char_spacing() {
        let n = norm();

        assert_eq!(n.collapse_spacing("a b"), "a b");
    }

    #[test]
    fn decodes_leet_speak() {
        let n = norm();
        assert_eq!(n.decode_leet("suk4"), "suka");
        assert_eq!(n.decode_leet("h3ll0"), "hello");
        assert_eq!(n.decode_leet("f@ck"), "fack");
    }

    #[test]
    fn transliterates_latin_suka() {
        let n = norm();
        assert_eq!(n.transliterate_mat("suka"), "сука");
    }

    #[test]
    fn transliterates_latin_blyat() {
        let n = norm();
        assert_eq!(n.transliterate_mat("blyat"), "блять");
    }

    #[test]
    fn transliterates_latin_pizdec() {
        let n = norm();
        assert_eq!(n.transliterate_mat("pizdec"), "піздець");
    }

    #[test]
    fn transliterates_latin_nahui() {
        let n = norm();
        assert_eq!(n.transliterate_mat("nahui"), "нахуй");
    }

    #[test]
    fn skips_transliteration_for_pure_cyrillic() {
        let n = norm();
        let text = "привіт як справи";
        assert_eq!(n.transliterate_mat(text), text);
    }

    #[test]
    fn unifies_cyrillic_homoglyphs() {
        let n = norm();

        assert_eq!(n.unify_homoglyphs("аое"), "aoe");
    }

    #[test]
    fn handles_mixed_script_evasion() {
        let n = norm();

        let mixed = "хyй";
        let unified = n.unify_homoglyphs(mixed);
        assert_eq!(unified, "xyй");
    }

    #[test]
    fn normalizes_spaced_suka() {
        let n = norm();
        let result = n.normalize("с у к а");

        assert_eq!(result, "cyкa");
    }

    #[test]
    fn normalizes_leet_suka() {
        let n = norm();
        let result = n.normalize("suk4");

        assert_eq!(result, "cyкa");
    }

    #[test]
    fn normalizes_mixed_script_hui() {
        let n = norm();

        let result = n.normalize("хyй");
        assert_eq!(result, "xyй");
    }

    #[test]
    fn normalizes_blyat_with_stars() {
        let n = norm();
        let result = n.normalize("b*l*y*a*t");

        assert_eq!(result, "блять");
    }

    #[test]
    fn normalizes_repeated_chars_evasion() {
        let n = norm();

        let result = n.normalize("suuuuuka");
        assert_eq!(result, "cyкa");
    }

    #[test]
    fn normalizes_clean_text_unchanged() {
        let n = norm();
        let result = n.normalize("Hello, how are you?");
        assert_eq!(result, "hello, how are you?");
    }

    #[test]
    fn semantic_normalization_preserves_word_shape_for_elongation() {
        let n = norm();

        assert_eq!(n.normalize_semantic("schoooool"), "school");
        assert_eq!(n.normalize_semantic("screeeenshots"), "screenshots");
    }

    #[test]
    fn semantic_normalization_handles_chat_noise() {
        let n = norm();
        let result = n.normalize_semantic("DM me on in$ta, delete this ch4t");

        assert_eq!(result, "dm me on insta, delete this chat");
    }

    #[test]
    fn semantic_normalization_preserves_sentence_punctuation() {
        let n = norm();
        let result = n.normalize_semantic("Stop it! Leave her alone!");

        assert_eq!(result, "stop it! leave her alone!");
    }

    #[test]
    fn normalizes_normal_ukrainian_unchanged() {
        let n = norm();
        let result = n.normalize("Привіт, як справи?");

        let expected = "пpивiт, як cпpaви?";
        assert_eq!(result, expected);
    }

    #[test]
    fn no_false_positive_pasuka() {
        let n = norm();
        let result = n.normalize("пасука");

        assert_eq!(result, "пacyкa");
    }

    #[test]
    fn performance_1000_normalizations() {
        let n = norm();
        let text = "Привіт, як справи? Це тестове повідомлення для перевірки швидкості.";

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = n.normalize(text);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 500,
            "1000 normalizations took {}ms, expected <500ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn performance_adversarial_input() {
        let n = norm();

        let text = "с\u{200B} у\u{200D} к\u{200B} аааа b*l*y*a*t suk444";

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = n.normalize(text);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 500,
            "1000 adversarial normalizations took {}ms, expected <500ms",
            elapsed.as_millis()
        );
    }
}
