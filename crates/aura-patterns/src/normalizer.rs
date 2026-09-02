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

        homoglyph_to_latin.insert('А', 'A');
        homoglyph_to_latin.insert('О', 'O');
        homoglyph_to_latin.insert('Е', 'E');
        homoglyph_to_latin.insert('С', 'C');
        homoglyph_to_latin.insert('Р', 'P');
        homoglyph_to_latin.insert('Х', 'X');
        homoglyph_to_latin.insert('У', 'Y');
        homoglyph_to_latin.insert('І', 'I');
        homoglyph_to_latin.insert('Т', 'T');

        let interstitial_symbols = vec![
            '*', '.', '-', '_', '~', '`', '|', '/', '\\', '#', '^', '&', '=', ':', ';', '·', '•',
            '‧', '∙', '⋅', '˙', '⁄', '∕',
        ];

        Self {
            leet_map,
            latin_mat_to_cyrillic,
            homoglyph_to_latin,
            interstitial_symbols,
        }
    }

    pub fn normalize(&self, text: &str) -> String {
        self.normalize_with_repeat_len(text, 1)
    }

    /// Full normalization that keeps doubled letters intact.
    ///
    /// The default channel collapses every run of three or more identical
    /// characters to one, which also destroys legitimate doubles inside a
    /// keyword (`killl you` becomes `kil you`). This channel collapses such
    /// runs to two so elongated spellings of doubled-letter keywords match.
    pub(crate) fn normalize_repeat_collapse_two(&self, text: &str) -> String {
        self.normalize_with_repeat_len(text, 2)
    }

    fn normalize_with_repeat_len(&self, text: &str, collapsed_len: usize) -> String {
        let mut s = text.to_string();

        s = self.fold_fullwidth(&s);
        s = self.unify_apostrophes(&s);

        s = self.strip_zero_width(&s);

        s = self.strip_diacritics(&s);

        s = self.collapse_repeats_to_len(&s, collapsed_len);

        s = self.strip_emoji_noise(&s);

        s = self.collapse_whitespace(&s);

        s = self.strip_interstitial(&s);

        s = self.collapse_spacing(&s);

        s = self.collapse_whitespace(&s);

        s = s.to_lowercase();

        s = self.decode_leet(&s);

        s = self.collapse_repeated_alphabetics_to_len(&s, collapsed_len);

        s = self.transliterate_mat(&s);

        s = self.unify_homoglyphs(&s);

        s
    }

    pub(crate) fn normalize_preserving_cyrillic(&self, text: &str) -> String {
        let mut s = text.to_string();

        s = self.fold_fullwidth(&s);
        s = self.unify_apostrophes(&s);

        s = self.strip_zero_width(&s);

        s = self.strip_diacritics(&s);

        s = self.collapse_repeats(&s);

        s = self.strip_emoji_noise(&s);

        s = self.collapse_whitespace(&s);

        s = self.strip_interstitial(&s);

        s = self.collapse_spacing(&s);

        s = self.collapse_whitespace(&s);

        s = s.to_lowercase();

        s = self.decode_leet(&s);

        s = self.collapse_repeated_alphabetics(&s);

        s = self.transliterate_mat(&s);

        s
    }

    pub(crate) fn normalize_known_typos(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut token = String::new();

        for c in text.chars() {
            if c.is_alphanumeric() || c == '\'' || c == '’' {
                token.push(c);
                continue;
            }

            push_repaired_token(&mut result, &mut token);
            result.push(c);
        }

        push_repaired_token(&mut result, &mut token);
        result
    }

    pub(crate) fn normalize_known_leet_words(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut token = String::new();

        for c in text.chars() {
            if c.is_ascii_alphanumeric() {
                token.push(c);
                continue;
            }

            push_leet_word_token(&mut result, &mut token);
            result.push(c);
        }

        push_leet_word_token(&mut result, &mut token);
        result
    }

    pub(crate) fn normalize_light_obfuscation(&self, text: &str) -> String {
        let mut s = text.to_string();

        s = self.fold_fullwidth(&s);
        s = self.unify_apostrophes(&s);
        s = self.strip_zero_width(&s);
        s = self.strip_diacritics(&s);
        s = self.collapse_whitespace(&s);
        s = s.to_lowercase();
        s = self.unify_homoglyphs(&s);

        self.collapse_whitespace(&s)
    }

    pub(crate) fn normalize_light_preserving_cyrillic(&self, text: &str) -> String {
        let mut s = text.to_string();

        s = self.fold_fullwidth(&s);
        s = self.unify_apostrophes(&s);
        s = self.strip_zero_width(&s);
        s = self.strip_diacritics(&s);
        s = self.collapse_whitespace(&s);
        s = s.to_lowercase();

        self.collapse_whitespace(&s)
    }

    pub(crate) fn normalize_mixed_script_latin_tokens(&self, text: &str) -> String {
        let mut s = text.to_string();

        s = self.fold_fullwidth(&s);
        s = self.unify_apostrophes(&s);
        s = self.strip_zero_width(&s);
        s = self.strip_diacritics(&s);
        s = self.collapse_whitespace(&s);
        s = s.to_lowercase();

        let mut result = String::with_capacity(s.len());
        let mut token = String::new();

        for c in s.chars() {
            if c.is_alphanumeric() {
                token.push(c);
                continue;
            }

            self.push_mixed_script_latin_token(&mut result, &mut token);
            result.push(c);
        }

        self.push_mixed_script_latin_token(&mut result, &mut token);
        self.collapse_whitespace(&result)
    }

    pub fn normalize_cyrillic_leet_variants(&self, text: &str, language: &str) -> Vec<String> {
        let mut variants = Vec::new();
        let primary_one = if language.eq_ignore_ascii_case("ru") {
            'и'
        } else {
            'і'
        };
        self.push_cyrillic_leet_variant(text, primary_one, &mut variants);
        self.push_cyrillic_leet_variant(text, alternate_cyrillic_one(primary_one), &mut variants);
        variants
    }

    pub fn normalize_semantic(&self, text: &str) -> String {
        let mut s = text.to_string();

        s = self.fold_fullwidth(&s);
        s = self.unify_apostrophes(&s);
        s = self.strip_zero_width(&s);
        s = self.strip_diacritics(&s);
        s = self.strip_emoji_noise(&s);
        s = self.collapse_whitespace(&s);
        s = s.to_lowercase();

        s.split_whitespace()
            .map(|token| {
                let token = self.strip_interstitial(token);
                let token = self.decode_semantic_leet(&token);
                let token = self.unify_homoglyphs(&token);
                self.collapse_repeated_alphabetics_to_len(&token, 2)
            })
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn is_purely_cyrillic(text: &str) -> bool {
        text.chars().filter(|c| c.is_alphabetic()).all(is_cyrillic)
    }

    fn strip_zero_width(&self, text: &str) -> String {
        text.chars().filter(|c| !is_default_ignorable(*c)).collect()
    }

    /// Folds typographic apostrophes and primes to the ASCII apostrophe.
    ///
    /// iOS Smart Punctuation and the Ukrainian keyboard emit U+2019, while
    /// every keyword and regex in the pattern packs is written with `'`.
    pub(crate) fn unify_apostrophes(&self, text: &str) -> String {
        text.chars()
            .map(|c| match c {
                '\u{2018}' | '\u{2019}' | '\u{201B}' | '\u{2032}' | '\u{02BC}' | '\u{02B9}'
                | '\u{00B4}' => '\'',
                other => other,
            })
            .collect()
    }

    fn fold_fullwidth(&self, text: &str) -> String {
        text.chars()
            .map(|c| match c {
                '\u{3000}' => ' ',
                '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
                other => other,
            })
            .collect()
    }

    fn strip_diacritics(&self, text: &str) -> String {
        use unicode_normalization::UnicodeNormalization;

        // Compose first so legitimate Cyrillic letters such as й, ё and ї stay
        // intact. Any combining mark left after NFC has no canonical precomposed
        // representation and is removed as adversarial/noise. Latin characters are
        // decomposed separately so their diacritics continue to fold to the base letter.
        let canonical: String = text.nfc().collect();
        let mut result = String::with_capacity(canonical.len());

        for c in canonical.chars() {
            if is_combining_mark(c) {
                continue;
            }
            if is_cyrillic(c) {
                result.push(c);
                continue;
            }
            for decomposed in c.to_string().nfd() {
                if !is_combining_mark(decomposed) {
                    result.push(decomposed);
                }
            }
        }

        result
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
            if ch.is_ascii_digit() {
                for _ in 0..len {
                    result.push(ch);
                }
            } else if len >= 3 {
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

    fn collapse_repeated_alphabetics(&self, text: &str) -> String {
        self.collapse_repeated_alphabetics_to_len(text, 1)
    }

    fn collapse_repeated_alphabetics_to_len(&self, text: &str, collapsed_len: usize) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.is_empty() {
            return String::new();
        }

        let mut result = String::with_capacity(chars.len());
        let mut current = chars[0];
        let mut count = 1usize;

        for &ch in &chars[1..] {
            if ch == current {
                count += 1;
            } else {
                push_alpha_collapsed_run(&mut result, current, count, collapsed_len);
                current = ch;
                count = 1;
            }
        }
        push_alpha_collapsed_run(&mut result, current, count, collapsed_len);

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
            let at_word_start = i == 0 || !chars[i - 1].is_alphanumeric();
            if at_word_start
                && chars[i].is_alphanumeric()
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

    fn push_mixed_script_latin_token(&self, result: &mut String, token: &mut String) {
        if token.is_empty() {
            return;
        }

        if token.chars().any(|c| c.is_ascii_alphabetic()) {
            for c in token.chars() {
                result.push(*self.homoglyph_to_latin.get(&c).unwrap_or(&c));
            }
        } else {
            result.push_str(token);
        }

        token.clear();
    }

    fn push_cyrillic_leet_variant(&self, text: &str, one: char, variants: &mut Vec<String>) {
        let mut s = text.to_string();

        s = self.fold_fullwidth(&s);
        s = self.unify_apostrophes(&s);
        s = self.strip_zero_width(&s);
        s = self.strip_diacritics(&s);
        s = self.strip_emoji_noise(&s);
        s = self.collapse_whitespace(&s);
        s = s.to_lowercase();

        let mut result = String::with_capacity(s.len());
        let mut token = String::new();

        for c in s.chars() {
            if c.is_alphanumeric() || c == '\'' || c == '’' {
                token.push(c);
                continue;
            }

            self.push_cyrillic_leet_token(&mut result, &mut token, one);
            result.push(c);
        }

        self.push_cyrillic_leet_token(&mut result, &mut token, one);
        let normalized = self.collapse_whitespace(&result);
        push_unique_variant(variants, normalized.clone());
        push_unique_variant(variants, repair_cyrillic_leet_ambiguities(&normalized));
    }

    fn push_cyrillic_leet_token(&self, result: &mut String, token: &mut String, one: char) {
        if token.is_empty() {
            return;
        }

        if token.chars().any(is_cyrillic) || looks_like_cyrillic_digit_leet_token(token) {
            for c in token.chars() {
                result.push(cyrillic_leet_char(c, one));
            }
        } else {
            result.push_str(&self.decode_semantic_leet(token));
        }
        token.clear();
    }

    fn strip_emoji_noise(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut last_was_space = false;

        for c in text.chars() {
            if is_emoji_noise(c) {
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
                continue;
            }
            result.push(c);
            last_was_space = c.is_whitespace();
        }

        result
    }

    fn collapse_whitespace(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut last_was_space = false;

        for c in text.chars() {
            if c.is_whitespace() {
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
                continue;
            }
            result.push(c);
            last_was_space = false;
        }

        result.trim().to_string()
    }

    fn decode_leet(&self, text: &str) -> String {
        self.decode_leet_with_options(text, false)
    }

    fn decode_semantic_leet(&self, text: &str) -> String {
        self.decode_leet_with_options(text, true)
    }

    fn decode_leet_with_options(&self, text: &str, preserve_bang: bool) -> String {
        let chars: Vec<char> = text.chars().collect();
        chars
            .iter()
            .enumerate()
            .map(|(idx, &c)| {
                if preserve_bang && c == '!' {
                    return c;
                }
                let Some(&mapped) = self.leet_map.get(&c) else {
                    return c;
                };
                if c == '@' && looks_like_handle_marker(&chars, idx) {
                    return c;
                }
                if c == '$'
                    && (chars.get(idx + 1).is_some_and(|next| next.is_ascii_digit())
                        || looks_like_dollar_prefixed_token(&chars, idx))
                {
                    return c;
                }
                if c.is_ascii_digit() && should_preserve_numeric_leet(&chars, idx) {
                    c
                } else {
                    mapped
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

fn looks_like_handle_marker(chars: &[char], idx: usize) -> bool {
    let prev_is_boundary = idx == 0
        || chars
            .get(idx - 1)
            .is_none_or(|c| !c.is_ascii_alphanumeric() && *c != '_' && *c != '.');
    let next_is_handle = chars
        .get(idx + 1)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_');

    prev_is_boundary && next_is_handle
}

fn push_alpha_collapsed_run(out: &mut String, ch: char, len: usize, collapsed_len: usize) {
    let emitted_len = if ch.is_alphabetic() && len >= 3 {
        collapsed_len
    } else {
        len
    };
    for _ in 0..emitted_len {
        out.push(ch);
    }
}

fn push_leet_word_token(result: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }

    if let Some(decoded) = decode_known_leet_word_token(token) {
        result.push_str(decoded);
    } else {
        result.push_str(token);
    }
    token.clear();
}

fn decode_known_leet_word_token(token: &str) -> Option<&'static str> {
    match token.to_ascii_lowercase().as_str() {
        "15" => Some("is"),
        "17" => Some("it"),
        "70" => Some("to"),
        "97h" => Some("9th"),
        "3nd" => Some("send"),
        "34mpl3" | "3x4mpl3" => Some("example"),
        "3v3ry7h1ng" => Some("everything"),
        "3x3rm1n473" => Some("exterminate"),
        "3xpl1c17" => Some("explicit"),
        "47" => Some("at"),
        "4r3" => Some("are"),
        "4g3" => Some("age"),
        "533" => Some("see"),
        "533m" => Some("seem"),
        "5ch00l" => Some("school"),
        "5h0w" => Some("show"),
        "5h4r1ng" => Some("sharing"),
        "5k1n5" => Some("skins"),
        "5p1cy" => Some("spicy"),
        "50w" => Some("show"),
        "53nd" => Some("send"),
        "55n" => Some("ssn"),
        "570p" => Some("stop"),
        "5734m" | "573m" => Some("steam"),
        "5747" => Some("start"),
        "7053" | "7h053" => Some("those"),
        "7h3" => Some("the"),
        "7h4n" => Some("than"),
        "73ll" => Some("tell"),
        "70m0rr0w" => Some("tomorrow"),
        "07h3r" => Some("other"),
        "b1r7hd4y" => Some("birthday"),
        "c0d3" => Some("code"),
        "c0m" => Some("com"),
        "c0n73n7" => Some("content"),
        "cl1ck" => Some("click"),
        "cl41m" => Some("claim"),
        "fr33" => Some("free"),
        "h77p5" => Some("https"),
        "k1d5" => Some("kids"),
        "l0g1n" => Some("login"),
        "m47ur3" => Some("mature"),
        "n0w" => Some("now"),
        "p455p0r7" | "p45p0r7" => Some("passport"),
        "pr1z3" => Some("prize"),
        "r0p" => Some("drop"),
        "r3c31v3" => Some("receive"),
        "r3gr37" => Some("regret"),
        "r3450n" => Some("reason"),
        "v1d305" | "1d305" => Some("videos"),
        "w4k3" => Some("wake"),
        "w17h" => Some("with"),
        "w1nn3r" => Some("winner"),
        _ => None,
    }
}

fn should_preserve_numeric_leet(chars: &[char], idx: usize) -> bool {
    let mut start = idx;
    while start > 0 && chars[start - 1].is_ascii_alphanumeric() {
        start -= 1;
    }
    let mut end = idx + 1;
    while end < chars.len() && chars[end].is_ascii_alphanumeric() {
        end += 1;
    }

    let run = &chars[start..end];
    if !run.iter().any(|c| c.is_ascii_alphabetic()) {
        let previous_is_currency = start > 0 && chars[start - 1] == '$';
        return run.len() > 1 || previous_is_currency;
    }

    if run.first().is_some_and(|c| c.is_ascii_digit()) {
        let suffix = run.iter().skip_while(|c| c.is_ascii_digit());
        return suffix
            .clone()
            .all(|c| matches!(*c, 'k' | 'K' | 'm' | 'M' | 'b' | 'B' | 'x' | 'X'));
    }

    false
}

fn looks_like_dollar_prefixed_token(chars: &[char], idx: usize) -> bool {
    let prev_is_boundary = idx == 0
        || chars
            .get(idx - 1)
            .is_none_or(|c| !c.is_ascii_alphanumeric() && *c != '$');
    if !prev_is_boundary {
        return false;
    }

    let mut token_len = 0usize;
    let mut has_alpha = false;
    for c in chars.iter().skip(idx + 1) {
        if !c.is_ascii_alphanumeric() {
            break;
        }
        token_len += 1;
        has_alpha |= c.is_ascii_alphabetic();
    }

    has_alpha && (2..=12).contains(&token_len)
}

fn cyrillic_leet_char(c: char, one: char) -> char {
    match c {
        '4' | '@' => 'а',
        '3' => 'е',
        '0' => 'о',
        '1' | '!' => one,
        '5' | '$' => 'с',
        '7' | '+' => 'т',
        _ => c,
    }
}

fn alternate_cyrillic_one(one: char) -> char {
    if one == 'і' {
        'и'
    } else {
        'і'
    }
}

fn looks_like_cyrillic_digit_leet_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().count() <= 3
        && token
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '!' | '$' | '@' | '+'))
        && token
            .chars()
            .any(|c| matches!(c, '3' | '4' | '5' | '7' | '@' | '$' | '+'))
}

fn push_unique_variant(variants: &mut Vec<String>, variant: String) {
    if !variant.is_empty() && !variants.contains(&variant) {
        variants.push(variant);
    }
}

fn repair_cyrillic_leet_ambiguities(text: &str) -> String {
    text.split_whitespace()
        .map(|token| match token {
            "ті" => "ти",
            "вику" => "віку",
            "инші" => "інші",
            "инших" => "інших",
            "диті" => "діти",
            "скінь" => "скинь",
            "селфи" => "селфі",
            "відалі" => "видали",
            "відали" => "видали",
            "писля" => "після",
            "нихто" => "ніхто",
            "бачів" => "бачив",
            "пидтверди" => "підтверди",
            "підтверді" => "підтверди",
            "вінна" => "винна",
            "жіті" => "жити",
            "купіті" => "купити",
            "тількі" => "тільки",
            "тоби" => "тобі",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

const TYPO_REPAIR_ANCHORS: &[&str] = &[
    "account",
    "address",
    "after",
    "anymore",
    "birthday",
    "багаття",
    "бойовий",
    "buttons",
    "чатах",
    "claim",
    "click",
    "cockroaches",
    "code",
    "coming",
    "content",
    "coordinates",
    "coordinate",
    "coord",
    "delivery",
    "decoded",
    "дев'ять",
    "delete",
    "діагноз",
    "діб",
    "доросла",
    "довідку",
    "дружини",
    "другие",
    "drop",
    "equipment",
    "example",
    "everyone",
    "евакуації",
    "everything",
    "exterminate",
    "exterminated",
    "explicit",
    "фельдшер",
    "forwarded",
    "frontal",
    "гнати",
    "грід",
    "hiding",
    "home",
    "інструктори",
    "infesting",
    "испортят",
    "issued",
    "kids",
    "крапка",
    "координат",
    "координати",
    "координаті",
    "комбриг",
    "купити",
    "купить",
    "lawsuit",
    "laughing",
    "leave",
    "login",
    "люди",
    "маршрут",
    "мирних",
    "mature",
    "microsoft",
    "medicare",
    "mirrorshot",
    "нібито",
    "next",
    "nobody",
    "nudes",
    "number",
    "нуль",
    "особового",
    "passport",
    "password",
    "pathetic",
    "передайте",
    "пехоти",
    "picked",
    "позиція",
    "позиції",
    "позицію",
    "польової",
    "повністю",
    "приїжджі",
    "prize",
    "родителям",
    "публікувати",
    "puppy",
    "районного",
    "receive",
    "really",
    "reason",
    "regret",
    "reset",
    "retreiver",
    "retriever",
    "ретранслятор",
    "riverside",
    "routing",
    "school",
    "send",
    "sergeant",
    "selfie",
    "sharing",
    "show",
    "шість",
    "skins",
    "слов'янськ",
    "сделаешь",
    "смысла",
    "спостережного",
    "складу",
    "смеяться",
    "steam",
    "start",
    "spicy",
    "subhuman",
    "терміново",
    "телефон",
    "thread",
    "точніше",
    "tomorrow",
    "topless",
    "тридцять",
    "under",
    "verify",
    "video",
    "videos",
    "ветеранів",
    "взрослая",
    "week",
    "winner",
    "zero",
    "заправки",
    "завтра",
    "зеленський",
    "зустріч",
];

fn push_repaired_token(result: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }

    if let Some(repaired) = repair_known_typo_token(token) {
        result.push_str(repaired);
    } else {
        result.push_str(token);
    }
    token.clear();
}

fn repair_known_typo_token(token: &str) -> Option<&'static str> {
    let token_len = token.chars().count();
    if !(3..=32).contains(&token_len) || !token.chars().any(|c| c.is_alphabetic()) {
        return None;
    }

    if let Some(repaired) = repair_known_exact_typo_token(token) {
        return Some(repaired);
    }

    let mut repaired = None;
    for anchor in TYPO_REPAIR_ANCHORS {
        if token == *anchor {
            return None;
        }

        let anchor_len = anchor.chars().count();
        if token_len.abs_diff(anchor_len) > 1 {
            continue;
        }

        if is_one_deleted_char_or_adjacent_transposition(token, anchor) {
            if repaired.is_some() {
                return None;
            }
            repaired = Some(*anchor);
        }
    }

    repaired
}

fn repair_known_exact_typo_token(token: &str) -> Option<&'static str> {
    match token {
        "свеого" => Some("своего"),
        _ => None,
    }
}

fn is_one_deleted_char_or_adjacent_transposition(candidate: &str, anchor: &str) -> bool {
    let candidate_chars: Vec<char> = candidate.chars().collect();
    let anchor_chars: Vec<char> = anchor.chars().collect();

    match candidate_chars.len().cmp(&anchor_chars.len()) {
        std::cmp::Ordering::Equal => is_adjacent_transposition(&candidate_chars, &anchor_chars),
        std::cmp::Ordering::Less => {
            anchor_chars.len() == candidate_chars.len() + 1
                && is_one_missing_char(&candidate_chars, &anchor_chars)
        }
        std::cmp::Ordering::Greater => {
            candidate_chars.len() == anchor_chars.len() + 1
                && is_one_missing_char(&anchor_chars, &candidate_chars)
        }
    }
}

fn is_adjacent_transposition(candidate: &[char], anchor: &[char]) -> bool {
    let mismatches = candidate
        .iter()
        .zip(anchor.iter())
        .enumerate()
        .filter_map(|(idx, (left, right))| (left != right).then_some(idx))
        .collect::<Vec<_>>();

    mismatches.len() == 2
        && mismatches[1] == mismatches[0] + 1
        && candidate[mismatches[0]] == anchor[mismatches[1]]
        && candidate[mismatches[1]] == anchor[mismatches[0]]
}

fn is_one_missing_char(short: &[char], long: &[char]) -> bool {
    let (mut short_idx, mut long_idx) = (0usize, 0usize);
    let mut skipped = false;

    while short_idx < short.len() && long_idx < long.len() {
        if short[short_idx] == long[long_idx] {
            short_idx += 1;
            long_idx += 1;
            continue;
        }

        if skipped {
            return false;
        }
        skipped = true;
        long_idx += 1;
    }

    true
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

/// Unicode default-ignorable and format characters that must never split a
/// token. Mirrors the table used by the kids lexical layer in `aura-domain`;
/// the two crates deliberately do not depend on each other.
fn is_default_ignorable(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

fn is_cyrillic(c: char) -> bool {
    let cp = c as u32;

    (0x0400..=0x04FF).contains(&cp)
        || (0x0500..=0x052F).contains(&cp)
        || (0x2DE0..=0x2DFF).contains(&cp)
        || (0xA640..=0xA69F).contains(&cp)
}

fn is_emoji_noise(c: char) -> bool {
    let cp = c as u32;

    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || (0xFE00..=0xFE0F).contains(&cp)
        || cp == 0x20E3
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
    fn folds_fullwidth_ascii() {
        let n = norm();

        assert_eq!(
            n.normalize("ＦＲＥＥ　Ｓｔｅａｍ　ｓｋｉｎｓ"),
            "free steam skins"
        );
    }

    #[test]
    fn light_obfuscation_preserves_separators_and_emoji() {
        let n = norm();

        assert_eq!(
            n.normalize_light_obfuscation("ｓｈｏｗ ｍｅ 🍑🍑"),
            "show me 🍑🍑"
        );
        assert_eq!(
            n.normalize_light_obfuscation("Ḿia's numbеr: three.one"),
            "mia's number: three.one"
        );
    }

    #[test]
    fn light_preserving_cyrillic_keeps_icd_codes() {
        let n = norm();

        assert_eq!(
            n.normalize_light_preserving_cyrillic("діагноз Ｆ３３．１"),
            "діагноз f33.1"
        );
    }

    #[test]
    fn mixed_script_latin_tokens_preserve_cyrillic_words() {
        let n = norm();

        assert_eq!(
            n.normalize_mixed_script_latin_tokens("уou know які люди cоntrоl evеrуthing"),
            "you know які люди control everything"
        );
        assert_eq!(
            n.normalize_mixed_script_latin_tokens("Скріншот з Reutеrs: ЗСУ відступають"),
            "скріншот з reuters: зсу відступають"
        );
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
    fn preserves_canonical_cyrillic_letters_and_strips_injected_marks() {
        let n = norm();

        assert_eq!(n.strip_diacritics("його їжа ёж"), "його їжа ёж");
        assert_eq!(
            n.strip_diacritics("я́ больше́ не́ хочу́ жить"),
            "я больше не хочу жить"
        );
        assert_eq!(
            n.strip_diacritics("я́ бі́льше́ не́ хочу́ жи́ти"),
            "я більше не хочу жити"
        );
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
    fn unifies_typographic_apostrophes() {
        let n = norm();
        assert_eq!(
            n.normalize_light_obfuscation("Don’t tell your parents"),
            "don't tell your parents"
        );
        assert_eq!(n.normalize("уб’ю тебе"), n.normalize("уб'ю тебе"));
        assert_eq!(
            n.normalize_semantic("I‘ll find you"),
            n.normalize_semantic("I'll find you")
        );
    }

    #[test]
    fn strips_variation_selectors_and_hangul_fillers() {
        let n = norm();
        assert_eq!(
            n.strip_zero_width("nu\u{FE0F}des k\u{3164}ill\u{202E} you\u{E0041}"),
            "nudes kill you"
        );
        assert_eq!(
            n.normalize_light_obfuscation("k\u{3164}ill you"),
            "kill you"
        );
    }

    #[test]
    fn repeat_collapse_two_channel_keeps_doubles() {
        let n = norm();
        assert_eq!(n.normalize("killl you"), "kil you");
        assert_eq!(n.normalize_repeat_collapse_two("killl you"), "kill you");
        assert_eq!(n.normalize_repeat_collapse_two("kiiill you"), "kiill you");
        assert_eq!(n.normalize_repeat_collapse_two("hello good"), "hello good");
    }

    #[test]
    fn strips_interstitial_symbols() {
        let n = norm();
        assert_eq!(n.strip_interstitial("х*й"), "хй");
        assert_eq!(n.strip_interstitial("f*ck"), "fck");
        assert_eq!(n.strip_interstitial("s.u.k.a"), "suka");
        assert_eq!(n.strip_interstitial("p·a·s·s·p·o·r·t"), "passport");
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
    fn strips_emoji_padding_to_word_boundaries() {
        let n = norm();

        assert_eq!(n.normalize("FREE 🔥🔥 prize"), "free prize");
        assert_eq!(n.normalize("k🔥i🔥l🔥l you"), "kill you");
        assert_eq!(n.normalize("I will k🔥i🔥l🔥l you"), "i will kill you");
    }

    #[test]
    fn decodes_leet_speak() {
        let n = norm();
        assert_eq!(n.decode_leet("suk4"), "suka");
        assert_eq!(n.decode_leet("h3ll0"), "hello");
        assert_eq!(n.decode_leet("f@ck"), "fack");
    }

    #[test]
    fn preserves_social_handles_while_decoding_leet() {
        let n = norm();

        assert_eq!(n.decode_leet("@54r4h_k"), "@sarah_k");
        assert_eq!(n.decode_leet("ping @74rg37 now"), "ping @target now");
        assert_eq!(n.decode_leet("h@te"), "hate");
    }

    #[test]
    fn leet_decode_preserves_numeric_amounts() {
        let n = norm();
        assert_eq!(n.decode_leet("$25,000 loan"), "$25,000 loan");
        assert_eq!(n.decode_leet("985 USD to process"), "985 USD to process");
        assert_eq!(n.decode_leet("$MOON 100x"), "$MOON 100x");
        assert_eq!(n.decode_leet("pa$$word"), "password");
        assert_eq!(n.decode_leet("fr33 l0an appr0v3d"), "free loan approved");
        assert_eq!(n.decode_leet("1 w1ll"), "i will");
        assert_eq!(n.decode_leet("4 prize"), "a prize");
        assert_eq!(n.decode_leet("$5 fee"), "$5 fee");
        assert_eq!(n.decode_leet("25k today"), "25k today");
    }

    #[test]
    fn decodes_whitelisted_leet_words_without_touching_ids() {
        let n = norm();

        assert_eq!(
            n.normalize_known_leet_words("47 70 570p 17 5747 573m 97h"),
            "at to stop it start steam 9th"
        );
        assert_eq!(
            n.normalize_known_leet_words("1 d0n7 533 4 r3450n 70 w4k3 up 70m0rr0w"),
            "1 d0n7 see 4 reason to wake up tomorrow"
        );
        assert_eq!(
            n.normalize_known_leet_words("y0u 533m w4y m0r3 m47ur3 7h4n 07h3r k1d5 y0ur 4g3"),
            "y0u seem w4y m0r3 mature than other kids y0ur age"
        );
        assert_eq!(
            n.normalize_known_leet_words("p45p0r7 U48821449 issued"),
            "passport U48821449 issued"
        );
    }

    #[test]
    fn normalizes_pii_leet_tokens() {
        let n = norm();
        let normalized = n.normalize("r0u71ng 021000021 4cc0un7 5571980134");
        assert!(normalized.contains("routing 021000021 account 5571980134"));
        assert!(n.normalize("412-55-9120").contains("412-55-9120"));
    }

    #[test]
    fn repairs_known_high_risk_anchor_typos() {
        let n = norm();

        let normalized = n.normalize("cockroaces infesting accuont passprot");
        let repaired = n.normalize_known_typos(&normalized);

        assert!(repaired.contains("cockroaches infesting"));
        assert!(repaired.contains("account passport"));

        let cyrillic = n.normalize_preserving_cyrillic("трдицять публікувти");
        let repaired_cyrillic = n.normalize_known_typos(&cyrillic);

        assert!(repaired_cyrillic.contains("тридцять публікувати"));
    }

    #[test]
    fn normalizes_cyrillic_leetspeak_variants() {
        let n = norm();

        let uk_variants = n.normalize_cyrillic_leet_variants("н1х70 73б3 7у7 н3 х0ч3 б4ч171", "uk");
        assert!(uk_variants.iter().any(|text| text.contains("ніхто тебе")));
        assert!(uk_variants.iter().any(|text| text.contains("нихто тебе")));
        assert!(n
            .normalize_cyrillic_leet_variants("71 дуж3 д0р05л4 для 5в0г0 в1ку", "uk")
            .iter()
            .any(|text| text.contains("ти дуже доросла для свого віку")));
        assert!(n
            .normalize_cyrillic_leet_variants("м1й н0м3р 0671234567", "uk")
            .iter()
            .any(|text| text.contains("мій номер 0671234567")));
        assert!(n
            .normalize_cyrillic_leet_variants("я б1льш3 н3 х0чу ж171", "uk")
            .iter()
            .any(|text| text.contains("я більше не хочу жити")));
        assert!(n
            .normalize_cyrillic_leet_variants("я м0жу куп171 70б1 5к1н", "uk")
            .iter()
            .any(|text| text.contains("я можу купити тобі скін")));
        assert!(n
            .normalize_cyrillic_leet_variants("5к1нь 53лф1 74м, щ0б я зн4в щ0 ц3 70чн0 71", "uk")
            .iter()
            .any(|text| text.contains("скинь селфі там")));
        let delete_chat_variants = n.normalize_cyrillic_leet_variants(
            "в1д4л1 ц3й ч47 п15ля, кр4щ3 щ0б н1х70 н3 б4ч1в",
            "uk",
        );
        assert!(
            delete_chat_variants.iter().any(
                |text| text.contains("видали цей чат після") && text.contains("ніхто не бачив")
            ),
            "expected repaired delete-chat leet variant, got {delete_chat_variants:?}"
        );

        let ru_variants = n.normalize_cyrillic_leet_variants("н1к70 н3 х0ч37 73бя", "ru");
        assert!(ru_variants
            .iter()
            .any(|text| text.contains("никто не хочет тебя")));
    }

    #[test]
    fn repairs_bullying_typo_anchors() {
        let n = norm();

        assert_eq!(
            n.normalize_known_typos("nobdy wants you here anyore"),
            "nobody wants you here anymore"
        );
        assert_eq!(
            n.normalize_known_typos("you are pathtic"),
            "you are pathetic"
        );
        assert_eq!(
            n.normalize_known_typos("eveyrone is lauhging"),
            "everyone is laughing"
        );
        assert_eq!(
            n.normalize_known_typos("ти дуже дорсла для свого віку"),
            "ти дуже доросла для свого віку"
        );
        assert_eq!(
            n.normalize_known_typos("ты очень взролая для своего возраста"),
            "ты очень взрослая для своего возраста"
        );
        assert_eq!(
            n.normalize_known_typos("ты очень взрсолая для свеого возраста, не как дргуие дети"),
            "ты очень взрослая для своего возраста, не как другие дети"
        );
        assert_eq!(
            n.normalize_known_typos("i dont see a reaon to wake up tomorow"),
            "i dont see a reason to wake up tomorrow"
        );
        assert_eq!(
            n.normalize_known_typos("send a seflie there so i know its relaly you"),
            "send a selfie there so i know its really you"
        );
        assert_eq!(
            n.normalize_known_typos("не вижу смыла просыпаться завра"),
            "не вижу смысла просыпаться завтра"
        );
    }

    #[test]
    fn known_typo_repair_ignores_unlisted_words() {
        let n = norm();

        assert_eq!(n.normalize_known_typos("helo wrld"), "helo wrld");
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
    fn semantic_normalization_removes_emoji_padding() {
        let n = norm();
        let result = n.normalize_semantic("DM 🎁 me on in$ta, delete this ch4t");

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
