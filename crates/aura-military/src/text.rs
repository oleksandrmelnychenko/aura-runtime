pub(crate) fn scan_variants(text: &str) -> Vec<String> {
    scan_variants_inner(text, false)
}

pub(crate) fn scan_variants_with_leet(text: &str) -> Vec<String> {
    scan_variants_inner(text, true)
}

fn scan_variants_inner(text: &str, decode_leet: bool) -> Vec<String> {
    let mut variants = Vec::with_capacity(5);
    push_unique(&mut variants, text.to_string());

    let normalized = normalize_chat_noise(text, false);
    push_unique(&mut variants, normalized.clone());

    let mixed_script_latin = normalize_mixed_script_latin_tokens(&normalized);
    push_unique(&mut variants, mixed_script_latin.clone());

    let repaired = repair_known_typos(&normalized);
    push_unique(&mut variants, repaired);

    let repaired = repair_known_typos(&mixed_script_latin);
    push_unique(&mut variants, repaired);

    if decode_leet {
        let leet_normalized = normalize_chat_noise(text, true);
        push_unique(&mut variants, leet_normalized.clone());

        let mixed_script_latin = normalize_mixed_script_latin_tokens(&leet_normalized);
        push_unique(&mut variants, mixed_script_latin.clone());

        let repaired = repair_known_typos(&leet_normalized);
        push_unique(&mut variants, repaired);

        let repaired = repair_known_typos(&mixed_script_latin);
        push_unique(&mut variants, repaired);
    }

    variants
}

fn normalize_chat_noise(text: &str, decode_leet: bool) -> String {
    let chars: Vec<char> = text.chars().map(fold_fullwidth_char).collect();
    let mut out = String::with_capacity(text.len());
    let mut last_was_space = true;

    for (idx, ch) in chars.iter().enumerate() {
        if is_zero_width_noise(*ch) || is_combining_mark(*ch) {
            continue;
        }

        if is_contextual_interstitial(&chars, idx) {
            continue;
        }

        if is_emoji_noise(*ch) {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }

        for lower in ch.to_lowercase() {
            let mapped = if decode_leet {
                decode_leet_char(lower)
            } else {
                lower
            };
            if mapped.is_alphanumeric()
                || matches!(mapped, '+' | '#' | '.' | ':' | '\'' | '’' | '-')
            {
                out.push(mapped);
                last_was_space = false;
            } else if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        }
    }

    out.trim().to_string()
}

fn normalize_mixed_script_latin_tokens(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut token = String::new();

    for ch in text.chars() {
        if ch.is_alphanumeric() {
            token.push(ch);
            continue;
        }

        push_mixed_script_latin_token(&mut result, &mut token);
        result.push(ch);
    }

    push_mixed_script_latin_token(&mut result, &mut token);
    result
}

fn push_mixed_script_latin_token(result: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }

    if token.chars().any(|ch| ch.is_ascii_alphabetic()) {
        for ch in token.chars() {
            result.push(fold_cyrillic_latin_homoglyph(ch));
        }
    } else {
        result.push_str(token);
    }

    token.clear();
}

fn fold_cyrillic_latin_homoglyph(ch: char) -> char {
    match ch {
        'а' => 'a',
        'е' => 'e',
        'і' => 'i',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        other => other,
    }
}

fn fold_fullwidth_char(ch: char) -> char {
    match ch {
        '\u{3000}' => ' ',
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        other => other,
    }
}

fn is_contextual_interstitial(chars: &[char], idx: usize) -> bool {
    if !matches!(
        chars[idx],
        '*' | '.'
            | '-'
            | '_'
            | '~'
            | '`'
            | '|'
            | '/'
            | '\\'
            | '#'
            | '^'
            | '&'
            | '='
            | ':'
            | ';'
            | '·'
            | '•'
            | '‧'
            | '∙'
            | '⋅'
            | '˙'
            | '⁄'
            | '∕'
    ) {
        return false;
    }

    let prev_letter = idx > 0 && chars[idx - 1].is_alphabetic();
    let next_letter = idx + 1 < chars.len() && chars[idx + 1].is_alphabetic();
    prev_letter && next_letter
}

fn decode_leet_char(ch: char) -> char {
    match ch {
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '8' => 'b',
        '@' => 'a',
        '$' => 's',
        other => other,
    }
}

fn push_unique(variants: &mut Vec<String>, variant: String) {
    if !variant.is_empty() && !variants.iter().any(|existing| existing == &variant) {
        variants.push(variant);
    }
}

const TYPO_REPAIR_ANCHORS: &[&str] = &[
    "багаття",
    "бойовий",
    "британські",
    "відділ",
    "ветеранів",
    "військових",
    "доставка",
    "дружини",
    "евакуації",
    "заправки",
    "зеленський",
    "інструктори",
    "капелан",
    "координат",
    "координати",
    "координаті",
    "комбриг",
    "маршрут",
    "мирних",
    "нібито",
    "ноутбуків",
    "особового",
    "передайте",
    "пехоти",
    "підрозділу",
    "позиція",
    "позиції",
    "позицію",
    "польової",
    "публікувати",
    "районного",
    "ретранслятор",
    "слов'янськ",
    "спостережного",
    "складу",
    "телефон",
    "терміново",
    "точніше",
    "тридцять",
    "фельдшер",
    "fund",
    "штабі",
];

fn repair_known_typos(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut token = String::new();

    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '\'' || ch == '’' {
            token.push(ch);
            continue;
        }
        push_repaired_token(&mut result, &mut token);
        result.push(ch);
    }

    push_repaired_token(&mut result, &mut token);
    result
}

fn push_repaired_token(result: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }

    if let Some(repaired) = repair_token(token) {
        result.push_str(repaired);
    } else {
        result.push_str(token);
    }
    token.clear();
}

fn repair_token(token: &str) -> Option<&'static str> {
    let token_len = token.chars().count();
    if !(3..=32).contains(&token_len) || !token.chars().any(|ch| ch.is_alphabetic()) {
        return None;
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

fn is_zero_width_noise(ch: char) -> bool {
    matches!(
        ch,
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
}

fn is_emoji_noise(ch: char) -> bool {
    let cp = ch as u32;

    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || (0xFE00..=0xFE0F).contains(&cp)
        || cp == 0x20E3
}

fn is_combining_mark(ch: char) -> bool {
    let cp = ch as u32;
    (0x0300..=0x036F).contains(&cp)
        || (0x1AB0..=0x1AFF).contains(&cp)
        || (0x1DC0..=0x1DFF).contains(&cp)
        || (0xFE20..=0xFE2F).contains(&cp)
}

#[cfg(test)]
mod tests {
    use super::{scan_variants, scan_variants_with_leet};

    #[test]
    fn strips_emoji_and_repairs_military_typos() {
        let variants = scan_variants("Ретрансляотр 😂 сидить на координаті");

        assert!(variants
            .iter()
            .any(|variant| variant.contains("ретранслятор сидить на координаті")));
    }

    #[test]
    fn leet_variant_decodes_social_engineering_words() {
        let variants = scan_variants_with_leet("V0lun733r Fnd передайе координати");

        assert!(variants
            .iter()
            .any(|variant| variant.contains("volunteer fund передайте координати")));
    }

    #[test]
    fn folds_fullwidth_and_interstitial_noise() {
        let variants = scan_variants("Ｖｏｌｕｎｔｅｅｒ·Ｆｕｎｄ передайте координати");

        assert!(variants
            .iter()
            .any(|variant| variant.contains("volunteerfund передайте координати")));
    }

    #[test]
    fn folds_mixed_script_latin_tokens_only() {
        let variants = scan_variants("Скріншот з Reutеrs і 1 Раra");

        assert!(variants
            .iter()
            .any(|variant| variant.contains("скріншот з reuters і 1 para")));
    }
}
