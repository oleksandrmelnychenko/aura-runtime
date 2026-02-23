pub fn contains_at_boundary(text: &str, pattern: &str) -> bool {
    find_at_boundary(text, pattern).is_some()
}

pub fn find_at_boundary(text: &str, pattern: &str) -> Option<usize> {
    if pattern.is_empty() {
        return None;
    }
    let mut start = 0;
    while start < text.len() {
        let haystack = &text[start..];
        let pos = match haystack.find(pattern) {
            Some(p) => p,
            None => return None,
        };
        let abs = start + pos;
        let end = abs + pattern.len();

        let before_ok =
            abs == 0 || text[..abs].chars().next_back().map_or(true, |c| !c.is_alphanumeric());
        let after_ok =
            end >= text.len() || text[end..].chars().next().map_or(true, |c| !c.is_alphanumeric());

        if before_ok && after_ok {
            return Some(abs);
        }

        start = end.max(abs + 1);
        while start < text.len() && !text.is_char_boundary(start) {
            start += 1;
        }
    }
    None
}

pub fn aho_match_at_boundary(text: &str, match_start: usize, match_end: usize) -> bool {
    let before_ok = match_start == 0
        || text[..match_start]
            .chars()
            .next_back()
            .map_or(true, |c| !c.is_alphanumeric());
    let after_ok = match_end >= text.len()
        || text[match_end..]
            .chars()
            .next()
            .map_or(true, |c| !c.is_alphanumeric());
    before_ok && after_ok
}

const NEGATION_EN: &[&str] = &[
    "not", "don't", "doesn't", "didn't", "won't", "wouldn't", "can't", "couldn't",
    "isn't", "aren't", "wasn't", "weren't", "never", "no", "nobody", "nothing", "hardly",
];

const NEGATION_UK: &[&str] = &[
    "не", "ні", "ніколи", "ніхто", "ніщо", "жодний", "жодна", "навряд",
];

const NEGATION_RU: &[&str] = &[
    "не", "ни", "никогда", "никто", "ничего", "нигде", "ничто", "едва",
];

pub fn is_negated(text: &str, match_start: usize, window_chars: usize) -> bool {
    let prefix = &text[..match_start];
    let start_byte = {
        let mut chars_remaining = window_chars;
        let mut pos = prefix.len();
        for (i, _) in prefix.char_indices().rev() {
            if chars_remaining == 0 {
                break;
            }
            pos = i;
            chars_remaining -= 1;
        }
        pos
    };
    let window = &text[start_byte..match_start];

    for neg in NEGATION_EN.iter().chain(NEGATION_UK.iter()).chain(NEGATION_RU.iter()) {
        if find_at_boundary(&window.to_lowercase(), neg).is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_does_not_match_meth() {
        assert!(!contains_at_boundary("method", "meth"));
    }

    #[test]
    fn something_does_not_match_meth() {
        assert!(!contains_at_boundary("something happened", "meth"));
    }

    #[test]
    fn cockpit_does_not_match_cock() {
        assert!(!contains_at_boundary("the cockpit was spacious", "cock"));
    }

    #[test]
    fn establish_does_not_match_stab() {
        assert!(!contains_at_boundary("establish a connection", "stab"));
    }

    #[test]
    fn stable_does_not_match_stab() {
        assert!(!contains_at_boundary("a stable environment", "stab"));
    }

    #[test]
    fn funeral_does_not_match_fun() {
        assert!(!contains_at_boundary("the funeral was quiet", "fun"));
    }

    #[test]
    fn crystal_does_not_match_cry() {
        assert!(!contains_at_boundary("the crystal was clear", "cry"));
    }

    #[test]
    fn encrypt_does_not_match_cry() {
        assert!(!contains_at_boundary("encrypt the data", "cry"));
    }

    #[test]
    fn scunthorpe_does_not_match_cunt() {
        assert!(!contains_at_boundary("I live in scunthorpe", "cunt"));
    }

    #[test]
    fn dickens_does_not_match_dick() {
        assert!(!contains_at_boundary("reading dickens today", "dick"));
    }

    #[test]
    fn shitake_does_not_match_shit() {
        assert!(!contains_at_boundary("shitake mushrooms are great", "shit"));
    }

    #[test]
    fn fatigue_does_not_match_fat() {
        assert!(!contains_at_boundary("feeling fatigue", "fat"));
    }

    #[test]
    fn studied_does_not_match_die() {
        assert!(!contains_at_boundary("I studied hard", "die"));
    }

    #[test]
    fn saddle_does_not_match_sad() {
        assert!(!contains_at_boundary("the saddle was old", "sad"));
    }

    #[test]
    fn ambassador_does_not_match_sad() {
        assert!(!contains_at_boundary("the ambassador spoke", "sad"));
    }

    #[test]
    fn cracking_does_not_match_crack() {
        assert!(!contains_at_boundary("cracking the code", "crack"));
    }

    #[test]
    fn standalone_word_matches() {
        assert!(contains_at_boundary("he said fuck off", "fuck"));
    }

    #[test]
    fn multi_word_phrase_matches() {
        assert!(contains_at_boundary("i'll kill you today", "kill you"));
    }

    #[test]
    fn boundary_with_punctuation() {
        assert!(contains_at_boundary("you're fat!", "fat"));
    }

    #[test]
    fn boundary_with_comma() {
        assert!(contains_at_boundary("die, you fool", "die"));
    }

    #[test]
    fn at_start_of_text() {
        assert!(contains_at_boundary("meth is bad", "meth"));
    }

    #[test]
    fn at_end_of_text() {
        assert!(contains_at_boundary("he took meth", "meth"));
    }

    #[test]
    fn entire_text_is_pattern() {
        assert!(contains_at_boundary("meth", "meth"));
    }

    #[test]
    fn cyrillic_insult_matches() {
        assert!(contains_at_boundary("тупий ідіот", "ідіот"));
    }

    #[test]
    fn cyrillic_threat_matches() {
        assert!(contains_at_boundary("я тебе вб'ю", "вб'ю"));
    }

    #[test]
    fn cyrillic_multi_word_matches() {
        assert!(contains_at_boundary("пішов нахуй звідси", "пішов нахуй"));
    }

    #[test]
    fn russian_insult_matches() {
        assert!(contains_at_boundary("ты тупой дебил", "дебил"));
    }

    #[test]
    fn find_returns_correct_position() {
        assert_eq!(find_at_boundary("he said fuck off", "fuck"), Some(8));
    }

    #[test]
    fn find_returns_none_for_embedded() {
        assert_eq!(find_at_boundary("method", "meth"), None);
    }

    #[test]
    fn find_returns_zero_at_start() {
        assert_eq!(find_at_boundary("fuck this", "fuck"), Some(0));
    }

    #[test]
    fn empty_pattern_returns_false() {
        assert!(!contains_at_boundary("some text", ""));
    }

    #[test]
    fn empty_text_returns_false() {
        assert!(!contains_at_boundary("", "word"));
    }

    #[test]
    fn pattern_with_spaces_at_boundary() {
        assert!(contains_at_boundary("hey, kill you now", "kill you"));
    }

    #[test]
    fn second_occurrence_at_boundary() {
        assert!(contains_at_boundary("I studied and might die", "die"));
    }

    #[test]
    fn aho_boundary_standalone() {
        let text = "he said fuck off";
        assert!(aho_match_at_boundary(text, 8, 12)); // "fuck" at [8..12)
    }

    #[test]
    fn aho_boundary_embedded() {
        let text = "method is good";
        assert!(!aho_match_at_boundary(text, 0, 4)); // "meth" at [0..4) — "o" follows
    }

    #[test]
    fn negation_wont_kill() {
        let text = "i won't kill you";
        let pos = find_at_boundary(text, "kill you").unwrap();
        assert!(is_negated(text, pos, 30));
    }

    #[test]
    fn no_negation_will_kill() {
        let text = "i will kill you";
        let pos = find_at_boundary(text, "kill you").unwrap();
        assert!(!is_negated(text, pos, 30));
    }

    #[test]
    fn negation_not_stupid() {
        let text = "you're not stupid";
        let pos = find_at_boundary(text, "stupid").unwrap();
        assert!(is_negated(text, pos, 30));
    }

    #[test]
    fn negation_never_hurt() {
        let text = "i would never hurt you";
        let pos = find_at_boundary(text, "hurt").unwrap();
        assert!(is_negated(text, pos, 30));
    }

    #[test]
    fn negation_ukrainian() {
        let text = "я не тупий";
        let pos = find_at_boundary(text, "тупий").unwrap();
        assert!(is_negated(text, pos, 30));
    }

    #[test]
    fn negation_russian() {
        let text = "я не глупый";
        let pos = find_at_boundary(text, "глупый").unwrap();
        assert!(is_negated(text, pos, 30));
    }

    #[test]
    fn negation_dont_say() {
        let text = "don't say fuck";
        let pos = find_at_boundary(text, "fuck").unwrap();
        assert!(is_negated(text, pos, 30));
    }

    #[test]
    fn negation_not_happy() {
        let text = "i'm not happy";
        let pos = find_at_boundary(text, "happy").unwrap();
        assert!(is_negated(text, pos, 30));
    }

    #[test]
    fn no_negation_far_away() {
        let text = "not in a million years would I ever say that you are stupid";
        let pos = find_at_boundary(text, "stupid").unwrap();
        assert!(!is_negated(text, pos, 30));
    }
}
