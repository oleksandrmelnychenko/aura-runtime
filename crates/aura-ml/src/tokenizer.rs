use std::collections::HashMap;
use std::fs;
use std::path::Path;

use tracing::debug;

pub struct WordPieceTokenizer {
    vocab: HashMap<String, i64>,
    unk_id: i64,
    cls_id: i64,
    sep_id: i64,
    pad_id: i64,
    max_seq_length: usize,
}

#[derive(Debug, Clone)]
pub struct TokenizedInput {
    pub input_ids: Vec<i64>,

    pub attention_mask: Vec<i64>,

    pub token_type_ids: Vec<i64>,
}

impl WordPieceTokenizer {
    pub fn from_file(vocab_path: &str, max_seq_length: usize) -> Result<Self, TokenizerError> {
        let content = fs::read_to_string(vocab_path)
            .map_err(|e| TokenizerError::VocabLoadFailed(e.to_string()))?;
        Self::from_vocab_text(&content, max_seq_length)
    }

    pub fn from_vocab_text(content: &str, max_seq_length: usize) -> Result<Self, TokenizerError> {
        let mut vocab = HashMap::new();
        for (idx, line) in content.lines().enumerate() {
            let token = line.trim();
            if !token.is_empty() {
                vocab.insert(token.to_string(), idx as i64);
            }
        }

        if vocab.is_empty() {
            return Err(TokenizerError::EmptyVocab);
        }

        let unk_id = *vocab.get("[UNK]").unwrap_or(&0);
        let cls_id = *vocab.get("[CLS]").unwrap_or(&101);
        let sep_id = *vocab.get("[SEP]").unwrap_or(&102);
        let pad_id = *vocab.get("[PAD]").unwrap_or(&0);

        debug!(
            vocab_size = vocab.len(),
            max_seq_length, "WordPiece tokenizer loaded"
        );

        Ok(Self {
            vocab,
            unk_id,
            cls_id,
            sep_id,
            pad_id,
            max_seq_length,
        })
    }

    pub fn minimal(max_seq_length: usize) -> Self {
        let mut vocab = HashMap::new();
        vocab.insert("[PAD]".to_string(), 0);
        vocab.insert("[UNK]".to_string(), 1);
        vocab.insert("[CLS]".to_string(), 101);
        vocab.insert("[SEP]".to_string(), 102);

        Self {
            vocab,
            unk_id: 1,
            cls_id: 101,
            sep_id: 102,
            pad_id: 0,
            max_seq_length,
        }
    }

    pub fn encode(&self, text: &str) -> TokenizedInput {
        let normalized = self.normalize(text);
        let words = self.basic_tokenize(&normalized);

        let mut tokens = Vec::with_capacity(self.max_seq_length);
        tokens.push(self.cls_id);

        for word in &words {
            let word_tokens = self.wordpiece_tokenize(word);

            if tokens.len() + word_tokens.len() >= self.max_seq_length - 1 {
                break;
            }
            tokens.extend(word_tokens);
        }

        tokens.push(self.sep_id);

        let real_len = tokens.len();
        tokens.resize(self.max_seq_length, self.pad_id);

        let mut attention_mask = vec![1i64; real_len];
        attention_mask.resize(self.max_seq_length, 0);

        let token_type_ids = vec![0i64; self.max_seq_length];

        TokenizedInput {
            input_ids: tokens,
            attention_mask,
            token_type_ids,
        }
    }

    fn normalize(&self, text: &str) -> String {
        text.chars()
            .map(|c| if c.is_control() || c == '\0' { ' ' } else { c })
            .collect::<String>()
            .to_lowercase()
    }

    fn basic_tokenize(&self, text: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();

        for ch in text.chars() {
            if ch.is_whitespace() {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            } else if is_punctuation(ch) {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                tokens.push(ch.to_string());
            } else {
                current.push(ch);
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        tokens
    }

    fn wordpiece_tokenize(&self, word: &str) -> Vec<i64> {
        if word.is_empty() {
            return vec![];
        }

        if let Some(&id) = self.vocab.get(word) {
            return vec![id];
        }

        let mut tokens = Vec::new();
        let chars: Vec<char> = word.chars().collect();
        let mut start = 0;

        while start < chars.len() {
            let mut end = chars.len();
            let mut found = false;

            while start < end {
                let substr: String = if start > 0 {
                    format!("##{}", chars[start..end].iter().collect::<String>())
                } else {
                    chars[start..end].iter().collect()
                };

                if let Some(&id) = self.vocab.get(&substr) {
                    tokens.push(id);
                    found = true;
                    start = end;
                    break;
                }
                end -= 1;
            }

            if !found {
                tokens.push(self.unk_id);
                start += 1;
            }
        }

        tokens
    }

    pub fn vocab_size(&self) -> usize {
        self.vocab.len()
    }

    pub fn vocab_exists(path: &str) -> bool {
        Path::new(path).exists()
    }
}

fn is_punctuation(ch: char) -> bool {
    let cp = ch as u32;

    if (0x21..=0x2F).contains(&cp)
        || (0x3A..=0x40).contains(&cp)
        || (0x5B..=0x60).contains(&cp)
        || (0x7B..=0x7E).contains(&cp)
    {
        return true;
    }

    ch.is_ascii_punctuation()
}

#[derive(Debug, thiserror::Error)]
pub enum TokenizerError {
    #[error("Failed to load vocabulary: {0}")]
    VocabLoadFailed(String),
    #[error("Vocabulary is empty")]
    EmptyVocab,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vocab() -> String {
        [
            "[PAD]",
            "[UNK]",
            "[CLS]",
            "[SEP]",
            "[MASK]",
            "hello",
            "world",
            "you",
            "are",
            "stupid",
            "kill",
            "##ing",
            "##ed",
            "the",
            "a",
            "i",
            "will",
            "hurt",
            "##ful",
            "ти",
            "дурний",
            "привіт",
            "вб",
            "##ию",
            "не",
            "кажи",
            "мамі",
            ",",
            ".",
            "!",
            "?",
        ]
        .join("\n")
    }

    #[test]
    fn loads_from_text() {
        let tok = WordPieceTokenizer::from_vocab_text(&test_vocab(), 32).unwrap();
        assert!(tok.vocab_size() > 10);
    }

    #[test]
    fn encodes_simple_text() {
        let tok = WordPieceTokenizer::from_vocab_text(&test_vocab(), 16).unwrap();
        let encoded = tok.encode("hello world");

        let cls_id = *tok.vocab.get("[CLS]").unwrap();
        assert_eq!(encoded.input_ids[0], cls_id);

        assert!(encoded.input_ids.len() == 16);

        assert_eq!(encoded.attention_mask[0], 1);
        assert_eq!(encoded.attention_mask[15], 0);

        assert!(encoded.token_type_ids.iter().all(|&t| t == 0));
    }

    #[test]
    fn encodes_ukrainian_text() {
        let tok = WordPieceTokenizer::from_vocab_text(&test_vocab(), 16).unwrap();
        let encoded = tok.encode("привіт ти дурний");

        let cls_id = *tok.vocab.get("[CLS]").unwrap();
        assert_eq!(encoded.input_ids[0], cls_id);

        let real_tokens: Vec<_> = encoded.attention_mask.iter().filter(|&&m| m == 1).collect();
        assert!(real_tokens.len() >= 4);
    }

    #[test]
    fn handles_unknown_words() {
        let tok = WordPieceTokenizer::from_vocab_text(&test_vocab(), 16).unwrap();
        let encoded = tok.encode("supercalifragilistic");

        let real_tokens: usize = encoded.attention_mask.iter().filter(|&&m| m == 1).count();
        assert!(
            real_tokens >= 2,
            "Should have at least [CLS] + [SEP], got {real_tokens}"
        );
    }

    #[test]
    fn wordpiece_splits_subwords() {
        let tok = WordPieceTokenizer::from_vocab_text(&test_vocab(), 16).unwrap();
        let encoded = tok.encode("killing");

        let kill_id = *tok.vocab.get("kill").unwrap();
        let ing_id = *tok.vocab.get("##ing").unwrap();

        let real: Vec<i64> = encoded
            .input_ids
            .iter()
            .copied()
            .zip(encoded.attention_mask.iter().copied())
            .filter(|(_, m)| *m == 1)
            .map(|(id, _)| id)
            .collect();

        assert!(real.contains(&kill_id), "Should find 'kill' token");
        assert!(real.contains(&ing_id), "Should find '##ing' subword token");
    }

    #[test]
    fn respects_max_length() {
        let tok = WordPieceTokenizer::from_vocab_text(&test_vocab(), 8).unwrap();
        let long_text = "hello world you are the a hello world you are the a";
        let encoded = tok.encode(long_text);

        assert_eq!(encoded.input_ids.len(), 8);
        assert_eq!(encoded.attention_mask.len(), 8);
        assert_eq!(encoded.token_type_ids.len(), 8);
    }

    #[test]
    fn punctuation_is_split() {
        let tok = WordPieceTokenizer::from_vocab_text(&test_vocab(), 16).unwrap();
        let encoded = tok.encode("hello, world!");

        let comma_id = *tok.vocab.get(",").unwrap();
        let real: Vec<i64> = encoded
            .input_ids
            .iter()
            .copied()
            .zip(encoded.attention_mask.iter().copied())
            .filter(|(_, m)| *m == 1)
            .map(|(id, _)| id)
            .collect();

        assert!(real.contains(&comma_id), "Comma should be a separate token");
    }

    #[test]
    fn minimal_tokenizer_works() {
        let tok = WordPieceTokenizer::minimal(16);
        let encoded = tok.encode("anything goes here");

        assert_eq!(encoded.input_ids[0], 101);

        assert_eq!(encoded.input_ids.len(), 16);
    }
}
