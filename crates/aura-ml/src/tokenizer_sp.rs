use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::tokenizer::TokenizedInput;

pub struct SentencePieceTokenizer {
    pieces: Vec<String>,
    piece_to_id: HashMap<String, i64>,
    scores: Vec<f32>,
    unk_id: i64,
    bos_id: i64,
    eos_id: i64,
    pad_id: i64,
    max_seq_length: usize,
    max_piece_len: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SpTokenizerError {
    #[error("failed to read model file: {0}")]
    ReadFailed(String),
    #[error("invalid model format: {0}")]
    InvalidFormat(String),
    #[error("empty vocabulary")]
    EmptyVocab,
}

impl SentencePieceTokenizer {
    pub fn from_vocab_file(path: &str, max_seq_length: usize) -> Result<Self, SpTokenizerError> {
        let content =
            fs::read_to_string(path).map_err(|e| SpTokenizerError::ReadFailed(e.to_string()))?;
        Self::from_vocab_text(&content, max_seq_length)
    }

    pub fn from_vocab_text(content: &str, max_seq_length: usize) -> Result<Self, SpTokenizerError> {
        let mut pieces = Vec::new();
        let mut scores = Vec::new();
        let mut piece_to_id = HashMap::new();

        for (idx, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (piece, score) = if let Some((p, s)) = line.split_once('\t') {
                let score = s.parse::<f32>().unwrap_or(0.0);
                (p.to_string(), score)
            } else {
                (line.to_string(), 0.0)
            };
            piece_to_id.insert(piece.clone(), idx as i64);
            pieces.push(piece);
            scores.push(score);
        }

        if pieces.is_empty() {
            return Err(SpTokenizerError::EmptyVocab);
        }

        let unk_id = piece_to_id.get("<unk>").copied().unwrap_or(0);
        let bos_id = piece_to_id.get("<s>").copied().unwrap_or(1);
        let eos_id = piece_to_id.get("</s>").copied().unwrap_or(2);
        let pad_id = piece_to_id.get("<pad>").copied().unwrap_or(0);

        let max_piece_len = pieces.iter().map(|p| p.chars().count()).max().unwrap_or(1);

        Ok(Self {
            pieces,
            piece_to_id,
            scores,
            unk_id,
            bos_id,
            eos_id,
            pad_id,
            max_seq_length,
            max_piece_len,
        })
    }

    pub fn minimal(max_seq_length: usize) -> Self {
        let pieces = vec![
            "<unk>".to_string(),
            "<s>".to_string(),
            "</s>".to_string(),
            "<pad>".to_string(),
        ];
        let mut piece_to_id = HashMap::new();
        for (i, p) in pieces.iter().enumerate() {
            piece_to_id.insert(p.clone(), i as i64);
        }
        Self {
            pieces,
            piece_to_id,
            scores: vec![0.0; 4],
            unk_id: 0,
            bos_id: 1,
            eos_id: 2,
            pad_id: 3,
            max_seq_length,
            max_piece_len: 5,
        }
    }

    pub fn encode(&self, text: &str) -> TokenizedInput {
        let normalized = self.normalize(text);
        let token_ids = self.tokenize(&normalized);

        let mut ids = Vec::with_capacity(self.max_seq_length);
        ids.push(self.bos_id);

        for &id in &token_ids {
            if ids.len() >= self.max_seq_length - 1 {
                break;
            }
            ids.push(id);
        }
        ids.push(self.eos_id);

        let real_len = ids.len();
        ids.resize(self.max_seq_length, self.pad_id);

        let mut attention_mask = vec![1i64; real_len];
        attention_mask.resize(self.max_seq_length, 0);

        let token_type_ids = vec![0i64; self.max_seq_length];

        TokenizedInput {
            input_ids: ids,
            attention_mask,
            token_type_ids,
        }
    }

    pub fn vocab_size(&self) -> usize {
        self.pieces.len()
    }

    pub fn vocab_exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    fn normalize(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len() + 1);
        result.push('\u{2581}');
        for ch in text.chars() {
            if ch.is_whitespace() {
                result.push('\u{2581}');
            } else if ch.is_control() || ch == '\0' {
                continue;
            } else {
                result.push(ch);
            }
        }
        result
    }

    fn tokenize(&self, text: &str) -> Vec<i64> {
        if text.is_empty() {
            return vec![];
        }

        let chars: Vec<char> = text.chars().collect();
        let n = chars.len();

        let max_piece_len = self.max_piece_len.min(n);

        let mut best_score = vec![f32::NEG_INFINITY; n + 1];
        let mut best_split = vec![0usize; n + 1];
        best_score[0] = 0.0;

        for end in 1..=n {
            let search_start = if end > max_piece_len {
                end - max_piece_len
            } else {
                0
            };

            for start in (search_start..end).rev() {
                let piece: String = chars[start..end].iter().collect();
                if let Some(&id) = self.piece_to_id.get(&piece) {
                    let score =
                        best_score[start] + self.scores.get(id as usize).copied().unwrap_or(0.0);
                    if score > best_score[end] {
                        best_score[end] = score;
                        best_split[end] = start;
                    }
                }
            }

            if best_score[end] == f32::NEG_INFINITY {
                best_score[end] = best_score[end - 1] + -100.0;
                best_split[end] = end - 1;
            }
        }

        let mut token_ids = Vec::new();
        let mut pos = n;
        while pos > 0 {
            let start = best_split[pos];
            let piece: String = chars[start..pos].iter().collect();
            let id = self.piece_to_id.get(&piece).copied().unwrap_or(self.unk_id);
            token_ids.push(id);
            pos = start;
        }
        token_ids.reverse();
        token_ids
    }
}

pub trait Tokenizer {
    fn encode(&self, text: &str) -> TokenizedInput;
    fn vocab_size(&self) -> usize;
}

impl Tokenizer for SentencePieceTokenizer {
    fn encode(&self, text: &str) -> TokenizedInput {
        self.encode(text)
    }
    fn vocab_size(&self) -> usize {
        self.vocab_size()
    }
}

impl Tokenizer for crate::tokenizer::WordPieceTokenizer {
    fn encode(&self, text: &str) -> TokenizedInput {
        self.encode(text)
    }
    fn vocab_size(&self) -> usize {
        self.vocab_size()
    }
}

pub enum AnyTokenizer {
    WordPiece(crate::tokenizer::WordPieceTokenizer),
    SentencePiece(SentencePieceTokenizer),
}

impl AnyTokenizer {
    pub fn encode(&self, text: &str) -> TokenizedInput {
        match self {
            AnyTokenizer::WordPiece(t) => t.encode(text),
            AnyTokenizer::SentencePiece(t) => t.encode(text),
        }
    }

    pub fn vocab_size(&self) -> usize {
        match self {
            AnyTokenizer::WordPiece(t) => t.vocab_size(),
            AnyTokenizer::SentencePiece(t) => t.vocab_size(),
        }
    }

    pub fn from_file(path: &str, max_seq_length: usize) -> Result<Self, SpTokenizerError> {
        if path.ends_with(".model") || path.ends_with(".spm") {
            let tok = SentencePieceTokenizer::from_vocab_file(path, max_seq_length)?;
            Ok(AnyTokenizer::SentencePiece(tok))
        } else {
            let tok = crate::tokenizer::WordPieceTokenizer::from_file(path, max_seq_length)
                .map_err(|e| SpTokenizerError::ReadFailed(e.to_string()))?;
            Ok(AnyTokenizer::WordPiece(tok))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sp_vocab() -> String {
        [
            "<unk>\t0",
            "<s>\t0",
            "</s>\t0",
            "<pad>\t0",
            "\u{2581}hello\t-1.0",
            "\u{2581}world\t-1.5",
            "\u{2581}kill\t-2.0",
            "\u{2581}you\t-1.0",
            "ing\t-3.0",
            "\u{2581}the\t-0.5",
            "\u{2581}\t-0.1",
            "h\t-5.0",
            "e\t-5.0",
            "l\t-5.0",
            "o\t-5.0",
            "w\t-5.0",
            "r\t-5.0",
            "d\t-5.0",
            "k\t-5.0",
            "i\t-5.0",
            "n\t-5.0",
            "g\t-5.0",
            "y\t-5.0",
            "u\t-5.0",
            "t\t-5.0",
            "\u{2581}\u{043F}\u{0440}\u{0438}\u{0432}\u{0456}\u{0442}\t-2.0",
            "\u{2581}\u{044F}\u{043A}\t-2.5",
            "\u{2581}\u{0441}\u{043F}\u{0440}\u{0430}\u{0432}\u{0438}\t-3.0",
        ]
        .join("\n")
    }

    #[test]
    fn loads_from_text() {
        let tok = SentencePieceTokenizer::from_vocab_text(&test_sp_vocab(), 32).unwrap();
        assert!(tok.vocab_size() > 10);
    }

    #[test]
    fn encodes_english() {
        let tok = SentencePieceTokenizer::from_vocab_text(&test_sp_vocab(), 32).unwrap();
        let encoded = tok.encode("hello world");
        assert_eq!(encoded.input_ids.len(), 32);
        assert_eq!(encoded.input_ids[0], tok.bos_id);
        let real_tokens: usize = encoded.attention_mask.iter().filter(|&&m| m == 1).count();
        assert!(
            real_tokens >= 3,
            "Expected at least BOS + tokens + EOS, got {real_tokens}"
        );
    }

    #[test]
    fn encodes_ukrainian() {
        let tok = SentencePieceTokenizer::from_vocab_text(&test_sp_vocab(), 32).unwrap();
        let encoded = tok.encode("\u{043F}\u{0440}\u{0438}\u{0432}\u{0456}\u{0442}");
        let real_tokens: usize = encoded.attention_mask.iter().filter(|&&m| m == 1).count();
        assert!(
            real_tokens >= 3,
            "Expected tokens for Ukrainian, got {real_tokens}"
        );
    }

    #[test]
    fn respects_max_length() {
        let tok = SentencePieceTokenizer::from_vocab_text(&test_sp_vocab(), 8).unwrap();
        let encoded = tok.encode("hello world hello world hello world");
        assert_eq!(encoded.input_ids.len(), 8);
        assert_eq!(encoded.attention_mask.len(), 8);
    }

    #[test]
    fn handles_unknown_tokens() {
        let tok = SentencePieceTokenizer::from_vocab_text(&test_sp_vocab(), 32).unwrap();
        let encoded = tok.encode("zzzzz");
        let real_tokens: usize = encoded.attention_mask.iter().filter(|&&m| m == 1).count();
        assert!(real_tokens >= 2, "Should have BOS + EOS at minimum");
    }

    #[test]
    fn minimal_tokenizer_works() {
        let tok = SentencePieceTokenizer::minimal(16);
        let encoded = tok.encode("anything goes");
        assert_eq!(encoded.input_ids.len(), 16);
        assert_eq!(encoded.input_ids[0], 1);
    }

    #[test]
    fn any_tokenizer_routes_by_extension() {
        let tok = AnyTokenizer::from_file("nonexistent.model", 32);
        assert!(tok.is_err());
        let tok = AnyTokenizer::from_file("nonexistent.txt", 32);
        assert!(tok.is_err());
    }

    #[test]
    fn tokenizer_trait_dispatch() {
        let tok = SentencePieceTokenizer::from_vocab_text(&test_sp_vocab(), 16).unwrap();
        let t: &dyn Tokenizer = &tok;
        let encoded = t.encode("hello");
        assert_eq!(encoded.input_ids.len(), 16);
        assert!(t.vocab_size() > 0);
    }

    #[test]
    fn bpe_viterbi_prefers_longer_pieces() {
        let tok = SentencePieceTokenizer::from_vocab_text(&test_sp_vocab(), 32).unwrap();
        let encoded = tok.encode("hello");
        let hello_id = tok.piece_to_id.get("\u{2581}hello").copied();
        assert!(hello_id.is_some());
        let real_ids: Vec<i64> = encoded
            .input_ids
            .iter()
            .copied()
            .zip(encoded.attention_mask.iter().copied())
            .filter(|(_, m)| *m == 1)
            .map(|(id, _)| id)
            .collect();
        assert!(
            real_ids.contains(&hello_id.unwrap()),
            "Should tokenize 'hello' as single piece, got {real_ids:?}"
        );
    }
}
