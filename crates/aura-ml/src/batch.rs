//! Batch inference accumulator for group chat messages.
//!
//! When multiple messages arrive within a short window, batches them
//! into a single ONNX forward pass for higher throughput. The ONNX
//! model supports batch dimension in input_ids shape [batch, seq_len].

use std::time::{Duration, Instant};

/// Accumulates messages for batched inference.
pub struct BatchAccumulator<T> {
    pending: Vec<T>,
    max_batch: usize,
    max_wait: Duration,
    batch_started: Option<Instant>,
}

impl<T> BatchAccumulator<T> {
    /// Creates a new accumulator with given batch size limit and wait window.
    pub fn new(max_batch: usize, max_wait_ms: u64) -> Self {
        Self {
            pending: Vec::with_capacity(max_batch),
            max_batch: max_batch.max(1),
            max_wait: Duration::from_millis(max_wait_ms),
            batch_started: None,
        }
    }

    /// Adds an item to the batch. Returns true if the batch is ready to flush.
    pub fn push(&mut self, item: T) -> bool {
        if self.batch_started.is_none() {
            self.batch_started = Some(Instant::now());
        }
        self.pending.push(item);
        self.is_ready()
    }

    /// Returns true if the batch should be flushed (full or timed out).
    pub fn is_ready(&self) -> bool {
        if self.pending.len() >= self.max_batch {
            return true;
        }
        if let Some(started) = self.batch_started {
            if started.elapsed() >= self.max_wait {
                return true;
            }
        }
        false
    }

    /// Drains all pending items for processing.
    pub fn flush(&mut self) -> Vec<T> {
        self.batch_started = None;
        std::mem::take(&mut self.pending)
    }

    /// Returns the number of pending items.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns true if no items are pending.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Forces a flush regardless of batch state.
    pub fn force_flush(&mut self) -> Vec<T> {
        self.flush()
    }
}

/// Pads a batch of token sequences to uniform length for ONNX batch input.
///
/// All sequences are padded to the length of the longest sequence in the
/// batch (or max_seq_length, whichever is shorter).
pub fn pad_batch_sequences(
    sequences: &[Vec<i64>],
    pad_id: i64,
    max_seq_length: usize,
) -> (Vec<Vec<i64>>, Vec<Vec<i64>>) {
    let max_len = sequences
        .iter()
        .map(|s| s.len())
        .max()
        .unwrap_or(0)
        .min(max_seq_length);

    let mut padded_ids = Vec::with_capacity(sequences.len());
    let mut attention_masks = Vec::with_capacity(sequences.len());

    for seq in sequences {
        let real_len = seq.len().min(max_len);
        let mut ids = seq[..real_len].to_vec();
        let mut mask = vec![1i64; real_len];

        ids.resize(max_len, pad_id);
        mask.resize(max_len, 0);

        padded_ids.push(ids);
        attention_masks.push(mask);
    }

    (padded_ids, attention_masks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_flushes_at_capacity() {
        let mut acc = BatchAccumulator::new(3, 1000);
        assert!(!acc.push("msg1"));
        assert!(!acc.push("msg2"));
        assert!(acc.push("msg3"));
        let batch = acc.flush();
        assert_eq!(batch.len(), 3);
        assert!(acc.is_empty());
    }

    #[test]
    fn accumulator_force_flush() {
        let mut acc = BatchAccumulator::new(10, 1000);
        acc.push("msg1");
        acc.push("msg2");
        let batch = acc.force_flush();
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn pad_batch_uniform_length() {
        let seqs = vec![
            vec![101, 1, 2, 102],
            vec![101, 3, 4, 5, 102],
            vec![101, 6, 102],
        ];
        let (padded, masks) = pad_batch_sequences(&seqs, 0, 128);

        assert_eq!(padded.len(), 3);
        // All padded to length 5 (longest sequence)
        for p in &padded {
            assert_eq!(p.len(), 5);
        }
        // Masks reflect real vs padded tokens
        assert_eq!(masks[0], vec![1, 1, 1, 1, 0]);
        assert_eq!(masks[1], vec![1, 1, 1, 1, 1]);
        assert_eq!(masks[2], vec![1, 1, 1, 0, 0]);
    }

    #[test]
    fn pad_batch_respects_max_length() {
        let seqs = vec![vec![101, 1, 2, 3, 4, 5, 6, 7, 8, 102]];
        let (padded, _masks) = pad_batch_sequences(&seqs, 0, 5);
        assert_eq!(padded[0].len(), 5);
    }

    #[test]
    fn pad_batch_empty() {
        let seqs: Vec<Vec<i64>> = vec![];
        let (padded, masks) = pad_batch_sequences(&seqs, 0, 128);
        assert!(padded.is_empty());
        assert!(masks.is_empty());
    }
}
