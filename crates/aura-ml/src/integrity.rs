//! Runtime model integrity verification.
//!
//! Provides periodic spot-check validation of loaded model files
//! and output range validation after each inference. Detects model
//! tampering without the cost of full re-hashing on every call.

use sha2::{Digest, Sha256};

/// Validates that all inference output scores are in valid range.
pub fn validate_output_range(scores: &[f32]) -> bool {
    for score in scores {
        if score.is_nan() || score.is_infinite() || *score < -1.0 || *score > 2.0 {
            return false;
        }
    }
    true
}

/// Validates that output tensor has the expected number of scores.
pub fn validate_output_shape(actual_len: usize, expected_len: usize) -> bool {
    actual_len == expected_len
}

/// Spot-checks a random block of model bytes against the full file hash.
///
/// Instead of re-hashing the entire model file (~18MB), reads a small
/// block and computes a block-level hash. This is probabilistic — it
/// detects random tampering with probability proportional to block
/// coverage, but cannot detect targeted byte-level modifications
/// outside the checked block.
pub struct IntegritySpotChecker {
    full_hash: [u8; 32],
    block_hashes: Vec<[u8; 32]>,
    block_size: usize,
    total_blocks: usize,
    checks_performed: u64,
    check_interval: u64,
}

impl IntegritySpotChecker {
    /// Pre-computes block hashes for a model file.
    ///
    /// Divides the file into blocks and hashes each one. Spot checks
    /// verify individual blocks, providing O(1) verification per check.
    pub fn from_file_bytes(data: &[u8], check_interval: u64) -> Self {
        let block_size = 4096;
        let total_blocks = (data.len() + block_size - 1) / block_size;

        let mut full_hasher = Sha256::new();
        full_hasher.update(data);
        let full_hash: [u8; 32] = full_hasher.finalize().into();

        let mut block_hashes = Vec::with_capacity(total_blocks);
        for i in 0..total_blocks {
            let start = i * block_size;
            let end = (start + block_size).min(data.len());
            let mut hasher = Sha256::new();
            hasher.update(&data[start..end]);
            block_hashes.push(hasher.finalize().into());
        }

        Self {
            full_hash,
            block_hashes,
            block_size,
            total_blocks,
            checks_performed: 0,
            check_interval,
        }
    }

    /// Returns the full SHA-256 hash of the model file.
    pub fn full_hash_hex(&self) -> String {
        hex_encode(&self.full_hash)
    }

    /// Called after each inference. Returns true if a spot check was
    /// performed this call, and whether it passed.
    pub fn maybe_check(&mut self, model_data: &[u8]) -> Option<bool> {
        self.checks_performed += 1;
        if self.checks_performed % self.check_interval != 0 {
            return None;
        }

        let block_idx = (self.checks_performed / self.check_interval) as usize % self.total_blocks;
        let start = block_idx * self.block_size;
        let end = (start + self.block_size).min(model_data.len());

        if end > model_data.len() || block_idx >= self.block_hashes.len() {
            return Some(false);
        }

        let mut hasher = Sha256::new();
        hasher.update(&model_data[start..end]);
        let actual: [u8; 32] = hasher.finalize().into();

        Some(actual == self.block_hashes[block_idx])
    }

    /// Returns the number of integrity checks performed so far.
    pub fn checks_performed(&self) -> u64 {
        self.checks_performed
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_range_valid() {
        assert!(validate_output_range(&[0.0, 0.5, 1.0]));
        assert!(validate_output_range(&[0.1, 0.9, 0.3, 0.7, 0.2, 0.8]));
    }

    #[test]
    fn output_range_rejects_nan() {
        assert!(!validate_output_range(&[0.5, f32::NAN, 0.3]));
    }

    #[test]
    fn output_range_rejects_infinity() {
        assert!(!validate_output_range(&[0.5, f32::INFINITY]));
    }

    #[test]
    fn output_range_rejects_extreme() {
        assert!(!validate_output_range(&[0.5, 5.0]));
    }

    #[test]
    fn output_shape_valid() {
        assert!(validate_output_shape(6, 6));
        assert!(!validate_output_shape(5, 6));
    }

    #[test]
    fn spot_checker_passes_on_unchanged_data() {
        let data = vec![42u8; 16384]; // 4 blocks
        let mut checker = IntegritySpotChecker::from_file_bytes(&data, 1);

        for _ in 0..10 {
            let result = checker.maybe_check(&data);
            if let Some(passed) = result {
                assert!(passed, "Unchanged data should pass spot check");
            }
        }
    }

    #[test]
    fn spot_checker_detects_tampering() {
        let data = vec![42u8; 16384];
        let mut checker = IntegritySpotChecker::from_file_bytes(&data, 1);

        let mut tampered = data.clone();
        tampered[0] = 99;

        // First check is on block 0 where we tampered
        // checks_performed starts at 0, increments to 1, 1 % 1 == 0, block = (1/1) % 4 = 1
        // We need to hit block 0. Let's run until we check block 0.
        let mut found_failure = false;
        for _ in 0..10 {
            if let Some(passed) = checker.maybe_check(&tampered) {
                if !passed {
                    found_failure = true;
                    break;
                }
            }
        }
        assert!(found_failure, "Should detect tampering in checked block");
    }

    #[test]
    fn spot_checker_respects_interval() {
        let data = vec![42u8; 8192];
        let mut checker = IntegritySpotChecker::from_file_bytes(&data, 100);

        // First 99 calls should return None (no check performed)
        for _ in 0..99 {
            assert!(checker.maybe_check(&data).is_none());
        }
        // 100th call performs a check
        assert!(checker.maybe_check(&data).is_some());
    }

    #[test]
    fn full_hash_is_consistent() {
        let data = b"test model content";
        let checker = IntegritySpotChecker::from_file_bytes(data, 1000);
        let hash = checker.full_hash_hex();
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }
}
