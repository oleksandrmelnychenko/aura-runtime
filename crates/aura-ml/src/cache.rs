//! LRU inference cache for deduplicating repeated text analysis.
//!
//! Keyed on a fast non-cryptographic hash of normalized text.
//! Avoids redundant ONNX inference for identical or near-identical messages
//! (common in group chats with forwards/reactions).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::types::MlResult;

struct CacheEntry {
    result: MlResult,
    inserted_at: Instant,
    access_order: u64,
}

/// Fixed-capacity LRU cache for inference results.
pub struct InferenceCache {
    entries: HashMap<u64, CacheEntry>,
    capacity: usize,
    ttl: Duration,
    next_order: u64,
    hits: u64,
    misses: u64,
}

impl InferenceCache {
    /// Creates a new cache with the given capacity and TTL.
    pub fn new(capacity: usize, ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity: capacity.max(1),
            ttl: Duration::from_secs(ttl_secs),
            next_order: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Looks up a cached result by text hash.
    pub fn get(&mut self, text_hash: u64) -> Option<&MlResult> {
        let now = Instant::now();
        let Some(entry) = self.entries.get_mut(&text_hash) else {
            self.misses += 1;
            return None;
        };
        if now.duration_since(entry.inserted_at) > self.ttl {
            self.entries.remove(&text_hash);
            self.misses += 1;
            return None;
        }
        entry.access_order = self.next_order;
        self.next_order += 1;
        self.hits += 1;
        Some(&self.entries[&text_hash].result)
    }

    /// Inserts a result into the cache, evicting the LRU entry if at capacity.
    pub fn insert(&mut self, text_hash: u64, result: MlResult) {
        if self.entries.len() >= self.capacity {
            self.evict_lru();
        }
        self.entries.insert(
            text_hash,
            CacheEntry {
                result,
                inserted_at: Instant::now(),
                access_order: self.next_order,
            },
        );
        self.next_order += 1;
    }

    /// Returns cache hit rate as a fraction in `[0.0, 1.0]`.
    pub fn hit_rate(&self) -> f32 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f32 / total as f32
    }

    /// Returns total hits and misses.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    /// Returns the current number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_lru(&mut self) {
        let mut oldest_key = None;
        let mut oldest_order = u64::MAX;
        for (key, entry) in &self.entries {
            if entry.access_order < oldest_order {
                oldest_order = entry.access_order;
                oldest_key = Some(*key);
            }
        }
        if let Some(key) = oldest_key {
            self.entries.remove(&key);
        }
    }
}

/// Fast non-cryptographic hash for cache keying.
pub fn text_hash(text: &str) -> u64 {
    // FNV-1a 64-bit: fast, good distribution, no dependencies.
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CascadeTier, MlResult};

    fn dummy_result() -> MlResult {
        MlResult {
            toxicity: None,
            sentiment: None,
            safety: None,
            intent: None,
            inference_time_us: 42,
            tier: CascadeTier::Deep,
            cache_hit: false,
        }
    }

    #[test]
    fn insert_and_retrieve() {
        let mut cache = InferenceCache::new(16, 300);
        let hash = text_hash("hello world");
        cache.insert(hash, dummy_result());
        assert!(cache.get(hash).is_some());
    }

    #[test]
    fn miss_on_unknown_key() {
        let mut cache = InferenceCache::new(16, 300);
        assert!(cache.get(12345).is_none());
    }

    #[test]
    fn evicts_lru_at_capacity() {
        let mut cache = InferenceCache::new(2, 300);
        cache.insert(1, dummy_result());
        cache.insert(2, dummy_result());
        cache.insert(3, dummy_result());
        assert_eq!(cache.len(), 2);
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
    }

    #[test]
    fn hit_rate_tracking() {
        let mut cache = InferenceCache::new(16, 300);
        cache.insert(1, dummy_result());
        cache.get(1);
        cache.get(1);
        cache.get(999);
        let (hits, misses) = cache.stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
        assert!((cache.hit_rate() - 0.6667).abs() < 0.01);
    }

    #[test]
    fn different_texts_produce_different_hashes() {
        assert_ne!(text_hash("hello"), text_hash("world"));
        assert_ne!(text_hash("kill you"), text_hash("hug you"));
    }

    #[test]
    fn same_text_produces_same_hash() {
        assert_eq!(text_hash("test message"), text_hash("test message"));
    }
}
