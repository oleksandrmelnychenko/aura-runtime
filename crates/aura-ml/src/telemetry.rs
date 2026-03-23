//! Fixed-size ring buffer for inference telemetry.
//!
//! Tracks latency, backend usage, cache hit rates, and cascade tier
//! distribution without heap allocation per event.

use serde::{Deserialize, Serialize};

use crate::types::CascadeTier;

const RING_SIZE: usize = 1024;

/// A single inference telemetry event.
#[derive(Debug, Clone, Copy)]
struct InferenceEvent {
    timestamp_ms: u64,
    latency_us: u32,
    tier: CascadeTier,
    cache_hit: bool,
    toxicity_score: f32,
    safety_score: f32,
}

impl Default for InferenceEvent {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            latency_us: 0,
            tier: CascadeTier::Gate,
            cache_hit: false,
            toxicity_score: 0.0,
            safety_score: 0.0,
        }
    }
}

/// Ring buffer for inference telemetry. Fixed 16KB, never allocates.
const HISTOGRAM_BUCKETS: [u32; 12] = [
    10, 50, 100, 500, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 500_000, 1_000_000,
];

pub struct InferenceTelemetry {
    ring: Box<[InferenceEvent; RING_SIZE]>,
    write_pos: usize,
    total_events: u64,
    latency_histogram: [u64; 13],
    gate_count: u64,
    deep_count: u64,
    cached_count: u64,
    cache_hit_count: u64,
}

impl InferenceTelemetry {
    /// Creates a new empty telemetry buffer.
    pub fn new() -> Self {
        Self {
            ring: Box::new([InferenceEvent::default(); RING_SIZE]),
            write_pos: 0,
            total_events: 0,
            latency_histogram: [0; 13],
            gate_count: 0,
            deep_count: 0,
            cached_count: 0,
            cache_hit_count: 0,
        }
    }

    /// Records an inference event.
    pub fn record(
        &mut self,
        timestamp_ms: u64,
        latency_us: u32,
        tier: CascadeTier,
        cache_hit: bool,
        toxicity_score: f32,
        safety_score: f32,
    ) {
        self.ring[self.write_pos] = InferenceEvent {
            timestamp_ms,
            latency_us,
            tier,
            cache_hit,
            toxicity_score,
            safety_score,
        };
        self.write_pos = (self.write_pos + 1) % RING_SIZE;
        self.total_events += 1;

        let bucket = histogram_bucket(latency_us);
        self.latency_histogram[bucket] += 1;

        match tier {
            CascadeTier::Gate => self.gate_count += 1,
            CascadeTier::Deep => self.deep_count += 1,
            CascadeTier::Cached => self.cached_count += 1,
        }
        if cache_hit {
            self.cache_hit_count += 1;
        }
    }

    /// Computes a summary of the telemetry data.
    pub fn summary(&self) -> TelemetrySummary {
        if self.total_events == 0 {
            return TelemetrySummary::default();
        }

        let p50 = percentile_from_histogram(&self.latency_histogram, self.total_events, 0.50);
        let p95 = percentile_from_histogram(&self.latency_histogram, self.total_events, 0.95);
        let p99 = percentile_from_histogram(&self.latency_histogram, self.total_events, 0.99);

        TelemetrySummary {
            total_inferences: self.total_events,
            gate_inferences: self.gate_count,
            deep_inferences: self.deep_count,
            cached_inferences: self.cached_count,
            cache_hits: self.cache_hit_count,
            cache_hit_rate: self.cache_hit_count as f32 / self.total_events as f32,
            p50_latency_us: p50,
            p95_latency_us: p95,
            p99_latency_us: p99,
            deep_model_rate: self.deep_count as f32 / self.total_events as f32,
            fallback_rate: self.gate_count as f32 / self.total_events as f32,
        }
    }

    /// Returns the total number of events recorded (including overwritten).
    pub fn total_events(&self) -> u64 {
        self.total_events
    }
}

fn histogram_bucket(latency_us: u32) -> usize {
    for (i, &boundary) in HISTOGRAM_BUCKETS.iter().enumerate() {
        if latency_us <= boundary {
            return i;
        }
    }
    HISTOGRAM_BUCKETS.len()
}

fn percentile_from_histogram(histogram: &[u64; 13], total: u64, percentile: f64) -> u32 {
    let target = (total as f64 * percentile) as u64;
    let mut cumulative = 0u64;
    for (i, &count) in histogram.iter().enumerate() {
        cumulative += count;
        if cumulative >= target {
            if i < HISTOGRAM_BUCKETS.len() {
                return HISTOGRAM_BUCKETS[i];
            }
            return HISTOGRAM_BUCKETS[HISTOGRAM_BUCKETS.len() - 1];
        }
    }
    HISTOGRAM_BUCKETS[HISTOGRAM_BUCKETS.len() - 1]
}

impl Default for InferenceTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated telemetry summary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetrySummary {
    pub total_inferences: u64,
    pub gate_inferences: u64,
    pub deep_inferences: u64,
    pub cached_inferences: u64,
    pub cache_hits: u64,
    pub cache_hit_rate: f32,
    pub p50_latency_us: u32,
    pub p95_latency_us: u32,
    pub p99_latency_us: u32,
    pub deep_model_rate: f32,
    pub fallback_rate: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_summary_is_default() {
        let telemetry = InferenceTelemetry::new();
        let summary = telemetry.summary();
        assert_eq!(summary.total_inferences, 0);
    }

    #[test]
    fn records_and_summarizes() {
        let mut telemetry = InferenceTelemetry::new();
        for i in 0..100 {
            telemetry.record(
                i * 1000,
                (i as u32 + 1) * 100,
                CascadeTier::Gate,
                false,
                0.1,
                0.0,
            );
        }
        let summary = telemetry.summary();
        assert_eq!(summary.total_inferences, 100);
        assert_eq!(summary.gate_inferences, 100);
        assert!(summary.p50_latency_us > 0);
        assert!(summary.p95_latency_us > summary.p50_latency_us);
    }

    #[test]
    fn tracks_tier_distribution() {
        let mut telemetry = InferenceTelemetry::new();
        for _ in 0..70 {
            telemetry.record(0, 100, CascadeTier::Gate, false, 0.0, 0.0);
        }
        for _ in 0..30 {
            telemetry.record(0, 5000, CascadeTier::Deep, false, 0.8, 0.5);
        }
        let summary = telemetry.summary();
        assert_eq!(summary.gate_inferences, 70);
        assert_eq!(summary.deep_inferences, 30);
        assert!((summary.deep_model_rate - 0.30).abs() < 0.01);
    }

    #[test]
    fn cache_hit_tracking() {
        let mut telemetry = InferenceTelemetry::new();
        telemetry.record(0, 10, CascadeTier::Cached, true, 0.0, 0.0);
        telemetry.record(0, 5000, CascadeTier::Deep, false, 0.5, 0.0);
        let summary = telemetry.summary();
        assert_eq!(summary.cache_hits, 1);
        assert!((summary.cache_hit_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn ring_buffer_wraps() {
        let mut telemetry = InferenceTelemetry::new();
        for i in 0..2000u64 {
            telemetry.record(i, i as u32, CascadeTier::Gate, false, 0.0, 0.0);
        }
        assert_eq!(telemetry.total_events(), 2000);
        let summary = telemetry.summary();
        assert_eq!(summary.total_inferences, 2000);
        // Summary should be based on last 1024 events
        assert!(summary.p50_latency_us >= 1000);
    }
}
