//! Privacy-preserving aggregate telemetry for the disabled temporal policy.

use std::collections::BTreeMap;
use std::time::Instant;

use aura_domain::DomainTemporalInput;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::temporal::{run_military_temporal_shadow_pipeline, temporal_enabled};

const INPUT_SCHEMA_VERSION: &str = "aura.military.temporal_shadow_input.v1";
const REPORT_SCHEMA_VERSION: &str = "aura.military.temporal_shadow_telemetry.v1";
const MIN_AGGREGATED_INPUTS: usize = 20;
const MAX_AGGREGATED_INPUTS: usize = 100_000;
const MAX_EVENTS_PER_INPUT: usize = 500;
const MIN_WINDOW_MS: u64 = 3_600_000;
const MAX_WINDOW_MS: u64 = 31 * 86_400_000;
const LATENCY_BUCKET_UPPER_US: [u64; 8] = [100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000];

const INFLUENCE_PRESSURE: &str = "military.temporal.influence_pressure";
const OPERATIONAL_COLLECTION: &str = "military.temporal.operational_collection_attempt";
const LINKED_DISCLOSURE: &str = "military.temporal.influence_linked_disclosure";

/// Supported host environments for aggregate temporal Shadow telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalShadowDeployment {
    OnPrem,
    Adk,
}

/// Error returned when a telemetry batch is unsafe or cannot be evaluated.
#[derive(Debug, Error)]
pub enum TemporalShadowTelemetryError {
    #[error("invalid temporal Shadow telemetry JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid temporal Shadow telemetry input: {0}")]
    InvalidInput(String),
    #[error("temporal Shadow policy unavailable: {0}")]
    Policy(String),
    #[error(
        "at least {minimum} observations are required before aggregate telemetry can be exported; observed {actual}"
    )]
    InsufficientAggregation { minimum: usize, actual: usize },
}

/// Count for one non-content temporal reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowSignalCount {
    pub reason_code: String,
    pub count: u64,
}

/// One coarse latency bucket. Individual timings are never exported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowLatencyBucket {
    pub upper_bound_us: Option<u64>,
    pub count: u64,
}

/// Aggregate Shadow observations for one bounded reporting period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowTelemetryMetrics {
    pub evaluated_inputs: u64,
    pub total_source_events: u64,
    pub inputs_with_signals: u64,
    pub inputs_without_signals: u64,
    pub emitted_signals: u64,
    pub multi_signal_inputs: u64,
    pub suppressed_actions: u64,
    pub max_events_per_input: usize,
    pub signals: Vec<TemporalShadowSignalCount>,
    pub latency_histogram: Vec<TemporalShadowLatencyBucket>,
}

/// Explicit privacy claims of the aggregate report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowTelemetryPrivacy {
    pub raw_text_collected: bool,
    pub actor_identifiers_collected: bool,
    pub content_hashes_collected: bool,
    pub event_timestamps_exported: bool,
    pub per_conversation_records_exported: bool,
    pub minimum_aggregation_inputs: usize,
}

/// Privacy-safe report pulled by an on-prem or ADK host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowTelemetryReport {
    pub schema_version: &'static str,
    pub overall_status: &'static str,
    pub deployment: TemporalShadowDeployment,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub runtime_policy_enabled: bool,
    pub action_execution_enabled: bool,
    pub metrics: TemporalShadowTelemetryMetrics,
    pub privacy: TemporalShadowTelemetryPrivacy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalShadowTelemetryBatch {
    schema_version: String,
    deployment: TemporalShadowDeployment,
    window_start_ms: u64,
    window_end_ms: u64,
    inputs: Vec<DomainTemporalInput>,
}

/// Bounded aggregate collector that never stores an input or per-conversation record.
pub struct TemporalShadowTelemetryCollector {
    deployment: TemporalShadowDeployment,
    window_start_ms: u64,
    window_end_ms: u64,
    evaluated_inputs: u64,
    total_source_events: u64,
    inputs_with_signals: u64,
    emitted_signals: u64,
    multi_signal_inputs: u64,
    suppressed_actions: u64,
    max_events_per_input: usize,
    signals: BTreeMap<&'static str, u64>,
    latency_histogram: [u64; LATENCY_BUCKET_UPPER_US.len() + 1],
}

impl TemporalShadowTelemetryCollector {
    /// Creates a collector for one reporting period.
    pub fn new(
        deployment: TemporalShadowDeployment,
        window_start_ms: u64,
        window_end_ms: u64,
    ) -> Result<Self, TemporalShadowTelemetryError> {
        validate_window(window_start_ms, window_end_ms)?;
        Ok(Self {
            deployment,
            window_start_ms,
            window_end_ms,
            evaluated_inputs: 0,
            total_source_events: 0,
            inputs_with_signals: 0,
            emitted_signals: 0,
            multi_signal_inputs: 0,
            suppressed_actions: 0,
            max_events_per_input: 0,
            signals: BTreeMap::from([
                (INFLUENCE_PRESSURE, 0),
                (LINKED_DISCLOSURE, 0),
                (OPERATIONAL_COLLECTION, 0),
            ]),
            latency_histogram: [0; LATENCY_BUCKET_UPPER_US.len() + 1],
        })
    }

    /// Evaluates one content-free input in Shadow mode and retains only counters.
    pub fn observe(
        &mut self,
        input: &DomainTemporalInput,
    ) -> Result<(), TemporalShadowTelemetryError> {
        validate_input(input, self.window_start_ms, self.window_end_ms)?;
        if self.evaluated_inputs >= MAX_AGGREGATED_INPUTS as u64 {
            return invalid_input(format!(
                "collector exceeds {MAX_AGGREGATED_INPUTS} observations"
            ));
        }
        let started = Instant::now();
        let output = run_military_temporal_shadow_pipeline(input)
            .map_err(TemporalShadowTelemetryError::Policy)?;
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.record_observation(input, output, elapsed_us)
    }

    /// Produces a report only after the privacy aggregation threshold is reached.
    pub fn finish(self) -> Result<TemporalShadowTelemetryReport, TemporalShadowTelemetryError> {
        let actual = usize::try_from(self.evaluated_inputs).unwrap_or(usize::MAX);
        if actual < MIN_AGGREGATED_INPUTS {
            return Err(TemporalShadowTelemetryError::InsufficientAggregation {
                minimum: MIN_AGGREGATED_INPUTS,
                actual,
            });
        }
        let runtime_policy_enabled = temporal_enabled();
        let overall_status = if !runtime_policy_enabled && self.suppressed_actions == 0 {
            "pass"
        } else {
            "fail"
        };
        let inputs_without_signals = self
            .evaluated_inputs
            .saturating_sub(self.inputs_with_signals);
        let signals = self
            .signals
            .into_iter()
            .map(|(reason_code, count)| TemporalShadowSignalCount {
                reason_code: reason_code.to_string(),
                count,
            })
            .collect();
        let latency_histogram = self
            .latency_histogram
            .into_iter()
            .enumerate()
            .map(|(index, count)| TemporalShadowLatencyBucket {
                upper_bound_us: LATENCY_BUCKET_UPPER_US.get(index).copied(),
                count,
            })
            .collect();

        Ok(TemporalShadowTelemetryReport {
            schema_version: REPORT_SCHEMA_VERSION,
            overall_status,
            deployment: self.deployment,
            window_start_ms: self.window_start_ms,
            window_end_ms: self.window_end_ms,
            runtime_policy_enabled,
            action_execution_enabled: false,
            metrics: TemporalShadowTelemetryMetrics {
                evaluated_inputs: self.evaluated_inputs,
                total_source_events: self.total_source_events,
                inputs_with_signals: self.inputs_with_signals,
                inputs_without_signals,
                emitted_signals: self.emitted_signals,
                multi_signal_inputs: self.multi_signal_inputs,
                suppressed_actions: self.suppressed_actions,
                max_events_per_input: self.max_events_per_input,
                signals,
                latency_histogram,
            },
            privacy: TemporalShadowTelemetryPrivacy {
                raw_text_collected: false,
                actor_identifiers_collected: false,
                content_hashes_collected: false,
                event_timestamps_exported: false,
                per_conversation_records_exported: false,
                minimum_aggregation_inputs: MIN_AGGREGATED_INPUTS,
            },
        })
    }

    fn record_observation(
        &mut self,
        input: &DomainTemporalInput,
        output: aura_domain::DomainTemporalOutput,
        elapsed_us: u64,
    ) -> Result<(), TemporalShadowTelemetryError> {
        for signal in &output.signals {
            let Some(count) = self.signals.get_mut(signal.reason_code.as_str()) else {
                return invalid_input(format!(
                    "Shadow policy emitted unsupported reason code {}",
                    signal.reason_code
                ));
            };
            *count = count.saturating_add(1);
        }
        self.evaluated_inputs = self.evaluated_inputs.saturating_add(1);
        self.total_source_events = self
            .total_source_events
            .saturating_add(input.events.len() as u64);
        self.inputs_with_signals = self
            .inputs_with_signals
            .saturating_add(u64::from(!output.signals.is_empty()));
        self.emitted_signals = self
            .emitted_signals
            .saturating_add(output.signals.len() as u64);
        self.multi_signal_inputs = self
            .multi_signal_inputs
            .saturating_add(u64::from(output.signals.len() > 1));
        self.suppressed_actions = self
            .suppressed_actions
            .saturating_add(u64::from(output.action.is_some()));
        self.max_events_per_input = self.max_events_per_input.max(input.events.len());
        let latency_bucket = LATENCY_BUCKET_UPPER_US
            .iter()
            .position(|upper| elapsed_us <= *upper)
            .unwrap_or(LATENCY_BUCKET_UPPER_US.len());
        self.latency_histogram[latency_bucket] =
            self.latency_histogram[latency_bucket].saturating_add(1);
        Ok(())
    }
}

/// Evaluates an on-prem or ADK JSON batch and returns only aggregate telemetry.
pub fn evaluate_temporal_shadow_telemetry_batch(
    json: &str,
) -> Result<TemporalShadowTelemetryReport, TemporalShadowTelemetryError> {
    let batch: TemporalShadowTelemetryBatch = serde_json::from_str(json)?;
    if batch.schema_version != INPUT_SCHEMA_VERSION {
        return invalid_input(format!(
            "schema_version {} is unsupported; expected {INPUT_SCHEMA_VERSION}",
            batch.schema_version
        ));
    }
    if !(MIN_AGGREGATED_INPUTS..=MAX_AGGREGATED_INPUTS).contains(&batch.inputs.len()) {
        return invalid_input(format!(
            "batch input count must be within {MIN_AGGREGATED_INPUTS}..={MAX_AGGREGATED_INPUTS}"
        ));
    }
    let mut collector = TemporalShadowTelemetryCollector::new(
        batch.deployment,
        batch.window_start_ms,
        batch.window_end_ms,
    )?;
    for input in &batch.inputs {
        collector.observe(input)?;
    }
    collector.finish()
}

fn validate_window(start_ms: u64, end_ms: u64) -> Result<(), TemporalShadowTelemetryError> {
    let Some(duration_ms) = end_ms.checked_sub(start_ms) else {
        return invalid_input("reporting window end precedes its start");
    };
    if !(MIN_WINDOW_MS..=MAX_WINDOW_MS).contains(&duration_ms) {
        return invalid_input(format!(
            "reporting window must be within {MIN_WINDOW_MS}..={MAX_WINDOW_MS} ms"
        ));
    }
    Ok(())
}

fn validate_input(
    input: &DomainTemporalInput,
    window_start_ms: u64,
    window_end_ms: u64,
) -> Result<(), TemporalShadowTelemetryError> {
    if input.as_of_ms < window_start_ms || input.as_of_ms > window_end_ms {
        return invalid_input("input as_of_ms is outside the reporting window");
    }
    if input.events.is_empty() || input.events.len() > MAX_EVENTS_PER_INPUT {
        return invalid_input(format!(
            "input event count must be within 1..={MAX_EVENTS_PER_INPUT}"
        ));
    }
    if input.events.iter().any(|event| {
        !event.confidence.is_finite()
            || !(0.0..=1.0).contains(&event.confidence)
            || !event.context.confidence.is_finite()
            || !(0.0..=1.0).contains(&event.context.confidence)
    }) {
        return invalid_input("input contains confidence outside 0..=1");
    }
    Ok(())
}

fn invalid_input<T>(message: impl Into<String>) -> Result<T, TemporalShadowTelemetryError> {
    Err(TemporalShadowTelemetryError::InvalidInput(message.into()))
}

#[cfg(test)]
mod tests {
    use aura_domain::{
        DomainConversationType, DomainEventKind, DomainTemporalActorRole, DomainTemporalContext,
        DomainTemporalDirectionality, DomainTemporalEvent, DomainTemporalSpeechAct,
        DomainTemporalStance,
    };

    use super::*;

    const WINDOW_START_MS: u64 = 1_000_000;
    const WINDOW_END_MS: u64 = WINDOW_START_MS + MIN_WINDOW_MS;

    fn clean_input(index: u64) -> DomainTemporalInput {
        let as_of_ms = WINDOW_START_MS + 1_000 + index;
        DomainTemporalInput {
            as_of_ms,
            current_actor_id: 7,
            current_content_hash: Some(index + 1),
            conversation_type: DomainConversationType::Direct,
            events: vec![DomainTemporalEvent {
                event_id: index + 1,
                timestamp_ms: as_of_ms,
                actor_id: 7,
                actor_role: DomainTemporalActorRole::External,
                kind: DomainEventKind::SuspiciousSource,
                confidence: 0.9,
                content_hash: Some(index + 1),
                context: DomainTemporalContext {
                    speech_act: DomainTemporalSpeechAct::Assert,
                    stance: DomainTemporalStance::Endorse,
                    directionality: DomainTemporalDirectionality::DirectedAtUser,
                    trusted_contact: false,
                    confidence: 0.9,
                },
            }],
        }
    }

    #[test]
    fn collector_exports_only_after_minimum_aggregation() {
        let mut collector = TemporalShadowTelemetryCollector::new(
            TemporalShadowDeployment::OnPrem,
            WINDOW_START_MS,
            WINDOW_END_MS,
        )
        .expect("valid window");
        for index in 0..MIN_AGGREGATED_INPUTS as u64 {
            collector.observe(&clean_input(index)).expect("clean input");
        }

        let report = collector.finish().expect("aggregate report");

        assert_eq!(
            report.metrics.evaluated_inputs,
            MIN_AGGREGATED_INPUTS as u64
        );
    }

    #[test]
    fn collector_rejects_export_below_privacy_threshold() {
        let collector = TemporalShadowTelemetryCollector::new(
            TemporalShadowDeployment::Adk,
            WINDOW_START_MS,
            WINDOW_END_MS,
        )
        .expect("valid window");

        let error = collector.finish().expect_err("insufficient aggregation");

        assert!(matches!(
            error,
            TemporalShadowTelemetryError::InsufficientAggregation { .. }
        ));
    }

    #[test]
    fn aggregate_report_contains_no_input_identifiers_or_hashes() {
        let mut collector = TemporalShadowTelemetryCollector::new(
            TemporalShadowDeployment::OnPrem,
            WINDOW_START_MS,
            WINDOW_END_MS,
        )
        .expect("valid window");
        for index in 0..MIN_AGGREGATED_INPUTS as u64 {
            collector.observe(&clean_input(index)).expect("clean input");
        }
        let report = collector.finish().expect("aggregate report");
        let json = serde_json::to_value(&report).expect("report JSON");

        assert!(!contains_forbidden_key(&json));
    }

    #[test]
    fn aggregate_report_keeps_runtime_actions_disabled() {
        let mut collector = TemporalShadowTelemetryCollector::new(
            TemporalShadowDeployment::Adk,
            WINDOW_START_MS,
            WINDOW_END_MS,
        )
        .expect("valid window");
        for index in 0..MIN_AGGREGATED_INPUTS as u64 {
            collector.observe(&clean_input(index)).expect("clean input");
        }

        let report = collector.finish().expect("aggregate report");

        assert!(!report.runtime_policy_enabled && !report.action_execution_enabled);
    }

    fn contains_forbidden_key(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "current_actor_id" | "actor_id" | "content_hash" | "event_id" | "timestamp_ms"
                ) || contains_forbidden_key(value)
            }),
            serde_json::Value::Array(values) => values.iter().any(contains_forbidden_key),
            _ => false,
        }
    }
}
