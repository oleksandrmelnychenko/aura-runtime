//! Deterministic, content-free evaluation for the disabled military temporal policy.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use aura_domain::{
    DomainAction, DomainConversationType, DomainEventKind, DomainTemporalActorRole,
    DomainTemporalContext, DomainTemporalDirectionality, DomainTemporalEvent, DomainTemporalInput,
    DomainTemporalSpeechAct, DomainTemporalStance,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::temporal::{
    run_military_temporal_pipeline, run_military_temporal_shadow_pipeline, temporal_enabled,
};
use crate::temporal_shadow_telemetry::{
    TemporalShadowDeployment, TemporalShadowTelemetryCollector, TemporalShadowTelemetryError,
    TemporalShadowTelemetryReport,
};

const CORPUS_SCHEMA_VERSION: u32 = 1;
const REPORT_SCHEMA_VERSION: &str = "aura.military.temporal_shadow_report.v1";
const MIN_TOTAL_CASES: usize = 30;
const MIN_NEGATIVE_CASES: usize = 18;
const MIN_POSITIVE_CASES_PER_SIGNAL: usize = 4;
const MIN_ADVERSARIAL_VARIANTS: usize = 200;
const ADVERSARIAL_TIME_SHIFT_MS: u64 = 86_400_000;

const INFLUENCE_PRESSURE: &str = "military.temporal.influence_pressure";
const OPERATIONAL_COLLECTION: &str = "military.temporal.operational_collection_attempt";
const LINKED_DISCLOSURE: &str = "military.temporal.influence_linked_disclosure";

const REQUIRED_COVERAGE_TAGS: &[&str] = &[
    "actor_isolation",
    "counter_speech",
    "directionality",
    "future_evidence",
    "group",
    "legacy_context",
    "missing_evidence",
    "negative_control",
    "ordering",
    "positive",
    "quote_report",
    "time_window",
    "trusted_contact",
];

/// Error returned when the Shadow corpus or embedded policy is invalid.
#[derive(Debug, Error)]
pub enum TemporalShadowError {
    #[error("invalid temporal Shadow corpus JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid temporal Shadow corpus: {0}")]
    InvalidCorpus(String),
    #[error("temporal Shadow policy unavailable: {0}")]
    Policy(String),
    #[error("temporal Shadow telemetry validation failed: {0}")]
    Telemetry(#[from] TemporalShadowTelemetryError),
}

/// Stable corpus identity included in every evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowManifest {
    pub schema_version: u32,
    pub dataset_id: String,
    pub dataset_label: String,
    pub maintainer: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub corpus_sha256: String,
}

/// Label-level counts for one temporal inference class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowLabelMetrics {
    pub reason_code: String,
    pub expected_count: usize,
    pub actual_count: usize,
    pub true_positive_count: usize,
    pub false_positive_count: usize,
    pub false_negative_count: usize,
}

/// Aggregate metrics for the complete temporal Shadow corpus.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalShadowMetrics {
    pub total_cases: usize,
    pub total_events: usize,
    pub positive_cases: usize,
    pub negative_cases: usize,
    pub exact_match_cases: usize,
    pub true_positive_labels: usize,
    pub false_positive_labels: usize,
    pub false_negative_labels: usize,
    pub precision: f64,
    pub recall: f64,
    pub clean_negative_false_positive_rate: f64,
    pub exact_match_rate: f64,
    pub storage_order_mismatch_cases: usize,
    pub adversarial_variants: usize,
    pub adversarial_mismatch_variants: usize,
    pub disabled_runtime_signal_cases: usize,
    pub shadow_action_cases: usize,
    pub max_events_per_case: usize,
    pub by_signal: Vec<TemporalShadowLabelMetrics>,
    pub by_adversarial_variant: Vec<TemporalAdversarialVariantMetrics>,
}

/// Metamorphic robustness results for one adversarial transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalAdversarialVariantMetrics {
    pub variant: String,
    pub evaluated_cases: usize,
    pub mismatch_cases: usize,
}

/// One strict release-gate assertion and its observed value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowGateCheck {
    pub name: String,
    pub requirement: String,
    pub actual: String,
    pub passed: bool,
}

/// Per-case evidence retained without message text or stable actor identifiers.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalShadowCaseResult {
    pub case_id: String,
    pub tags: Vec<String>,
    pub event_count: usize,
    pub expected_reason_codes: Vec<String>,
    pub actual_reason_codes: Vec<String>,
    pub exact_match: bool,
    pub storage_order_invariant: bool,
    pub adversarial_invariant: bool,
    pub adversarial_mismatch_variants: Vec<String>,
    pub disabled_runtime_clean: bool,
    pub shadow_action: Option<DomainAction>,
}

/// Machine-readable Shadow report used by the temporal release gate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemporalShadowReport {
    pub schema_version: &'static str,
    pub overall_status: &'static str,
    pub manifest: TemporalShadowManifest,
    pub runtime_policy_enabled: bool,
    pub privacy: TemporalShadowPrivacy,
    pub metrics: TemporalShadowMetrics,
    pub coverage_tags: BTreeMap<String, usize>,
    pub gate_checks: Vec<TemporalShadowGateCheck>,
    pub cases: Vec<TemporalShadowCaseResult>,
}

/// Privacy invariants of the evaluation input and generated report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalShadowPrivacy {
    pub raw_text_present: bool,
    pub stable_actor_identifiers_present: bool,
    pub content_hashes_reported: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalShadowCorpusFile {
    schema_version: u32,
    dataset_id: String,
    dataset_label: String,
    maintainer: String,
    created_at_ms: u64,
    updated_at_ms: u64,
    cases: Vec<TemporalShadowCaseSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalShadowCaseSpec {
    id: String,
    #[serde(default)]
    tags: Vec<String>,
    as_of_ms: u64,
    current_actor_id: u32,
    current_content_hash: Option<u64>,
    #[serde(default)]
    conversation_type: DomainConversationType,
    #[serde(default)]
    expected_reason_codes: Vec<String>,
    events: Vec<TemporalShadowEventSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalShadowEventSpec {
    event_id: u64,
    timestamp_ms: u64,
    actor_id: u32,
    actor_role: DomainTemporalActorRole,
    kind: DomainEventKind,
    #[serde(default = "default_confidence")]
    confidence: f32,
    content_hash: Option<u64>,
    #[serde(default = "default_speech_act")]
    speech_act: DomainTemporalSpeechAct,
    #[serde(default = "default_stance")]
    stance: DomainTemporalStance,
    #[serde(default = "default_directionality")]
    directionality: DomainTemporalDirectionality,
    #[serde(default)]
    trusted_contact: bool,
    #[serde(default = "default_confidence")]
    context_confidence: f32,
}

pub(crate) struct TemporalReviewTarget {
    pub dataset_id: String,
    pub corpus_sha256: String,
    pub expected_labels: BTreeMap<String, BTreeSet<String>>,
    pub case_tags: BTreeMap<String, BTreeSet<String>>,
    pub cases: BTreeMap<String, DomainTemporalInput>,
}

#[derive(Default)]
struct LabelAccumulator {
    expected_count: usize,
    actual_count: usize,
    true_positive_count: usize,
    false_positive_count: usize,
    false_negative_count: usize,
}

#[derive(Default)]
struct AdversarialAccumulator {
    evaluated_cases: usize,
    mismatch_cases: usize,
}

/// Runs the embedded, versioned temporal Shadow corpus.
///
/// The evaluator enables a private copy of the policy. Runtime policy state is
/// not mutated, and the ordinary military module remains disabled.
pub fn run_embedded_temporal_shadow_report() -> Result<TemporalShadowReport, TemporalShadowError> {
    run_temporal_shadow_report(include_str!("../data/temporal_shadow_corpus.json"))
}

pub(crate) fn embedded_temporal_review_target() -> Result<TemporalReviewTarget, TemporalShadowError>
{
    temporal_review_target(include_str!("../data/temporal_shadow_corpus.json"))
}

pub(crate) fn temporal_review_target(
    raw: &str,
) -> Result<TemporalReviewTarget, TemporalShadowError> {
    let file: TemporalShadowCorpusFile = serde_json::from_str(raw)?;
    validate_corpus(&file)?;
    let expected_labels = file
        .cases
        .iter()
        .map(|case| {
            (
                case.id.clone(),
                case.expected_reason_codes.iter().cloned().collect(),
            )
        })
        .collect();
    let case_tags = file
        .cases
        .iter()
        .map(|case| (case.id.clone(), case.tags.iter().cloned().collect()))
        .collect();
    let cases = file
        .cases
        .iter()
        .map(|case| (case.id.clone(), case.to_input()))
        .collect();
    Ok(TemporalReviewTarget {
        dataset_id: file.dataset_id,
        corpus_sha256: sha256_hex(raw.as_bytes()),
        expected_labels,
        case_tags,
        cases,
    })
}

/// Parses and evaluates a content-free temporal Shadow corpus.
pub fn run_temporal_shadow_report(json: &str) -> Result<TemporalShadowReport, TemporalShadowError> {
    let file: TemporalShadowCorpusFile = serde_json::from_str(json)?;
    validate_corpus(&file)?;
    evaluate_corpus(file, json)
}

/// Runs the embedded corpus through the aggregate on-prem or ADK collector.
pub fn run_embedded_temporal_shadow_telemetry_report(
    deployment: TemporalShadowDeployment,
) -> Result<TemporalShadowTelemetryReport, TemporalShadowError> {
    let raw = include_str!("../data/temporal_shadow_corpus.json");
    let file: TemporalShadowCorpusFile = serde_json::from_str(raw)?;
    validate_corpus(&file)?;
    let window_start_ms = file
        .cases
        .iter()
        .map(|case| case.as_of_ms)
        .min()
        .ok_or_else(|| TemporalShadowError::InvalidCorpus("corpus has no cases".to_string()))?;
    let window_end_ms = file
        .cases
        .iter()
        .map(|case| case.as_of_ms)
        .max()
        .ok_or_else(|| TemporalShadowError::InvalidCorpus("corpus has no cases".to_string()))?;
    let mut collector =
        TemporalShadowTelemetryCollector::new(deployment, window_start_ms, window_end_ms)?;
    for case in &file.cases {
        collector.observe(&case.to_input())?;
    }
    collector.finish().map_err(TemporalShadowError::from)
}

fn evaluate_corpus(
    file: TemporalShadowCorpusFile,
    raw_json: &str,
) -> Result<TemporalShadowReport, TemporalShadowError> {
    let mut case_results = Vec::with_capacity(file.cases.len());
    let mut labels = known_reason_codes()
        .into_iter()
        .map(|reason_code| (reason_code.to_string(), LabelAccumulator::default()))
        .collect::<BTreeMap<_, _>>();
    let mut coverage_tags = BTreeMap::<String, usize>::new();
    let mut total_events = 0usize;
    let mut positive_cases = 0usize;
    let mut negative_cases = 0usize;
    let mut exact_match_cases = 0usize;
    let mut clean_false_positive_cases = 0usize;
    let mut storage_order_mismatch_cases = 0usize;
    let mut adversarial = BTreeMap::<String, AdversarialAccumulator>::new();
    let mut disabled_runtime_signal_cases = 0usize;
    let mut shadow_action_cases = 0usize;
    let mut max_events_per_case = 0usize;

    for case in &file.cases {
        let input = case.to_input();
        let output =
            run_military_temporal_shadow_pipeline(&input).map_err(TemporalShadowError::Policy)?;
        let mut reversed_input = input.clone();
        reversed_input.events.reverse();
        let reversed_output = run_military_temporal_shadow_pipeline(&reversed_input)
            .map_err(TemporalShadowError::Policy)?;
        let mut adversarial_mismatch_variants = Vec::new();
        record_adversarial_result(
            &mut adversarial,
            "reverse_storage",
            &output,
            &reversed_output,
            &mut adversarial_mismatch_variants,
        );
        for (variant, variant_input) in adversarial_inputs(&input) {
            let variant_output = run_military_temporal_shadow_pipeline(&variant_input)
                .map_err(TemporalShadowError::Policy)?;
            record_adversarial_result(
                &mut adversarial,
                variant,
                &output,
                &variant_output,
                &mut adversarial_mismatch_variants,
            );
        }
        let runtime_output = run_military_temporal_pipeline(&input);

        let expected = case
            .expected_reason_codes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let actual = output
            .signals
            .iter()
            .map(|signal| signal.reason_code.clone())
            .collect::<BTreeSet<_>>();

        positive_cases += usize::from(!expected.is_empty());
        negative_cases += usize::from(expected.is_empty());
        let exact_match = expected == actual;
        exact_match_cases += usize::from(exact_match);
        clean_false_positive_cases += usize::from(expected.is_empty() && !actual.is_empty());
        let storage_order_invariant = output == reversed_output;
        storage_order_mismatch_cases += usize::from(!storage_order_invariant);
        let disabled_runtime_clean =
            runtime_output.signals.is_empty() && runtime_output.action.is_none();
        disabled_runtime_signal_cases += usize::from(!disabled_runtime_clean);
        shadow_action_cases += usize::from(output.action.is_some());
        total_events += case.events.len();
        max_events_per_case = max_events_per_case.max(case.events.len());

        for reason_code in expected.union(&actual) {
            let accumulator = labels.get_mut(reason_code).ok_or_else(|| {
                TemporalShadowError::InvalidCorpus(format!(
                    "case {} produced unsupported reason code {reason_code}",
                    case.id
                ))
            })?;
            let is_expected = expected.contains(reason_code);
            let is_actual = actual.contains(reason_code);
            accumulator.expected_count += usize::from(is_expected);
            accumulator.actual_count += usize::from(is_actual);
            accumulator.true_positive_count += usize::from(is_expected && is_actual);
            accumulator.false_positive_count += usize::from(!is_expected && is_actual);
            accumulator.false_negative_count += usize::from(is_expected && !is_actual);
        }

        for tag in &case.tags {
            *coverage_tags.entry(tag.clone()).or_default() += 1;
        }

        case_results.push(TemporalShadowCaseResult {
            case_id: case.id.clone(),
            tags: case.tags.clone(),
            event_count: case.events.len(),
            expected_reason_codes: expected.into_iter().collect(),
            actual_reason_codes: actual.into_iter().collect(),
            exact_match,
            storage_order_invariant,
            adversarial_invariant: adversarial_mismatch_variants.is_empty(),
            adversarial_mismatch_variants,
            disabled_runtime_clean,
            shadow_action: output.action,
        });
    }

    let true_positive_labels = labels
        .values()
        .map(|metrics| metrics.true_positive_count)
        .sum();
    let false_positive_labels = labels
        .values()
        .map(|metrics| metrics.false_positive_count)
        .sum();
    let false_negative_labels = labels
        .values()
        .map(|metrics| metrics.false_negative_count)
        .sum();
    let precision = ratio(
        true_positive_labels,
        true_positive_labels + false_positive_labels,
    );
    let recall = ratio(
        true_positive_labels,
        true_positive_labels + false_negative_labels,
    );
    let clean_negative_false_positive_rate = ratio(clean_false_positive_cases, negative_cases);
    let exact_match_rate = ratio(exact_match_cases, file.cases.len());
    let by_signal = labels
        .into_iter()
        .map(|(reason_code, metrics)| TemporalShadowLabelMetrics {
            reason_code,
            expected_count: metrics.expected_count,
            actual_count: metrics.actual_count,
            true_positive_count: metrics.true_positive_count,
            false_positive_count: metrics.false_positive_count,
            false_negative_count: metrics.false_negative_count,
        })
        .collect::<Vec<_>>();
    let by_adversarial_variant = adversarial
        .into_iter()
        .map(|(variant, metrics)| TemporalAdversarialVariantMetrics {
            variant,
            evaluated_cases: metrics.evaluated_cases,
            mismatch_cases: metrics.mismatch_cases,
        })
        .collect::<Vec<_>>();
    let adversarial_variants = by_adversarial_variant
        .iter()
        .map(|variant| variant.evaluated_cases)
        .sum();
    let adversarial_mismatch_variants = by_adversarial_variant
        .iter()
        .map(|variant| variant.mismatch_cases)
        .sum();
    let metrics = TemporalShadowMetrics {
        total_cases: file.cases.len(),
        total_events,
        positive_cases,
        negative_cases,
        exact_match_cases,
        true_positive_labels,
        false_positive_labels,
        false_negative_labels,
        precision,
        recall,
        clean_negative_false_positive_rate,
        exact_match_rate,
        storage_order_mismatch_cases,
        adversarial_variants,
        adversarial_mismatch_variants,
        disabled_runtime_signal_cases,
        shadow_action_cases,
        max_events_per_case,
        by_signal,
        by_adversarial_variant,
    };
    let runtime_policy_enabled = temporal_enabled();
    let gate_checks = build_gate_checks(&metrics, &coverage_tags, runtime_policy_enabled);
    let overall_status = if gate_checks.iter().all(|check| check.passed) {
        "pass"
    } else {
        "fail"
    };

    Ok(TemporalShadowReport {
        schema_version: REPORT_SCHEMA_VERSION,
        overall_status,
        manifest: TemporalShadowManifest {
            schema_version: file.schema_version,
            dataset_id: file.dataset_id,
            dataset_label: file.dataset_label,
            maintainer: file.maintainer,
            created_at_ms: file.created_at_ms,
            updated_at_ms: file.updated_at_ms,
            corpus_sha256: sha256_hex(raw_json.as_bytes()),
        },
        runtime_policy_enabled,
        privacy: TemporalShadowPrivacy {
            raw_text_present: false,
            stable_actor_identifiers_present: false,
            content_hashes_reported: false,
        },
        metrics,
        coverage_tags,
        gate_checks,
        cases: case_results,
    })
}

fn build_gate_checks(
    metrics: &TemporalShadowMetrics,
    coverage_tags: &BTreeMap<String, usize>,
    runtime_policy_enabled: bool,
) -> Vec<TemporalShadowGateCheck> {
    let mut checks = vec![
        minimum_check("minimum_total_cases", metrics.total_cases, MIN_TOTAL_CASES),
        minimum_check(
            "minimum_negative_cases",
            metrics.negative_cases,
            MIN_NEGATIVE_CASES,
        ),
        exact_ratio_check("minimum_precision", metrics.precision, 1.0, true),
        exact_ratio_check("minimum_recall", metrics.recall, 1.0, true),
        exact_ratio_check(
            "maximum_clean_negative_false_positive_rate",
            metrics.clean_negative_false_positive_rate,
            0.0,
            false,
        ),
        exact_ratio_check(
            "minimum_exact_match_rate",
            metrics.exact_match_rate,
            1.0,
            true,
        ),
        zero_check(
            "storage_order_mismatch_cases",
            metrics.storage_order_mismatch_cases,
        ),
        minimum_check(
            "minimum_adversarial_variants",
            metrics.adversarial_variants,
            MIN_ADVERSARIAL_VARIANTS,
        ),
        zero_check(
            "adversarial_mismatch_variants",
            metrics.adversarial_mismatch_variants,
        ),
        zero_check(
            "disabled_runtime_signal_cases",
            metrics.disabled_runtime_signal_cases,
        ),
        zero_check("shadow_action_cases", metrics.shadow_action_cases),
        TemporalShadowGateCheck {
            name: "runtime_policy_disabled".to_string(),
            requirement: "false".to_string(),
            actual: runtime_policy_enabled.to_string(),
            passed: !runtime_policy_enabled,
        },
    ];

    for signal in &metrics.by_signal {
        checks.push(minimum_check(
            &format!("minimum_support.{}", signal.reason_code),
            signal.expected_count,
            MIN_POSITIVE_CASES_PER_SIGNAL,
        ));
    }
    for required_tag in REQUIRED_COVERAGE_TAGS {
        let count = coverage_tags
            .get(*required_tag)
            .copied()
            .unwrap_or_default();
        checks.push(minimum_check(
            &format!("required_coverage_tag.{required_tag}"),
            count,
            1,
        ));
    }
    checks
}

fn record_adversarial_result(
    accumulators: &mut BTreeMap<String, AdversarialAccumulator>,
    variant: &str,
    baseline: &aura_domain::DomainTemporalOutput,
    candidate: &aura_domain::DomainTemporalOutput,
    mismatch_variants: &mut Vec<String>,
) {
    let accumulator = accumulators.entry(variant.to_string()).or_default();
    accumulator.evaluated_cases += 1;
    if baseline != candidate {
        accumulator.mismatch_cases += 1;
        mismatch_variants.push(variant.to_string());
    }
}

fn adversarial_inputs(input: &DomainTemporalInput) -> Vec<(&'static str, DomainTemporalInput)> {
    let mut rotated = input.clone();
    if !rotated.events.is_empty() {
        let midpoint = rotated.events.len() / 2;
        rotated.events.rotate_left(midpoint);
    }

    let mut remapped_actors = input.clone();
    remapped_actors.current_actor_id = remapped_actors.current_actor_id.wrapping_add(0x4000_0000);
    for event in &mut remapped_actors.events {
        event.actor_id = event.actor_id.wrapping_add(0x4000_0000);
    }

    let mut remapped_event_ids = input.clone();
    for event in &mut remapped_event_ids.events {
        event.event_id ^= 0x8000_0000_0000_0000;
    }

    let mut shifted_time = input.clone();
    shifted_time.as_of_ms = shifted_time
        .as_of_ms
        .saturating_add(ADVERSARIAL_TIME_SHIFT_MS);
    for event in &mut shifted_time.events {
        event.timestamp_ms = event.timestamp_ms.saturating_add(ADVERSARIAL_TIME_SHIFT_MS);
    }

    let mut filtered_decoys = input.clone();
    for index in 0..4_u64 {
        filtered_decoys.events.push(DomainTemporalEvent {
            event_id: u64::MAX - index,
            timestamp_ms: input.as_of_ms,
            actor_id: input.current_actor_id.wrapping_add(0x2000_0000),
            actor_role: DomainTemporalActorRole::External,
            kind: DomainEventKind::IntelGathering,
            confidence: 0.0,
            content_hash: Some(u64::MAX - index),
            context: DomainTemporalContext {
                speech_act: DomainTemporalSpeechAct::Solicit,
                stance: DomainTemporalStance::Endorse,
                directionality: DomainTemporalDirectionality::DirectedAtUser,
                trusted_contact: false,
                confidence: 1.0,
            },
        });
    }

    let mut replayed_events = input.clone();
    replayed_events.events.extend(input.events.iter().cloned());

    vec![
        ("rotate_storage", rotated),
        ("actor_id_bijection", remapped_actors),
        ("event_id_bijection", remapped_event_ids),
        ("global_time_shift", shifted_time),
        ("filtered_decoy_injection", filtered_decoys),
        ("replay_duplication", replayed_events),
    ]
}

fn minimum_check(name: &str, actual: usize, minimum: usize) -> TemporalShadowGateCheck {
    TemporalShadowGateCheck {
        name: name.to_string(),
        requirement: format!(">={minimum}"),
        actual: actual.to_string(),
        passed: actual >= minimum,
    }
}

fn zero_check(name: &str, actual: usize) -> TemporalShadowGateCheck {
    TemporalShadowGateCheck {
        name: name.to_string(),
        requirement: "=0".to_string(),
        actual: actual.to_string(),
        passed: actual == 0,
    }
}

fn exact_ratio_check(
    name: &str,
    actual: f64,
    threshold: f64,
    minimum: bool,
) -> TemporalShadowGateCheck {
    TemporalShadowGateCheck {
        name: name.to_string(),
        requirement: if minimum {
            format!(">={threshold:.4}")
        } else {
            format!("<={threshold:.4}")
        },
        actual: format!("{actual:.4}"),
        passed: if minimum {
            actual >= threshold
        } else {
            actual <= threshold
        },
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn sha256_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(input);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn known_reason_codes() -> BTreeSet<&'static str> {
    BTreeSet::from([
        INFLUENCE_PRESSURE,
        LINKED_DISCLOSURE,
        OPERATIONAL_COLLECTION,
    ])
}

fn validate_corpus(file: &TemporalShadowCorpusFile) -> Result<(), TemporalShadowError> {
    if file.schema_version != CORPUS_SCHEMA_VERSION {
        return invalid_corpus(format!(
            "schema_version {} is unsupported; expected {CORPUS_SCHEMA_VERSION}",
            file.schema_version
        ));
    }
    if file.dataset_id.trim().is_empty()
        || file.dataset_label.trim().is_empty()
        || file.maintainer.trim().is_empty()
    {
        return invalid_corpus("dataset identity fields must not be empty");
    }
    if file.created_at_ms == 0 || file.updated_at_ms < file.created_at_ms {
        return invalid_corpus("dataset timestamps are invalid");
    }
    if file.cases.is_empty() || file.cases.len() > 10_000 {
        return invalid_corpus("case count must be within 1..=10000");
    }

    let known = known_reason_codes();
    let mut case_ids = HashSet::with_capacity(file.cases.len());
    for case in &file.cases {
        if case.id.trim().is_empty() || case.id.len() > 128 {
            return invalid_corpus("case id must be within 1..=128 bytes");
        }
        if !case_ids.insert(case.id.as_str()) {
            return invalid_corpus(format!("duplicate case id {}", case.id));
        }
        if case.tags.is_empty()
            || case
                .tags
                .iter()
                .any(|tag| tag.trim().is_empty() || tag.len() > 64)
        {
            return invalid_corpus(format!("case {} has invalid coverage tags", case.id));
        }
        let unique_tags = case.tags.iter().collect::<HashSet<_>>();
        if unique_tags.len() != case.tags.len() {
            return invalid_corpus(format!("case {} has duplicate coverage tags", case.id));
        }
        let expected = case
            .expected_reason_codes
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        if expected.len() != case.expected_reason_codes.len()
            || expected.iter().any(|reason| !known.contains(reason))
        {
            return invalid_corpus(format!(
                "case {} has duplicate or unsupported expected reason codes",
                case.id
            ));
        }
        let tagged_positive = case.tags.iter().any(|tag| tag == "positive");
        let tagged_negative = case.tags.iter().any(|tag| tag == "negative_control");
        if tagged_positive == tagged_negative || tagged_positive == expected.is_empty() {
            return invalid_corpus(format!(
                "case {} must have exactly one label tag matching its expectations",
                case.id
            ));
        }
        if case.events.is_empty() || case.events.len() > 500 {
            return invalid_corpus(format!(
                "case {} event count must be within 1..=500",
                case.id
            ));
        }
        let mut event_ids = HashSet::with_capacity(case.events.len());
        for event in &case.events {
            if !event_ids.insert(event.event_id) {
                return invalid_corpus(format!(
                    "case {} has duplicate event id {}",
                    case.id, event.event_id
                ));
            }
            if !unit_interval(event.confidence) || !unit_interval(event.context_confidence) {
                return invalid_corpus(format!("case {} has confidence outside 0..=1", case.id));
            }
        }
    }
    Ok(())
}

fn invalid_corpus<T>(message: impl Into<String>) -> Result<T, TemporalShadowError> {
    Err(TemporalShadowError::InvalidCorpus(message.into()))
}

fn unit_interval(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn default_confidence() -> f32 {
    0.9
}

fn default_speech_act() -> DomainTemporalSpeechAct {
    DomainTemporalSpeechAct::Assert
}

fn default_stance() -> DomainTemporalStance {
    DomainTemporalStance::Endorse
}

fn default_directionality() -> DomainTemporalDirectionality {
    DomainTemporalDirectionality::DirectedAtUser
}

impl TemporalShadowCaseSpec {
    fn to_input(&self) -> DomainTemporalInput {
        DomainTemporalInput {
            as_of_ms: self.as_of_ms,
            current_actor_id: self.current_actor_id,
            current_content_hash: self.current_content_hash,
            conversation_type: self.conversation_type,
            events: self
                .events
                .iter()
                .map(TemporalShadowEventSpec::to_event)
                .collect(),
        }
    }
}

impl TemporalShadowEventSpec {
    fn to_event(&self) -> DomainTemporalEvent {
        DomainTemporalEvent {
            event_id: self.event_id,
            timestamp_ms: self.timestamp_ms,
            actor_id: self.actor_id,
            actor_role: self.actor_role,
            kind: self.kind,
            confidence: self.confidence,
            content_hash: self.content_hash,
            context: DomainTemporalContext {
                speech_act: self.speech_act,
                stance: self.stance,
                directionality: self.directionality,
                trusted_contact: self.trusted_contact,
                confidence: self.context_confidence,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_temporal_shadow_report_passes_strict_gates() {
        let report = run_embedded_temporal_shadow_report().expect("valid embedded Shadow corpus");

        assert_eq!(report.overall_status, "pass");
    }

    #[test]
    fn embedded_temporal_shadow_report_is_deterministic() {
        let first = run_embedded_temporal_shadow_report().expect("first Shadow report");
        let second = run_embedded_temporal_shadow_report().expect("second Shadow report");

        assert_eq!(first, second);
    }

    #[test]
    fn embedded_temporal_shadow_corpus_contains_no_message_text_fields() {
        let raw = include_str!("../data/temporal_shadow_corpus.json");

        assert!(!raw.contains("\"text\"") && !raw.contains("sender_id"));
    }

    #[test]
    fn corpus_parser_rejects_unknown_schema() {
        let raw = include_str!("../data/temporal_shadow_corpus.json").replacen(
            "\"schema_version\": 1",
            "\"schema_version\": 99",
            1,
        );

        let error = run_temporal_shadow_report(&raw).expect_err("unsupported schema");

        assert!(error.to_string().contains("schema_version 99"));
    }

    #[test]
    fn gate_fails_when_expected_signal_is_removed() {
        let raw = include_str!("../data/temporal_shadow_corpus.json");
        let mut file: TemporalShadowCorpusFile = serde_json::from_str(raw).expect("corpus JSON");
        let positive = file
            .cases
            .iter_mut()
            .find(|case| !case.expected_reason_codes.is_empty())
            .expect("positive case");
        positive.expected_reason_codes.clear();

        let report = evaluate_corpus(file, raw).expect("evaluation remains valid");

        assert_eq!(report.overall_status, "fail");
    }

    #[test]
    fn embedded_corpus_validates_on_prem_shadow_telemetry() {
        let report =
            run_embedded_temporal_shadow_telemetry_report(TemporalShadowDeployment::OnPrem)
                .expect("on-prem aggregate telemetry");

        assert_eq!(report.overall_status, "pass");
    }

    #[test]
    fn embedded_corpus_validates_adk_shadow_telemetry() {
        let report = run_embedded_temporal_shadow_telemetry_report(TemporalShadowDeployment::Adk)
            .expect("ADK aggregate telemetry");

        assert_eq!(report.overall_status, "pass");
    }
}
