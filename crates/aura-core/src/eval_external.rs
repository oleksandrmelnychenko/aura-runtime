use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use aura_patterns::PatternDatabase;
use serde::Deserialize;

use crate::{
    canonical_policy_action_expectations, evaluate_policy_action_gates,
    evaluate_scenario_quality_gates, pre_release_policy_action_gates, run_scenario_case,
    summarize_policy_actions_with_expectation_names, summarize_scenario_runs, AccountType,
    AuraConfig, ContentType, ConversationType, MessageInput, PolicyActionQualityGates,
    PolicyActionSummary, ProtectionLevel, ScenarioCase, ScenarioEvaluationSummary,
    ScenarioGateReport, ScenarioQualityGates, ScenarioRunResult, ScenarioStep, ThreatType,
};

const MIN_EXTERNAL_SLICE_CALIBRATION_EXAMPLES: usize = 12;
const MIN_EXTERNAL_SLICE_LEAD_TIME_CASES: usize = 8;
const EXTERNAL_CURATED_SCHEMA_VERSION: u32 = 1;
const EXTERNAL_CURATED_SEED_REVIEWED: &str = "seed_reviewed";
const EXTERNAL_CURATED_GOLD_REVIEWED: &str = "gold_reviewed";
const EXTERNAL_CURATED_MIXED_REVIEW_TIERS: &str = "mixed_review_tiers";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCuratedManifest {
    pub schema_version: u32,
    pub dataset_id: String,
    pub dataset_label: String,
    pub curation_status: String,
    pub maintainer: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ExternalCuratedBundle {
    pub manifest: ExternalCuratedManifest,
    pub scenarios: Vec<ExternalCuratedScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCuratedMetadata {
    pub scenario_name: String,
    pub source_family: String,
    pub review_status: String,
    pub default_language: String,
    pub age_band: String,
    pub relationship: String,
    pub policy_expectation_case: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExternalCuratedScenario {
    pub metadata: ExternalCuratedMetadata,
    pub case: ScenarioCase,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExternalCuratedSliceSummary {
    pub slice_id: String,
    pub case_count: usize,
    pub scenario_names: Vec<String>,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
}

#[derive(Debug, Clone)]
pub struct ExternalCuratedSuiteSummary {
    pub manifest: ExternalCuratedManifest,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
    pub by_source_family: Vec<ExternalCuratedSliceSummary>,
    pub by_review_status: Vec<ExternalCuratedSliceSummary>,
    pub by_language: Vec<ExternalCuratedSliceSummary>,
    pub by_relationship: Vec<ExternalCuratedSliceSummary>,
    pub by_age_band: Vec<ExternalCuratedSliceSummary>,
    pub scenarios: Vec<ExternalCuratedMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalCuratedFile {
    schema_version: u32,
    dataset_id: String,
    dataset_label: String,
    curation_status: String,
    maintainer: String,
    created_at_ms: u64,
    updated_at_ms: u64,
    cases: Vec<ExternalCuratedCaseSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalCuratedCaseSpec {
    id: String,
    source_family: String,
    review_status: String,
    default_language: String,
    age_band: String,
    relationship: String,
    #[serde(default)]
    conversation_type: ConversationType,
    #[serde(default = "default_external_detection_threshold")]
    detection_threshold: f32,
    #[serde(default)]
    primary_threat: Option<ThreatType>,
    #[serde(default)]
    onset_step: Option<usize>,
    #[serde(default)]
    tracked_threats: Vec<ThreatType>,
    #[serde(default = "default_external_step_interval_ms")]
    step_interval_ms: u64,
    #[serde(default = "default_external_account_type")]
    account_type: AccountType,
    #[serde(default = "default_external_protection_level")]
    protection_level: ProtectionLevel,
    #[serde(default)]
    policy_expectation_case: Option<String>,
    messages: Vec<ExternalCuratedMessageSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalCuratedMessageSpec {
    text: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    observed_threats: Vec<ThreatType>,
}

pub fn external_curated_chat_scenarios() -> Vec<ExternalCuratedScenario> {
    external_curated_bundle().scenarios
}

pub fn external_curated_bundle() -> ExternalCuratedBundle {
    let file = external_curated_chat_file();
    build_external_curated_bundle(file)
}

pub fn parse_external_curated_bundle(json: &str) -> Result<ExternalCuratedBundle, String> {
    let file = serde_json::from_str::<ExternalCuratedFile>(json)
        .map_err(|err| format!("invalid external curated corpus json: {err}"))?;
    validate_external_curated_file(&file)?;
    Ok(build_external_curated_bundle(&file))
}

pub fn parse_external_curated_chat_scenarios(
    json: &str,
) -> Result<Vec<ExternalCuratedScenario>, String> {
    Ok(parse_external_curated_bundle(json)?.scenarios)
}

pub fn pre_release_external_curated_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.30),
        max_expected_calibration_error: Some(0.30),
        min_positive_detection_rate: Some(0.80),
        max_negative_false_positive_rate: Some(0.05),
        min_pre_onset_detection_rate: Some(0.20),
        per_threat: Vec::new(),
    }
}

pub fn pre_release_external_curated_gold_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.20),
        max_expected_calibration_error: Some(0.15),
        min_positive_detection_rate: Some(0.90),
        max_negative_false_positive_rate: Some(0.03),
        min_pre_onset_detection_rate: Some(0.30),
        per_threat: Vec::new(),
    }
}

pub fn pre_release_external_curated_gates_for_manifest(
    manifest: &ExternalCuratedManifest,
) -> ScenarioQualityGates {
    match manifest.curation_status.as_str() {
        EXTERNAL_CURATED_GOLD_REVIEWED => merge_stricter_quality_gates(
            &pre_release_external_curated_gates(),
            &pre_release_external_curated_gold_gates(),
        ),
        _ => pre_release_external_curated_gates(),
    }
}

pub fn pre_release_external_curated_policy_gates() -> PolicyActionQualityGates {
    pre_release_policy_action_gates()
}

pub fn run_external_curated_suite(
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> ExternalCuratedSuiteSummary {
    let bundle = external_curated_bundle();
    run_external_curated_suite_for_bundle(&bundle, pattern_db, bin_count)
}

pub fn external_curated_gold_bundle() -> ExternalCuratedBundle {
    let bundle = external_curated_bundle();
    filter_external_curated_bundle_by_review_status(&bundle, EXTERNAL_CURATED_GOLD_REVIEWED)
        .expect("builtin external curated corpus contains gold-reviewed cases")
}

pub fn run_external_curated_gold_suite(
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> ExternalCuratedSuiteSummary {
    let bundle = external_curated_gold_bundle();
    run_external_curated_suite_for_bundle(&bundle, pattern_db, bin_count)
}

pub fn run_external_curated_suite_for_bundle(
    bundle: &ExternalCuratedBundle,
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> ExternalCuratedSuiteSummary {
    run_external_curated_suite_for_scenarios(
        &bundle.manifest,
        &bundle.scenarios,
        pattern_db,
        bin_count,
    )
}

pub fn run_external_curated_suite_for_scenarios(
    manifest: &ExternalCuratedManifest,
    scenarios: &[ExternalCuratedScenario],
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> ExternalCuratedSuiteSummary {
    let runs: Vec<_> = scenarios
        .iter()
        .map(|scenario| run_scenario_case(pattern_db, &scenario.case))
        .collect();
    let expectations = canonical_policy_action_expectations();
    let expected_policy_cases = expectations
        .iter()
        .map(|expectation| expectation.scenario_name.as_str())
        .collect::<BTreeSet<_>>();

    let overall_policy_indices = scenarios
        .iter()
        .enumerate()
        .filter_map(|(idx, scenario)| {
            scenario
                .metadata
                .policy_expectation_case
                .as_ref()
                .filter(|case| expected_policy_cases.contains(case.as_str()))
                .map(|_| idx)
        })
        .collect::<Vec<_>>();

    let overall_policy_runs = overall_policy_indices
        .iter()
        .map(|idx| runs[*idx].clone())
        .collect::<Vec<_>>();
    let overall_expectation_names = overall_policy_indices
        .iter()
        .map(|idx| {
            scenarios[*idx]
                .metadata
                .policy_expectation_case
                .clone()
                .expect("validated policy expectation")
        })
        .collect::<Vec<_>>();

    ExternalCuratedSuiteSummary {
        manifest: manifest.clone(),
        evaluation: summarize_scenario_runs(&runs, bin_count),
        policy: summarize_policy_actions_with_expectation_names(
            &overall_policy_runs,
            &overall_expectation_names,
            &expectations,
        ),
        by_source_family: summarize_external_slices(
            scenarios,
            &runs,
            &expectations,
            |metadata| metadata.source_family.clone(),
            bin_count,
        ),
        by_review_status: summarize_external_slices(
            scenarios,
            &runs,
            &expectations,
            |metadata| metadata.review_status.clone(),
            bin_count,
        ),
        by_language: summarize_external_slices(
            scenarios,
            &runs,
            &expectations,
            |metadata| metadata.default_language.clone(),
            bin_count,
        ),
        by_relationship: summarize_external_slices(
            scenarios,
            &runs,
            &expectations,
            |metadata| metadata.relationship.clone(),
            bin_count,
        ),
        by_age_band: summarize_external_slices(
            scenarios,
            &runs,
            &expectations,
            |metadata| metadata.age_band.clone(),
            bin_count,
        ),
        scenarios: scenarios
            .iter()
            .map(|scenario| scenario.metadata.clone())
            .collect(),
    }
}

pub fn filter_external_curated_bundle_by_review_status(
    bundle: &ExternalCuratedBundle,
    review_status: &str,
) -> Result<ExternalCuratedBundle, String> {
    if !is_supported_external_review_status(review_status) {
        return Err(format!(
            "external curated review_status {} is unsupported",
            review_status
        ));
    }

    let scenarios = bundle
        .scenarios
        .iter()
        .filter(|scenario| scenario.metadata.review_status == review_status)
        .cloned()
        .collect::<Vec<_>>();

    if scenarios.is_empty() {
        return Err(format!(
            "external curated bundle {} contains no {} cases",
            bundle.manifest.dataset_id, review_status
        ));
    }

    Ok(ExternalCuratedBundle {
        manifest: ExternalCuratedManifest {
            schema_version: bundle.manifest.schema_version,
            dataset_id: format!("{}_{}", bundle.manifest.dataset_id, review_status),
            dataset_label: format!("{} ({review_status})", bundle.manifest.dataset_label),
            curation_status: review_status.to_string(),
            maintainer: bundle.manifest.maintainer.clone(),
            created_at_ms: bundle.manifest.created_at_ms,
            updated_at_ms: bundle.manifest.updated_at_ms,
        },
        scenarios,
    })
}

fn build_external_curated_bundle(file: &ExternalCuratedFile) -> ExternalCuratedBundle {
    ExternalCuratedBundle {
        manifest: ExternalCuratedManifest {
            schema_version: file.schema_version,
            dataset_id: file.dataset_id.clone(),
            dataset_label: file.dataset_label.clone(),
            curation_status: file.curation_status.clone(),
            maintainer: file.maintainer.clone(),
            created_at_ms: file.created_at_ms,
            updated_at_ms: file.updated_at_ms,
        },
        scenarios: file
            .cases
            .iter()
            .map(build_external_curated_scenario)
            .collect(),
    }
}

pub fn evaluate_external_curated_suite(
    summary: &ExternalCuratedSuiteSummary,
    gates: &ScenarioQualityGates,
) -> (
    ScenarioGateReport,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
) {
    let overall = evaluate_scenario_quality_gates(&summary.evaluation, gates);
    let by_source_family = summary
        .by_source_family
        .iter()
        .map(|slice| {
            let slice_gates = external_slice_quality_gates(&slice.evaluation, gates);
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, &slice_gates),
            )
        })
        .collect();
    let by_review_status = summary
        .by_review_status
        .iter()
        .map(|slice| {
            let review_gates = external_review_status_quality_gates(&slice.slice_id, gates);
            let slice_gates = external_slice_quality_gates(&slice.evaluation, &review_gates);
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, &slice_gates),
            )
        })
        .collect();
    let by_language = summary
        .by_language
        .iter()
        .map(|slice| {
            let slice_gates = external_slice_quality_gates(&slice.evaluation, gates);
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, &slice_gates),
            )
        })
        .collect();
    let by_relationship = summary
        .by_relationship
        .iter()
        .map(|slice| {
            let slice_gates = external_slice_quality_gates(&slice.evaluation, gates);
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, &slice_gates),
            )
        })
        .collect();
    let by_age_band = summary
        .by_age_band
        .iter()
        .map(|slice| {
            let slice_gates = external_slice_quality_gates(&slice.evaluation, gates);
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, &slice_gates),
            )
        })
        .collect();

    (
        overall,
        by_source_family,
        by_review_status,
        by_language,
        by_relationship,
        by_age_band,
    )
}

pub fn evaluate_external_curated_policy_suite(
    summary: &ExternalCuratedSuiteSummary,
    gates: &PolicyActionQualityGates,
) -> (
    ScenarioGateReport,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
) {
    let overall = evaluate_policy_action_gates(&summary.policy, gates);
    let by_source_family = summary
        .by_source_family
        .iter()
        .filter(|slice| slice.policy.total_scenarios > 0)
        .map(|slice| {
            (
                slice.slice_id.clone(),
                evaluate_policy_action_gates(&slice.policy, gates),
            )
        })
        .collect();
    let by_review_status = summary
        .by_review_status
        .iter()
        .filter(|slice| slice.policy.total_scenarios > 0)
        .map(|slice| {
            (
                slice.slice_id.clone(),
                evaluate_policy_action_gates(&slice.policy, gates),
            )
        })
        .collect();
    let by_language = summary
        .by_language
        .iter()
        .filter(|slice| slice.policy.total_scenarios > 0)
        .map(|slice| {
            (
                slice.slice_id.clone(),
                evaluate_policy_action_gates(&slice.policy, gates),
            )
        })
        .collect();
    let by_relationship = summary
        .by_relationship
        .iter()
        .filter(|slice| slice.policy.total_scenarios > 0)
        .map(|slice| {
            (
                slice.slice_id.clone(),
                evaluate_policy_action_gates(&slice.policy, gates),
            )
        })
        .collect();
    let by_age_band = summary
        .by_age_band
        .iter()
        .filter(|slice| slice.policy.total_scenarios > 0)
        .map(|slice| {
            (
                slice.slice_id.clone(),
                evaluate_policy_action_gates(&slice.policy, gates),
            )
        })
        .collect();

    (
        overall,
        by_source_family,
        by_review_status,
        by_language,
        by_relationship,
        by_age_band,
    )
}

fn external_slice_quality_gates(
    summary: &ScenarioEvaluationSummary,
    gates: &ScenarioQualityGates,
) -> ScenarioQualityGates {
    let mut adapted = gates.clone();

    if summary.calibration.count < MIN_EXTERNAL_SLICE_CALIBRATION_EXAMPLES {
        adapted.max_brier_score = None;
        adapted.max_expected_calibration_error = None;
    }

    if summary.classification.total_positive_scenarios == 0 {
        adapted.min_positive_detection_rate = None;
        adapted.min_pre_onset_detection_rate = None;
    }

    if summary.classification.total_negative_scenarios == 0 {
        adapted.max_negative_false_positive_rate = None;
    }

    if summary.lead_time.total_cases < MIN_EXTERNAL_SLICE_LEAD_TIME_CASES {
        adapted.min_pre_onset_detection_rate = None;
    }

    adapted
}

fn external_review_status_quality_gates(
    review_status: &str,
    gates: &ScenarioQualityGates,
) -> ScenarioQualityGates {
    match review_status {
        EXTERNAL_CURATED_GOLD_REVIEWED => {
            merge_stricter_quality_gates(gates, &pre_release_external_curated_gold_gates())
        }
        _ => gates.clone(),
    }
}

fn merge_stricter_quality_gates(
    base: &ScenarioQualityGates,
    stricter: &ScenarioQualityGates,
) -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: stricter_max_threshold(base.max_brier_score, stricter.max_brier_score),
        max_expected_calibration_error: stricter_max_threshold(
            base.max_expected_calibration_error,
            stricter.max_expected_calibration_error,
        ),
        min_positive_detection_rate: stricter_min_threshold(
            base.min_positive_detection_rate,
            stricter.min_positive_detection_rate,
        ),
        max_negative_false_positive_rate: stricter_max_threshold(
            base.max_negative_false_positive_rate,
            stricter.max_negative_false_positive_rate,
        ),
        min_pre_onset_detection_rate: stricter_min_threshold(
            base.min_pre_onset_detection_rate,
            stricter.min_pre_onset_detection_rate,
        ),
        per_threat: merge_stricter_per_threat_gates(&base.per_threat, &stricter.per_threat),
    }
}

fn merge_stricter_per_threat_gates(
    base: &[crate::ThreatCalibrationGate],
    stricter: &[crate::ThreatCalibrationGate],
) -> Vec<crate::ThreatCalibrationGate> {
    let mut merged = base.to_vec();

    for strict_gate in stricter {
        if let Some(existing) = merged
            .iter_mut()
            .find(|gate| gate.threat_type == strict_gate.threat_type)
        {
            existing.min_example_count = stricter_min_count_threshold(
                existing.min_example_count,
                strict_gate.min_example_count,
            );
            existing.max_brier_score =
                stricter_max_threshold(existing.max_brier_score, strict_gate.max_brier_score);
            existing.max_expected_calibration_error = stricter_max_threshold(
                existing.max_expected_calibration_error,
                strict_gate.max_expected_calibration_error,
            );
        } else {
            merged.push(strict_gate.clone());
        }
    }

    merged
}

fn stricter_max_threshold(base: Option<f32>, stricter: Option<f32>) -> Option<f32> {
    match (base, stricter) {
        (Some(base), Some(stricter)) => Some(base.min(stricter)),
        (Some(base), None) => Some(base),
        (None, Some(stricter)) => Some(stricter),
        (None, None) => None,
    }
}

fn stricter_min_threshold(base: Option<f32>, stricter: Option<f32>) -> Option<f32> {
    match (base, stricter) {
        (Some(base), Some(stricter)) => Some(base.max(stricter)),
        (Some(base), None) => Some(base),
        (None, Some(stricter)) => Some(stricter),
        (None, None) => None,
    }
}

fn stricter_min_count_threshold(base: Option<usize>, stricter: Option<usize>) -> Option<usize> {
    match (base, stricter) {
        (Some(base), Some(stricter)) => Some(base.max(stricter)),
        (Some(base), None) => Some(base),
        (None, Some(stricter)) => Some(stricter),
        (None, None) => None,
    }
}

fn summarize_external_slices<F>(
    scenarios: &[ExternalCuratedScenario],
    runs: &[ScenarioRunResult],
    expectations: &[crate::ScenarioPolicyExpectation],
    key_fn: F,
    bin_count: usize,
) -> Vec<ExternalCuratedSliceSummary>
where
    F: Fn(&ExternalCuratedMetadata) -> String,
{
    let expected_policy_cases = expectations
        .iter()
        .map(|expectation| expectation.scenario_name.as_str())
        .collect::<BTreeSet<_>>();
    let mut grouped = BTreeMap::<String, Vec<usize>>::new();

    for (idx, scenario) in scenarios.iter().enumerate() {
        grouped
            .entry(key_fn(&scenario.metadata))
            .or_default()
            .push(idx);
    }

    grouped
        .into_iter()
        .map(|(slice_id, indices)| {
            let slice_runs = indices
                .iter()
                .map(|idx| runs[*idx].clone())
                .collect::<Vec<_>>();
            let policy_indices = indices
                .iter()
                .copied()
                .filter(|idx| {
                    scenarios[*idx]
                        .metadata
                        .policy_expectation_case
                        .as_ref()
                        .is_some_and(|case| expected_policy_cases.contains(case.as_str()))
                })
                .collect::<Vec<_>>();
            let policy_runs = policy_indices
                .iter()
                .map(|idx| runs[*idx].clone())
                .collect::<Vec<_>>();
            let expectation_names = policy_indices
                .iter()
                .map(|idx| {
                    scenarios[*idx]
                        .metadata
                        .policy_expectation_case
                        .clone()
                        .expect("validated policy expectation")
                })
                .collect::<Vec<_>>();

            ExternalCuratedSliceSummary {
                slice_id,
                case_count: indices.len(),
                scenario_names: indices
                    .iter()
                    .map(|idx| scenarios[*idx].metadata.scenario_name.clone())
                    .collect(),
                evaluation: summarize_scenario_runs(&slice_runs, bin_count),
                policy: summarize_policy_actions_with_expectation_names(
                    &policy_runs,
                    &expectation_names,
                    expectations,
                ),
            }
        })
        .collect()
}

fn external_curated_chat_file() -> &'static ExternalCuratedFile {
    static FILE: OnceLock<ExternalCuratedFile> = OnceLock::new();
    FILE.get_or_init(|| {
        let file = serde_json::from_str::<ExternalCuratedFile>(include_str!(
            "../data/external_curated_chat_cases.json"
        ))
        .expect("valid external curated corpus json");
        validate_external_curated_file(&file).expect("valid external curated corpus");
        file
    })
}

fn validate_external_curated_file(file: &ExternalCuratedFile) -> Result<(), String> {
    if file.schema_version != EXTERNAL_CURATED_SCHEMA_VERSION {
        return Err(format!(
            "external curated corpus schema_version {} is unsupported, expected {}",
            file.schema_version, EXTERNAL_CURATED_SCHEMA_VERSION
        ));
    }
    if file.dataset_id.trim().is_empty() {
        return Err("external curated corpus dataset_id must not be empty".to_string());
    }
    if file.dataset_label.trim().is_empty() {
        return Err("external curated corpus dataset_label must not be empty".to_string());
    }
    if file.curation_status.trim().is_empty() {
        return Err("external curated corpus curation_status must not be empty".to_string());
    }
    if !is_supported_external_curation_status(&file.curation_status) {
        return Err(format!(
            "external curated corpus curation_status {} is unsupported",
            file.curation_status
        ));
    }
    if file.maintainer.trim().is_empty() {
        return Err("external curated corpus maintainer must not be empty".to_string());
    }
    if file.created_at_ms == 0 {
        return Err("external curated corpus created_at_ms must be non-zero".to_string());
    }
    if file.updated_at_ms == 0 {
        return Err("external curated corpus updated_at_ms must be non-zero".to_string());
    }
    if file.updated_at_ms < file.created_at_ms {
        return Err("external curated corpus updated_at_ms must be >= created_at_ms".to_string());
    }
    let known_policy_cases = canonical_policy_action_expectations()
        .into_iter()
        .map(|expectation| expectation.scenario_name)
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    let mut review_statuses = BTreeSet::new();

    for case in &file.cases {
        if case.id.trim().is_empty() {
            return Err("external curated case id must not be empty".to_string());
        }
        if !ids.insert(case.id.clone()) {
            return Err(format!("duplicate external curated case id: {}", case.id));
        }
        if case.source_family.trim().is_empty() {
            return Err(format!(
                "external curated case {} has empty source_family",
                case.id
            ));
        }
        if case.review_status.trim().is_empty() {
            return Err(format!(
                "external curated case {} has empty review_status",
                case.id
            ));
        }
        if !is_supported_external_review_status(&case.review_status) {
            return Err(format!(
                "external curated case {} has unsupported review_status {}",
                case.id, case.review_status
            ));
        }
        review_statuses.insert(case.review_status.clone());
        if case.default_language.trim().is_empty() {
            return Err(format!(
                "external curated case {} has empty default_language",
                case.id
            ));
        }
        if case.age_band.trim().is_empty() {
            return Err(format!(
                "external curated case {} has empty age_band",
                case.id
            ));
        }
        if case.relationship.trim().is_empty() {
            return Err(format!(
                "external curated case {} has empty relationship",
                case.id
            ));
        }
        if !(0.0..=1.0).contains(&case.detection_threshold) {
            return Err(format!(
                "external curated case {} has invalid detection_threshold {}",
                case.id, case.detection_threshold
            ));
        }
        if case.step_interval_ms == 0 {
            return Err(format!(
                "external curated case {} has zero step_interval_ms",
                case.id
            ));
        }
        if case.messages.is_empty() {
            return Err(format!("external curated case {} has no messages", case.id));
        }
        if let Some(onset_step) = case.onset_step {
            if onset_step >= case.messages.len() {
                return Err(format!(
                    "external curated case {} onset_step {} is out of bounds",
                    case.id, onset_step
                ));
            }
        }
        if let Some(policy_case) = &case.policy_expectation_case {
            if !known_policy_cases.contains(policy_case) {
                return Err(format!(
                    "external curated case {} references unknown policy expectation {}",
                    case.id, policy_case
                ));
            }
        }
        for message in &case.messages {
            if message.text.trim().is_empty() {
                return Err(format!(
                    "external curated case {} contains empty message text",
                    case.id
                ));
            }
            if message
                .language
                .as_deref()
                .is_some_and(|language| language.trim().is_empty())
            {
                return Err(format!(
                    "external curated case {} contains empty message language",
                    case.id
                ));
            }
        }
    }

    match file.curation_status.as_str() {
        EXTERNAL_CURATED_SEED_REVIEWED => {
            if review_statuses.len() != 1
                || !review_statuses.contains(EXTERNAL_CURATED_SEED_REVIEWED)
            {
                return Err(
                    "external curated corpus curation_status seed_reviewed must contain only seed_reviewed cases"
                        .to_string(),
                );
            }
        }
        EXTERNAL_CURATED_GOLD_REVIEWED => {
            if review_statuses.len() != 1
                || !review_statuses.contains(EXTERNAL_CURATED_GOLD_REVIEWED)
            {
                return Err(
                    "external curated corpus curation_status gold_reviewed must contain only gold_reviewed cases"
                        .to_string(),
                );
            }
        }
        EXTERNAL_CURATED_MIXED_REVIEW_TIERS => {
            if review_statuses.len() < 2
                || !review_statuses.contains(EXTERNAL_CURATED_SEED_REVIEWED)
                || !review_statuses.contains(EXTERNAL_CURATED_GOLD_REVIEWED)
            {
                return Err(
                    "external curated corpus curation_status mixed_review_tiers must contain both seed_reviewed and gold_reviewed cases"
                        .to_string(),
                );
            }
        }
        _ => unreachable!("validated external curated curation_status"),
    }

    Ok(())
}

fn is_supported_external_curation_status(status: &str) -> bool {
    matches!(
        status,
        EXTERNAL_CURATED_SEED_REVIEWED
            | EXTERNAL_CURATED_GOLD_REVIEWED
            | EXTERNAL_CURATED_MIXED_REVIEW_TIERS
    )
}

fn is_supported_external_review_status(status: &str) -> bool {
    matches!(
        status,
        EXTERNAL_CURATED_SEED_REVIEWED | EXTERNAL_CURATED_GOLD_REVIEWED
    )
}

fn build_external_curated_scenario(spec: &ExternalCuratedCaseSpec) -> ExternalCuratedScenario {
    let config = AuraConfig {
        account_type: spec.account_type,
        protection_level: spec.protection_level,
        language: spec.default_language.clone(),
        ..AuraConfig::default()
    };

    let tracked_threats = if spec.tracked_threats.is_empty() {
        spec.primary_threat.into_iter().collect()
    } else {
        spec.tracked_threats.clone()
    };

    let steps = spec
        .messages
        .iter()
        .enumerate()
        .map(|(idx, message)| ScenarioStep {
            timestamp_ms: idx as u64 * spec.step_interval_ms,
            input: MessageInput {
                content_type: ContentType::Text,
                text: Some(message.text.clone()),
                image_data: None,
                sender_id: message
                    .sender_id
                    .clone()
                    .unwrap_or_else(|| format!("{}_sender_{idx}", spec.id)),
                conversation_id: spec.id.clone(),
                language: Some(
                    message
                        .language
                        .clone()
                        .unwrap_or_else(|| spec.default_language.clone()),
                ),
                conversation_type: spec.conversation_type,
                member_count: matches!(spec.conversation_type, ConversationType::GroupChat)
                    .then_some(6),
            },
            observed_threats: message.observed_threats.clone(),
        })
        .collect::<Vec<_>>();

    ExternalCuratedScenario {
        metadata: ExternalCuratedMetadata {
            scenario_name: spec.id.clone(),
            source_family: spec.source_family.clone(),
            review_status: spec.review_status.clone(),
            default_language: spec.default_language.clone(),
            age_band: spec.age_band.clone(),
            relationship: spec.relationship.clone(),
            policy_expectation_case: spec.policy_expectation_case.clone(),
        },
        case: ScenarioCase {
            name: spec.id.clone(),
            config,
            primary_threat: spec.primary_threat,
            onset_step: spec.onset_step,
            detection_threshold: spec.detection_threshold,
            tracked_threats,
            steps,
        },
    }
}

fn default_external_detection_threshold() -> f32 {
    0.55
}

fn default_external_step_interval_ms() -> u64 {
    3_600_000
}

fn default_external_account_type() -> AccountType {
    AccountType::Child
}

fn default_external_protection_level() -> ProtectionLevel {
    ProtectionLevel::High
}

#[cfg(test)]
mod tests {
    use aura_patterns::PatternDatabase;

    use super::*;

    #[test]
    fn external_curated_file_loads_expected_cases() {
        let file = external_curated_chat_file();
        assert_eq!(file.schema_version, EXTERNAL_CURATED_SCHEMA_VERSION);
        assert_eq!(file.dataset_id, "aura_external_curated_mixed");
        assert_eq!(file.curation_status, EXTERNAL_CURATED_MIXED_REVIEW_TIERS);
        assert!(file.cases.len() >= 8);
        assert!(file
            .cases
            .iter()
            .any(|case| case.id == "external_en_child_stranger_secrecy_probe"));
        assert!(file
            .cases
            .iter()
            .any(|case| case.id == "external_uk_supportive_friend_help_path"));
        assert!(file
            .cases
            .iter()
            .any(|case| case.review_status == EXTERNAL_CURATED_GOLD_REVIEWED));
        assert!(file
            .cases
            .iter()
            .any(|case| case.review_status == EXTERNAL_CURATED_SEED_REVIEWED));
    }

    #[test]
    fn external_curated_chat_scenarios_cover_policy_for_all_cases() {
        let scenarios = external_curated_chat_scenarios();
        assert!(!scenarios.is_empty());
        assert!(scenarios
            .iter()
            .all(|scenario| scenario.metadata.policy_expectation_case.is_some()));
    }

    #[test]
    fn external_curated_parser_accepts_builtin_json() {
        let parsed =
            parse_external_curated_bundle(include_str!("../data/external_curated_chat_cases.json"))
                .expect("builtin external curated corpus parses");
        assert_eq!(
            parsed.manifest.schema_version,
            EXTERNAL_CURATED_SCHEMA_VERSION
        );
        assert_eq!(parsed.manifest.dataset_id, "aura_external_curated_mixed");
        assert!(!parsed.scenarios.is_empty());
    }

    #[test]
    fn external_curated_suite_builds_source_and_review_slices() {
        let db = PatternDatabase::default_mvp();
        let summary = run_external_curated_suite(&db, 5);

        assert_eq!(summary.manifest.dataset_id, "aura_external_curated_mixed");
        assert!(!summary.by_source_family.is_empty());
        assert!(!summary.by_review_status.is_empty());
        assert!(!summary.by_language.is_empty());
        assert!(!summary.by_relationship.is_empty());
        assert!(!summary.by_age_band.is_empty());
        assert_eq!(summary.policy.total_scenarios, summary.scenarios.len());
    }

    #[test]
    fn gold_reviewed_external_gates_are_stricter_than_base() {
        let base = pre_release_external_curated_gates();
        let gold = pre_release_external_curated_gold_gates();

        assert!(gold.max_brier_score.unwrap() < base.max_brier_score.unwrap());
        assert!(
            gold.max_expected_calibration_error.unwrap()
                < base.max_expected_calibration_error.unwrap()
        );
        assert!(
            gold.min_positive_detection_rate.unwrap() > base.min_positive_detection_rate.unwrap()
        );
        assert!(
            gold.max_negative_false_positive_rate.unwrap()
                < base.max_negative_false_positive_rate.unwrap()
        );
        assert!(
            gold.min_pre_onset_detection_rate.unwrap() > base.min_pre_onset_detection_rate.unwrap()
        );
    }

    #[test]
    fn stricter_quality_gate_merge_preserves_per_threat_rules() {
        let base = ScenarioQualityGates {
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.30),
            min_positive_detection_rate: Some(0.80),
            max_negative_false_positive_rate: Some(0.05),
            min_pre_onset_detection_rate: Some(0.20),
            per_threat: vec![crate::ThreatCalibrationGate {
                threat_type: ThreatType::Manipulation,
                min_example_count: Some(10),
                max_brier_score: Some(0.25),
                max_expected_calibration_error: Some(0.20),
            }],
        };
        let stricter = ScenarioQualityGates {
            max_brier_score: Some(0.20),
            max_expected_calibration_error: Some(0.15),
            min_positive_detection_rate: Some(0.90),
            max_negative_false_positive_rate: Some(0.03),
            min_pre_onset_detection_rate: Some(0.30),
            per_threat: vec![crate::ThreatCalibrationGate {
                threat_type: ThreatType::Manipulation,
                min_example_count: Some(12),
                max_brier_score: Some(0.18),
                max_expected_calibration_error: Some(0.14),
            }],
        };

        let merged = merge_stricter_quality_gates(&base, &stricter);
        let manipulation = merged
            .per_threat
            .iter()
            .find(|gate| gate.threat_type == ThreatType::Manipulation)
            .expect("merged manipulation gate");

        assert_eq!(manipulation.min_example_count, Some(12));
        assert_eq!(manipulation.max_brier_score, Some(0.18));
        assert_eq!(manipulation.max_expected_calibration_error, Some(0.14));
    }

    #[test]
    fn gold_only_external_bundle_derives_gold_manifest() {
        let gold_bundle = external_curated_gold_bundle();

        assert_eq!(
            gold_bundle.manifest.curation_status,
            EXTERNAL_CURATED_GOLD_REVIEWED
        );
        assert!(gold_bundle
            .manifest
            .dataset_id
            .ends_with(EXTERNAL_CURATED_GOLD_REVIEWED));
        assert!(!gold_bundle.scenarios.is_empty());
        assert!(gold_bundle
            .scenarios
            .iter()
            .all(|scenario| scenario.metadata.review_status == EXTERNAL_CURATED_GOLD_REVIEWED));
    }

    #[test]
    fn gold_only_external_suite_passes_manifest_aware_gates() {
        let db = PatternDatabase::default_mvp();
        let summary = run_external_curated_gold_suite(&db, 5);
        let gates = pre_release_external_curated_gates_for_manifest(&summary.manifest);
        let (overall, _, _, _, _, _) = evaluate_external_curated_suite(&summary, &gates);

        assert!(
            overall.passed,
            "gold-only external curated gates failed: {overall:?}"
        );
    }

    #[test]
    fn external_curated_suite_passes_pre_release_gates() {
        let db = PatternDatabase::default_mvp();
        let summary = run_external_curated_suite(&db, 5);
        let (overall, _, _, _, _, _) =
            evaluate_external_curated_suite(&summary, &pre_release_external_curated_gates());

        assert!(overall.passed, "external curated gates failed: {overall:?}");
    }

    #[test]
    fn external_curated_policy_suite_passes_pre_release_gates() {
        let db = PatternDatabase::default_mvp();
        let summary = run_external_curated_suite(&db, 5);
        let (
            overall,
            by_source_family,
            by_review_status,
            by_language,
            by_relationship,
            by_age_band,
        ) = evaluate_external_curated_policy_suite(
            &summary,
            &pre_release_external_curated_policy_gates(),
        );

        assert!(
            overall.passed,
            "external curated policy gates failed: {overall:?}"
        );
        for (slice, report) in by_source_family {
            assert!(
                report.passed,
                "source-family policy slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_review_status {
            assert!(
                report.passed,
                "review-status policy slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_language {
            assert!(
                report.passed,
                "language policy slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_relationship {
            assert!(
                report.passed,
                "relationship policy slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_age_band {
            assert!(
                report.passed,
                "age-band policy slice {slice} failed: {report:?}"
            );
        }
    }

    #[test]
    fn external_curated_slice_quality_gates_pass_with_support_aware_rules() {
        let db = PatternDatabase::default_mvp();
        let summary = run_external_curated_suite(&db, 5);
        let (
            _overall,
            by_source_family,
            by_review_status,
            by_language,
            by_relationship,
            by_age_band,
        ) = evaluate_external_curated_suite(&summary, &pre_release_external_curated_gates());

        for (slice, report) in by_source_family {
            assert!(
                report.passed,
                "source-family eval slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_review_status {
            assert!(
                report.passed,
                "review-status eval slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_language {
            assert!(
                report.passed,
                "language eval slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_relationship {
            assert!(
                report.passed,
                "relationship eval slice {slice} failed: {report:?}"
            );
        }
        for (slice, report) in by_age_band {
            assert!(
                report.passed,
                "age-band eval slice {slice} failed: {report:?}"
            );
        }
    }

    #[test]
    fn external_curated_review_status_slices_include_gold_and_seed() {
        let db = PatternDatabase::default_mvp();
        let summary = run_external_curated_suite(&db, 5);
        let slice_ids = summary
            .by_review_status
            .iter()
            .map(|slice| slice.slice_id.as_str())
            .collect::<BTreeSet<_>>();

        assert!(slice_ids.contains(EXTERNAL_CURATED_GOLD_REVIEWED));
        assert!(slice_ids.contains(EXTERNAL_CURATED_SEED_REVIEWED));
    }
}
