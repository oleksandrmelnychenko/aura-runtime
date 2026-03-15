use std::collections::{BTreeSet, HashMap};

use aura_patterns::PatternDatabase;

use crate::analyzer::Analyzer;
use crate::config::AuraConfig;
use crate::types::{AnalysisResult, MessageInput, ThreatType};

#[derive(Debug, Clone)]
pub struct RiskExample {
    pub threat_type: ThreatType,
    pub language: String,
    pub predicted_score: f32,
    pub observed: bool,
    pub target_probability: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CalibrationBin {
    pub lower_bound: f32,
    pub upper_bound: f32,
    pub count: usize,
    pub avg_prediction: f32,
    pub observed_rate: f32,
    pub gap: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThreatCalibrationReport {
    pub threat_type: ThreatType,
    pub count: usize,
    pub brier_score: f32,
    pub expected_calibration_error: f32,
    pub bins: Vec<CalibrationBin>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CalibrationReport {
    pub count: usize,
    pub brier_score: f32,
    pub expected_calibration_error: f32,
    pub bins: Vec<CalibrationBin>,
    pub by_threat: Vec<ThreatCalibrationReport>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LeadTimePoint {
    pub timestamp_ms: u64,
    pub score: f32,
}

#[derive(Debug, Clone)]
pub struct LeadTimeCase {
    pub threat_type: ThreatType,
    pub onset_ms: u64,
    pub detection_threshold: f32,
    pub timeline: Vec<LeadTimePoint>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LeadTimeResult {
    pub threat_type: ThreatType,
    pub onset_ms: u64,
    pub first_detection_ms: Option<u64>,
    pub detected_before_onset: bool,
    pub detected_after_onset: bool,
    pub lead_time_ms: Option<u64>,
    pub delay_after_onset_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LeadTimeSummary {
    pub total_cases: usize,
    pub detected_cases: usize,
    pub detected_before_onset_cases: usize,
    pub missed_cases: usize,
    pub mean_lead_time_ms: Option<f32>,
    pub median_lead_time_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ScenarioStep {
    pub timestamp_ms: u64,
    pub input: MessageInput,
    pub observed_threats: Vec<ThreatType>,
}

#[derive(Debug, Clone)]
pub struct ScenarioCase {
    pub name: String,
    pub config: AuraConfig,
    pub primary_threat: Option<ThreatType>,
    pub onset_step: Option<usize>,
    pub detection_threshold: f32,
    pub tracked_threats: Vec<ThreatType>,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioLeadTimeRecord {
    pub name: String,
    pub result: LeadTimeResult,
}

#[derive(Debug, Clone)]
pub struct ScenarioRunResult {
    pub name: String,
    pub primary_threat: Option<ThreatType>,
    pub detection_threshold: f32,
    pub tracked_threats: Vec<ThreatType>,
    pub languages: Vec<String>,
    pub step_timestamps: Vec<u64>,
    pub step_results: Vec<AnalysisResult>,
    pub calibration_examples: Vec<RiskExample>,
    pub lead_time: Option<LeadTimeResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioClassificationRecord {
    pub name: String,
    pub primary_threat: Option<ThreatType>,
    pub threshold: f32,
    pub peak_score: f32,
    pub first_detection_step: Option<usize>,
    pub first_detection_ms: Option<u64>,
    pub detected: bool,
    pub false_positive: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioClassificationSummary {
    pub total_positive_scenarios: usize,
    pub detected_positive_scenarios: usize,
    pub missed_positive_scenarios: usize,
    pub positive_detection_rate: f32,
    pub total_negative_scenarios: usize,
    pub clean_negative_scenarios: usize,
    pub false_positive_scenarios: usize,
    pub negative_false_positive_rate: f32,
    pub scenarios: Vec<ScenarioClassificationRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioEvaluationSummary {
    pub calibration: CalibrationReport,
    pub lead_time: LeadTimeSummary,
    pub classification: ScenarioClassificationSummary,
    pub language_slices: Vec<LanguageSliceSummary>,
    pub scenarios: Vec<ScenarioLeadTimeRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LanguageSliceSummary {
    pub language: String,
    pub scenario_count: usize,
    pub calibration: CalibrationReport,
    pub lead_time: LeadTimeSummary,
    pub classification: ScenarioClassificationSummary,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioQualityGates {
    pub max_brier_score: Option<f32>,
    pub max_expected_calibration_error: Option<f32>,
    pub min_positive_detection_rate: Option<f32>,
    pub max_negative_false_positive_rate: Option<f32>,
    pub min_pre_onset_detection_rate: Option<f32>,
    pub per_threat: Vec<ThreatCalibrationGate>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThreatCalibrationGate {
    pub threat_type: ThreatType,
    pub min_example_count: Option<usize>,
    pub max_brier_score: Option<f32>,
    pub max_expected_calibration_error: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateComparison {
    AtMost,
    AtLeast,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioGateCheck {
    pub name: String,
    pub comparison: GateComparison,
    pub actual: f32,
    pub threshold: f32,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioGateReport {
    pub passed: bool,
    pub checks: Vec<ScenarioGateCheck>,
}

pub fn calibration_for_threat(
    report: &CalibrationReport,
    threat_type: ThreatType,
) -> Option<&ThreatCalibrationReport> {
    report
        .by_threat
        .iter()
        .find(|threat_report| threat_report.threat_type == threat_type)
}

pub fn predicted_score_for_threat(result: &AnalysisResult, threat_type: ThreatType) -> f32 {
    let detected_score = result
        .detected_threats
        .iter()
        .find(|(kind, _)| *kind == threat_type)
        .map(|(_, score)| *score)
        .unwrap_or(0.0);

    if result.threat_type == threat_type {
        detected_score.max(result.score).clamp(0.0, 1.0)
    } else {
        detected_score.clamp(0.0, 1.0)
    }
}

pub fn risk_example_from_result(
    result: &AnalysisResult,
    threat_type: ThreatType,
    observed: bool,
) -> RiskExample {
    risk_example_from_result_with_target_in_language(
        result,
        threat_type,
        observed,
        normalize_language_code(None),
        if observed { 1.0 } else { 0.0 },
    )
}

pub fn risk_example_from_result_with_target(
    result: &AnalysisResult,
    threat_type: ThreatType,
    observed: bool,
    target_probability: f32,
) -> RiskExample {
    risk_example_from_result_with_target_in_language(
        result,
        threat_type,
        observed,
        normalize_language_code(None),
        target_probability,
    )
}

pub fn risk_example_from_result_with_target_in_language(
    result: &AnalysisResult,
    threat_type: ThreatType,
    observed: bool,
    language: impl Into<String>,
    target_probability: f32,
) -> RiskExample {
    let language = language.into();
    RiskExample {
        threat_type,
        language: normalize_language_code(Some(language.as_str())),
        predicted_score: predicted_score_for_threat(result, threat_type),
        observed,
        target_probability: target_probability.clamp(0.0, 1.0),
    }
}

pub fn build_calibration_report(examples: &[RiskExample], bin_count: usize) -> CalibrationReport {
    let overall = build_single_calibration_report(examples, bin_count);

    let mut grouped: HashMap<ThreatType, Vec<RiskExample>> = HashMap::new();
    for example in examples {
        grouped
            .entry(example.threat_type)
            .or_default()
            .push(example.clone());
    }

    let mut by_threat = Vec::new();
    for threat_type in all_scored_threat_types() {
        let Some(group) = grouped.get(&threat_type) else {
            continue;
        };
        let report = build_single_calibration_report(group, bin_count);
        by_threat.push(ThreatCalibrationReport {
            threat_type,
            count: report.count,
            brier_score: report.brier_score,
            expected_calibration_error: report.expected_calibration_error,
            bins: report.bins,
        });
    }

    CalibrationReport {
        count: overall.count,
        brier_score: overall.brier_score,
        expected_calibration_error: overall.expected_calibration_error,
        bins: overall.bins,
        by_threat,
    }
}

pub fn evaluate_lead_time(case: &LeadTimeCase) -> LeadTimeResult {
    let mut timeline = case.timeline.clone();
    timeline.sort_by_key(|point| point.timestamp_ms);

    let first_detection_ms = timeline
        .iter()
        .find(|point| point.score >= case.detection_threshold)
        .map(|point| point.timestamp_ms);

    let detected_before_onset = first_detection_ms.is_some_and(|ts| ts < case.onset_ms);
    let detected_after_onset = first_detection_ms.is_some_and(|ts| ts >= case.onset_ms);

    LeadTimeResult {
        threat_type: case.threat_type,
        onset_ms: case.onset_ms,
        first_detection_ms,
        detected_before_onset,
        detected_after_onset,
        lead_time_ms: first_detection_ms
            .filter(|ts| *ts < case.onset_ms)
            .map(|ts| case.onset_ms - ts),
        delay_after_onset_ms: first_detection_ms
            .filter(|ts| *ts >= case.onset_ms)
            .map(|ts| ts - case.onset_ms),
    }
}

pub fn summarize_lead_time(cases: &[LeadTimeCase]) -> LeadTimeSummary {
    let results: Vec<_> = cases.iter().map(evaluate_lead_time).collect();
    summarize_lead_time_results(&results)
}

pub fn summarize_lead_time_results(results: &[LeadTimeResult]) -> LeadTimeSummary {
    let detected_cases = results
        .iter()
        .filter(|result| result.first_detection_ms.is_some())
        .count();
    let detected_before_onset_cases = results
        .iter()
        .filter(|result| result.detected_before_onset)
        .count();
    let mut lead_times: Vec<u64> = results
        .iter()
        .filter_map(|result| result.lead_time_ms)
        .collect();
    lead_times.sort_unstable();

    let mean_lead_time_ms = if lead_times.is_empty() {
        None
    } else {
        Some(lead_times.iter().sum::<u64>() as f32 / lead_times.len() as f32)
    };
    let median_lead_time_ms = if lead_times.is_empty() {
        None
    } else {
        let mid = lead_times.len() / 2;
        Some(if lead_times.len() % 2 == 0 {
            let lower = lead_times[mid - 1];
            let upper = lead_times[mid];
            lower + (upper - lower) / 2
        } else {
            lead_times[mid]
        })
    };

    LeadTimeSummary {
        total_cases: results.len(),
        detected_cases,
        detected_before_onset_cases,
        missed_cases: results.len().saturating_sub(detected_cases),
        mean_lead_time_ms,
        median_lead_time_ms,
    }
}

pub fn summarize_scenario_classification(
    runs: &[ScenarioRunResult],
) -> ScenarioClassificationSummary {
    let mut records = Vec::with_capacity(runs.len());

    for run in runs {
        let relevant_threats = if let Some(primary_threat) = run.primary_threat {
            vec![primary_threat]
        } else if run.tracked_threats.is_empty() {
            Vec::new()
        } else {
            run.tracked_threats.clone()
        };

        let mut peak_score: f32 = 0.0;
        let mut first_detection_step = None;
        let mut first_detection_ms = None;

        for (idx, result) in run.step_results.iter().enumerate() {
            let score = relevant_threats
                .iter()
                .map(|threat_type| predicted_score_for_threat(result, *threat_type))
                .fold(0.0, f32::max);
            peak_score = peak_score.max(score);

            if first_detection_step.is_none() && score >= run.detection_threshold {
                first_detection_step = Some(idx);
                first_detection_ms = run.step_timestamps.get(idx).copied();
            }
        }

        let detected = first_detection_step.is_some();
        let false_positive = run.primary_threat.is_none() && detected;

        records.push(ScenarioClassificationRecord {
            name: run.name.clone(),
            primary_threat: run.primary_threat,
            threshold: run.detection_threshold,
            peak_score,
            first_detection_step,
            first_detection_ms,
            detected,
            false_positive,
        });
    }

    let total_positive_scenarios = records
        .iter()
        .filter(|record| record.primary_threat.is_some())
        .count();
    let detected_positive_scenarios = records
        .iter()
        .filter(|record| record.primary_threat.is_some() && record.detected)
        .count();
    let total_negative_scenarios = records
        .iter()
        .filter(|record| record.primary_threat.is_none())
        .count();
    let false_positive_scenarios = records
        .iter()
        .filter(|record| record.false_positive)
        .count();

    ScenarioClassificationSummary {
        total_positive_scenarios,
        detected_positive_scenarios,
        missed_positive_scenarios: total_positive_scenarios
            .saturating_sub(detected_positive_scenarios),
        positive_detection_rate: if total_positive_scenarios == 0 {
            0.0
        } else {
            detected_positive_scenarios as f32 / total_positive_scenarios as f32
        },
        total_negative_scenarios,
        clean_negative_scenarios: total_negative_scenarios.saturating_sub(false_positive_scenarios),
        false_positive_scenarios,
        negative_false_positive_rate: if total_negative_scenarios == 0 {
            0.0
        } else {
            false_positive_scenarios as f32 / total_negative_scenarios as f32
        },
        scenarios: records,
    }
}

pub fn summarize_runs_by_language(
    runs: &[ScenarioRunResult],
    bin_count: usize,
) -> Vec<LanguageSliceSummary> {
    let languages: BTreeSet<String> = runs
        .iter()
        .flat_map(|run| run.languages.iter().cloned())
        .collect();

    let mut slices = Vec::new();
    for language in languages {
        let language_runs: Vec<_> = runs
            .iter()
            .filter(|run| run.languages.iter().any(|candidate| candidate == &language))
            .cloned()
            .collect();
        let calibration_examples: Vec<_> = runs
            .iter()
            .flat_map(|run| {
                run.calibration_examples
                    .iter()
                    .filter(|example| example.language == language)
                    .cloned()
            })
            .collect();
        let lead_time_results: Vec<_> = language_runs
            .iter()
            .filter_map(|run| run.lead_time.clone())
            .collect();

        slices.push(LanguageSliceSummary {
            language,
            scenario_count: language_runs.len(),
            calibration: build_calibration_report(&calibration_examples, bin_count),
            lead_time: summarize_lead_time_results(&lead_time_results),
            classification: summarize_scenario_classification(&language_runs),
        });
    }

    slices
}

pub fn run_scenario_case(pattern_db: &PatternDatabase, case: &ScenarioCase) -> ScenarioRunResult {
    let mut analyzer = Analyzer::new(case.config.clone(), pattern_db);
    let mut step_results = Vec::with_capacity(case.steps.len());
    let mut languages = BTreeSet::new();

    for step in &case.steps {
        languages.insert(step_language(step, case));
        let result = analyzer.analyze_with_context(&step.input, step.timestamp_ms);
        step_results.push(result);
    }

    let tracked_threats = if case.tracked_threats.is_empty() {
        case.primary_threat.into_iter().collect::<Vec<_>>()
    } else {
        case.tracked_threats.clone()
    };

    let mut calibration_examples = Vec::new();
    for (step_idx, (step, result)) in case.steps.iter().zip(step_results.iter()).enumerate() {
        let language = step_language(step, case);
        for threat_type in &tracked_threats {
            let observed = step.observed_threats.contains(threat_type);
            let target_probability =
                scenario_target_probability(case, step_idx, *threat_type, observed);
            calibration_examples.push(risk_example_from_result_with_target_in_language(
                result,
                *threat_type,
                observed,
                language.clone(),
                target_probability,
            ));
        }
    }

    let lead_time = case.primary_threat.and_then(|threat_type| {
        let onset_step = case.onset_step?;
        let onset = case.steps.get(onset_step)?;
        Some(evaluate_lead_time(&LeadTimeCase {
            threat_type,
            onset_ms: onset.timestamp_ms,
            detection_threshold: case.detection_threshold,
            timeline: case
                .steps
                .iter()
                .zip(step_results.iter())
                .map(|(step, result)| LeadTimePoint {
                    timestamp_ms: step.timestamp_ms,
                    score: predicted_score_for_threat(result, threat_type),
                })
                .collect(),
        }))
    });

    ScenarioRunResult {
        name: case.name.clone(),
        primary_threat: case.primary_threat,
        detection_threshold: case.detection_threshold,
        tracked_threats,
        languages: languages.into_iter().collect(),
        step_timestamps: case.steps.iter().map(|step| step.timestamp_ms).collect(),
        step_results,
        calibration_examples,
        lead_time,
    }
}

pub fn summarize_scenario_runs(
    runs: &[ScenarioRunResult],
    bin_count: usize,
) -> ScenarioEvaluationSummary {
    let classification = summarize_scenario_classification(runs);
    let calibration_examples: Vec<_> = runs
        .iter()
        .flat_map(|run| run.calibration_examples.iter().cloned())
        .collect();
    let lead_time_records: Vec<_> = runs
        .iter()
        .filter_map(|run| {
            run.lead_time.clone().map(|result| ScenarioLeadTimeRecord {
                name: run.name.clone(),
                result,
            })
        })
        .collect();
    let lead_time_summary = summarize_lead_time_results(
        &lead_time_records
            .iter()
            .map(|record| record.result.clone())
            .collect::<Vec<_>>(),
    );

    ScenarioEvaluationSummary {
        calibration: build_calibration_report(&calibration_examples, bin_count),
        lead_time: lead_time_summary,
        classification,
        language_slices: summarize_runs_by_language(runs, bin_count),
        scenarios: lead_time_records,
    }
}

pub fn pre_release_child_safety_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.22),
        max_expected_calibration_error: Some(0.25),
        min_positive_detection_rate: Some(0.70),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.40),
        per_threat: vec![
            ThreatCalibrationGate {
                threat_type: ThreatType::Grooming,
                min_example_count: Some(18),
                max_brier_score: Some(0.16),
                max_expected_calibration_error: Some(0.18),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Bullying,
                min_example_count: Some(8),
                max_brier_score: Some(0.18),
                max_expected_calibration_error: Some(0.25),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::SelfHarm,
                min_example_count: Some(6),
                max_brier_score: Some(0.22),
                max_expected_calibration_error: Some(0.25),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Phishing,
                min_example_count: Some(4),
                max_brier_score: Some(0.05),
                max_expected_calibration_error: Some(0.10),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Manipulation,
                min_example_count: Some(20),
                max_brier_score: Some(0.22),
                max_expected_calibration_error: Some(0.25),
            },
        ],
    }
}

pub fn pre_release_manipulation_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.24),
        max_expected_calibration_error: Some(0.24),
        min_positive_detection_rate: Some(0.80),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.35),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Manipulation,
            min_example_count: Some(28),
            max_brier_score: Some(0.20),
            max_expected_calibration_error: Some(0.22),
        }],
    }
}

pub fn pre_release_noisy_slang_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.28),
        min_positive_detection_rate: Some(0.75),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.25),
        per_threat: vec![
            ThreatCalibrationGate {
                threat_type: ThreatType::Grooming,
                min_example_count: Some(6),
                max_brier_score: Some(0.22),
                max_expected_calibration_error: Some(0.24),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Manipulation,
                min_example_count: Some(10),
                max_brier_score: Some(0.28),
                max_expected_calibration_error: Some(0.30),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::SelfHarm,
                min_example_count: Some(3),
                max_brier_score: Some(0.26),
                max_expected_calibration_error: Some(0.28),
            },
        ],
    }
}

pub fn pre_release_multilingual_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.28),
        min_positive_detection_rate: Some(0.80),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.25),
        per_threat: Vec::new(),
    }
}

pub fn evaluate_scenario_quality_gates(
    summary: &ScenarioEvaluationSummary,
    gates: &ScenarioQualityGates,
) -> ScenarioGateReport {
    let mut checks = Vec::new();

    if let Some(threshold) = gates.max_brier_score {
        checks.push(ScenarioGateCheck {
            name: "max_brier_score".to_string(),
            comparison: GateComparison::AtMost,
            actual: summary.calibration.brier_score,
            threshold,
            passed: summary.calibration.brier_score <= threshold,
        });
    }

    if let Some(threshold) = gates.max_expected_calibration_error {
        checks.push(ScenarioGateCheck {
            name: "max_expected_calibration_error".to_string(),
            comparison: GateComparison::AtMost,
            actual: summary.calibration.expected_calibration_error,
            threshold,
            passed: summary.calibration.expected_calibration_error <= threshold,
        });
    }

    if let Some(threshold) = gates.min_positive_detection_rate {
        checks.push(ScenarioGateCheck {
            name: "min_positive_detection_rate".to_string(),
            comparison: GateComparison::AtLeast,
            actual: summary.classification.positive_detection_rate,
            threshold,
            passed: summary.classification.positive_detection_rate >= threshold,
        });
    }

    if let Some(threshold) = gates.max_negative_false_positive_rate {
        checks.push(ScenarioGateCheck {
            name: "max_negative_false_positive_rate".to_string(),
            comparison: GateComparison::AtMost,
            actual: summary.classification.negative_false_positive_rate,
            threshold,
            passed: summary.classification.negative_false_positive_rate <= threshold,
        });
    }

    if let Some(threshold) = gates.min_pre_onset_detection_rate {
        let actual = if summary.lead_time.total_cases == 0 {
            0.0
        } else {
            summary.lead_time.detected_before_onset_cases as f32
                / summary.lead_time.total_cases as f32
        };
        checks.push(ScenarioGateCheck {
            name: "min_pre_onset_detection_rate".to_string(),
            comparison: GateComparison::AtLeast,
            actual,
            threshold,
            passed: actual >= threshold,
        });
    }

    for threat_gate in &gates.per_threat {
        let threat_report = calibration_for_threat(&summary.calibration, threat_gate.threat_type);
        let threat_name = format!("{:?}", threat_gate.threat_type).to_lowercase();

        if let Some(threshold) = threat_gate.min_example_count {
            let actual = threat_report
                .map(|report| report.count as f32)
                .unwrap_or(0.0);
            checks.push(ScenarioGateCheck {
                name: format!("per_threat.{threat_name}.min_example_count"),
                comparison: GateComparison::AtLeast,
                actual,
                threshold: threshold as f32,
                passed: actual >= threshold as f32,
            });
        }

        if let Some(threshold) = threat_gate.max_brier_score {
            let actual = threat_report
                .map(|report| report.brier_score)
                .unwrap_or(f32::NAN);
            checks.push(ScenarioGateCheck {
                name: format!("per_threat.{threat_name}.max_brier_score"),
                comparison: GateComparison::AtMost,
                actual,
                threshold,
                passed: threat_report.is_some_and(|report| report.brier_score <= threshold),
            });
        }

        if let Some(threshold) = threat_gate.max_expected_calibration_error {
            let actual = threat_report
                .map(|report| report.expected_calibration_error)
                .unwrap_or(f32::NAN);
            checks.push(ScenarioGateCheck {
                name: format!("per_threat.{threat_name}.max_expected_calibration_error"),
                comparison: GateComparison::AtMost,
                actual,
                threshold,
                passed: threat_report
                    .is_some_and(|report| report.expected_calibration_error <= threshold),
            });
        }
    }

    ScenarioGateReport {
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn build_single_calibration_report(
    examples: &[RiskExample],
    bin_count: usize,
) -> CalibrationReport {
    let bin_count = bin_count.max(1);
    let mut buckets: Vec<Vec<&RiskExample>> = vec![Vec::new(); bin_count];

    for example in examples {
        let score = example.predicted_score.clamp(0.0, 1.0);
        let mut idx = (score * bin_count as f32).floor() as usize;
        if idx >= bin_count {
            idx = bin_count - 1;
        }
        buckets[idx].push(example);
    }

    let mut bins = Vec::new();
    for (idx, bucket) in buckets.into_iter().enumerate() {
        if bucket.is_empty() {
            continue;
        }
        let count = bucket.len();
        let avg_prediction = bucket
            .iter()
            .map(|example| example.predicted_score)
            .sum::<f32>()
            / count as f32;
        let observed_rate = bucket
            .iter()
            .map(|example| example.target_probability)
            .sum::<f32>()
            / count as f32;
        let lower_bound = idx as f32 / bin_count as f32;
        let upper_bound = (idx + 1) as f32 / bin_count as f32;
        let gap = (avg_prediction - observed_rate).abs();
        bins.push(CalibrationBin {
            lower_bound,
            upper_bound,
            count,
            avg_prediction,
            observed_rate,
            gap,
        });
    }

    let count = examples.len();
    let brier_score = if examples.is_empty() {
        0.0
    } else {
        examples
            .iter()
            .map(|example| {
                let y = example.target_probability.clamp(0.0, 1.0);
                (example.predicted_score.clamp(0.0, 1.0) - y).powi(2)
            })
            .sum::<f32>()
            / examples.len() as f32
    };
    let expected_calibration_error = if examples.is_empty() {
        0.0
    } else {
        bins.iter()
            .map(|bin| bin.gap * (bin.count as f32 / examples.len() as f32))
            .sum()
    };

    CalibrationReport {
        count,
        brier_score,
        expected_calibration_error,
        bins,
        by_threat: Vec::new(),
    }
}

fn scenario_target_probability(
    case: &ScenarioCase,
    step_idx: usize,
    threat_type: ThreatType,
    observed: bool,
) -> f32 {
    if !observed {
        return 0.0;
    }

    if case.primary_threat == Some(threat_type) {
        if let Some(onset_step) = case.onset_step {
            if step_idx < onset_step {
                let progress = (step_idx + 1) as f32 / (onset_step + 1) as f32;
                return (0.2 + 0.4 * progress).clamp(0.0, 0.8);
            }
        }
    }

    1.0
}

fn step_language(step: &ScenarioStep, case: &ScenarioCase) -> String {
    normalize_language_code(
        step.input
            .language
            .as_deref()
            .or(Some(&case.config.language)),
    )
}

fn normalize_language_code(language: Option<&str>) -> String {
    language
        .map(str::trim)
        .filter(|language| !language.is_empty())
        .map(|language| language.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

fn all_scored_threat_types() -> [ThreatType; 13] {
    [
        ThreatType::Bullying,
        ThreatType::Grooming,
        ThreatType::Explicit,
        ThreatType::Threat,
        ThreatType::SelfHarm,
        ThreatType::Spam,
        ThreatType::Scam,
        ThreatType::Phishing,
        ThreatType::Manipulation,
        ThreatType::Nsfw,
        ThreatType::HateSpeech,
        ThreatType::Doxxing,
        ThreatType::PiiLeakage,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AccountType, Action, AnalysisResult, Confidence, ContactSnapshot, ContentType,
        ConversationType, InferenceSummary, MessageInput, ProtectionLevel, RiskBreakdown,
    };
    use aura_patterns::PatternDatabase;

    fn sample_result() -> AnalysisResult {
        AnalysisResult {
            threat_type: ThreatType::Grooming,
            confidence: Confidence::High,
            action: Action::Warn,
            score: 0.82,
            explanation: "sample".to_string(),
            detected_threats: vec![
                (ThreatType::Grooming, 0.75),
                (ThreatType::Manipulation, 0.41),
            ],
            signals: Vec::new(),
            recommended_action: None,
            risk_breakdown: RiskBreakdown::default(),
            contact_snapshot: Some(ContactSnapshot {
                sender_id: "x".to_string(),
                rating: 40.0,
                trust_level: 0.2,
                circle_tier: crate::types::CircleTier::New,
                trend: crate::types::BehavioralTrend::RapidWorsening,
                is_trusted: false,
                is_new_contact: true,
                first_seen_ms: 0,
                last_seen_ms: 1,
                conversation_count: 1,
            }),
            reason_codes: vec!["conversation.grooming.stage_sequence".to_string()],
            inference: InferenceSummary::default(),
            analysis_time_us: 123,
        }
    }

    #[test]
    fn predicted_score_for_primary_threat_prefers_final_score() {
        let result = sample_result();
        assert_eq!(
            predicted_score_for_threat(&result, ThreatType::Grooming),
            0.82
        );
        assert_eq!(
            predicted_score_for_threat(&result, ThreatType::Manipulation),
            0.41
        );
        assert_eq!(
            predicted_score_for_threat(&result, ThreatType::SelfHarm),
            0.0
        );
    }

    #[test]
    fn calibration_report_computes_brier_and_bins() {
        let examples = vec![
            RiskExample {
                threat_type: ThreatType::Grooming,
                language: "en".to_string(),
                predicted_score: 0.9,
                observed: true,
                target_probability: 1.0,
            },
            RiskExample {
                threat_type: ThreatType::Grooming,
                language: "en".to_string(),
                predicted_score: 0.8,
                observed: true,
                target_probability: 1.0,
            },
            RiskExample {
                threat_type: ThreatType::Grooming,
                language: "en".to_string(),
                predicted_score: 0.2,
                observed: false,
                target_probability: 0.0,
            },
            RiskExample {
                threat_type: ThreatType::Bullying,
                language: "en".to_string(),
                predicted_score: 0.7,
                observed: false,
                target_probability: 0.0,
            },
        ];

        let report = build_calibration_report(&examples, 5);
        assert_eq!(report.count, 4);
        assert!(!report.bins.is_empty());
        assert!(report.brier_score >= 0.0);
        assert!(report.expected_calibration_error >= 0.0);
        assert_eq!(report.by_threat.len(), 2);
    }

    #[test]
    fn lead_time_detects_early_warning() {
        let case = LeadTimeCase {
            threat_type: ThreatType::SelfHarm,
            onset_ms: 10_000,
            detection_threshold: 0.7,
            timeline: vec![
                LeadTimePoint {
                    timestamp_ms: 2_000,
                    score: 0.35,
                },
                LeadTimePoint {
                    timestamp_ms: 7_000,
                    score: 0.72,
                },
                LeadTimePoint {
                    timestamp_ms: 11_000,
                    score: 0.95,
                },
            ],
        };

        let result = evaluate_lead_time(&case);
        assert!(result.detected_before_onset);
        assert_eq!(result.first_detection_ms, Some(7_000));
        assert_eq!(result.lead_time_ms, Some(3_000));
    }

    #[test]
    fn lead_time_summary_handles_missed_cases() {
        let cases = vec![
            LeadTimeCase {
                threat_type: ThreatType::Grooming,
                onset_ms: 10_000,
                detection_threshold: 0.6,
                timeline: vec![LeadTimePoint {
                    timestamp_ms: 4_000,
                    score: 0.7,
                }],
            },
            LeadTimeCase {
                threat_type: ThreatType::Bullying,
                onset_ms: 10_000,
                detection_threshold: 0.6,
                timeline: vec![LeadTimePoint {
                    timestamp_ms: 9_000,
                    score: 0.2,
                }],
            },
        ];

        let summary = summarize_lead_time(&cases);
        assert_eq!(summary.total_cases, 2);
        assert_eq!(summary.detected_cases, 1);
        assert_eq!(summary.detected_before_onset_cases, 1);
        assert_eq!(summary.missed_cases, 1);
        assert_eq!(summary.median_lead_time_ms, Some(6_000));
    }

    #[test]
    fn lead_time_summary_averages_even_median() {
        let cases = vec![
            LeadTimeCase {
                threat_type: ThreatType::Grooming,
                onset_ms: 10_000,
                detection_threshold: 0.6,
                timeline: vec![LeadTimePoint {
                    timestamp_ms: 6_000,
                    score: 0.7,
                }],
            },
            LeadTimeCase {
                threat_type: ThreatType::Bullying,
                onset_ms: 10_000,
                detection_threshold: 0.6,
                timeline: vec![LeadTimePoint {
                    timestamp_ms: 2_000,
                    score: 0.8,
                }],
            },
        ];

        let summary = summarize_lead_time(&cases);
        assert_eq!(summary.median_lead_time_ms, Some(6_000));
    }

    #[test]
    fn risk_example_from_result_uses_threat_specific_score() {
        let result = sample_result();
        let example = risk_example_from_result(&result, ThreatType::Manipulation, true);
        assert_eq!(example.threat_type, ThreatType::Manipulation);
        assert_eq!(example.predicted_score, 0.41);
        assert!(example.observed);
    }

    #[test]
    fn scenario_runner_builds_examples_and_lead_time() {
        let db = PatternDatabase::default_mvp();
        let case = ScenarioCase {
            name: "acute_selfharm".to_string(),
            config: AuraConfig {
                account_type: AccountType::Child,
                protection_level: ProtectionLevel::High,
                language: "en".to_string(),
                ..AuraConfig::default()
            },
            primary_threat: Some(ThreatType::SelfHarm),
            onset_step: Some(1),
            detection_threshold: 0.7,
            tracked_threats: vec![ThreatType::SelfHarm],
            steps: vec![
                ScenarioStep {
                    timestamp_ms: 1_000,
                    input: MessageInput {
                        content_type: ContentType::Text,
                        text: Some("I feel hopeless and alone".to_string()),
                        image_data: None,
                        sender_id: "child".to_string(),
                        conversation_id: "diary".to_string(),
                        language: Some("en".to_string()),
                        conversation_type: ConversationType::Direct,
                        member_count: None,
                    },
                    observed_threats: vec![ThreatType::SelfHarm],
                },
                ScenarioStep {
                    timestamp_ms: 2_000,
                    input: MessageInput {
                        content_type: ContentType::Text,
                        text: Some("Goodbye everyone. I want to end it all.".to_string()),
                        image_data: None,
                        sender_id: "child".to_string(),
                        conversation_id: "diary".to_string(),
                        language: Some("en".to_string()),
                        conversation_type: ConversationType::Direct,
                        member_count: None,
                    },
                    observed_threats: vec![ThreatType::SelfHarm],
                },
            ],
        };

        let run = run_scenario_case(&db, &case);
        assert_eq!(run.step_results.len(), 2);
        assert_eq!(run.calibration_examples.len(), 2);
        assert_eq!(run.step_timestamps, vec![1_000, 2_000]);
        assert!(run.lead_time.is_some());
        assert!(run.lead_time.unwrap().first_detection_ms.is_some());
    }

    #[test]
    fn scenario_summary_aggregates_runs() {
        let db = PatternDatabase::default_mvp();
        let case = ScenarioCase {
            name: "grooming_case".to_string(),
            config: AuraConfig {
                account_type: AccountType::Child,
                protection_level: ProtectionLevel::High,
                language: "en".to_string(),
                ..AuraConfig::default()
            },
            primary_threat: Some(ThreatType::Grooming),
            onset_step: Some(1),
            detection_threshold: 0.5,
            tracked_threats: vec![ThreatType::Grooming],
            steps: vec![
                ScenarioStep {
                    timestamp_ms: 1_000,
                    input: MessageInput {
                        content_type: ContentType::Text,
                        text: Some("You're so special and mature for your age".to_string()),
                        image_data: None,
                        sender_id: "stranger".to_string(),
                        conversation_id: "dm".to_string(),
                        language: Some("en".to_string()),
                        conversation_type: ConversationType::Direct,
                        member_count: None,
                    },
                    observed_threats: vec![ThreatType::Grooming],
                },
                ScenarioStep {
                    timestamp_ms: 2_000,
                    input: MessageInput {
                        content_type: ContentType::Text,
                        text: Some(
                            "Don't tell your parents about me. Let's move to Telegram.".to_string(),
                        ),
                        image_data: None,
                        sender_id: "stranger".to_string(),
                        conversation_id: "dm".to_string(),
                        language: Some("en".to_string()),
                        conversation_type: ConversationType::Direct,
                        member_count: None,
                    },
                    observed_threats: vec![ThreatType::Grooming],
                },
            ],
        };

        let run = run_scenario_case(&db, &case);
        let summary = summarize_scenario_runs(&[run], 5);
        assert_eq!(summary.calibration.count, 2);
        assert_eq!(summary.lead_time.total_cases, 1);
        assert_eq!(summary.classification.total_positive_scenarios, 1);
        assert_eq!(summary.classification.detected_positive_scenarios, 1);
        assert_eq!(summary.scenarios.len(), 1);
    }

    #[test]
    fn scenario_summary_builds_language_slices() {
        let db = PatternDatabase::default_mvp();
        let case = ScenarioCase {
            name: "mixed_case".to_string(),
            config: AuraConfig {
                account_type: AccountType::Child,
                protection_level: ProtectionLevel::High,
                language: "en".to_string(),
                ..AuraConfig::default()
            },
            primary_threat: Some(ThreatType::Grooming),
            onset_step: Some(1),
            detection_threshold: 0.5,
            tracked_threats: vec![ThreatType::Grooming],
            steps: vec![
                ScenarioStep {
                    timestamp_ms: 1_000,
                    input: MessageInput {
                        content_type: ContentType::Text,
                        text: Some("You're so mature for your age.".to_string()),
                        image_data: None,
                        sender_id: "stranger".to_string(),
                        conversation_id: "dm".to_string(),
                        language: Some("en".to_string()),
                        conversation_type: ConversationType::Direct,
                        member_count: None,
                    },
                    observed_threats: vec![ThreatType::Grooming],
                },
                ScenarioStep {
                    timestamp_ms: 2_000,
                    input: MessageInput {
                        content_type: ContentType::Text,
                        text: Some("Нікому не кажи про наші чати.".to_string()),
                        image_data: None,
                        sender_id: "stranger".to_string(),
                        conversation_id: "dm".to_string(),
                        language: Some("uk".to_string()),
                        conversation_type: ConversationType::Direct,
                        member_count: None,
                    },
                    observed_threats: vec![ThreatType::Grooming],
                },
            ],
        };

        let run = run_scenario_case(&db, &case);
        let summary = summarize_scenario_runs(&[run], 5);

        let en_slice = summary
            .language_slices
            .iter()
            .find(|slice| slice.language == "en")
            .expect("english slice");
        let uk_slice = summary
            .language_slices
            .iter()
            .find(|slice| slice.language == "uk")
            .expect("ukrainian slice");

        assert_eq!(en_slice.scenario_count, 1);
        assert_eq!(uk_slice.scenario_count, 1);
        assert!(en_slice.calibration.count > 0);
        assert!(uk_slice.calibration.count > 0);
    }

    #[test]
    fn scenario_classification_distinguishes_positive_and_negative_runs() {
        let mut positive = AnalysisResult::clean(1);
        positive.threat_type = ThreatType::Grooming;
        positive.score = 0.72;
        positive.detected_threats = vec![(ThreatType::Grooming, 0.72)];

        let negative = AnalysisResult::clean(2);

        let false_positive = AnalysisResult {
            score: 0.81,
            threat_type: ThreatType::Manipulation,
            detected_threats: vec![(ThreatType::Manipulation, 0.81)],
            ..AnalysisResult::clean(3)
        };

        let runs = vec![
            ScenarioRunResult {
                name: "positive_case".to_string(),
                primary_threat: Some(ThreatType::Grooming),
                detection_threshold: 0.6,
                tracked_threats: vec![ThreatType::Grooming],
                languages: vec!["en".to_string()],
                step_timestamps: vec![1_000],
                step_results: vec![positive],
                calibration_examples: Vec::new(),
                lead_time: None,
            },
            ScenarioRunResult {
                name: "negative_case".to_string(),
                primary_threat: None,
                detection_threshold: 0.6,
                tracked_threats: vec![ThreatType::Manipulation],
                languages: vec!["en".to_string()],
                step_timestamps: vec![2_000],
                step_results: vec![negative],
                calibration_examples: Vec::new(),
                lead_time: None,
            },
            ScenarioRunResult {
                name: "false_positive_case".to_string(),
                primary_threat: None,
                detection_threshold: 0.6,
                tracked_threats: vec![ThreatType::Manipulation],
                languages: vec!["en".to_string()],
                step_timestamps: vec![3_000],
                step_results: vec![false_positive],
                calibration_examples: Vec::new(),
                lead_time: None,
            },
        ];

        let summary = summarize_scenario_classification(&runs);
        assert_eq!(summary.total_positive_scenarios, 1);
        assert_eq!(summary.detected_positive_scenarios, 1);
        assert_eq!(summary.total_negative_scenarios, 2);
        assert_eq!(summary.false_positive_scenarios, 1);
        assert!(
            (summary.negative_false_positive_rate - 0.5).abs() < f32::EPSILON,
            "expected 1/2 false-positive negative scenarios"
        );
    }

    #[test]
    fn quality_gates_report_failing_checks() {
        let summary = ScenarioEvaluationSummary {
            calibration: CalibrationReport {
                count: 10,
                brier_score: 0.30,
                expected_calibration_error: 0.28,
                bins: Vec::new(),
                by_threat: Vec::new(),
            },
            lead_time: LeadTimeSummary {
                total_cases: 4,
                detected_cases: 2,
                detected_before_onset_cases: 1,
                missed_cases: 2,
                mean_lead_time_ms: None,
                median_lead_time_ms: None,
            },
            classification: ScenarioClassificationSummary {
                total_positive_scenarios: 4,
                detected_positive_scenarios: 2,
                missed_positive_scenarios: 2,
                positive_detection_rate: 0.5,
                total_negative_scenarios: 2,
                clean_negative_scenarios: 1,
                false_positive_scenarios: 1,
                negative_false_positive_rate: 0.5,
                scenarios: Vec::new(),
            },
            language_slices: Vec::new(),
            scenarios: Vec::new(),
        };

        let report = evaluate_scenario_quality_gates(
            &summary,
            &ScenarioQualityGates {
                max_brier_score: Some(0.2),
                max_expected_calibration_error: Some(0.2),
                min_positive_detection_rate: Some(0.8),
                max_negative_false_positive_rate: Some(0.1),
                min_pre_onset_detection_rate: Some(0.5),
                per_threat: Vec::new(),
            },
        );

        assert!(!report.passed);
        assert_eq!(report.checks.len(), 5);
        assert!(report.checks.iter().all(|check| !check.passed));
    }

    #[test]
    fn quality_gates_can_fail_on_per_threat_calibration() {
        let summary = ScenarioEvaluationSummary {
            calibration: CalibrationReport {
                count: 20,
                brier_score: 0.10,
                expected_calibration_error: 0.10,
                bins: Vec::new(),
                by_threat: vec![ThreatCalibrationReport {
                    threat_type: ThreatType::Manipulation,
                    count: 24,
                    brier_score: 0.28,
                    expected_calibration_error: 0.31,
                    bins: Vec::new(),
                }],
            },
            lead_time: LeadTimeSummary {
                total_cases: 4,
                detected_cases: 4,
                detected_before_onset_cases: 2,
                missed_cases: 0,
                mean_lead_time_ms: None,
                median_lead_time_ms: None,
            },
            classification: ScenarioClassificationSummary {
                total_positive_scenarios: 4,
                detected_positive_scenarios: 4,
                missed_positive_scenarios: 0,
                positive_detection_rate: 1.0,
                total_negative_scenarios: 2,
                clean_negative_scenarios: 2,
                false_positive_scenarios: 0,
                negative_false_positive_rate: 0.0,
                scenarios: Vec::new(),
            },
            language_slices: Vec::new(),
            scenarios: Vec::new(),
        };

        let report = evaluate_scenario_quality_gates(
            &summary,
            &ScenarioQualityGates {
                max_brier_score: Some(0.2),
                max_expected_calibration_error: Some(0.2),
                min_positive_detection_rate: Some(0.8),
                max_negative_false_positive_rate: Some(0.1),
                min_pre_onset_detection_rate: Some(0.5),
                per_threat: vec![ThreatCalibrationGate {
                    threat_type: ThreatType::Manipulation,
                    min_example_count: Some(20),
                    max_brier_score: Some(0.22),
                    max_expected_calibration_error: Some(0.25),
                }],
            },
        );

        assert!(!report.passed);
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "per_threat.manipulation.max_brier_score" && !check.passed));
        assert!(report.checks.iter().any(|check| check.name
            == "per_threat.manipulation.max_expected_calibration_error"
            && !check.passed));
    }

    #[test]
    fn calibration_lookup_returns_specific_threat_report() {
        let report = CalibrationReport {
            count: 2,
            brier_score: 0.1,
            expected_calibration_error: 0.1,
            bins: Vec::new(),
            by_threat: vec![ThreatCalibrationReport {
                threat_type: ThreatType::Phishing,
                count: 5,
                brier_score: 0.02,
                expected_calibration_error: 0.04,
                bins: Vec::new(),
            }],
        };

        let phishing = calibration_for_threat(&report, ThreatType::Phishing)
            .expect("phishing report should be present");
        assert_eq!(phishing.count, 5);
        assert!(calibration_for_threat(&report, ThreatType::Manipulation).is_none());
    }
}
