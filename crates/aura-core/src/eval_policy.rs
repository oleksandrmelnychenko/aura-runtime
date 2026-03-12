use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Deserialize;

use crate::{
    canonical_messenger_scenarios, canonical_multilingual_scenarios, suicide_coercion_case,
    GateComparison, ScenarioCase, ScenarioGateCheck, ScenarioGateReport, ScenarioRunResult,
    UiAction,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioPolicyExpectation {
    pub scenario_name: String,
    pub required_any: Vec<UiAction>,
    pub required_by_onset: Vec<UiAction>,
    pub forbidden_any: Vec<UiAction>,
    pub forbid_any_action: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioPolicyRecord {
    pub scenario_name: String,
    pub expectation_name: String,
    pub all_actions: Vec<UiAction>,
    pub actions_by_onset: Vec<UiAction>,
    pub missing_required_any: Vec<UiAction>,
    pub missing_required_by_onset: Vec<UiAction>,
    pub forbidden_actions_present: Vec<UiAction>,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyActionSummary {
    pub total_scenarios: usize,
    pub passed_scenarios: usize,
    pub failed_scenarios: usize,
    pub scenario_pass_rate: f32,
    pub required_any_coverage: f32,
    pub required_by_onset_coverage: f32,
    pub forbidden_violation_rate: f32,
    pub scenarios: Vec<ScenarioPolicyRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyActionQualityGates {
    pub min_scenario_pass_rate: Option<f32>,
    pub min_required_any_coverage: Option<f32>,
    pub min_required_by_onset_coverage: Option<f32>,
    pub max_forbidden_violation_rate: Option<f32>,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyExpectationFile {
    scenarios: Vec<PolicyExpectationSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyExpectationSpec {
    scenario_name: String,
    #[serde(default)]
    required_any: Vec<UiAction>,
    #[serde(default)]
    required_by_onset: Vec<UiAction>,
    #[serde(default)]
    forbidden_any: Vec<UiAction>,
    #[serde(default)]
    forbid_any_action: bool,
}

pub fn canonical_policy_action_expectations() -> Vec<ScenarioPolicyExpectation> {
    policy_expectation_file()
        .scenarios
        .iter()
        .map(|spec| ScenarioPolicyExpectation {
            scenario_name: spec.scenario_name.clone(),
            required_any: dedupe_actions(&spec.required_any),
            required_by_onset: dedupe_actions(&spec.required_by_onset),
            forbidden_any: dedupe_actions(&spec.forbidden_any),
            forbid_any_action: spec.forbid_any_action,
        })
        .collect()
}

pub fn pre_release_policy_action_gates() -> PolicyActionQualityGates {
    PolicyActionQualityGates {
        min_scenario_pass_rate: Some(1.0),
        min_required_any_coverage: Some(1.0),
        min_required_by_onset_coverage: Some(1.0),
        max_forbidden_violation_rate: Some(0.0),
    }
}

pub fn summarize_policy_actions(
    runs: &[ScenarioRunResult],
    expectations: &[ScenarioPolicyExpectation],
) -> PolicyActionSummary {
    let expectation_names = runs.iter().map(|run| run.name.clone()).collect::<Vec<_>>();
    summarize_policy_actions_with_expectation_names(runs, &expectation_names, expectations)
}

pub fn summarize_policy_actions_with_expectation_names(
    runs: &[ScenarioRunResult],
    expectation_names: &[String],
    expectations: &[ScenarioPolicyExpectation],
) -> PolicyActionSummary {
    assert_eq!(
        runs.len(),
        expectation_names.len(),
        "runs and expectation_names must have same length"
    );

    let expectation_map: BTreeMap<_, _> = expectations
        .iter()
        .map(|expectation| (expectation.scenario_name.as_str(), expectation))
        .collect();
    let mut records = Vec::with_capacity(runs.len());

    let mut required_any_expectations = 0usize;
    let mut required_any_hits = 0usize;
    let mut required_by_onset_expectations = 0usize;
    let mut required_by_onset_hits = 0usize;
    let mut forbidden_checks = 0usize;
    let mut forbidden_violations = 0usize;

    for (run, expectation_name) in runs.iter().zip(expectation_names.iter()) {
        let expectation = expectation_map
            .get(expectation_name.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "missing policy expectation {} for run {}",
                    expectation_name, run.name
                )
            });
        let all_actions = collect_actions(run.step_results.iter().flat_map(step_actions));
        let actions_by_onset = collect_actions(
            run.step_results
                .iter()
                .take(
                    onset_end_index(run)
                        .map(|idx| idx + 1)
                        .unwrap_or(run.step_results.len()),
                )
                .flat_map(step_actions),
        );

        let missing_required_any: Vec<_> = expectation
            .required_any
            .iter()
            .copied()
            .filter(|action| !all_actions.contains(action))
            .collect();
        required_any_expectations += expectation.required_any.len();
        required_any_hits += expectation.required_any.len() - missing_required_any.len();

        let missing_required_by_onset: Vec<_> = expectation
            .required_by_onset
            .iter()
            .copied()
            .filter(|action| !actions_by_onset.contains(action))
            .collect();
        required_by_onset_expectations += expectation.required_by_onset.len();
        required_by_onset_hits +=
            expectation.required_by_onset.len() - missing_required_by_onset.len();

        let forbidden_any = if expectation.forbid_any_action {
            all_ui_actions()
        } else {
            expectation.forbidden_any.clone()
        };
        let forbidden_actions_present: Vec<_> = forbidden_any
            .iter()
            .copied()
            .filter(|action| all_actions.contains(action))
            .collect();

        if expectation.forbid_any_action {
            forbidden_checks += usize::from(!all_actions.is_empty());
        } else if !forbidden_any.is_empty() {
            forbidden_checks += 1;
            if !forbidden_actions_present.is_empty() {
                forbidden_violations += 1;
            }
        }

        let passed = missing_required_any.is_empty()
            && missing_required_by_onset.is_empty()
            && forbidden_actions_present.is_empty();

        records.push(ScenarioPolicyRecord {
            scenario_name: run.name.clone(),
            expectation_name: expectation_name.clone(),
            all_actions: all_actions.into_iter().collect(),
            actions_by_onset: actions_by_onset.into_iter().collect(),
            missing_required_any,
            missing_required_by_onset,
            forbidden_actions_present,
            passed,
        });
    }

    let passed_scenarios = records.iter().filter(|record| record.passed).count();
    let failed_scenarios = records.len().saturating_sub(passed_scenarios);

    PolicyActionSummary {
        total_scenarios: records.len(),
        passed_scenarios,
        failed_scenarios,
        scenario_pass_rate: rate(passed_scenarios, records.len()),
        required_any_coverage: rate(required_any_hits, required_any_expectations),
        required_by_onset_coverage: rate(required_by_onset_hits, required_by_onset_expectations),
        forbidden_violation_rate: violation_rate(forbidden_violations, forbidden_checks),
        scenarios: records,
    }
}

pub fn evaluate_policy_action_gates(
    summary: &PolicyActionSummary,
    gates: &PolicyActionQualityGates,
) -> ScenarioGateReport {
    let mut checks = Vec::new();

    evaluate_gate(
        &mut checks,
        "policy.scenario_pass_rate",
        GateComparison::AtLeast,
        summary.scenario_pass_rate,
        gates.min_scenario_pass_rate,
    );
    evaluate_gate(
        &mut checks,
        "policy.required_any_coverage",
        GateComparison::AtLeast,
        summary.required_any_coverage,
        gates.min_required_any_coverage,
    );
    evaluate_gate(
        &mut checks,
        "policy.required_by_onset_coverage",
        GateComparison::AtLeast,
        summary.required_by_onset_coverage,
        gates.min_required_by_onset_coverage,
    );
    evaluate_gate(
        &mut checks,
        "policy.forbidden_violation_rate",
        GateComparison::AtMost,
        summary.forbidden_violation_rate,
        gates.max_forbidden_violation_rate,
    );

    ScenarioGateReport {
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn onset_end_index(run: &ScenarioRunResult) -> Option<usize> {
    run.lead_time.as_ref().and_then(|lead_time| {
        run.step_timestamps
            .iter()
            .position(|ts| *ts == lead_time.onset_ms)
    })
}

fn step_actions<'a>(result: &'a crate::AnalysisResult) -> impl Iterator<Item = UiAction> + 'a {
    result
        .recommended_action
        .iter()
        .flat_map(|recommendation| recommendation.ui_actions.iter().copied())
}

fn collect_actions(actions: impl Iterator<Item = UiAction>) -> BTreeSet<UiAction> {
    actions.collect()
}

fn dedupe_actions(actions: &[UiAction]) -> Vec<UiAction> {
    actions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn all_ui_actions() -> Vec<UiAction> {
    vec![
        UiAction::WarnBeforeSend,
        UiAction::WarnBeforeDisplay,
        UiAction::BlurUntilTap,
        UiAction::ConfirmBeforeOpenLink,
        UiAction::SuggestBlockContact,
        UiAction::SuggestReport,
        UiAction::RestrictUnknownContact,
        UiAction::SlowDownConversation,
        UiAction::ShowCrisisSupport,
        UiAction::EscalateToGuardian,
    ]
}

fn evaluate_gate(
    checks: &mut Vec<ScenarioGateCheck>,
    name: &str,
    comparison: GateComparison,
    actual: f32,
    threshold: Option<f32>,
) {
    let Some(threshold) = threshold else {
        return;
    };

    let passed = match comparison {
        GateComparison::AtMost => actual <= threshold,
        GateComparison::AtLeast => actual >= threshold,
    };

    checks.push(ScenarioGateCheck {
        name: name.to_string(),
        comparison,
        actual,
        threshold,
        passed,
    });
}

fn rate(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f32 / denominator as f32
    }
}

fn violation_rate(violations: usize, checks: usize) -> f32 {
    if checks == 0 {
        0.0
    } else {
        violations as f32 / checks as f32
    }
}

fn policy_expectation_file() -> &'static PolicyExpectationFile {
    static FILE: OnceLock<PolicyExpectationFile> = OnceLock::new();

    FILE.get_or_init(|| {
        let file: PolicyExpectationFile =
            serde_json::from_str(include_str!("../data/action_policy_expectations.json"))
                .expect("valid policy expectation file");
        validate_policy_expectation_file(&file).expect("valid policy expectations");
        file
    })
}

fn validate_policy_expectation_file(file: &PolicyExpectationFile) -> Result<(), String> {
    let policy_cases = canonical_policy_expectation_cases();
    let expected_names = policy_cases
        .into_iter()
        .map(|case| case.name)
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();

    for scenario in &file.scenarios {
        if !seen.insert(scenario.scenario_name.clone()) {
            return Err(format!(
                "duplicate policy expectation scenario {}",
                scenario.scenario_name
            ));
        }
        if !expected_names.contains(&scenario.scenario_name) {
            return Err(format!(
                "unknown policy expectation scenario {}",
                scenario.scenario_name
            ));
        }
        if scenario.forbid_any_action && !scenario.forbidden_any.is_empty() {
            return Err(format!(
                "scenario {} cannot set forbid_any_action together with forbidden_any",
                scenario.scenario_name
            ));
        }
        if scenario.required_by_onset.is_empty() {
            continue;
        }

        let case = canonical_policy_expectation_cases()
            .into_iter()
            .find(|case| case.name == scenario.scenario_name)
            .expect("scenario exists");
        if case.onset_step.is_none() {
            return Err(format!(
                "scenario {} requires by-onset actions but has no onset_step",
                scenario.scenario_name
            ));
        }
    }

    if seen != expected_names {
        let missing = expected_names
            .difference(&seen)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("missing policy expectations for: {missing}"));
    }

    Ok(())
}

fn canonical_policy_expectation_cases() -> Vec<ScenarioCase> {
    let mut names = BTreeSet::new();
    canonical_messenger_scenarios()
        .into_iter()
        .chain(canonical_multilingual_scenarios())
        .chain(std::iter::once(suicide_coercion_case()))
        .filter(|case| names.insert(case.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use aura_patterns::PatternDatabase;

    use super::*;
    use crate::run_scenario_case;

    #[test]
    fn policy_expectation_file_covers_canonical_scenarios() {
        let expectations = canonical_policy_action_expectations();
        let expected_names = canonical_policy_expectation_cases()
            .into_iter()
            .map(|case| case.name)
            .collect::<BTreeSet<_>>();
        let actual_names = expectations
            .into_iter()
            .map(|expectation| expectation.scenario_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(actual_names, expected_names);
    }

    #[test]
    fn negative_controls_forbid_any_action() {
        let expectations = canonical_policy_action_expectations();
        let safe_cases = [
            "negative_control_trusted_adult",
            "negative_control_teen_flirting",
            "false_positive_friends",
            "negative_control_multilingual_support",
            "negative_control_multilingual_peer_chat",
        ];

        for name in safe_cases {
            let expectation = expectations
                .iter()
                .find(|expectation| expectation.scenario_name == name)
                .expect("expectation present");
            assert!(expectation.forbid_any_action);
        }
    }

    #[test]
    fn policy_action_pre_release_gates_pass() {
        let db = PatternDatabase::default_mvp();
        let runs = canonical_policy_expectation_cases()
            .into_iter()
            .map(|case| run_scenario_case(&db, &case))
            .collect::<Vec<_>>();
        let summary = summarize_policy_actions(&runs, &canonical_policy_action_expectations());
        let report = evaluate_policy_action_gates(&summary, &pre_release_policy_action_gates());

        assert!(
            report.passed,
            "policy action gates should pass, got failed scenarios: {:?}, checks: {:?}",
            summary
                .scenarios
                .iter()
                .filter(|scenario| !scenario.passed)
                .collect::<Vec<_>>(),
            report.checks
        );
    }
}
