//! Benign everyday-chat negative suite.
//!
//! Every case is a genuinely benign child or teen message: school, homework,
//! gaming, family logistics, sports, food, weather, plans, tech support, and
//! emotions without crisis. The corpus deliberately reuses vocabulary shared
//! with risky compositions ("kill this level", "take care", "my phone is
//! dead", "login") so the detector cannot regress into warnings or guardian
//! alerts on ordinary chat without failing a release gate.
//!
//! The suite is negatives-only. Recall metrics are meaningless here and are
//! never gated; the release gate is the false-positive rate, measured both by
//! the shared threshold-based classification and by the stricter product
//! criterion "any step produced a threat type or a non-`Allow` action".

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aura_patterns::PatternDatabase;

use crate::eval::{
    evaluate_scenario_quality_gates, run_scenario_cases, summarize_scenario_runs, GateComparison,
    ScenarioEvaluationSummary, ScenarioGateCheck, ScenarioGateReport, ScenarioQualityGates,
    ScenarioRunResult,
};
use crate::eval_realistic::{
    parse_realistic_chat_bundle, RealisticChatBundle, RealisticChatManifest, RealisticChatMetadata,
    RealisticChatScenario,
};
use crate::types::Action;

/// Dataset identity pinned by the corpus file and the dataset changelog.
pub const BENIGN_EVERYDAY_CHAT_DATASET_ID: &str = "aura_benign_everyday_chat_v1";

/// Maximum share of benign conversations that may produce any threat type or
/// any action other than `Allow` on any step.
pub const BENIGN_CHAT_MAX_ACTION_FALSE_POSITIVE_RATE: f32 = 0.01;

/// Name of the product-level false-positive gate check.
pub const BENIGN_CHAT_ACTION_GATE_NAME: &str = "max_action_false_positive_rate";

#[derive(Debug, Clone)]
pub struct BenignChatSliceSummary {
    pub slice_id: String,
    pub case_count: usize,
    pub evaluation: ScenarioEvaluationSummary,
    pub action_flagged_scenarios: usize,
    pub action_false_positive_rate: f32,
}

#[derive(Debug, Clone)]
pub struct BenignChatSuiteSummary {
    pub manifest: RealisticChatManifest,
    pub evaluation: ScenarioEvaluationSummary,
    pub action_flagged_scenarios: usize,
    pub action_false_positive_rate: f32,
    pub flagged_scenario_names: Vec<String>,
    pub by_language: Vec<BenignChatSliceSummary>,
    pub scenarios: Vec<RealisticChatMetadata>,
}

type BenignSuiteGateResult = (ScenarioGateReport, Vec<(String, ScenarioGateReport)>);

pub fn benign_everyday_chat_bundle() -> RealisticChatBundle {
    static BUNDLE: OnceLock<RealisticChatBundle> = OnceLock::new();
    BUNDLE
        .get_or_init(|| {
            parse_benign_everyday_chat_bundle(include_str!(
                "../data/benign_everyday_chat_cases.json"
            ))
            .expect("valid benign everyday chat corpus")
        })
        .clone()
}

pub fn benign_everyday_chat_scenarios() -> Vec<RealisticChatScenario> {
    benign_everyday_chat_bundle().scenarios
}

/// Parses the corpus with the shared realistic-chat loader and then enforces
/// the negatives-only contract.
pub fn parse_benign_everyday_chat_bundle(json: &str) -> Result<RealisticChatBundle, String> {
    let bundle = parse_realistic_chat_bundle(json)?;
    validate_benign_bundle(&bundle)?;
    Ok(bundle)
}

fn validate_benign_bundle(bundle: &RealisticChatBundle) -> Result<(), String> {
    if bundle.manifest.dataset_id != BENIGN_EVERYDAY_CHAT_DATASET_ID {
        return Err(format!(
            "benign corpus dataset_id must be {BENIGN_EVERYDAY_CHAT_DATASET_ID}, got {}",
            bundle.manifest.dataset_id
        ));
    }
    if bundle.scenarios.is_empty() {
        return Err("benign corpus must contain at least one case".to_string());
    }
    for scenario in &bundle.scenarios {
        let name = &scenario.metadata.scenario_name;
        if scenario.case.primary_threat.is_some() {
            return Err(format!(
                "benign case {name} must not declare primary_threat"
            ));
        }
        if scenario.case.onset_step.is_some() {
            return Err(format!("benign case {name} must not declare onset_step"));
        }
        if scenario.case.tracked_threats.is_empty() {
            return Err(format!(
                "benign case {name} must track threat families for false-positive accounting"
            ));
        }
        if scenario
            .case
            .steps
            .iter()
            .any(|step| !step.observed_threats.is_empty())
        {
            return Err(format!(
                "benign case {name} must not declare observed_threats"
            ));
        }
        if scenario
            .metadata
            .source_family
            .as_deref()
            .is_none_or(str::is_empty)
        {
            return Err(format!("benign case {name} must record a source_family"));
        }
        if !matches!(
            scenario.metadata.review_status.as_deref(),
            Some("seed_reviewed" | "gold_reviewed")
        ) {
            return Err(format!(
                "benign case {name} must record a supported review_status"
            ));
        }
        if scenario.metadata.policy_expectation_case.is_none() {
            return Err(format!(
                "benign case {name} must reference a policy expectation case"
            ));
        }
    }
    Ok(())
}

pub fn pre_release_benign_chat_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: None,
        max_expected_calibration_error: None,
        min_positive_detection_rate: None,
        max_negative_false_positive_rate: Some(BENIGN_CHAT_MAX_ACTION_FALSE_POSITIVE_RATE),
        min_pre_onset_detection_rate: None,
        per_threat: Vec::new(),
    }
}

pub fn run_benign_everyday_chat_suite(
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> BenignChatSuiteSummary {
    let bundle = benign_everyday_chat_bundle();
    let scenarios = bundle.scenarios;
    let runs = run_scenario_cases(pattern_db, scenarios.iter().map(|scenario| &scenario.case)).runs;

    let flagged_scenario_names = runs
        .iter()
        .filter(|run| scenario_is_action_flagged(run))
        .map(|run| run.name.clone())
        .collect::<Vec<_>>();
    let action_flagged_scenarios = flagged_scenario_names.len();

    let mut grouped = BTreeMap::<String, Vec<usize>>::new();
    for (idx, scenario) in scenarios.iter().enumerate() {
        grouped
            .entry(scenario.metadata.default_language.clone())
            .or_default()
            .push(idx);
    }
    let by_language = grouped
        .into_iter()
        .map(|(slice_id, indices)| {
            let slice_runs = indices
                .iter()
                .map(|idx| runs[*idx].clone())
                .collect::<Vec<_>>();
            let flagged = slice_runs
                .iter()
                .filter(|run| scenario_is_action_flagged(run))
                .count();
            BenignChatSliceSummary {
                slice_id,
                case_count: indices.len(),
                evaluation: summarize_scenario_runs(&slice_runs, bin_count),
                action_flagged_scenarios: flagged,
                action_false_positive_rate: rate(flagged, indices.len()),
            }
        })
        .collect();

    BenignChatSuiteSummary {
        manifest: bundle.manifest,
        evaluation: summarize_scenario_runs(&runs, bin_count),
        action_flagged_scenarios,
        action_false_positive_rate: rate(action_flagged_scenarios, runs.len()),
        flagged_scenario_names,
        by_language,
        scenarios: scenarios
            .into_iter()
            .map(|scenario| scenario.metadata)
            .collect(),
    }
}

/// Evaluates the shared classification gates and adds the product-level
/// action gate to the overall and per-language reports.
pub fn evaluate_benign_chat_suite(
    summary: &BenignChatSuiteSummary,
    gates: &ScenarioQualityGates,
) -> BenignSuiteGateResult {
    let overall = with_action_gate(
        evaluate_scenario_quality_gates(&summary.evaluation, gates),
        summary.action_false_positive_rate,
    );
    let by_language = summary
        .by_language
        .iter()
        .map(|slice| {
            (
                slice.slice_id.clone(),
                with_action_gate(
                    evaluate_scenario_quality_gates(&slice.evaluation, gates),
                    slice.action_false_positive_rate,
                ),
            )
        })
        .collect();
    (overall, by_language)
}

fn scenario_is_action_flagged(run: &ScenarioRunResult) -> bool {
    run.step_results
        .iter()
        .any(|result| result.action != Action::Allow || result.is_threat())
}

fn with_action_gate(mut report: ScenarioGateReport, actual: f32) -> ScenarioGateReport {
    let passed = actual <= BENIGN_CHAT_MAX_ACTION_FALSE_POSITIVE_RATE;
    report.checks.push(ScenarioGateCheck {
        name: BENIGN_CHAT_ACTION_GATE_NAME.to_string(),
        comparison: GateComparison::AtMost,
        actual,
        threshold: BENIGN_CHAT_MAX_ACTION_FALSE_POSITIVE_RATE,
        passed,
    });
    report.passed &= passed;
    report
}

fn rate(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_corpus_is_negatives_only_and_balanced_across_languages() {
        let bundle = benign_everyday_chat_bundle();
        assert_eq!(bundle.manifest.dataset_id, BENIGN_EVERYDAY_CHAT_DATASET_ID);
        let mut per_language = BTreeMap::<String, usize>::new();
        for scenario in &bundle.scenarios {
            assert!(scenario.case.primary_threat.is_none());
            assert_eq!(
                scenario.metadata.source_family.as_deref(),
                Some("aura_core_team_synthetic")
            );
            assert_eq!(
                scenario.metadata.review_status.as_deref(),
                Some("seed_reviewed")
            );
            assert!(scenario.metadata.policy_expectation_case.is_some());
            *per_language
                .entry(scenario.metadata.default_language.clone())
                .or_default() += 1;
        }
        for language in ["en", "uk", "ru"] {
            assert!(
                per_language.get(language).copied().unwrap_or(0) >= 60,
                "language {language} needs at least 60 benign cases"
            );
        }
    }

    #[test]
    fn benign_loader_rejects_positive_cases() {
        let json = r#"{
          "schema_version": 1,
          "dataset_id": "aura_benign_everyday_chat_v1",
          "dataset_label": "x",
          "maintainer": "aura_core_team",
          "created_at_ms": 1,
          "updated_at_ms": 1,
          "cases": [{
            "id": "bad",
            "default_language": "en",
            "age_band": "child",
            "relationship": "peer",
            "primary_threat": "grooming",
            "onset_step": 0,
            "tracked_threats": ["grooming"],
            "messages": [{"text": "hello", "sender_id": "peer_1"}]
          }]
        }"#;
        assert!(parse_benign_everyday_chat_bundle(json).is_err());
    }

    #[test]
    fn action_gate_fails_when_a_benign_scenario_is_flagged() {
        let report = with_action_gate(
            ScenarioGateReport {
                passed: true,
                checks: Vec::new(),
            },
            0.05,
        );
        assert!(!report.passed);
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].name, BENIGN_CHAT_ACTION_GATE_NAME);
    }

    #[test]
    fn verified_school_peer_meetings_stay_benign_across_languages() {
        let database = PatternDatabase::default_mvp();
        let scenarios = benign_everyday_chat_scenarios();
        let school_meetings = scenarios
            .iter()
            .filter(|scenario| scenario.metadata.scenario_name.ends_with("_plans_01"))
            .collect::<Vec<_>>();
        assert_eq!(school_meetings.len(), 3);

        for scenario in &school_meetings {
            assert_eq!(
                scenario.metadata.sender_relationship,
                crate::SenderRelationship::Peer
            );
            assert_eq!(
                scenario.metadata.relationship_trust_source,
                crate::RelationshipTrustSource::SchoolDirectory
            );
        }

        let runs = run_scenario_cases(
            &database,
            school_meetings.iter().map(|scenario| &scenario.case),
        );
        assert!(
            runs.runs.iter().all(|run| !scenario_is_action_flagged(run)),
            "verified school-peer logistics must remain benign: {:#?}",
            runs.runs
        );
    }
}
