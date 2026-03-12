use std::collections::BTreeSet;
use std::sync::OnceLock;

use aura_patterns::PatternDatabase;
use serde::Deserialize;

use crate::{
    canonical_corpus_seed_scenarios, canonical_policy_action_expectations,
    default_corpus_style_profiles, evaluate_policy_action_gates, evaluate_scenario_quality_gates,
    generate_corpus_style_variants, pre_release_corpus_style_gates,
    pre_release_policy_action_gates, run_scenario_case,
    summarize_policy_actions_with_expectation_names, summarize_scenario_runs, AccountType,
    ConversationType, CorpusStyleProfile, PolicyActionQualityGates, PolicyActionSummary,
    ScenarioCase, ScenarioEvaluationSummary, ScenarioGateReport, ScenarioQualityGates, ThreatType,
};

#[derive(Debug, Clone, PartialEq)]
pub struct SocialContextCohortSummary {
    pub cohort_id: String,
    pub description: String,
    pub variant_count: usize,
    pub base_cases: Vec<String>,
    pub style_profiles: Vec<String>,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
}

#[derive(Debug, Clone)]
pub struct SocialContextSuiteSummary {
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
    pub cohorts: Vec<SocialContextCohortSummary>,
    pub variants: Vec<SocialContextVariantRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SocialContextVariantRecord {
    pub base_case_name: String,
    pub variant_name: String,
    pub style_profile: Option<String>,
    pub mutated_steps: usize,
}

#[derive(Debug, Clone)]
struct PreparedSocialContextCase {
    variant: SocialContextVariantRecord,
    case: ScenarioCase,
}

#[derive(Debug, Clone, Deserialize)]
struct SocialContextFile {
    cohorts: Vec<SocialContextCohortSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct SocialContextCohortSpec {
    id: String,
    description: String,
    base_case_names: Vec<String>,
    #[serde(default)]
    account_types: Vec<AccountType>,
    #[serde(default)]
    conversation_types: Vec<ConversationType>,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    style_profiles: Vec<String>,
    gates: SocialContextGateSpec,
}

#[derive(Debug, Clone, Deserialize)]
struct SocialContextGateSpec {
    #[serde(default)]
    max_brier_score: Option<f32>,
    #[serde(default)]
    max_expected_calibration_error: Option<f32>,
    #[serde(default)]
    min_positive_detection_rate: Option<f32>,
    #[serde(default)]
    max_negative_false_positive_rate: Option<f32>,
    #[serde(default)]
    min_pre_onset_detection_rate: Option<f32>,
    #[serde(default)]
    per_threat: Vec<SocialContextThreatGateSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct SocialContextThreatGateSpec {
    threat_type: ThreatType,
    #[serde(default)]
    min_example_count: Option<usize>,
    #[serde(default)]
    max_brier_score: Option<f32>,
    #[serde(default)]
    max_expected_calibration_error: Option<f32>,
}

pub fn canonical_social_context_seed_scenarios() -> Vec<crate::ScenarioCase> {
    canonical_corpus_seed_scenarios()
}

pub fn default_social_context_profiles() -> Vec<CorpusStyleProfile> {
    default_corpus_style_profiles()
}

pub fn pre_release_social_context_gates() -> ScenarioQualityGates {
    pre_release_corpus_style_gates()
}

pub fn run_social_context_suite(
    pattern_db: &PatternDatabase,
    cases: &[ScenarioCase],
    profiles: &[CorpusStyleProfile],
    bin_count: usize,
) -> SocialContextSuiteSummary {
    let prepared = prepare_social_context_cases(cases, profiles);
    let runs: Vec<_> = prepared
        .iter()
        .map(|prepared| run_scenario_case(pattern_db, &prepared.case))
        .collect();
    let expectations = canonical_policy_action_expectations();
    let expected_policy_cases = expectations
        .iter()
        .map(|expectation| expectation.scenario_name.as_str())
        .collect::<BTreeSet<_>>();

    let mut cohort_summaries = Vec::new();
    let mut overall_indices = BTreeSet::new();

    for cohort in &social_context_file().cohorts {
        let matching_indices: Vec<_> = prepared
            .iter()
            .enumerate()
            .filter_map(|(idx, prepared)| variant_matches_cohort(prepared, cohort).then_some(idx))
            .collect();
        if matching_indices.is_empty() {
            continue;
        }

        overall_indices.extend(matching_indices.iter().copied());

        let cohort_runs: Vec<_> = matching_indices
            .iter()
            .map(|idx| runs[*idx].clone())
            .collect();
        let policy_indices = matching_indices
            .iter()
            .copied()
            .filter(|idx| {
                expected_policy_cases.contains(prepared[*idx].variant.base_case_name.as_str())
            })
            .collect::<Vec<_>>();
        let policy_runs = policy_indices
            .iter()
            .map(|idx| runs[*idx].clone())
            .collect::<Vec<_>>();
        let expectation_names = policy_indices
            .iter()
            .map(|idx| prepared[*idx].variant.base_case_name.clone())
            .collect::<Vec<_>>();
        let base_cases = matching_indices
            .iter()
            .map(|idx| prepared[*idx].variant.base_case_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let style_profiles = matching_indices
            .iter()
            .map(|idx| {
                prepared[*idx]
                    .variant
                    .style_profile
                    .clone()
                    .unwrap_or_else(|| "baseline".to_string())
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        cohort_summaries.push(SocialContextCohortSummary {
            cohort_id: cohort.id.clone(),
            description: cohort.description.clone(),
            variant_count: matching_indices.len(),
            base_cases,
            style_profiles,
            evaluation: summarize_scenario_runs(&cohort_runs, bin_count),
            policy: summarize_policy_actions_with_expectation_names(
                &policy_runs,
                &expectation_names,
                &expectations,
            ),
        });
    }

    let matched_variants: Vec<_> = overall_indices
        .iter()
        .map(|idx| prepared[*idx].variant.clone())
        .collect();
    let matched_runs: Vec<_> = overall_indices
        .iter()
        .map(|idx| runs[*idx].clone())
        .collect();
    let overall_policy_indices = overall_indices
        .iter()
        .copied()
        .filter(|idx| {
            expected_policy_cases.contains(prepared[*idx].variant.base_case_name.as_str())
        })
        .collect::<Vec<_>>();
    let overall_policy_runs = overall_policy_indices
        .iter()
        .map(|idx| runs[*idx].clone())
        .collect::<Vec<_>>();
    let overall_expectation_names = overall_policy_indices
        .iter()
        .map(|idx| prepared[*idx].variant.base_case_name.clone())
        .collect::<Vec<_>>();

    SocialContextSuiteSummary {
        evaluation: summarize_scenario_runs(&matched_runs, bin_count),
        policy: summarize_policy_actions_with_expectation_names(
            &overall_policy_runs,
            &overall_expectation_names,
            &expectations,
        ),
        cohorts: cohort_summaries,
        variants: matched_variants,
    }
}

pub fn evaluate_social_context_suite(
    summary: &SocialContextSuiteSummary,
    gates: &ScenarioQualityGates,
) -> (ScenarioGateReport, Vec<(String, ScenarioGateReport)>) {
    let overall = evaluate_scenario_quality_gates(&summary.evaluation, gates);
    let by_cohort = summary
        .cohorts
        .iter()
        .map(|cohort| {
            (
                cohort.cohort_id.clone(),
                evaluate_scenario_quality_gates(
                    &cohort.evaluation,
                    &social_context_cohort_gates(&cohort.cohort_id),
                ),
            )
        })
        .collect();

    (overall, by_cohort)
}

pub fn evaluate_social_context_policy_suite(
    summary: &SocialContextSuiteSummary,
    gates: &PolicyActionQualityGates,
) -> (ScenarioGateReport, Vec<(String, ScenarioGateReport)>) {
    let overall = evaluate_policy_action_gates(&summary.policy, gates);
    let by_cohort = summary
        .cohorts
        .iter()
        .map(|cohort| {
            (
                cohort.cohort_id.clone(),
                evaluate_policy_action_gates(&cohort.policy, gates),
            )
        })
        .collect();

    (overall, by_cohort)
}

pub fn social_context_cohort_gates(cohort_id: &str) -> ScenarioQualityGates {
    social_context_file()
        .cohorts
        .iter()
        .find(|cohort| cohort.id == cohort_id)
        .map(convert_gate_spec)
        .unwrap_or_else(|| panic!("unknown social context cohort id: {cohort_id}"))
}

pub fn pre_release_social_context_policy_gates() -> PolicyActionQualityGates {
    pre_release_policy_action_gates()
}

fn convert_gate_spec(cohort: &SocialContextCohortSpec) -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: cohort.gates.max_brier_score,
        max_expected_calibration_error: cohort.gates.max_expected_calibration_error,
        min_positive_detection_rate: cohort.gates.min_positive_detection_rate,
        max_negative_false_positive_rate: cohort.gates.max_negative_false_positive_rate,
        min_pre_onset_detection_rate: cohort.gates.min_pre_onset_detection_rate,
        per_threat: cohort
            .gates
            .per_threat
            .iter()
            .map(|gate| crate::ThreatCalibrationGate {
                threat_type: gate.threat_type,
                min_example_count: gate.min_example_count,
                max_brier_score: gate.max_brier_score,
                max_expected_calibration_error: gate.max_expected_calibration_error,
            })
            .collect(),
    }
}

fn variant_matches_cohort(
    prepared: &PreparedSocialContextCase,
    cohort: &SocialContextCohortSpec,
) -> bool {
    if !cohort
        .base_case_names
        .contains(&prepared.variant.base_case_name)
    {
        return false;
    }

    if !cohort.account_types.is_empty()
        && !cohort
            .account_types
            .contains(&prepared.case.config.account_type)
    {
        return false;
    }

    if !cohort.style_profiles.is_empty()
        && !cohort
            .style_profiles
            .iter()
            .any(|profile| Some(profile.as_str()) == prepared.variant.style_profile.as_deref())
    {
        return false;
    }

    if !cohort.conversation_types.is_empty()
        && !prepared.case.steps.iter().any(|step| {
            cohort
                .conversation_types
                .contains(&step.input.conversation_type)
        })
    {
        return false;
    }

    if !cohort.languages.is_empty() {
        let cohort_languages = cohort
            .languages
            .iter()
            .map(|language| normalize_language_code(Some(language.as_str())))
            .collect::<BTreeSet<_>>();
        let variant_languages = prepared
            .case
            .steps
            .iter()
            .map(|step| {
                normalize_language_code(
                    step.input
                        .language
                        .as_deref()
                        .or(Some(prepared.case.config.language.as_str())),
                )
            })
            .collect::<BTreeSet<_>>();
        if cohort_languages.is_disjoint(&variant_languages) {
            return false;
        }
    }

    true
}

fn prepare_social_context_cases(
    cases: &[ScenarioCase],
    profiles: &[CorpusStyleProfile],
) -> Vec<PreparedSocialContextCase> {
    let mut prepared = cases
        .iter()
        .map(|case| PreparedSocialContextCase {
            variant: SocialContextVariantRecord {
                base_case_name: case.name.clone(),
                variant_name: format!("{}_baseline", case.name),
                style_profile: None,
                mutated_steps: 0,
            },
            case: case.clone(),
        })
        .collect::<Vec<_>>();

    prepared.extend(
        generate_corpus_style_variants(cases, profiles)
            .into_iter()
            .map(|variant| PreparedSocialContextCase {
                variant: SocialContextVariantRecord {
                    base_case_name: variant.base_case_name,
                    variant_name: variant.variant_name,
                    style_profile: Some(variant.profile.label().to_string()),
                    mutated_steps: variant.mutated_steps,
                },
                case: variant.case,
            }),
    );

    prepared
}

fn normalize_language_code(language: Option<&str>) -> String {
    language
        .map(str::trim)
        .filter(|language| !language.is_empty())
        .map(|language| {
            language
                .split('-')
                .next()
                .unwrap_or(language)
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn social_context_file() -> &'static SocialContextFile {
    static SOCIAL_CONTEXT_FILE: OnceLock<SocialContextFile> = OnceLock::new();
    SOCIAL_CONTEXT_FILE.get_or_init(|| {
        let file = serde_json::from_str::<SocialContextFile>(include_str!(
            "../data/social_context_cohorts.json"
        ))
        .expect("valid social context cohort json");
        validate_social_context_file(&file).expect("valid social context cohorts");
        file
    })
}

fn validate_social_context_file(file: &SocialContextFile) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let known_cases = canonical_corpus_seed_scenarios()
        .into_iter()
        .map(|case| case.name)
        .collect::<BTreeSet<_>>();
    let known_profiles = default_corpus_style_profiles()
        .into_iter()
        .map(|profile| profile.label().to_string())
        .collect::<BTreeSet<_>>();

    for cohort in &file.cohorts {
        if cohort.id.trim().is_empty() {
            return Err("social context cohort id must not be empty".to_string());
        }
        if !ids.insert(cohort.id.clone()) {
            return Err(format!("duplicate social context cohort id: {}", cohort.id));
        }
        if cohort.description.trim().is_empty() {
            return Err(format!(
                "social context cohort {} has empty description",
                cohort.id
            ));
        }
        if cohort.base_case_names.is_empty() {
            return Err(format!(
                "social context cohort {} has no base_case_names",
                cohort.id
            ));
        }
        for case_name in &cohort.base_case_names {
            if !known_cases.contains(case_name) {
                return Err(format!(
                    "social context cohort {} references unknown base case {}",
                    cohort.id, case_name
                ));
            }
        }
        for profile in &cohort.style_profiles {
            if !known_profiles.contains(profile) {
                return Err(format!(
                    "social context cohort {} references unknown style profile {}",
                    cohort.id, profile
                ));
            }
        }
        for language in &cohort.languages {
            if language.trim().is_empty() {
                return Err(format!(
                    "social context cohort {} contains empty language filter",
                    cohort.id
                ));
            }
        }
        validate_gate_spec(&cohort.id, &cohort.gates)?;
    }

    Ok(())
}

fn validate_gate_spec(cohort_id: &str, gates: &SocialContextGateSpec) -> Result<(), String> {
    validate_probability_threshold(cohort_id, "max_brier_score", gates.max_brier_score)?;
    validate_probability_threshold(
        cohort_id,
        "max_expected_calibration_error",
        gates.max_expected_calibration_error,
    )?;
    validate_probability_threshold(
        cohort_id,
        "min_positive_detection_rate",
        gates.min_positive_detection_rate,
    )?;
    validate_probability_threshold(
        cohort_id,
        "max_negative_false_positive_rate",
        gates.max_negative_false_positive_rate,
    )?;
    validate_probability_threshold(
        cohort_id,
        "min_pre_onset_detection_rate",
        gates.min_pre_onset_detection_rate,
    )?;

    let mut threats = BTreeSet::new();
    for gate in &gates.per_threat {
        if !threats.insert(format!("{:?}", gate.threat_type)) {
            return Err(format!(
                "social context cohort {cohort_id} has duplicate per-threat gate for {:?}",
                gate.threat_type
            ));
        }
        if gate.min_example_count.is_some_and(|count| count == 0) {
            return Err(format!(
                "social context cohort {cohort_id} has zero min_example_count for {:?}",
                gate.threat_type
            ));
        }
        validate_probability_threshold(
            cohort_id,
            "per_threat.max_brier_score",
            gate.max_brier_score,
        )?;
        validate_probability_threshold(
            cohort_id,
            "per_threat.max_expected_calibration_error",
            gate.max_expected_calibration_error,
        )?;
    }

    Ok(())
}

fn validate_probability_threshold(
    cohort_id: &str,
    field_name: &str,
    value: Option<f32>,
) -> Result<(), String> {
    if let Some(value) = value {
        if !(0.0..=1.0).contains(&value) {
            return Err(format!(
                "social context cohort {cohort_id} has invalid {field_name}={value}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn social_context_file_loads_expected_cohorts() {
        let file = social_context_file();
        let ids = file
            .cohorts
            .iter()
            .map(|cohort| cohort.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(ids.contains("child_stranger_direct"));
        assert!(ids.contains("trusted_adult_authority_boundary"));
        assert!(ids.contains("peer_intimacy_boundary"));
        assert!(ids.contains("school_group_social_pressure"));
        assert!(ids.contains("selfharm_disclosure_support_boundary"));
        assert!(ids.contains("image_blackmail_reputation_control"));
    }

    #[test]
    fn social_context_suite_builds_all_defined_cohorts() {
        let db = PatternDatabase::default_mvp();
        let summary = run_social_context_suite(
            &db,
            &canonical_social_context_seed_scenarios(),
            &default_social_context_profiles(),
            6,
        );
        let built = summary
            .cohorts
            .iter()
            .map(|cohort| cohort.cohort_id.as_str())
            .collect::<BTreeSet<_>>();
        let expected = social_context_file()
            .cohorts
            .iter()
            .map(|cohort| cohort.id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(built, expected);
        assert!(summary.variants.len() >= summary.cohorts.len());
    }

    #[test]
    fn trusted_adult_boundary_contains_safe_and_risky_cases() {
        let db = PatternDatabase::default_mvp();
        let summary = run_social_context_suite(
            &db,
            &canonical_social_context_seed_scenarios(),
            &default_social_context_profiles(),
            6,
        );
        let cohort = summary
            .cohorts
            .iter()
            .find(|cohort| cohort.cohort_id == "trusted_adult_authority_boundary")
            .expect("trusted adult cohort");

        assert!(cohort
            .base_cases
            .contains(&"trusted_adult_grooming".to_string()));
        assert!(cohort
            .base_cases
            .contains(&"negative_control_trusted_adult".to_string()));
        assert!(cohort
            .base_cases
            .contains(&"curated_negative_uk_school_logistics".to_string()));
    }

    #[test]
    fn social_context_suite_returns_reports_for_each_cohort() {
        let db = PatternDatabase::default_mvp();
        let summary = run_social_context_suite(
            &db,
            &canonical_social_context_seed_scenarios(),
            &default_social_context_profiles(),
            6,
        );
        let (_, reports) =
            evaluate_social_context_suite(&summary, &pre_release_social_context_gates());

        assert_eq!(reports.len(), summary.cohorts.len());
    }

    #[test]
    fn social_context_policy_suite_returns_reports_for_each_cohort() {
        let db = PatternDatabase::default_mvp();
        let summary = run_social_context_suite(
            &db,
            &canonical_social_context_seed_scenarios(),
            &default_social_context_profiles(),
            6,
        );
        let (_, reports) = evaluate_social_context_policy_suite(
            &summary,
            &pre_release_social_context_policy_gates(),
        );

        assert_eq!(reports.len(), summary.cohorts.len());
    }

    #[test]
    fn social_context_pre_release_gates_pass() {
        let db = PatternDatabase::default_mvp();
        let summary = run_social_context_suite(
            &db,
            &canonical_social_context_seed_scenarios(),
            &default_social_context_profiles(),
            6,
        );
        let (overall, cohorts) =
            evaluate_social_context_suite(&summary, &pre_release_social_context_gates());

        assert!(
            overall.passed,
            "overall social-context gates failed: {overall:?}"
        );
        for (cohort_id, report) in cohorts {
            assert!(report.passed, "cohort {cohort_id} failed gates: {report:?}");
        }
    }

    #[test]
    fn social_context_policy_gates_pass() {
        let db = PatternDatabase::default_mvp();
        let summary = run_social_context_suite(
            &db,
            &canonical_social_context_seed_scenarios(),
            &default_social_context_profiles(),
            6,
        );
        let (overall, cohorts) = evaluate_social_context_policy_suite(
            &summary,
            &pre_release_social_context_policy_gates(),
        );

        assert!(
            overall.passed,
            "overall social-context policy gates failed: {overall:?}"
        );
        for (cohort_id, report) in cohorts {
            assert!(
                report.passed,
                "cohort {cohort_id} failed social-context policy gates: {report:?}"
            );
        }
    }
}
