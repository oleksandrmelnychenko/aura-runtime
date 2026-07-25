use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use aura_patterns::PatternDatabase;
use serde::Deserialize;

use crate::{
    canonical_corpus_seed_scenarios, canonical_policy_action_expectations,
    canonical_propaganda_scenarios, default_corpus_style_profiles, direct_threat_case,
    evaluate_policy_action_gates, evaluate_scenario_quality_gates, generate_corpus_style_variants,
    military_coordinate_leak_case, negative_control_counter_speech_propaganda_case,
    negative_control_opsec_warning_case, negative_control_quoted_threat_report_case,
    negative_control_supportive_selfharm_response_case, pre_release_corpus_style_gates,
    pre_release_policy_action_gates, run_scenario_cases,
    summarize_policy_actions_with_expectation_names, summarize_scenario_runs, AccountType,
    ConversationType, CorpusStyleProfile, DomainMode, LatentStateKind, PolicyActionQualityGates,
    PolicyActionSummary, RiskHorizon, ScenarioCase, ScenarioEvaluationSummary, ScenarioGateReport,
    ScenarioQualityGates, ScenarioRunResult, ThreatType,
};

const MANDATORY_BOUNDARY_COHORTS: [&str; 6] = [
    "propaganda_discussion_boundary",
    "selfharm_support_boundary",
    "peer_banter_boundary",
    "trusted_adult_logistics_boundary",
    "opsec_warning_boundary",
    "hate_counter_speech_boundary",
];

#[derive(Debug, Clone, PartialEq)]
pub struct SocialContextCohortSummary {
    pub cohort_id: String,
    pub description: String,
    pub variant_count: usize,
    pub base_cases: Vec<String>,
    pub style_profiles: Vec<String>,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
    pub inference_expectations: Vec<SocialContextInferenceExpectationSummary>,
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
    #[serde(default)]
    inference_expectations: Vec<SocialContextInferenceExpectationSpec>,
    #[serde(default)]
    boundary_coverage: Option<SocialContextBoundaryCoverageSpec>,
    gates: SocialContextGateSpec,
}

#[derive(Debug, Clone, Deserialize)]
struct SocialContextBoundaryCoverageSpec {
    risky_case_name: String,
    safe_case_name: String,
    account_type: AccountType,
    domain_mode: DomainMode,
    style_profile: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocialContextInferenceScope {
    #[default]
    FinalStep,
    AnyStep,
}

#[derive(Debug, Clone, Deserialize)]
struct SocialContextInferenceExpectationSpec {
    base_case_name: String,
    #[serde(default)]
    scope: SocialContextInferenceScope,
    #[serde(default)]
    risk_horizon: Option<RiskHorizon>,
    #[serde(default)]
    min_escalation_likelihood_24h: Option<f32>,
    #[serde(default)]
    max_escalation_likelihood_24h: Option<f32>,
    #[serde(default)]
    required_latent_states: Vec<LatentStateKind>,
    #[serde(default)]
    forbidden_latent_states: Vec<LatentStateKind>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SocialContextInferenceExpectationSummary {
    pub base_case_name: String,
    pub variant_count: usize,
    pub scope: SocialContextInferenceScope,
    pub passed: bool,
    pub failures: Vec<String>,
}

pub fn canonical_social_context_seed_scenarios() -> Vec<crate::ScenarioCase> {
    let mut names = BTreeSet::new();
    canonical_corpus_seed_scenarios()
        .into_iter()
        .chain(canonical_propaganda_scenarios())
        .chain(crate::scenario_packs::hate_speech::canonical_hate_speech_scenarios())
        .chain([
            direct_threat_case(),
            negative_control_quoted_threat_report_case(),
            negative_control_supportive_selfharm_response_case(),
            negative_control_counter_speech_propaganda_case(),
            military_coordinate_leak_case(),
            negative_control_opsec_warning_case(),
        ])
        .filter(|case| names.insert(case.name.clone()))
        .collect()
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
    let runs = run_scenario_cases(pattern_db, prepared.iter().map(|prepared| &prepared.case)).runs;
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
        let inference_expectations =
            evaluate_inference_expectations_for_cohort(cohort, &matching_indices, &prepared, &runs);

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
            inference_expectations,
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

fn evaluate_inference_expectations_for_cohort(
    cohort: &SocialContextCohortSpec,
    matching_indices: &[usize],
    prepared: &[PreparedSocialContextCase],
    runs: &[ScenarioRunResult],
) -> Vec<SocialContextInferenceExpectationSummary> {
    cohort
        .inference_expectations
        .iter()
        .map(|expectation| {
            let case_indices = matching_indices
                .iter()
                .copied()
                .filter(|idx| prepared[*idx].variant.base_case_name == expectation.base_case_name)
                .collect::<Vec<_>>();
            let mut failures = Vec::new();

            for idx in &case_indices {
                evaluate_inference_expectation_for_run(
                    expectation,
                    &prepared[*idx].variant.variant_name,
                    &runs[*idx],
                    &mut failures,
                );
            }

            SocialContextInferenceExpectationSummary {
                base_case_name: expectation.base_case_name.clone(),
                variant_count: case_indices.len(),
                scope: expectation.scope,
                passed: !case_indices.is_empty() && failures.is_empty(),
                failures,
            }
        })
        .collect()
}

fn evaluate_inference_expectation_for_run(
    expectation: &SocialContextInferenceExpectationSpec,
    variant_name: &str,
    run: &ScenarioRunResult,
    failures: &mut Vec<String>,
) {
    if let Some(expected_horizon) = expectation.risk_horizon {
        let passed = match expectation.scope {
            SocialContextInferenceScope::FinalStep => run
                .step_results
                .last()
                .is_some_and(|result| result.inference.risk_horizon == expected_horizon),
            SocialContextInferenceScope::AnyStep => run
                .step_results
                .iter()
                .any(|result| result.inference.risk_horizon == expected_horizon),
        };
        if !passed {
            failures.push(format!(
                "{variant_name}: expected risk_horizon={expected_horizon:?} with scope={:?}, observed={}",
                expectation.scope,
                summarize_risk_horizons(run)
            ));
        }
    }

    if let Some(min) = expectation.min_escalation_likelihood_24h {
        let actual = observed_peak_escalation(run, expectation.scope);
        if actual < min {
            failures.push(format!(
                "{variant_name}: expected escalation_likelihood_24h >= {min:.2}, observed={actual:.2}"
            ));
        }
    }

    if let Some(max) = expectation.max_escalation_likelihood_24h {
        let actual = observed_peak_escalation(run, expectation.scope);
        if actual > max {
            failures.push(format!(
                "{variant_name}: expected escalation_likelihood_24h <= {max:.2}, observed={actual:.2}"
            ));
        }
    }

    for state in &expectation.required_latent_states {
        if !run_contains_latent_state(run, expectation.scope, *state) {
            failures.push(format!(
                "{variant_name}: missing required latent state {state:?}, observed={}",
                summarize_latent_states(run)
            ));
        }
    }

    for state in &expectation.forbidden_latent_states {
        if run_contains_latent_state(run, expectation.scope, *state) {
            failures.push(format!(
                "{variant_name}: forbidden latent state {state:?} observed={}",
                summarize_latent_states(run)
            ));
        }
    }
}

fn observed_peak_escalation(run: &ScenarioRunResult, scope: SocialContextInferenceScope) -> f32 {
    match scope {
        SocialContextInferenceScope::FinalStep => run
            .step_results
            .last()
            .map(|result| result.inference.escalation_likelihood_24h)
            .unwrap_or(0.0),
        SocialContextInferenceScope::AnyStep => run
            .step_results
            .iter()
            .map(|result| result.inference.escalation_likelihood_24h)
            .fold(0.0, f32::max),
    }
}

fn run_contains_latent_state(
    run: &ScenarioRunResult,
    scope: SocialContextInferenceScope,
    state: LatentStateKind,
) -> bool {
    match scope {
        SocialContextInferenceScope::FinalStep => run.step_results.last().is_some_and(|result| {
            result
                .inference
                .latent_states
                .iter()
                .any(|latent| latent.kind == state)
        }),
        SocialContextInferenceScope::AnyStep => run.step_results.iter().any(|result| {
            result
                .inference
                .latent_states
                .iter()
                .any(|latent| latent.kind == state)
        }),
    }
}

fn summarize_risk_horizons(run: &ScenarioRunResult) -> String {
    run.step_results
        .iter()
        .map(|result| format!("{:?}", result.inference.risk_horizon))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
}

fn summarize_latent_states(run: &ScenarioRunResult) -> String {
    run.step_results
        .iter()
        .flat_map(|result| {
            result
                .inference
                .latent_states
                .iter()
                .map(|latent| latent.kind)
        })
        .map(|kind| format!("{kind:?}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
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
    let known_cases = canonical_social_context_seed_scenarios()
        .into_iter()
        .map(|case| (case.name.clone(), case))
        .collect::<BTreeMap<_, _>>();
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
            if !known_cases.contains_key(case_name) {
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
        validate_inference_expectations(cohort)?;
        validate_gate_spec(&cohort.id, &cohort.gates)?;
    }

    validate_mandatory_boundary_coverage(file, &known_cases, &known_profiles)?;

    Ok(())
}

fn validate_mandatory_boundary_coverage(
    file: &SocialContextFile,
    known_cases: &BTreeMap<String, ScenarioCase>,
    known_profiles: &BTreeSet<String>,
) -> Result<(), String> {
    for cohort_id in MANDATORY_BOUNDARY_COHORTS {
        let cohort = file
            .cohorts
            .iter()
            .find(|cohort| cohort.id == cohort_id)
            .ok_or_else(|| format!("missing mandatory boundary cohort {cohort_id}"))?;
        let coverage = cohort.boundary_coverage.as_ref().ok_or_else(|| {
            format!("mandatory boundary cohort {cohort_id} has no boundary_coverage")
        })?;

        let risky = validate_boundary_case(cohort, known_cases, &coverage.risky_case_name)?;
        let safe = validate_boundary_case(cohort, known_cases, &coverage.safe_case_name)?;

        if risky.primary_threat.is_none()
            || !risky.steps.iter().any(|step| {
                step.observed_threats
                    .iter()
                    .any(|threat| Some(*threat) == risky.primary_threat)
            })
        {
            return Err(format!(
                "mandatory boundary cohort {cohort_id} risky case {} is not a labeled positive",
                coverage.risky_case_name
            ));
        }
        if risky.steps.len() < 2 || risky.onset_step.is_none() {
            return Err(format!(
                "mandatory boundary cohort {cohort_id} risky case {} is not a multi-turn escalation",
                coverage.risky_case_name
            ));
        }
        if safe.primary_threat.is_some()
            || safe
                .steps
                .iter()
                .any(|step| !step.observed_threats.is_empty())
        {
            return Err(format!(
                "mandatory boundary cohort {cohort_id} safe case {} is not a clean negative",
                coverage.safe_case_name
            ));
        }
        if safe.steps.len() < 2 {
            return Err(format!(
                "mandatory boundary cohort {cohort_id} safe case {} cannot exercise restart continuation",
                coverage.safe_case_name
            ));
        }
        for case in [risky, safe] {
            if case.config.account_type != coverage.account_type {
                return Err(format!(
                    "mandatory boundary cohort {cohort_id} case {} does not match account boundary {:?}",
                    case.name, coverage.account_type
                ));
            }
            if case.config.effective_domain_mode() != coverage.domain_mode {
                return Err(format!(
                    "mandatory boundary cohort {cohort_id} case {} does not match domain boundary {:?}",
                    case.name, coverage.domain_mode
                ));
            }
        }
        if !known_profiles.contains(&coverage.style_profile) {
            return Err(format!(
                "mandatory boundary cohort {cohort_id} references unknown boundary style profile {}",
                coverage.style_profile
            ));
        }
    }

    Ok(())
}

fn validate_boundary_case<'a>(
    cohort: &SocialContextCohortSpec,
    known_cases: &'a BTreeMap<String, ScenarioCase>,
    case_name: &str,
) -> Result<&'a ScenarioCase, String> {
    if !cohort
        .base_case_names
        .iter()
        .any(|candidate| candidate == case_name)
    {
        return Err(format!(
            "mandatory boundary cohort {} coverage references case {} outside base_case_names",
            cohort.id, case_name
        ));
    }

    known_cases.get(case_name).ok_or_else(|| {
        format!(
            "mandatory boundary cohort {} coverage references unknown case {}",
            cohort.id, case_name
        )
    })
}

fn validate_inference_expectations(cohort: &SocialContextCohortSpec) -> Result<(), String> {
    let mut base_case_names = BTreeSet::new();

    for expectation in &cohort.inference_expectations {
        if !cohort.base_case_names.contains(&expectation.base_case_name) {
            return Err(format!(
                "social context cohort {} has inference expectation for unknown base case {}",
                cohort.id, expectation.base_case_name
            ));
        }
        if !base_case_names.insert(expectation.base_case_name.clone()) {
            return Err(format!(
                "social context cohort {} has duplicate inference expectation for {}",
                cohort.id, expectation.base_case_name
            ));
        }
        if expectation.min_escalation_likelihood_24h.is_none()
            && expectation.max_escalation_likelihood_24h.is_none()
            && expectation.risk_horizon.is_none()
            && expectation.required_latent_states.is_empty()
            && expectation.forbidden_latent_states.is_empty()
        {
            return Err(format!(
                "social context cohort {} has empty inference expectation for {}",
                cohort.id, expectation.base_case_name
            ));
        }
        validate_probability_threshold(
            &cohort.id,
            "inference_expectations.min_escalation_likelihood_24h",
            expectation.min_escalation_likelihood_24h,
        )?;
        validate_probability_threshold(
            &cohort.id,
            "inference_expectations.max_escalation_likelihood_24h",
            expectation.max_escalation_likelihood_24h,
        )?;
        if let (Some(min), Some(max)) = (
            expectation.min_escalation_likelihood_24h,
            expectation.max_escalation_likelihood_24h,
        ) {
            if min > max {
                return Err(format!(
                    "social context cohort {} has inference expectation with min_escalation_likelihood_24h > max_escalation_likelihood_24h for {}",
                    cohort.id, expectation.base_case_name
                ));
            }
        }

        let mut required = BTreeSet::new();
        for state in &expectation.required_latent_states {
            if !required.insert(format!("{state:?}")) {
                return Err(format!(
                    "social context cohort {} has duplicate required latent state {:?} for {}",
                    cohort.id, state, expectation.base_case_name
                ));
            }
        }

        let mut forbidden = BTreeSet::new();
        for state in &expectation.forbidden_latent_states {
            if !forbidden.insert(format!("{state:?}")) {
                return Err(format!(
                    "social context cohort {} has duplicate forbidden latent state {:?} for {}",
                    cohort.id, state, expectation.base_case_name
                ));
            }
            if expectation
                .required_latent_states
                .iter()
                .any(|required_state| required_state == state)
            {
                return Err(format!(
                    "social context cohort {} requires and forbids latent state {:?} for {}",
                    cohort.id, state, expectation.base_case_name
                ));
            }
        }
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
    use std::sync::OnceLock;

    use super::*;
    use crate::{
        acute_selfharm_case, generate_corpus_style_variants, negative_control_trusted_adult_case,
        predicted_score_for_threat, run_scenario_case, trusted_adult_grooming_case, AnalysisResult,
        Analyzer, LatentStateKind, RiskHorizon, ScenarioRunResult,
    };

    fn final_result(case: &ScenarioCase) -> AnalysisResult {
        scenario_run(case)
            .step_results
            .last()
            .cloned()
            .expect("scenario should produce at least one result")
    }

    fn scenario_run(case: &ScenarioCase) -> ScenarioRunResult {
        let db = PatternDatabase::default_mvp();
        run_scenario_case(&db, case)
    }

    fn cached_social_context_summary() -> &'static SocialContextSuiteSummary {
        static SUMMARY: OnceLock<SocialContextSuiteSummary> = OnceLock::new();
        SUMMARY.get_or_init(|| {
            let db = PatternDatabase::default_mvp();
            run_social_context_suite(
                &db,
                &canonical_social_context_seed_scenarios(),
                &default_social_context_profiles(),
                6,
            )
        })
    }

    fn mandatory_boundary_cohorts() -> Vec<&'static SocialContextCohortSpec> {
        MANDATORY_BOUNDARY_COHORTS
            .iter()
            .map(|cohort_id| {
                social_context_file()
                    .cohorts
                    .iter()
                    .find(|cohort| cohort.id == *cohort_id)
                    .unwrap_or_else(|| panic!("missing mandatory cohort {cohort_id}"))
            })
            .collect()
    }

    fn seed_case(case_name: &str) -> ScenarioCase {
        canonical_social_context_seed_scenarios()
            .into_iter()
            .find(|case| case.name == case_name)
            .unwrap_or_else(|| panic!("missing social-context seed case {case_name}"))
    }

    fn normalized_result(result: &AnalysisResult) -> serde_json::Value {
        let mut value = serde_json::to_value(result).expect("serialize analysis result");
        value
            .as_object_mut()
            .expect("analysis result object")
            .insert("analysis_time_us".to_string(), serde_json::Value::from(0));
        value
    }

    fn analyze_case(case: &ScenarioCase) -> Vec<AnalysisResult> {
        let db = PatternDatabase::default_mvp();
        let mut analyzer = Analyzer::new(case.config.clone(), &db);
        case.steps
            .iter()
            .map(|step| analyzer.analyze_with_context(&step.input, step.timestamp_ms))
            .collect()
    }

    fn analyze_case_with_restart(case: &ScenarioCase) -> Vec<AnalysisResult> {
        assert!(case.steps.len() >= 2, "restart case must be multi-turn");
        let split = case.steps.len() / 2;
        let db = PatternDatabase::default_mvp();
        let mut before_restart = Analyzer::new(case.config.clone(), &db);
        let mut results = case.steps[..split]
            .iter()
            .map(|step| before_restart.analyze_with_context(&step.input, step.timestamp_ms))
            .collect::<Vec<_>>();

        let context_state = before_restart.export_context_state();
        let kids_state = before_restart.export_kids_memory_state();
        let mut after_restart = Analyzer::new(case.config.clone(), &db);
        after_restart
            .import_context_state(context_state)
            .expect("restart context state should import");
        assert!(
            after_restart.import_kids_memory_state(&kids_state),
            "restart kids state should import"
        );

        results.extend(
            case.steps[split..]
                .iter()
                .map(|step| after_restart.analyze_with_context(&step.input, step.timestamp_ms)),
        );
        results
    }

    fn corpus_style_profile(label: &str) -> CorpusStyleProfile {
        default_social_context_profiles()
            .into_iter()
            .find(|profile| profile.label() == label)
            .unwrap_or_else(|| panic!("missing corpus style profile {label}"))
    }

    #[test]
    fn social_context_file_loads_expected_cohorts() {
        let file = social_context_file();
        let ids = file
            .cohorts
            .iter()
            .map(|cohort| cohort.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(ids.contains("child_stranger_direct"));
        assert!(ids.contains("trusted_adult_logistics_boundary"));
        assert!(ids.contains("peer_intimacy_boundary"));
        assert!(ids.contains("peer_banter_boundary"));
        assert!(ids.contains("selfharm_support_boundary"));
        assert!(ids.contains("image_blackmail_reputation_control"));
        assert!(ids.contains("quote_report_direct_threat_boundary"));
        assert!(ids.contains("propaganda_discussion_boundary"));
        assert!(ids.contains("opsec_warning_boundary"));
        assert!(ids.contains("hate_counter_speech_boundary"));
    }

    #[test]
    fn social_context_suite_builds_all_defined_cohorts() {
        let summary = cached_social_context_summary();
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
        let summary = cached_social_context_summary();
        let cohort = summary
            .cohorts
            .iter()
            .find(|cohort| cohort.cohort_id == "trusted_adult_logistics_boundary")
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
    fn quote_report_boundary_contains_safe_and_risky_cases() {
        let summary = cached_social_context_summary();
        let cohort = summary
            .cohorts
            .iter()
            .find(|cohort| cohort.cohort_id == "quote_report_direct_threat_boundary")
            .expect("quote/report boundary cohort");

        assert!(cohort.base_cases.contains(&"direct_threat".to_string()));
        assert!(cohort
            .base_cases
            .contains(&"negative_control_quoted_threat_report".to_string()));
    }

    #[test]
    fn propaganda_discussion_boundary_contains_safe_and_risky_cases() {
        let summary = cached_social_context_summary();
        let cohort = summary
            .cohorts
            .iter()
            .find(|cohort| cohort.cohort_id == "propaganda_discussion_boundary")
            .expect("propaganda discussion boundary cohort");

        assert!(cohort
            .base_cases
            .contains(&"propaganda_bot_multi_chat".to_string()));
        assert!(cohort
            .base_cases
            .contains(&"negative_control_news_sharing".to_string()));
        assert!(cohort
            .base_cases
            .contains(&"negative_control_counter_speech_propaganda".to_string()));
    }

    #[test]
    fn military_opsec_boundary_contains_safe_and_risky_cases() {
        let summary = cached_social_context_summary();
        let cohort = summary
            .cohorts
            .iter()
            .find(|cohort| cohort.cohort_id == "opsec_warning_boundary")
            .expect("military opsec boundary cohort");

        assert!(cohort
            .base_cases
            .contains(&"military_coordinate_leak".to_string()));
        assert!(cohort
            .base_cases
            .contains(&"negative_control_opsec_warning".to_string()));
    }

    #[test]
    fn hate_counter_speech_boundary_contains_safe_and_risky_cases() {
        let summary = cached_social_context_summary();
        let cohort = summary
            .cohorts
            .iter()
            .find(|cohort| cohort.cohort_id == "hate_counter_speech_boundary")
            .expect("hate counter-speech boundary cohort");

        assert!(cohort
            .base_cases
            .contains(&"hate_dehumanizing_metaphor_en".to_string()));
        assert!(cohort
            .base_cases
            .contains(&"hate_neg_counterspeech".to_string()));
    }

    #[test]
    fn mandatory_boundaries_have_detected_counterfactual_pairs_and_profile_variants() {
        for cohort in mandatory_boundary_cohorts() {
            let coverage = cohort
                .boundary_coverage
                .as_ref()
                .expect("mandatory boundary coverage");
            let risky = seed_case(&coverage.risky_case_name);
            let safe = seed_case(&coverage.safe_case_name);
            let primary_threat = risky.primary_threat.expect("risky primary threat");
            let risky_run = scenario_run(&risky);
            let safe_run = scenario_run(&safe);
            let risky_peak = risky_run
                .step_results
                .iter()
                .map(|result| predicted_score_for_threat(result, primary_threat))
                .fold(0.0, f32::max);
            let safe_peak = safe_run
                .step_results
                .iter()
                .map(|result| predicted_score_for_threat(result, primary_threat))
                .fold(0.0, f32::max);

            assert!(
                risky_peak >= risky.detection_threshold,
                "cohort {} risky case {} missed: peak={risky_peak:.3}, threshold={:.3}",
                cohort.id,
                risky.name,
                risky.detection_threshold
            );
            assert!(
                safe_peak < safe.detection_threshold,
                "cohort {} safe case {} false-positive: peak={safe_peak:.3}, threshold={:.3}",
                cohort.id,
                safe.name,
                safe.detection_threshold
            );

            let profile = corpus_style_profile(&coverage.style_profile);
            let variants =
                generate_corpus_style_variants(&[risky.clone(), safe.clone()], &[profile]);
            let variant_cases = variants
                .iter()
                .map(|variant| variant.base_case_name.as_str())
                .collect::<BTreeSet<_>>();
            assert!(
                variant_cases.contains(risky.name.as_str())
                    || variant_cases.contains(safe.name.as_str()),
                "cohort {} lacks profile-boundary variants for {}",
                cohort.id,
                coverage.style_profile
            );
        }
    }

    #[test]
    fn mandatory_boundary_restart_continuation_matches_uninterrupted_analysis() {
        for cohort in mandatory_boundary_cohorts() {
            let coverage = cohort
                .boundary_coverage
                .as_ref()
                .expect("mandatory boundary coverage");
            for case_name in [&coverage.risky_case_name, &coverage.safe_case_name] {
                let case = seed_case(case_name);
                let uninterrupted = analyze_case(&case);
                let restarted = analyze_case_with_restart(&case);
                let uninterrupted = uninterrupted
                    .iter()
                    .map(normalized_result)
                    .collect::<Vec<_>>();
                let restarted = restarted.iter().map(normalized_result).collect::<Vec<_>>();

                assert_eq!(
                    restarted, uninterrupted,
                    "cohort {} case {} changed after state export/import restart",
                    cohort.id, case.name
                );
            }
        }
    }

    #[test]
    fn mandatory_boundary_outputs_are_deterministic() {
        for cohort in mandatory_boundary_cohorts() {
            let coverage = cohort
                .boundary_coverage
                .as_ref()
                .expect("mandatory boundary coverage");
            for case_name in [&coverage.risky_case_name, &coverage.safe_case_name] {
                let case = seed_case(case_name);
                let first = analyze_case(&case)
                    .iter()
                    .map(normalized_result)
                    .collect::<Vec<_>>();
                let second = analyze_case(&case)
                    .iter()
                    .map(normalized_result)
                    .collect::<Vec<_>>();
                assert_eq!(
                    second, first,
                    "cohort {} case {} produced nondeterministic ordering or output",
                    cohort.id, case.name
                );
            }
        }
    }

    #[test]
    fn mandatory_safe_boundaries_are_not_contaminated_by_unrelated_risky_memory() {
        for cohort in mandatory_boundary_cohorts() {
            let coverage = cohort
                .boundary_coverage
                .as_ref()
                .expect("mandatory boundary coverage");
            let risky = seed_case(&coverage.risky_case_name);
            let safe = seed_case(&coverage.safe_case_name);
            let db = PatternDatabase::default_mvp();
            let mut contaminated = Analyzer::new(risky.config.clone(), &db);

            for step in &risky.steps {
                let _ = contaminated.analyze_with_context(&step.input, step.timestamp_ms);
            }
            let after_risky = safe
                .steps
                .iter()
                .map(|step| contaminated.analyze_with_context(&step.input, step.timestamp_ms))
                .collect::<Vec<_>>();
            let clean = analyze_case(&safe);
            let after_risky = after_risky
                .iter()
                .map(normalized_result)
                .collect::<Vec<_>>();
            let clean = clean.iter().map(normalized_result).collect::<Vec<_>>();

            assert_eq!(
                after_risky, clean,
                "cohort {} safe case {} was contaminated by unrelated risky memory",
                cohort.id, safe.name
            );
        }
    }

    #[test]
    fn quote_report_boundary_keeps_safe_inference_unknown_but_direct_threat_immediate() {
        let safe = final_result(&negative_control_quoted_threat_report_case());
        let risky = final_result(&direct_threat_case());

        assert_eq!(safe.inference.risk_horizon, RiskHorizon::Unknown);
        assert!(
            safe.inference.escalation_likelihood_24h <= 0.25,
            "quoted report should not keep high escalation likelihood: {:?}",
            safe.inference
        );
        assert!(
            safe.inference.latent_states.is_empty(),
            "quoted report should not infer hostile latent states: {:?}",
            safe.inference.latent_states
        );

        assert_eq!(risky.inference.risk_horizon, RiskHorizon::Immediate);
        assert!(
            risky.score >= 0.70,
            "direct threat boundary case should still score above threshold: {:?}",
            risky
        );
    }

    #[test]
    fn selfharm_support_boundary_swaps_crisis_for_protective_support() {
        let safe = final_result(&negative_control_supportive_selfharm_response_case());
        let risky_run = scenario_run(&acute_selfharm_case());

        assert_eq!(safe.inference.risk_horizon, RiskHorizon::Unknown);
        assert!(
            !safe
                .inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::CrisisVulnerability),
            "supportive self-harm response should not keep crisis latent state: {:?}",
            safe.inference.latent_states
        );
        assert!(
            safe.inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::ProtectiveSupport),
            "supportive self-harm response should surface protective support: {:?}",
            safe.inference.latent_states
        );

        assert!(risky_run.step_results.iter().any(|result| {
            result
                .inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::CrisisVulnerability)
        }));
        assert!(risky_run
            .step_results
            .iter()
            .any(|result| { result.inference.escalation_likelihood_24h >= 0.70 }));
    }

    #[test]
    fn trusted_adult_boundary_preserves_grooming_inference_but_not_school_logistics() {
        let safe = final_result(&negative_control_trusted_adult_case());
        let risky = final_result(&trusted_adult_grooming_case());

        assert_eq!(safe.inference.risk_horizon, RiskHorizon::Unknown);
        assert!(
            !safe.inference.latent_states.iter().any(|state| {
                matches!(
                    state.kind,
                    LatentStateKind::DependencyBuilding | LatentStateKind::IsolationPressure
                )
            }),
            "routine trusted-adult logistics should not infer grooming dynamics: {:?}",
            safe.inference.latent_states
        );

        assert_eq!(risky.inference.risk_horizon, RiskHorizon::ShortTerm);
        assert!(
            risky
                .inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::DependencyBuilding),
            "trusted-adult grooming should keep dependency-building latent state: {:?}",
            risky.inference.latent_states
        );
        assert!(
            risky
                .inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::IsolationPressure),
            "trusted-adult grooming should keep isolation latent state: {:?}",
            risky.inference.latent_states
        );
    }

    #[test]
    fn military_opsec_boundary_keeps_warning_inference_clean_but_leak_risky() {
        let safe = final_result(&negative_control_opsec_warning_case());
        let risky = final_result(&military_coordinate_leak_case());

        assert_eq!(safe.inference.risk_horizon, RiskHorizon::Unknown);
        assert!(
            safe.inference.escalation_likelihood_24h <= 0.25,
            "opsec warning should stay low-escalation: {:?}",
            safe.inference
        );
        assert!(
            !safe.inference.latent_states.iter().any(|state| {
                matches!(
                    state.kind,
                    LatentStateKind::DependencyBuilding
                        | LatentStateKind::IsolationPressure
                        | LatentStateKind::CoerciveControl
                        | LatentStateKind::Humiliation
                        | LatentStateKind::CrisisVulnerability
                        | LatentStateKind::GroupEscalation
                )
            }),
            "opsec warning should not infer harmful latent states: {:?}",
            safe.inference.latent_states
        );

        assert_eq!(risky.threat_type, ThreatType::CoordinateLeak);
        assert!(
            risky.score >= 0.55,
            "military coordinate leak should remain above threshold: {:?}",
            risky
        );
    }

    #[test]
    fn social_context_declarative_inference_expectations_pass() {
        let summary = cached_social_context_summary();
        let total_expectations = summary
            .cohorts
            .iter()
            .map(|cohort| cohort.inference_expectations.len())
            .sum::<usize>();

        assert!(
            total_expectations >= 7,
            "expected declarative inference expectations to be loaded"
        );

        for cohort in &summary.cohorts {
            for expectation in &cohort.inference_expectations {
                assert!(
                    expectation.passed,
                    "cohort {} failed inference expectation for {}: {:?}",
                    cohort.cohort_id, expectation.base_case_name, expectation.failures
                );
            }
        }
    }

    #[test]
    fn social_context_suite_returns_reports_for_each_cohort() {
        let summary = cached_social_context_summary();
        let (_, reports) =
            evaluate_social_context_suite(summary, &pre_release_social_context_gates());

        assert_eq!(reports.len(), summary.cohorts.len());
    }

    #[test]
    fn social_context_policy_suite_returns_reports_for_each_cohort() {
        let summary = cached_social_context_summary();
        let (_, reports) = evaluate_social_context_policy_suite(
            summary,
            &pre_release_social_context_policy_gates(),
        );

        assert_eq!(reports.len(), summary.cohorts.len());
    }

    #[test]
    fn social_context_pre_release_gates_pass() {
        let summary = cached_social_context_summary();
        let (overall, cohorts) =
            evaluate_social_context_suite(summary, &pre_release_social_context_gates());

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
        let summary = cached_social_context_summary();
        let (overall, cohorts) = evaluate_social_context_policy_suite(
            summary,
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
