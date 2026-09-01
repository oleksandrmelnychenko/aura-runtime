use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use aura_patterns::PatternDatabase;
use serde::{Deserialize, Serialize};

use crate::ids::ConversationId;
use crate::{
    evaluate_policy_action_gates, evaluate_scenario_quality_gates, pre_release_policy_action_gates,
    run_scenario_cases, summarize_policy_actions_with_expectation_names, summarize_scenario_runs,
    AccountType, AuraConfig, ContentType, ConversationType, MessageInput, PolicyActionQualityGates,
    PolicyActionSummary, ProtectionLevel, ScenarioCase, ScenarioEvaluationSummary,
    ScenarioGateReport, ScenarioPolicyExpectation, ScenarioQualityGates, ScenarioRunResult,
    ScenarioStep, ThreatType, UiAction,
};

const PILOT_SIMULATION_REGRESSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotCaseClass {
    HardSafetyRegression,
    TaxonomyCleanup,
    AmbiguousAcceptable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotLabelInvariant {
    StrictPrimary,
    ActionLevelBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotSliceTag {
    TeenGroup,
    TeenSocialBanter,
    SocialMediaHumiliation,
    CoerciveFriendshipDynamics,
    TrustedAdultAmbiguity,
    SupportiveSelfHarmContext,
    RiskySelfHarmContext,
    UnknownContactEscalation,
    LinkSafety,
    ReputationImageAbuse,
    SubstancePressure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PilotSimulationRegressionManifest {
    pub schema_version: u32,
    pub suite_id: String,
    pub suite_label: String,
    pub maintainer: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PilotSimulationRegressionMetadata {
    pub scenario_name: String,
    pub source_family: String,
    pub source_case: String,
    pub default_language: String,
    pub case_class: PilotCaseClass,
    pub label_invariant: PilotLabelInvariant,
    pub acceptable_primary_threats: Vec<ThreatType>,
    pub pilot_slice_tags: Vec<PilotSliceTag>,
}

#[derive(Debug, Clone)]
pub struct PilotSimulationRegressionScenario {
    pub metadata: PilotSimulationRegressionMetadata,
    pub case: ScenarioCase,
    pub policy_expectation: ScenarioPolicyExpectation,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PilotSimulationRegressionSliceSummary {
    pub slice_id: String,
    pub case_count: usize,
    pub scenario_names: Vec<String>,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct PilotSimulationRegressionSuiteSummary {
    pub manifest: PilotSimulationRegressionManifest,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
    pub by_case_class: Vec<PilotSimulationRegressionSliceSummary>,
    pub by_pilot_slice: Vec<PilotSimulationRegressionSliceSummary>,
    pub by_source_family: Vec<PilotSimulationRegressionSliceSummary>,
    pub by_language: Vec<PilotSimulationRegressionSliceSummary>,
    pub scenarios: Vec<PilotSimulationRegressionMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PilotSimulationRegressionReport {
    pub schema_version: &'static str,
    pub manifest: PilotSimulationRegressionManifest,
    pub overall_status: &'static str,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
    pub evaluation_gates: ScenarioGateReport,
    pub policy_gates: ScenarioGateReport,
    pub source_family_gates: Vec<(String, ScenarioGateReport)>,
    pub language_gates: Vec<(String, ScenarioGateReport)>,
    pub by_case_class: Vec<PilotSimulationRegressionSliceSummary>,
    pub by_pilot_slice: Vec<PilotSimulationRegressionSliceSummary>,
    pub by_source_family: Vec<PilotSimulationRegressionSliceSummary>,
    pub by_language: Vec<PilotSimulationRegressionSliceSummary>,
    pub scenarios: Vec<PilotSimulationRegressionMetadata>,
}

#[derive(Debug, Clone)]
pub struct PilotSimulationRegressionBundle {
    pub manifest: PilotSimulationRegressionManifest,
    pub scenarios: Vec<PilotSimulationRegressionScenario>,
}

type SliceGateReports = Vec<(String, ScenarioGateReport)>;
type PilotSimulationGateResult = (ScenarioGateReport, SliceGateReports, SliceGateReports);

#[derive(Debug, Clone, Deserialize)]
struct PilotSimulationRegressionFile {
    schema_version: u32,
    suite_id: String,
    suite_label: String,
    maintainer: String,
    created_at_ms: u64,
    updated_at_ms: u64,
    cases: Vec<PilotSimulationRegressionCaseSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct PilotSimulationRegressionCaseSpec {
    id: String,
    source_family: String,
    source_case: String,
    default_language: String,
    #[serde(default = "default_pilot_case_class")]
    case_class: PilotCaseClass,
    #[serde(default = "default_pilot_label_invariant")]
    label_invariant: PilotLabelInvariant,
    #[serde(default)]
    acceptable_primary_threats: Vec<ThreatType>,
    #[serde(default)]
    pilot_slice_tags: Vec<PilotSliceTag>,
    #[serde(default)]
    conversation_type: ConversationType,
    #[serde(default)]
    member_count: Option<u32>,
    #[serde(default = "default_detection_threshold")]
    detection_threshold: f32,
    #[serde(default)]
    primary_threat: Option<ThreatType>,
    #[serde(default)]
    onset_step: Option<usize>,
    #[serde(default)]
    tracked_threats: Vec<ThreatType>,
    #[serde(default = "default_step_interval_ms")]
    step_interval_ms: u64,
    #[serde(default = "default_account_type")]
    account_type: AccountType,
    #[serde(default = "default_protection_level")]
    protection_level: ProtectionLevel,
    policy_expectation: PilotSimulationRegressionPolicySpec,
    messages: Vec<PilotSimulationRegressionMessageSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct PilotSimulationRegressionPolicySpec {
    #[serde(default)]
    required_any: Vec<UiAction>,
    #[serde(default)]
    required_by_onset: Vec<UiAction>,
    #[serde(default)]
    forbidden_any: Vec<UiAction>,
    #[serde(default)]
    forbid_any_action: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct PilotSimulationRegressionMessageSpec {
    text: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    observed_threats: Vec<ThreatType>,
}

pub fn pilot_simulation_regression_bundle() -> PilotSimulationRegressionBundle {
    let file = pilot_simulation_regression_file();
    build_pilot_simulation_regression_bundle(file)
}

pub fn pilot_simulation_regression_scenarios() -> Vec<PilotSimulationRegressionScenario> {
    pilot_simulation_regression_bundle().scenarios
}

pub fn parse_pilot_simulation_regression_bundle(
    json: &str,
) -> Result<PilotSimulationRegressionBundle, String> {
    let file = serde_json::from_str::<PilotSimulationRegressionFile>(json)
        .map_err(|err| format!("invalid pilot simulation regression json: {err}"))?;
    validate_pilot_simulation_regression_file(&file)?;
    Ok(build_pilot_simulation_regression_bundle(&file))
}

pub fn pre_release_pilot_simulation_regression_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.35),
        max_expected_calibration_error: Some(0.35),
        min_positive_detection_rate: Some(0.70),
        max_negative_false_positive_rate: Some(0.0),
        min_pre_onset_detection_rate: Some(0.25),
        per_threat: Vec::new(),
    }
}

pub fn pre_release_pilot_simulation_regression_policy_gates() -> PolicyActionQualityGates {
    pre_release_policy_action_gates()
}

pub fn run_pilot_simulation_regression_suite(
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> PilotSimulationRegressionSuiteSummary {
    let bundle = pilot_simulation_regression_bundle();
    let scenarios = bundle.scenarios;
    let runs = run_scenario_cases(pattern_db, scenarios.iter().map(|scenario| &scenario.case)).runs;
    let expectations = scenarios
        .iter()
        .map(|scenario| scenario.policy_expectation.clone())
        .collect::<Vec<_>>();
    let expectation_names = scenarios
        .iter()
        .map(|scenario| scenario.metadata.scenario_name.clone())
        .collect::<Vec<_>>();

    PilotSimulationRegressionSuiteSummary {
        manifest: bundle.manifest,
        evaluation: summarize_scenario_runs(&runs, bin_count),
        policy: summarize_policy_actions_with_expectation_names(
            &runs,
            &expectation_names,
            &expectations,
        ),
        by_case_class: summarize_pilot_regression_slices(
            &scenarios,
            &runs,
            &expectations,
            |metadata| {
                serde_json::to_string(&metadata.case_class)
                    .expect("serializable pilot case class")
                    .trim_matches('"')
                    .to_string()
            },
            bin_count,
        ),
        by_pilot_slice: summarize_pilot_regression_multi_slices(
            &scenarios,
            &runs,
            &expectations,
            |metadata| {
                metadata
                    .pilot_slice_tags
                    .iter()
                    .map(|tag| {
                        serde_json::to_string(tag)
                            .expect("serializable pilot slice tag")
                            .trim_matches('"')
                            .to_string()
                    })
                    .collect()
            },
            bin_count,
        ),
        by_source_family: summarize_pilot_regression_slices(
            &scenarios,
            &runs,
            &expectations,
            |metadata| metadata.source_family.clone(),
            bin_count,
        ),
        by_language: summarize_pilot_regression_slices(
            &scenarios,
            &runs,
            &expectations,
            |metadata| metadata.default_language.clone(),
            bin_count,
        ),
        scenarios: scenarios
            .into_iter()
            .map(|scenario| scenario.metadata)
            .collect(),
    }
}

pub fn evaluate_pilot_simulation_regression_suite(
    summary: &PilotSimulationRegressionSuiteSummary,
    gates: &ScenarioQualityGates,
) -> PilotSimulationGateResult {
    let overall = evaluate_scenario_quality_gates(&summary.evaluation, gates);
    let by_source_family = summary
        .by_source_family
        .iter()
        .map(|slice| {
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, gates),
            )
        })
        .collect();
    let by_language = summary
        .by_language
        .iter()
        .map(|slice| {
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, gates),
            )
        })
        .collect();

    (overall, by_source_family, by_language)
}

pub fn run_pilot_simulation_regression_report(
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> PilotSimulationRegressionReport {
    let summary = run_pilot_simulation_regression_suite(pattern_db, bin_count);
    let evaluation_gates = pre_release_pilot_simulation_regression_gates();
    let policy_gates = pre_release_pilot_simulation_regression_policy_gates();
    let (overall_eval, source_family_gates, language_gates) =
        evaluate_pilot_simulation_regression_suite(&summary, &evaluation_gates);
    let overall_policy = evaluate_policy_action_gates(&summary.policy, &policy_gates);
    let overall_status = if overall_eval.passed
        && overall_policy.passed
        && source_family_gates.iter().all(|(_, gate)| gate.passed)
        && language_gates.iter().all(|(_, gate)| gate.passed)
    {
        "pass"
    } else {
        "fail"
    };

    PilotSimulationRegressionReport {
        schema_version: "aura.pilot_simulation_regression_report.v1",
        manifest: summary.manifest.clone(),
        overall_status,
        evaluation: summary.evaluation.clone(),
        policy: summary.policy.clone(),
        evaluation_gates: overall_eval,
        policy_gates: overall_policy,
        source_family_gates,
        language_gates,
        by_case_class: summary.by_case_class,
        by_pilot_slice: summary.by_pilot_slice,
        by_source_family: summary.by_source_family,
        by_language: summary.by_language,
        scenarios: summary.scenarios,
    }
}

fn summarize_pilot_regression_slices(
    scenarios: &[PilotSimulationRegressionScenario],
    runs: &[ScenarioRunResult],
    expectations: &[ScenarioPolicyExpectation],
    slice_key: impl Fn(&PilotSimulationRegressionMetadata) -> String,
    bin_count: usize,
) -> Vec<PilotSimulationRegressionSliceSummary> {
    let expectation_map = expectations
        .iter()
        .map(|expectation| (expectation.scenario_name.as_str(), expectation.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut grouped = BTreeMap::<String, Vec<usize>>::new();
    for (idx, scenario) in scenarios.iter().enumerate() {
        grouped
            .entry(slice_key(&scenario.metadata))
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
            let slice_expectations = indices
                .iter()
                .map(|idx| {
                    expectation_map
                        .get(scenarios[*idx].metadata.scenario_name.as_str())
                        .expect("validated pilot expectation")
                        .clone()
                })
                .collect::<Vec<_>>();
            let expectation_names = slice_expectations
                .iter()
                .map(|expectation| expectation.scenario_name.clone())
                .collect::<Vec<_>>();

            PilotSimulationRegressionSliceSummary {
                slice_id,
                case_count: indices.len(),
                scenario_names: indices
                    .iter()
                    .map(|idx| scenarios[*idx].metadata.scenario_name.clone())
                    .collect(),
                evaluation: summarize_scenario_runs(&slice_runs, bin_count),
                policy: summarize_policy_actions_with_expectation_names(
                    &slice_runs,
                    &expectation_names,
                    &slice_expectations,
                ),
            }
        })
        .collect()
}

fn summarize_pilot_regression_multi_slices(
    scenarios: &[PilotSimulationRegressionScenario],
    runs: &[ScenarioRunResult],
    expectations: &[ScenarioPolicyExpectation],
    slice_keys: impl Fn(&PilotSimulationRegressionMetadata) -> Vec<String>,
    bin_count: usize,
) -> Vec<PilotSimulationRegressionSliceSummary> {
    let expectation_map = expectations
        .iter()
        .map(|expectation| (expectation.scenario_name.as_str(), expectation.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut grouped = BTreeMap::<String, Vec<usize>>::new();
    for (idx, scenario) in scenarios.iter().enumerate() {
        for slice_id in slice_keys(&scenario.metadata) {
            grouped.entry(slice_id).or_default().push(idx);
        }
    }

    grouped
        .into_iter()
        .map(|(slice_id, indices)| {
            let slice_runs = indices
                .iter()
                .map(|idx| runs[*idx].clone())
                .collect::<Vec<_>>();
            let slice_expectations = indices
                .iter()
                .map(|idx| {
                    expectation_map
                        .get(scenarios[*idx].metadata.scenario_name.as_str())
                        .expect("validated pilot expectation")
                        .clone()
                })
                .collect::<Vec<_>>();
            let expectation_names = slice_expectations
                .iter()
                .map(|expectation| expectation.scenario_name.clone())
                .collect::<Vec<_>>();

            PilotSimulationRegressionSliceSummary {
                slice_id,
                case_count: indices.len(),
                scenario_names: indices
                    .iter()
                    .map(|idx| scenarios[*idx].metadata.scenario_name.clone())
                    .collect(),
                evaluation: summarize_scenario_runs(&slice_runs, bin_count),
                policy: summarize_policy_actions_with_expectation_names(
                    &slice_runs,
                    &expectation_names,
                    &slice_expectations,
                ),
            }
        })
        .collect()
}

fn build_pilot_simulation_regression_bundle(
    file: &PilotSimulationRegressionFile,
) -> PilotSimulationRegressionBundle {
    PilotSimulationRegressionBundle {
        manifest: PilotSimulationRegressionManifest {
            schema_version: file.schema_version,
            suite_id: file.suite_id.clone(),
            suite_label: file.suite_label.clone(),
            maintainer: file.maintainer.clone(),
            created_at_ms: file.created_at_ms,
            updated_at_ms: file.updated_at_ms,
        },
        scenarios: file
            .cases
            .iter()
            .map(|spec| {
                let conversation_id: ConversationId = spec.id.as_str().into();
                let case = ScenarioCase {
                    name: spec.id.clone(),
                    config: AuraConfig {
                        account_type: spec.account_type,
                        protection_level: spec.protection_level,
                        language: spec.default_language.clone(),
                        ..AuraConfig::default()
                    },
                    primary_threat: spec.primary_threat,
                    onset_step: spec.onset_step,
                    detection_threshold: spec.detection_threshold,
                    tracked_threats: spec.tracked_threats.clone(),
                    steps: spec
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
                                    .unwrap_or_else(|| format!("{}_sender", spec.id))
                                    .into(),
                                conversation_id: conversation_id.clone(),
                                language: Some(
                                    message
                                        .language
                                        .clone()
                                        .unwrap_or_else(|| spec.default_language.clone()),
                                ),
                                language_evidence: None,
                                conversation_type: spec.conversation_type,
                                member_count: spec.member_count,
                                sender_relationship: Default::default(),
                                relationship_trust_source: Default::default(),
                            },
                            observed_threats: message.observed_threats.clone(),
                        })
                        .collect(),
                };
                let metadata = PilotSimulationRegressionMetadata {
                    scenario_name: spec.id.clone(),
                    source_family: spec.source_family.clone(),
                    source_case: spec.source_case.clone(),
                    default_language: spec.default_language.clone(),
                    case_class: spec.case_class,
                    label_invariant: spec.label_invariant,
                    acceptable_primary_threats: spec.acceptable_primary_threats.clone(),
                    pilot_slice_tags: spec.pilot_slice_tags.clone(),
                };
                let policy_expectation = ScenarioPolicyExpectation {
                    scenario_name: spec.id.clone(),
                    required_any: dedupe_actions(&spec.policy_expectation.required_any),
                    required_by_onset: dedupe_actions(&spec.policy_expectation.required_by_onset),
                    forbidden_any: dedupe_actions(&spec.policy_expectation.forbidden_any),
                    forbid_any_action: spec.policy_expectation.forbid_any_action,
                };
                PilotSimulationRegressionScenario {
                    metadata,
                    case,
                    policy_expectation,
                }
            })
            .collect(),
    }
}

fn validate_pilot_simulation_regression_file(
    file: &PilotSimulationRegressionFile,
) -> Result<(), String> {
    if file.schema_version != PILOT_SIMULATION_REGRESSION_SCHEMA_VERSION {
        return Err(format!(
            "unsupported pilot simulation regression schema_version {}",
            file.schema_version
        ));
    }
    if file.cases.is_empty() {
        return Err(
            "pilot simulation regression corpus must contain at least one case".to_string(),
        );
    }

    let mut seen = BTreeSet::new();
    for case in &file.cases {
        if !seen.insert(case.id.clone()) {
            return Err(format!(
                "duplicate pilot simulation regression case {}",
                case.id
            ));
        }
        if !(0.0..=1.0).contains(&case.detection_threshold) {
            return Err(format!(
                "case {} has invalid detection_threshold {}",
                case.id, case.detection_threshold
            ));
        }
        if case.messages.is_empty() {
            return Err(format!(
                "case {} must include at least one message",
                case.id
            ));
        }
        if case.label_invariant == PilotLabelInvariant::ActionLevelBehavior
            && case.acceptable_primary_threats.is_empty()
            && case.primary_threat.is_some()
        {
            return Err(format!(
                "case {} uses action_level_behavior but does not declare acceptable_primary_threats",
                case.id
            ));
        }
        if let Some(onset_step) = case.onset_step {
            if onset_step >= case.messages.len() {
                return Err(format!(
                    "case {} onset_step {} out of bounds for {} messages",
                    case.id,
                    onset_step,
                    case.messages.len()
                ));
            }
        }
        if !case.policy_expectation.required_by_onset.is_empty() && case.onset_step.is_none() {
            return Err(format!(
                "case {} requires by-onset actions but has no onset_step",
                case.id
            ));
        }
        if case.policy_expectation.forbid_any_action
            && !case.policy_expectation.forbidden_any.is_empty()
        {
            return Err(format!(
                "case {} cannot set forbid_any_action together with forbidden_any",
                case.id
            ));
        }
        for (idx, message) in case.messages.iter().enumerate() {
            if message.text.trim().is_empty() {
                return Err(format!("case {} message {} has empty text", case.id, idx));
            }
        }
    }

    Ok(())
}

fn pilot_simulation_regression_file() -> &'static PilotSimulationRegressionFile {
    static FILE: OnceLock<PilotSimulationRegressionFile> = OnceLock::new();
    FILE.get_or_init(|| {
        let file: PilotSimulationRegressionFile = serde_json::from_str(include_str!(
            "../data/pilot_simulation_regression_cases.json"
        ))
        .expect("valid builtin pilot simulation regression corpus");
        validate_pilot_simulation_regression_file(&file)
            .expect("valid builtin pilot simulation regression corpus");
        file
    })
}

fn dedupe_actions(actions: &[UiAction]) -> Vec<UiAction> {
    actions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn default_detection_threshold() -> f32 {
    0.55
}

fn default_step_interval_ms() -> u64 {
    60_000
}

fn default_account_type() -> AccountType {
    AccountType::Child
}

fn default_protection_level() -> ProtectionLevel {
    ProtectionLevel::High
}

fn default_pilot_case_class() -> PilotCaseClass {
    PilotCaseClass::HardSafetyRegression
}

fn default_pilot_label_invariant() -> PilotLabelInvariant {
    PilotLabelInvariant::StrictPrimary
}

#[cfg(test)]
mod tests {
    use aura_patterns::PatternDatabase;

    use super::*;

    #[test]
    fn pilot_simulation_regression_file_loads_expected_cases() {
        let bundle = pilot_simulation_regression_bundle();
        assert_eq!(bundle.manifest.schema_version, 1);
        assert_eq!(bundle.scenarios.len(), 12);
        assert!(bundle
            .scenarios
            .iter()
            .any(|scenario| scenario.metadata.source_family == "olena_world"));
        assert!(bundle
            .scenarios
            .iter()
            .any(|scenario| scenario.metadata.source_family == "mega_simulation"));
        assert!(bundle.scenarios.iter().any(|scenario| {
            scenario
                .metadata
                .pilot_slice_tags
                .contains(&PilotSliceTag::TrustedAdultAmbiguity)
        }));
    }

    #[test]
    fn pilot_simulation_regression_suite_passes_gates() {
        let db = PatternDatabase::default_mvp();
        let report = run_pilot_simulation_regression_report(&db, 6);
        assert_eq!(
            report.overall_status, "pass",
            "pilot simulation regression should pass: evaluation_gates={:?} policy_gates={:?}",
            report.evaluation_gates, report.policy_gates
        );
        assert!(report
            .source_family_gates
            .iter()
            .all(|(_, gate)| gate.passed));
        assert!(report.language_gates.iter().all(|(_, gate)| gate.passed));
    }

    #[test]
    fn pilot_simulation_regression_report_serializes() {
        let db = PatternDatabase::default_mvp();
        let report = run_pilot_simulation_regression_report(&db, 6);
        let json = serde_json::to_string(&report).expect("serialize pilot regression report");
        assert!(json.contains("aura.pilot_simulation_regression_report.v1"));
        assert!(json.contains("pilot_olena_grooming_private_escalation"));
        assert!(json.contains("trusted_adult_ambiguity"));
    }
}
