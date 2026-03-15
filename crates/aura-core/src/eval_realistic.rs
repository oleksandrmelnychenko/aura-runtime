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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealisticChatMetadata {
    pub scenario_name: String,
    pub default_language: String,
    pub age_band: String,
    pub relationship: String,
    pub policy_expectation_case: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RealisticChatScenario {
    pub metadata: RealisticChatMetadata,
    pub case: ScenarioCase,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RealisticChatSliceSummary {
    pub slice_id: String,
    pub case_count: usize,
    pub scenario_names: Vec<String>,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
}

#[derive(Debug, Clone)]
pub struct RealisticChatSuiteSummary {
    pub manifest: RealisticChatManifest,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
    pub by_language: Vec<RealisticChatSliceSummary>,
    pub by_relationship: Vec<RealisticChatSliceSummary>,
    pub by_age_band: Vec<RealisticChatSliceSummary>,
    pub scenarios: Vec<RealisticChatMetadata>,
}

const MIN_REALISTIC_SLICE_CALIBRATION_EXAMPLES: usize = 12;
const MIN_REALISTIC_SLICE_LEAD_TIME_CASES: usize = 8;
const REALISTIC_CHAT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealisticChatManifest {
    pub schema_version: u32,
    pub dataset_id: String,
    pub dataset_label: String,
    pub maintainer: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RealisticChatBundle {
    pub manifest: RealisticChatManifest,
    pub scenarios: Vec<RealisticChatScenario>,
}

#[derive(Debug, Clone, Deserialize)]
struct RealisticChatFile {
    schema_version: u32,
    dataset_id: String,
    dataset_label: String,
    maintainer: String,
    created_at_ms: u64,
    updated_at_ms: u64,
    cases: Vec<RealisticChatCaseSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct RealisticChatCaseSpec {
    id: String,
    default_language: String,
    age_band: String,
    relationship: String,
    #[serde(default)]
    conversation_type: ConversationType,
    #[serde(default = "default_realistic_detection_threshold")]
    detection_threshold: f32,
    #[serde(default)]
    primary_threat: Option<ThreatType>,
    #[serde(default)]
    onset_step: Option<usize>,
    #[serde(default)]
    tracked_threats: Vec<ThreatType>,
    #[serde(default = "default_realistic_step_interval_ms")]
    step_interval_ms: u64,
    #[serde(default = "default_realistic_account_type")]
    account_type: AccountType,
    #[serde(default = "default_realistic_protection_level")]
    protection_level: ProtectionLevel,
    #[serde(default)]
    policy_expectation_case: Option<String>,
    messages: Vec<RealisticChatMessageSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct RealisticChatMessageSpec {
    text: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    observed_threats: Vec<ThreatType>,
}

pub fn realistic_chat_scenarios() -> Vec<RealisticChatScenario> {
    realistic_chat_bundle().scenarios
}

pub fn realistic_chat_bundle() -> RealisticChatBundle {
    let file = realistic_chat_file();
    build_realistic_chat_bundle(file)
}

pub fn parse_realistic_chat_bundle(json: &str) -> Result<RealisticChatBundle, String> {
    let file = serde_json::from_str::<RealisticChatFile>(json)
        .map_err(|err| format!("invalid realistic chat corpus json: {err}"))?;
    validate_realistic_chat_file(&file)?;
    Ok(build_realistic_chat_bundle(&file))
}

pub fn pre_release_realistic_chat_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.32),
        max_expected_calibration_error: Some(0.32),
        min_positive_detection_rate: Some(0.80),
        max_negative_false_positive_rate: Some(0.05),
        min_pre_onset_detection_rate: Some(0.20),
        per_threat: Vec::new(),
    }
}

pub fn pre_release_realistic_chat_policy_gates() -> PolicyActionQualityGates {
    pre_release_policy_action_gates()
}

pub fn run_realistic_chat_suite(
    pattern_db: &PatternDatabase,
    bin_count: usize,
) -> RealisticChatSuiteSummary {
    let bundle = realistic_chat_bundle();
    let scenarios = bundle.scenarios;
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

    RealisticChatSuiteSummary {
        manifest: bundle.manifest,
        evaluation: summarize_scenario_runs(&runs, bin_count),
        policy: summarize_policy_actions_with_expectation_names(
            &overall_policy_runs,
            &overall_expectation_names,
            &expectations,
        ),
        by_language: summarize_realistic_slices(
            &scenarios,
            &runs,
            &expectations,
            |metadata| metadata.default_language.clone(),
            bin_count,
        ),
        by_relationship: summarize_realistic_slices(
            &scenarios,
            &runs,
            &expectations,
            |metadata| metadata.relationship.clone(),
            bin_count,
        ),
        by_age_band: summarize_realistic_slices(
            &scenarios,
            &runs,
            &expectations,
            |metadata| metadata.age_band.clone(),
            bin_count,
        ),
        scenarios: scenarios
            .into_iter()
            .map(|scenario| scenario.metadata)
            .collect(),
    }
}

pub fn evaluate_realistic_chat_suite(
    summary: &RealisticChatSuiteSummary,
    gates: &ScenarioQualityGates,
) -> (
    ScenarioGateReport,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
) {
    let overall = evaluate_scenario_quality_gates(&summary.evaluation, gates);
    let by_language = summary
        .by_language
        .iter()
        .map(|slice| {
            let slice_gates = realistic_slice_quality_gates(&slice.evaluation, gates);
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
            let slice_gates = realistic_slice_quality_gates(&slice.evaluation, gates);
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
            let slice_gates = realistic_slice_quality_gates(&slice.evaluation, gates);
            (
                slice.slice_id.clone(),
                evaluate_scenario_quality_gates(&slice.evaluation, &slice_gates),
            )
        })
        .collect();

    (overall, by_language, by_relationship, by_age_band)
}

fn realistic_slice_quality_gates(
    summary: &ScenarioEvaluationSummary,
    gates: &ScenarioQualityGates,
) -> ScenarioQualityGates {
    let mut adapted = gates.clone();

    if summary.calibration.count < MIN_REALISTIC_SLICE_CALIBRATION_EXAMPLES {
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

    if summary.lead_time.total_cases < MIN_REALISTIC_SLICE_LEAD_TIME_CASES {
        adapted.min_pre_onset_detection_rate = None;
    }

    adapted
}

pub fn evaluate_realistic_chat_policy_suite(
    summary: &RealisticChatSuiteSummary,
    gates: &PolicyActionQualityGates,
) -> (
    ScenarioGateReport,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
    Vec<(String, ScenarioGateReport)>,
) {
    let overall = evaluate_policy_action_gates(&summary.policy, gates);
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

    (overall, by_language, by_relationship, by_age_band)
}

fn summarize_realistic_slices<F>(
    scenarios: &[RealisticChatScenario],
    runs: &[ScenarioRunResult],
    expectations: &[crate::ScenarioPolicyExpectation],
    key_fn: F,
    bin_count: usize,
) -> Vec<RealisticChatSliceSummary>
where
    F: Fn(&RealisticChatMetadata) -> String,
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

            RealisticChatSliceSummary {
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

fn realistic_chat_file() -> &'static RealisticChatFile {
    static FILE: OnceLock<RealisticChatFile> = OnceLock::new();
    FILE.get_or_init(|| {
        let file = serde_json::from_str::<RealisticChatFile>(include_str!(
            "../data/realistic_chat_cases.json"
        ))
        .expect("valid realistic chat corpus json");
        validate_realistic_chat_file(&file).expect("valid realistic chat corpus");
        file
    })
}

fn build_realistic_chat_bundle(file: &RealisticChatFile) -> RealisticChatBundle {
    RealisticChatBundle {
        manifest: RealisticChatManifest {
            schema_version: file.schema_version,
            dataset_id: file.dataset_id.clone(),
            dataset_label: file.dataset_label.clone(),
            maintainer: file.maintainer.clone(),
            created_at_ms: file.created_at_ms,
            updated_at_ms: file.updated_at_ms,
        },
        scenarios: file
            .cases
            .iter()
            .map(build_realistic_chat_scenario)
            .collect(),
    }
}

fn validate_realistic_chat_file(file: &RealisticChatFile) -> Result<(), String> {
    if file.schema_version != REALISTIC_CHAT_SCHEMA_VERSION {
        return Err(format!(
            "realistic chat corpus schema_version {} is unsupported, expected {}",
            file.schema_version, REALISTIC_CHAT_SCHEMA_VERSION
        ));
    }
    if file.dataset_id.trim().is_empty() {
        return Err("realistic chat corpus dataset_id must not be empty".to_string());
    }
    if file.dataset_label.trim().is_empty() {
        return Err("realistic chat corpus dataset_label must not be empty".to_string());
    }
    if file.maintainer.trim().is_empty() {
        return Err("realistic chat corpus maintainer must not be empty".to_string());
    }
    if file.created_at_ms == 0 {
        return Err("realistic chat corpus created_at_ms must be non-zero".to_string());
    }
    if file.updated_at_ms == 0 {
        return Err("realistic chat corpus updated_at_ms must be non-zero".to_string());
    }
    if file.updated_at_ms < file.created_at_ms {
        return Err("realistic chat corpus updated_at_ms must be >= created_at_ms".to_string());
    }
    let known_policy_cases = canonical_policy_action_expectations()
        .into_iter()
        .map(|expectation| expectation.scenario_name)
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();

    for case in &file.cases {
        if case.id.trim().is_empty() {
            return Err("realistic chat case id must not be empty".to_string());
        }
        if !ids.insert(case.id.clone()) {
            return Err(format!("duplicate realistic chat case id: {}", case.id));
        }
        if case.default_language.trim().is_empty() {
            return Err(format!(
                "realistic chat case {} has empty default_language",
                case.id
            ));
        }
        if case.age_band.trim().is_empty() {
            return Err(format!(
                "realistic chat case {} has empty age_band",
                case.id
            ));
        }
        if case.relationship.trim().is_empty() {
            return Err(format!(
                "realistic chat case {} has empty relationship",
                case.id
            ));
        }
        if !(0.0..=1.0).contains(&case.detection_threshold) {
            return Err(format!(
                "realistic chat case {} has invalid detection_threshold {}",
                case.id, case.detection_threshold
            ));
        }
        if case.step_interval_ms == 0 {
            return Err(format!(
                "realistic chat case {} has zero step_interval_ms",
                case.id
            ));
        }
        if case.messages.is_empty() {
            return Err(format!("realistic chat case {} has no messages", case.id));
        }
        if let Some(onset_step) = case.onset_step {
            if onset_step >= case.messages.len() {
                return Err(format!(
                    "realistic chat case {} onset_step {} is out of bounds",
                    case.id, onset_step
                ));
            }
        }
        if let Some(policy_case) = &case.policy_expectation_case {
            if !known_policy_cases.contains(policy_case) {
                return Err(format!(
                    "realistic chat case {} references unknown policy expectation {}",
                    case.id, policy_case
                ));
            }
        }
        for message in &case.messages {
            if message.text.trim().is_empty() {
                return Err(format!(
                    "realistic chat case {} contains empty message text",
                    case.id
                ));
            }
            if message
                .language
                .as_deref()
                .is_some_and(|language| language.trim().is_empty())
            {
                return Err(format!(
                    "realistic chat case {} contains empty message language",
                    case.id
                ));
            }
        }
    }

    Ok(())
}

fn build_realistic_chat_scenario(spec: &RealisticChatCaseSpec) -> RealisticChatScenario {
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

    RealisticChatScenario {
        metadata: RealisticChatMetadata {
            scenario_name: spec.id.clone(),
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

fn default_realistic_detection_threshold() -> f32 {
    0.55
}

fn default_realistic_step_interval_ms() -> u64 {
    3_600_000
}

fn default_realistic_account_type() -> AccountType {
    AccountType::Child
}

fn default_realistic_protection_level() -> ProtectionLevel {
    ProtectionLevel::High
}

#[cfg(test)]
mod tests {
    use aura_patterns::PatternDatabase;

    use super::*;

    #[test]
    fn realistic_chat_file_loads_expected_cases() {
        let file = realistic_chat_file();
        assert_eq!(file.schema_version, REALISTIC_CHAT_SCHEMA_VERSION);
        assert_eq!(file.dataset_id, "aura_realistic_chat_v1");
        assert!(file.cases.len() >= 10);
        assert!(file
            .cases
            .iter()
            .any(|case| case.id == "realistic_en_trusted_adult_boundary_push"));
        assert!(file
            .cases
            .iter()
            .any(|case| case.id == "realistic_ru_safe_peer_chat"));
    }

    #[test]
    fn realistic_chat_parser_accepts_builtin_json() {
        let parsed = parse_realistic_chat_bundle(include_str!("../data/realistic_chat_cases.json"))
            .expect("parse built-in realistic corpus");

        assert_eq!(
            parsed.manifest.schema_version,
            REALISTIC_CHAT_SCHEMA_VERSION
        );
        assert_eq!(parsed.manifest.dataset_id, "aura_realistic_chat_v1");
        assert!(!parsed.scenarios.is_empty());
    }

    #[test]
    fn realistic_chat_scenarios_cover_policy_for_all_cases() {
        let scenarios = realistic_chat_scenarios();
        assert!(!scenarios.is_empty());
        assert!(scenarios
            .iter()
            .all(|scenario| scenario.metadata.policy_expectation_case.is_some()));
    }

    #[test]
    fn realistic_chat_suite_builds_language_relationship_and_age_slices() {
        let db = PatternDatabase::default_mvp();
        let summary = run_realistic_chat_suite(&db, 5);

        assert_eq!(summary.manifest.dataset_id, "aura_realistic_chat_v1");
        assert_eq!(summary.by_language.len(), 3);
        assert!(!summary.by_relationship.is_empty());
        assert!(!summary.by_age_band.is_empty());
        assert_eq!(summary.policy.total_scenarios, summary.scenarios.len());
    }

    #[test]
    fn realistic_chat_suite_passes_pre_release_gates() {
        let db = PatternDatabase::default_mvp();
        let summary = run_realistic_chat_suite(&db, 5);
        let (overall, _, _, _) =
            evaluate_realistic_chat_suite(&summary, &pre_release_realistic_chat_gates());

        assert!(overall.passed, "realistic chat gates failed: {overall:?}");
    }

    #[test]
    fn realistic_chat_policy_suite_passes_pre_release_gates() {
        let db = PatternDatabase::default_mvp();
        let summary = run_realistic_chat_suite(&db, 5);
        let (overall, by_language, by_relationship, by_age_band) =
            evaluate_realistic_chat_policy_suite(
                &summary,
                &pre_release_realistic_chat_policy_gates(),
            );

        assert!(
            overall.passed,
            "realistic chat policy gates failed: {overall:?}"
        );
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
    fn realistic_chat_slice_quality_gates_pass_with_support_aware_rules() {
        let db = PatternDatabase::default_mvp();
        let summary = run_realistic_chat_suite(&db, 5);
        let (_, by_language, by_relationship, by_age_band) =
            evaluate_realistic_chat_suite(&summary, &pre_release_realistic_chat_gates());

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
}
