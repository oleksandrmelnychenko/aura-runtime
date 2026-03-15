use std::collections::BTreeMap;

use aura_patterns::PatternDatabase;
use chrono::Utc;
use serde::Serialize;

use crate::{
    calibration_for_threat, canonical_manipulation_scenarios, canonical_messenger_scenarios,
    canonical_multilingual_scenarios, canonical_noisy_slang_scenarios,
    canonical_social_context_seed_scenarios, default_corpus_style_profiles,
    default_robustness_profiles, default_social_context_profiles,
    evaluate_corpus_style_policy_suite, evaluate_corpus_style_suite,
    evaluate_external_curated_policy_suite, evaluate_external_curated_suite,
    evaluate_realistic_chat_policy_suite, evaluate_realistic_chat_suite, evaluate_robustness_suite,
    evaluate_scenario_quality_gates, evaluate_social_context_policy_suite,
    evaluate_social_context_suite, pre_release_child_safety_gates, pre_release_corpus_policy_gates,
    pre_release_corpus_style_gates, pre_release_external_curated_gates_for_manifest,
    pre_release_external_curated_policy_gates, pre_release_manipulation_gates,
    pre_release_multilingual_gates, pre_release_noisy_slang_gates,
    pre_release_realistic_chat_gates, pre_release_realistic_chat_policy_gates,
    pre_release_robustness_gates, pre_release_social_context_gates,
    pre_release_social_context_policy_gates, run_corpus_style_suite,
    run_external_curated_gold_suite, run_external_curated_suite, run_realistic_chat_suite,
    run_robustness_suite, run_scenario_case, run_social_context_suite, summarize_scenario_runs,
    CorpusStyleSuiteSummary, GateComparison, LanguageSliceSummary, PolicyActionSummary,
    RealisticChatSuiteSummary, RobustnessSuiteSummary, ScenarioEvaluationSummary,
    ScenarioGateCheck, ScenarioGateReport, ScenarioQualityGates, SocialContextSuiteSummary,
    ThreatType,
};

pub const RELEASE_REPORT_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Pass,
    Fail,
    InsufficientSupport,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportEnforcement {
    ReportOnly,
    ReleaseBlocking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReleaseSupportThresholds {
    pub min_reportable_calibration_examples: usize,
    pub min_reportable_onset_cases: usize,
    pub min_blocking_calibration_examples: usize,
    pub min_blocking_positive_scenarios: usize,
    pub min_blocking_negative_scenarios: usize,
    pub min_blocking_onset_cases: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ReleaseDriftThresholds {
    pub max_brier_delta: f32,
    pub max_expected_calibration_error_delta: f32,
    pub max_positive_detection_rate_delta: f32,
    pub max_negative_false_positive_rate_delta: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportRequirementSnapshot {
    pub requirement: String,
    pub actual: usize,
    pub required: usize,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportAssessmentSnapshot {
    pub calibration_examples: usize,
    pub positive_scenarios: usize,
    pub negative_scenarios: usize,
    pub onset_cases: usize,
    pub reportable: bool,
    pub release_blocking_ready: bool,
    pub reportable_basis: Vec<String>,
    pub missing_release_blocking: Vec<SupportRequirementSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThreatCalibrationSnapshot {
    pub threat_type: String,
    pub count: usize,
    pub brier_score: f32,
    pub expected_calibration_error: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvaluationMetricsSnapshot {
    pub calibration_count: usize,
    pub brier_score: f32,
    pub expected_calibration_error: f32,
    pub positive_detection_rate: f32,
    pub negative_false_positive_rate: f32,
    pub pre_onset_detection_rate: Option<f32>,
    pub positive_scenarios: usize,
    pub negative_scenarios: usize,
    pub onset_cases: usize,
    pub by_threat: Vec<ThreatCalibrationSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyMetricsSnapshot {
    pub total_scenarios: usize,
    pub passed_scenarios: usize,
    pub failed_scenarios: usize,
    pub scenario_pass_rate: f32,
    pub required_any_coverage: f32,
    pub required_by_onset_coverage: f32,
    pub forbidden_violation_rate: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateCheckSnapshot {
    pub name: String,
    pub comparison: String,
    pub actual: Option<f32>,
    pub threshold: f32,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateReportSnapshot {
    pub passed: bool,
    pub checks: Vec<GateCheckSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyReleaseSnapshot {
    pub metrics: PolicyMetricsSnapshot,
    pub gates: GateReportSnapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SliceReleaseReport {
    pub group: String,
    pub slice_id: String,
    pub support_enforcement: SupportEnforcement,
    pub status: ReleaseStatus,
    pub support: SupportAssessmentSnapshot,
    pub evaluation: EvaluationMetricsSnapshot,
    pub evaluation_gates: GateReportSnapshot,
    pub policy: Option<PolicyReleaseSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SuiteReleaseReport {
    pub suite_id: String,
    pub status: ReleaseStatus,
    pub missing_required_slices: Vec<String>,
    pub evaluation: EvaluationMetricsSnapshot,
    pub evaluation_gates: GateReportSnapshot,
    pub policy: Option<PolicyReleaseSnapshot>,
    pub slices: Vec<SliceReleaseReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DriftMetricsSnapshot {
    pub brier_delta: f32,
    pub expected_calibration_error_delta: f32,
    pub positive_detection_rate_delta: f32,
    pub negative_false_positive_rate_delta: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SuiteDriftReport {
    pub comparison_id: String,
    pub baseline_suite_id: String,
    pub candidate_suite_id: String,
    pub baseline_status: ReleaseStatus,
    pub candidate_status: ReleaseStatus,
    pub release_blocking_ready: bool,
    pub status: ReleaseStatus,
    pub metrics: DriftMetricsSnapshot,
    pub gates: GateReportSnapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PreReleaseReport {
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub runtime_version: String,
    pub support_thresholds: ReleaseSupportThresholds,
    pub drift_thresholds: ReleaseDriftThresholds,
    pub overall_status: ReleaseStatus,
    pub suites: Vec<SuiteReleaseReport>,
    pub drift_checks: Vec<SuiteDriftReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequiredSlice {
    group: &'static str,
    slice_id: &'static str,
}

impl RequiredSlice {
    const fn new(group: &'static str, slice_id: &'static str) -> Self {
        Self { group, slice_id }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SuiteSliceSupportPolicy {
    default_enforcement: SupportEnforcement,
    required_slices: &'static [RequiredSlice],
}

impl SuiteSliceSupportPolicy {
    fn enforcement_for(self, group: &str, slice_id: &str) -> SupportEnforcement {
        if self
            .required_slices
            .iter()
            .any(|required| required.group == group && required.slice_id == slice_id)
        {
            SupportEnforcement::ReleaseBlocking
        } else {
            self.default_enforcement
        }
    }

    fn missing_required_slices(self, slices: &[SliceReleaseReport]) -> Vec<String> {
        self.required_slices
            .iter()
            .filter(|required| {
                !slices.iter().any(|slice| {
                    slice.group == required.group && slice.slice_id == required.slice_id
                })
            })
            .map(|required| format!("{}:{}", required.group, required.slice_id))
            .collect()
    }
}

const NO_REQUIRED_SLICES: &[RequiredSlice] = &[];
const REALISTIC_REQUIRED_SLICES: &[RequiredSlice] = &[
    RequiredSlice::new("age_band", "child"),
    RequiredSlice::new("relationship", "group_peer"),
    RequiredSlice::new("relationship", "self"),
    RequiredSlice::new("relationship", "stranger"),
    RequiredSlice::new("relationship", "trusted_adult"),
];
const EXTERNAL_REQUIRED_SLICES: &[RequiredSlice] = &[
    RequiredSlice::new("age_band", "child"),
    RequiredSlice::new("language", "ru"),
    RequiredSlice::new("language", "uk"),
    RequiredSlice::new("relationship", "group_peer"),
    RequiredSlice::new("relationship", "supportive_peer"),
    RequiredSlice::new("relationship", "trusted_adult"),
];

pub fn default_release_support_thresholds() -> ReleaseSupportThresholds {
    ReleaseSupportThresholds {
        min_reportable_calibration_examples: 12,
        min_reportable_onset_cases: 8,
        min_blocking_calibration_examples: 24,
        min_blocking_positive_scenarios: 8,
        min_blocking_negative_scenarios: 8,
        min_blocking_onset_cases: 8,
    }
}

pub fn default_release_drift_thresholds() -> ReleaseDriftThresholds {
    ReleaseDriftThresholds {
        max_brier_delta: 0.05,
        max_expected_calibration_error_delta: 0.05,
        max_positive_detection_rate_delta: 0.10,
        max_negative_false_positive_rate_delta: 0.03,
    }
}

fn report_only_slice_policy() -> SuiteSliceSupportPolicy {
    SuiteSliceSupportPolicy {
        default_enforcement: SupportEnforcement::ReportOnly,
        required_slices: NO_REQUIRED_SLICES,
    }
}

fn realistic_slice_policy() -> SuiteSliceSupportPolicy {
    SuiteSliceSupportPolicy {
        default_enforcement: SupportEnforcement::ReportOnly,
        required_slices: REALISTIC_REQUIRED_SLICES,
    }
}

fn external_slice_policy() -> SuiteSliceSupportPolicy {
    SuiteSliceSupportPolicy {
        default_enforcement: SupportEnforcement::ReportOnly,
        required_slices: EXTERNAL_REQUIRED_SLICES,
    }
}

pub fn run_pre_release_report(pattern_db: &PatternDatabase, bin_count: usize) -> PreReleaseReport {
    let support_thresholds = default_release_support_thresholds();
    let drift_thresholds = default_release_drift_thresholds();

    let canonical_runs: Vec<_> = canonical_messenger_scenarios()
        .iter()
        .map(|case| run_scenario_case(pattern_db, case))
        .collect();
    let canonical_summary = summarize_scenario_runs(&canonical_runs, bin_count);
    let canonical_suite = build_scenario_suite_report(
        "canonical_messenger",
        &canonical_summary,
        &pre_release_child_safety_gates(),
        support_thresholds,
    );

    let manipulation_runs: Vec<_> = canonical_manipulation_scenarios()
        .iter()
        .map(|case| run_scenario_case(pattern_db, case))
        .collect();
    let manipulation_summary = summarize_scenario_runs(&manipulation_runs, bin_count);
    let manipulation_suite = build_scenario_suite_report(
        "canonical_manipulation",
        &manipulation_summary,
        &pre_release_manipulation_gates(),
        support_thresholds,
    );

    let multilingual_runs: Vec<_> = canonical_multilingual_scenarios()
        .iter()
        .map(|case| run_scenario_case(pattern_db, case))
        .collect();
    let multilingual_summary = summarize_scenario_runs(&multilingual_runs, bin_count);
    let multilingual_suite = build_scenario_suite_report(
        "canonical_multilingual",
        &multilingual_summary,
        &pre_release_multilingual_gates(),
        support_thresholds,
    );

    let noisy_runs: Vec<_> = canonical_noisy_slang_scenarios()
        .iter()
        .map(|case| run_scenario_case(pattern_db, case))
        .collect();
    let noisy_summary = summarize_scenario_runs(&noisy_runs, bin_count);
    let noisy_suite = build_scenario_suite_report(
        "canonical_noisy_slang",
        &noisy_summary,
        &pre_release_noisy_slang_gates(),
        support_thresholds,
    );

    let robustness_summary = run_robustness_suite(
        pattern_db,
        &crate::canonical_robustness_seed_scenarios(),
        &default_robustness_profiles(),
        bin_count,
    );
    let robustness_suite = build_robustness_suite_report(&robustness_summary, support_thresholds);

    let corpus_summary = run_corpus_style_suite(
        pattern_db,
        &crate::canonical_corpus_seed_scenarios(),
        &default_corpus_style_profiles(),
        bin_count,
    );
    let corpus_suite = build_corpus_suite_report(&corpus_summary, support_thresholds);

    let social_context_summary = run_social_context_suite(
        pattern_db,
        &canonical_social_context_seed_scenarios(),
        &default_social_context_profiles(),
        bin_count,
    );
    let social_context_suite =
        build_social_context_suite_report(&social_context_summary, support_thresholds);

    let realistic_summary = run_realistic_chat_suite(pattern_db, bin_count);
    let realistic_suite = build_realistic_suite_report(&realistic_summary, support_thresholds);

    let external_mixed_summary = run_external_curated_suite(pattern_db, bin_count);
    let external_mixed_suite = build_external_suite_report(
        "external_curated_mixed",
        &external_mixed_summary,
        support_thresholds,
    );

    let external_gold_summary = run_external_curated_gold_suite(pattern_db, bin_count);
    let external_gold_suite = build_external_suite_report(
        "external_curated_gold",
        &external_gold_summary,
        support_thresholds,
    );

    let suites = vec![
        canonical_suite,
        manipulation_suite,
        multilingual_suite,
        noisy_suite,
        robustness_suite,
        corpus_suite,
        social_context_suite,
        realistic_suite,
        external_mixed_suite,
        external_gold_suite,
    ];

    let suite_index: BTreeMap<_, _> = suites
        .iter()
        .map(|suite| (suite.suite_id.as_str(), suite))
        .collect();
    let drift_checks = vec![
        build_drift_report(
            "canonical_vs_realistic",
            suite_index["canonical_messenger"],
            suite_index["realistic_chat"],
            drift_thresholds,
        ),
        build_drift_report(
            "canonical_vs_external_mixed",
            suite_index["canonical_messenger"],
            suite_index["external_curated_mixed"],
            drift_thresholds,
        ),
        build_drift_report(
            "realistic_vs_external_mixed",
            suite_index["realistic_chat"],
            suite_index["external_curated_mixed"],
            drift_thresholds,
        ),
        build_drift_report(
            "external_mixed_vs_gold",
            suite_index["external_curated_mixed"],
            suite_index["external_curated_gold"],
            drift_thresholds,
        ),
    ];

    let overall_status = combine_statuses(
        suites
            .iter()
            .map(|suite| suite.status)
            .chain(drift_checks.iter().map(|report| report.status)),
    );

    PreReleaseReport {
        schema_version: RELEASE_REPORT_SCHEMA_VERSION,
        generated_at_utc: Utc::now().to_rfc3339(),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        support_thresholds,
        drift_thresholds,
        overall_status,
        suites,
        drift_checks,
    }
}

fn build_scenario_suite_report(
    suite_id: &str,
    summary: &ScenarioEvaluationSummary,
    gates: &ScenarioQualityGates,
    support_thresholds: ReleaseSupportThresholds,
) -> SuiteReleaseReport {
    let support_policy = report_only_slice_policy();
    let evaluation_gates = evaluate_scenario_quality_gates(summary, gates);
    let slices = summary
        .language_slices
        .iter()
        .map(|slice| {
            let slice_summary = scenario_summary_from_language_slice(slice);
            let slice_gates = support_aware_slice_gates(&slice_summary, gates, support_thresholds);
            let gate_report = evaluate_scenario_quality_gates(&slice_summary, &slice_gates);
            build_slice_report(
                "language",
                &slice.language,
                &slice_summary,
                &gate_report,
                None,
                support_policy.enforcement_for("language", &slice.language),
                support_thresholds,
            )
        })
        .collect::<Vec<_>>();
    let missing_required_slices = support_policy.missing_required_slices(&slices);

    SuiteReleaseReport {
        suite_id: suite_id.to_string(),
        status: suite_status(&evaluation_gates, None, &slices, &missing_required_slices),
        missing_required_slices,
        evaluation: evaluation_metrics_from_summary(summary),
        evaluation_gates: gate_report_snapshot(&evaluation_gates),
        policy: None,
        slices,
    }
}

fn build_robustness_suite_report(
    summary: &RobustnessSuiteSummary,
    support_thresholds: ReleaseSupportThresholds,
) -> SuiteReleaseReport {
    let support_policy = report_only_slice_policy();
    let (overall_eval, by_profile_eval) =
        evaluate_robustness_suite(summary, &pre_release_robustness_gates());
    let eval_map = by_profile_eval
        .into_iter()
        .map(|(profile, report)| (profile.label().to_string(), report))
        .collect::<BTreeMap<_, _>>();
    let mut lookup_failed = false;

    let slices = summary
        .profiles
        .iter()
        .map(|profile| {
            let profile_id = profile.profile.label().to_string();
            let gate_report = cloned_gate_report(
                &eval_map,
                &profile_id,
                "robustness.profile",
                &mut lookup_failed,
            );
            build_slice_report(
                "profile",
                &profile_id,
                &profile.evaluation,
                &gate_report,
                None,
                support_policy.enforcement_for("profile", &profile_id),
                support_thresholds,
            )
        })
        .collect::<Vec<_>>();
    let missing_required_slices = support_policy.missing_required_slices(&slices);

    SuiteReleaseReport {
        suite_id: "robustness".to_string(),
        status: finalize_suite_status(
            suite_status(&overall_eval, None, &slices, &missing_required_slices),
            lookup_failed,
        ),
        missing_required_slices,
        evaluation: evaluation_metrics_from_summary(&summary.evaluation),
        evaluation_gates: gate_report_snapshot(&overall_eval),
        policy: None,
        slices,
    }
}

fn build_corpus_suite_report(
    summary: &CorpusStyleSuiteSummary,
    support_thresholds: ReleaseSupportThresholds,
) -> SuiteReleaseReport {
    let support_policy = report_only_slice_policy();
    let (overall_eval, by_profile_eval) =
        evaluate_corpus_style_suite(summary, &pre_release_corpus_style_gates());
    let (overall_policy, by_profile_policy) =
        evaluate_corpus_style_policy_suite(summary, &pre_release_corpus_policy_gates());
    let eval_map = by_profile_eval
        .into_iter()
        .map(|(profile, report)| (profile.label().to_string(), report))
        .collect::<BTreeMap<_, _>>();
    let policy_map = by_profile_policy
        .into_iter()
        .map(|(profile, report)| (profile.label().to_string(), report))
        .collect::<BTreeMap<_, _>>();
    let mut lookup_failed = false;

    let slices = summary
        .profiles
        .iter()
        .map(|profile| {
            let profile_id = profile.profile.label().to_string();
            let gate_report =
                cloned_gate_report(&eval_map, &profile_id, "corpus.profile", &mut lookup_failed);
            let policy_gate_report = cloned_gate_report(
                &policy_map,
                &profile_id,
                "corpus.profile_policy",
                &mut lookup_failed,
            );
            build_slice_report(
                "profile",
                &profile_id,
                &profile.evaluation,
                &gate_report,
                Some((&profile.policy, &policy_gate_report)),
                support_policy.enforcement_for("profile", &profile_id),
                support_thresholds,
            )
        })
        .collect::<Vec<_>>();
    let missing_required_slices = support_policy.missing_required_slices(&slices);

    SuiteReleaseReport {
        suite_id: "corpus_style".to_string(),
        status: finalize_suite_status(
            suite_status(
                &overall_eval,
                Some(&overall_policy),
                &slices,
                &missing_required_slices,
            ),
            lookup_failed,
        ),
        missing_required_slices,
        evaluation: evaluation_metrics_from_summary(&summary.evaluation),
        evaluation_gates: gate_report_snapshot(&overall_eval),
        policy: Some(policy_release_snapshot(&summary.policy, &overall_policy)),
        slices,
    }
}

fn build_social_context_suite_report(
    summary: &SocialContextSuiteSummary,
    support_thresholds: ReleaseSupportThresholds,
) -> SuiteReleaseReport {
    let support_policy = report_only_slice_policy();
    let (overall_eval, by_cohort_eval) =
        evaluate_social_context_suite(summary, &pre_release_social_context_gates());
    let (overall_policy, by_cohort_policy) =
        evaluate_social_context_policy_suite(summary, &pre_release_social_context_policy_gates());
    let eval_map = by_cohort_eval.into_iter().collect::<BTreeMap<_, _>>();
    let policy_map = by_cohort_policy.into_iter().collect::<BTreeMap<_, _>>();
    let mut lookup_failed = false;

    let slices = summary
        .cohorts
        .iter()
        .map(|cohort| {
            let gate_report = cloned_gate_report(
                &eval_map,
                &cohort.cohort_id,
                "social_context.cohort",
                &mut lookup_failed,
            );
            let policy_gate_report = cloned_gate_report(
                &policy_map,
                &cohort.cohort_id,
                "social_context.cohort_policy",
                &mut lookup_failed,
            );
            build_slice_report(
                "cohort",
                &cohort.cohort_id,
                &cohort.evaluation,
                &gate_report,
                Some((&cohort.policy, &policy_gate_report)),
                support_policy.enforcement_for("cohort", &cohort.cohort_id),
                support_thresholds,
            )
        })
        .collect::<Vec<_>>();
    let missing_required_slices = support_policy.missing_required_slices(&slices);

    SuiteReleaseReport {
        suite_id: "social_context".to_string(),
        status: finalize_suite_status(
            suite_status(
                &overall_eval,
                Some(&overall_policy),
                &slices,
                &missing_required_slices,
            ),
            lookup_failed,
        ),
        missing_required_slices,
        evaluation: evaluation_metrics_from_summary(&summary.evaluation),
        evaluation_gates: gate_report_snapshot(&overall_eval),
        policy: Some(policy_release_snapshot(&summary.policy, &overall_policy)),
        slices,
    }
}

fn build_realistic_suite_report(
    summary: &RealisticChatSuiteSummary,
    support_thresholds: ReleaseSupportThresholds,
) -> SuiteReleaseReport {
    let support_policy = realistic_slice_policy();
    let (overall_eval, by_language_eval, by_relationship_eval, by_age_eval) =
        evaluate_realistic_chat_suite(summary, &pre_release_realistic_chat_gates());
    let (overall_policy, by_language_policy, by_relationship_policy, by_age_policy) =
        evaluate_realistic_chat_policy_suite(summary, &pre_release_realistic_chat_policy_gates());

    let language_eval = by_language_eval.into_iter().collect::<BTreeMap<_, _>>();
    let relationship_eval = by_relationship_eval.into_iter().collect::<BTreeMap<_, _>>();
    let age_eval = by_age_eval.into_iter().collect::<BTreeMap<_, _>>();
    let language_policy = by_language_policy.into_iter().collect::<BTreeMap<_, _>>();
    let relationship_policy = by_relationship_policy
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let age_policy = by_age_policy.into_iter().collect::<BTreeMap<_, _>>();

    let mut slices = Vec::new();
    let mut lookup_failed = false;
    for slice in &summary.by_language {
        let gate_report = cloned_gate_report(
            &language_eval,
            &slice.slice_id,
            "realistic.language",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &language_policy,
            &slice.slice_id,
            "realistic.language_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "language",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("language", &slice.slice_id),
            support_thresholds,
        ));
    }
    for slice in &summary.by_relationship {
        let gate_report = cloned_gate_report(
            &relationship_eval,
            &slice.slice_id,
            "realistic.relationship",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &relationship_policy,
            &slice.slice_id,
            "realistic.relationship_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "relationship",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("relationship", &slice.slice_id),
            support_thresholds,
        ));
    }
    for slice in &summary.by_age_band {
        let gate_report = cloned_gate_report(
            &age_eval,
            &slice.slice_id,
            "realistic.age_band",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &age_policy,
            &slice.slice_id,
            "realistic.age_band_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "age_band",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("age_band", &slice.slice_id),
            support_thresholds,
        ));
    }
    let missing_required_slices = support_policy.missing_required_slices(&slices);

    SuiteReleaseReport {
        suite_id: "realistic_chat".to_string(),
        status: finalize_suite_status(
            suite_status(
                &overall_eval,
                Some(&overall_policy),
                &slices,
                &missing_required_slices,
            ),
            lookup_failed,
        ),
        missing_required_slices,
        evaluation: evaluation_metrics_from_summary(&summary.evaluation),
        evaluation_gates: gate_report_snapshot(&overall_eval),
        policy: Some(policy_release_snapshot(&summary.policy, &overall_policy)),
        slices,
    }
}

fn build_external_suite_report(
    suite_id: &str,
    summary: &crate::ExternalCuratedSuiteSummary,
    support_thresholds: ReleaseSupportThresholds,
) -> SuiteReleaseReport {
    let support_policy = external_slice_policy();
    let (
        overall_eval,
        by_source_family_eval,
        by_review_status_eval,
        by_language_eval,
        by_relationship_eval,
        by_age_eval,
    ) = evaluate_external_curated_suite(
        summary,
        &pre_release_external_curated_gates_for_manifest(&summary.manifest),
    );
    let (
        overall_policy,
        by_source_family_policy,
        by_review_status_policy,
        by_language_policy,
        by_relationship_policy,
        by_age_policy,
    ) = evaluate_external_curated_policy_suite(
        summary,
        &pre_release_external_curated_policy_gates(),
    );

    let source_eval = by_source_family_eval
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let review_eval = by_review_status_eval
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let language_eval = by_language_eval.into_iter().collect::<BTreeMap<_, _>>();
    let relationship_eval = by_relationship_eval.into_iter().collect::<BTreeMap<_, _>>();
    let age_eval = by_age_eval.into_iter().collect::<BTreeMap<_, _>>();
    let source_policy = by_source_family_policy
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let review_policy = by_review_status_policy
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let language_policy = by_language_policy.into_iter().collect::<BTreeMap<_, _>>();
    let relationship_policy = by_relationship_policy
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let age_policy = by_age_policy.into_iter().collect::<BTreeMap<_, _>>();

    let mut slices = Vec::new();
    let mut lookup_failed = false;
    for slice in &summary.by_source_family {
        let gate_report = cloned_gate_report(
            &source_eval,
            &slice.slice_id,
            "external.source_family",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &source_policy,
            &slice.slice_id,
            "external.source_family_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "source_family",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("source_family", &slice.slice_id),
            support_thresholds,
        ));
    }
    for slice in &summary.by_review_status {
        let gate_report = cloned_gate_report(
            &review_eval,
            &slice.slice_id,
            "external.review_status",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &review_policy,
            &slice.slice_id,
            "external.review_status_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "review_status",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("review_status", &slice.slice_id),
            support_thresholds,
        ));
    }
    for slice in &summary.by_language {
        let gate_report = cloned_gate_report(
            &language_eval,
            &slice.slice_id,
            "external.language",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &language_policy,
            &slice.slice_id,
            "external.language_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "language",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("language", &slice.slice_id),
            support_thresholds,
        ));
    }
    for slice in &summary.by_relationship {
        let gate_report = cloned_gate_report(
            &relationship_eval,
            &slice.slice_id,
            "external.relationship",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &relationship_policy,
            &slice.slice_id,
            "external.relationship_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "relationship",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("relationship", &slice.slice_id),
            support_thresholds,
        ));
    }
    for slice in &summary.by_age_band {
        let gate_report = cloned_gate_report(
            &age_eval,
            &slice.slice_id,
            "external.age_band",
            &mut lookup_failed,
        );
        let policy_gate_report = cloned_gate_report(
            &age_policy,
            &slice.slice_id,
            "external.age_band_policy",
            &mut lookup_failed,
        );
        slices.push(build_slice_report(
            "age_band",
            &slice.slice_id,
            &slice.evaluation,
            &gate_report,
            Some((&slice.policy, &policy_gate_report)),
            support_policy.enforcement_for("age_band", &slice.slice_id),
            support_thresholds,
        ));
    }
    let missing_required_slices = support_policy.missing_required_slices(&slices);

    SuiteReleaseReport {
        suite_id: suite_id.to_string(),
        status: finalize_suite_status(
            suite_status(
                &overall_eval,
                Some(&overall_policy),
                &slices,
                &missing_required_slices,
            ),
            lookup_failed,
        ),
        missing_required_slices,
        evaluation: evaluation_metrics_from_summary(&summary.evaluation),
        evaluation_gates: gate_report_snapshot(&overall_eval),
        policy: Some(policy_release_snapshot(&summary.policy, &overall_policy)),
        slices,
    }
}

fn build_slice_report(
    group: &str,
    slice_id: &str,
    evaluation: &ScenarioEvaluationSummary,
    evaluation_gates: &ScenarioGateReport,
    policy: Option<(&PolicyActionSummary, &ScenarioGateReport)>,
    support_enforcement: SupportEnforcement,
    support_thresholds: ReleaseSupportThresholds,
) -> SliceReleaseReport {
    let support = support_assessment_from_summary(evaluation, support_thresholds);
    let policy_snapshot = policy.map(|(summary, gates)| policy_release_snapshot(summary, gates));
    let policy_gate_report = policy.map(|(_, gates)| gates);

    SliceReleaseReport {
        group: group.to_string(),
        slice_id: slice_id.to_string(),
        support_enforcement,
        status: status_from_gate_and_support(evaluation_gates, policy_gate_report, &support),
        support,
        evaluation: evaluation_metrics_from_summary(evaluation),
        evaluation_gates: gate_report_snapshot(evaluation_gates),
        policy: policy_snapshot,
    }
}

fn build_drift_report(
    comparison_id: &str,
    baseline: &SuiteReleaseReport,
    candidate: &SuiteReleaseReport,
    thresholds: ReleaseDriftThresholds,
) -> SuiteDriftReport {
    let metrics = DriftMetricsSnapshot {
        brier_delta: (baseline.evaluation.brier_score - candidate.evaluation.brier_score).abs(),
        expected_calibration_error_delta: (baseline.evaluation.expected_calibration_error
            - candidate.evaluation.expected_calibration_error)
            .abs(),
        positive_detection_rate_delta: (baseline.evaluation.positive_detection_rate
            - candidate.evaluation.positive_detection_rate)
            .abs(),
        negative_false_positive_rate_delta: (baseline.evaluation.negative_false_positive_rate
            - candidate.evaluation.negative_false_positive_rate)
            .abs(),
    };
    let checks = vec![
        drift_check(
            "max_brier_delta",
            metrics.brier_delta,
            thresholds.max_brier_delta,
        ),
        drift_check(
            "max_expected_calibration_error_delta",
            metrics.expected_calibration_error_delta,
            thresholds.max_expected_calibration_error_delta,
        ),
        drift_check(
            "max_positive_detection_rate_delta",
            metrics.positive_detection_rate_delta,
            thresholds.max_positive_detection_rate_delta,
        ),
        drift_check(
            "max_negative_false_positive_rate_delta",
            metrics.negative_false_positive_rate_delta,
            thresholds.max_negative_false_positive_rate_delta,
        ),
    ];
    let gates = ScenarioGateReport {
        passed: checks.iter().all(|check| check.passed),
        checks,
    };
    let release_blocking_ready =
        baseline.status == ReleaseStatus::Pass && candidate.status == ReleaseStatus::Pass;

    SuiteDriftReport {
        comparison_id: comparison_id.to_string(),
        baseline_suite_id: baseline.suite_id.clone(),
        candidate_suite_id: candidate.suite_id.clone(),
        baseline_status: baseline.status,
        candidate_status: candidate.status,
        release_blocking_ready,
        status: drift_status(&gates, release_blocking_ready),
        metrics,
        gates: gate_report_snapshot(&gates),
    }
}

fn drift_status(gates: &ScenarioGateReport, release_blocking_ready: bool) -> ReleaseStatus {
    if gates.passed {
        ReleaseStatus::Pass
    } else if release_blocking_ready {
        ReleaseStatus::Fail
    } else {
        ReleaseStatus::InsufficientSupport
    }
}

fn drift_check(name: &str, actual: f32, threshold: f32) -> ScenarioGateCheck {
    ScenarioGateCheck {
        name: name.to_string(),
        comparison: GateComparison::AtMost,
        actual,
        threshold,
        passed: actual <= threshold,
    }
}

fn cloned_gate_report(
    reports: &BTreeMap<String, ScenarioGateReport>,
    slice_id: &str,
    context: &str,
    lookup_failed: &mut bool,
) -> ScenarioGateReport {
    match reports.get(slice_id) {
        Some(report) => report.clone(),
        None => {
            *lookup_failed = true;
            missing_gate_report(context, slice_id)
        }
    }
}

fn missing_gate_report(context: &str, slice_id: &str) -> ScenarioGateReport {
    ScenarioGateReport {
        passed: false,
        checks: vec![ScenarioGateCheck {
            name: format!("internal.{context}.{slice_id}.gate_report_present"),
            comparison: GateComparison::AtLeast,
            actual: 0.0,
            threshold: 1.0,
            passed: false,
        }],
    }
}

fn scenario_summary_from_language_slice(slice: &LanguageSliceSummary) -> ScenarioEvaluationSummary {
    ScenarioEvaluationSummary {
        calibration: slice.calibration.clone(),
        lead_time: slice.lead_time.clone(),
        classification: slice.classification.clone(),
        language_slices: Vec::new(),
        scenarios: Vec::new(),
    }
}

fn support_aware_slice_gates(
    summary: &ScenarioEvaluationSummary,
    base: &ScenarioQualityGates,
    thresholds: ReleaseSupportThresholds,
) -> ScenarioQualityGates {
    let mut adapted = base.clone();
    adapted.per_threat = base
        .per_threat
        .iter()
        .filter_map(|gate| {
            let count = calibration_for_threat(&summary.calibration, gate.threat_type)
                .map(|report| report.count)
                .unwrap_or(0);
            if count < thresholds.min_reportable_calibration_examples {
                return None;
            }

            let mut adapted_gate = gate.clone();
            adapted_gate.min_example_count = adapted_gate
                .min_example_count
                .map(|required| required.min(count));
            Some(adapted_gate)
        })
        .collect();

    if summary.calibration.count < thresholds.min_reportable_calibration_examples {
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
    if summary.lead_time.total_cases < thresholds.min_reportable_onset_cases {
        adapted.min_pre_onset_detection_rate = None;
    }

    adapted
}

fn support_assessment_from_summary(
    summary: &ScenarioEvaluationSummary,
    thresholds: ReleaseSupportThresholds,
) -> SupportAssessmentSnapshot {
    let calibration_examples = summary.calibration.count;
    let positive_scenarios = summary.classification.total_positive_scenarios;
    let negative_scenarios = summary.classification.total_negative_scenarios;
    let onset_cases = summary.lead_time.total_cases;

    let mut reportable_basis = Vec::new();
    if calibration_examples >= thresholds.min_reportable_calibration_examples {
        reportable_basis.push("calibration_examples".to_string());
    }
    if onset_cases >= thresholds.min_reportable_onset_cases {
        reportable_basis.push("onset_cases".to_string());
    }

    let missing_release_blocking = vec![
        support_requirement(
            "min_blocking_calibration_examples",
            calibration_examples,
            thresholds.min_blocking_calibration_examples,
        ),
        support_requirement(
            "min_blocking_positive_scenarios",
            positive_scenarios,
            thresholds.min_blocking_positive_scenarios,
        ),
        support_requirement(
            "min_blocking_negative_scenarios",
            negative_scenarios,
            thresholds.min_blocking_negative_scenarios,
        ),
        support_requirement(
            "min_blocking_onset_cases",
            onset_cases,
            thresholds.min_blocking_onset_cases,
        ),
    ]
    .into_iter()
    .filter(|requirement| !requirement.passed)
    .collect::<Vec<_>>();

    SupportAssessmentSnapshot {
        calibration_examples,
        positive_scenarios,
        negative_scenarios,
        onset_cases,
        reportable: !reportable_basis.is_empty(),
        release_blocking_ready: missing_release_blocking.is_empty(),
        reportable_basis,
        missing_release_blocking,
    }
}

fn support_requirement(
    requirement: &str,
    actual: usize,
    required: usize,
) -> SupportRequirementSnapshot {
    SupportRequirementSnapshot {
        requirement: requirement.to_string(),
        actual,
        required,
        passed: actual >= required,
    }
}

fn evaluation_metrics_from_summary(
    summary: &ScenarioEvaluationSummary,
) -> EvaluationMetricsSnapshot {
    EvaluationMetricsSnapshot {
        calibration_count: summary.calibration.count,
        brier_score: summary.calibration.brier_score,
        expected_calibration_error: summary.calibration.expected_calibration_error,
        positive_detection_rate: summary.classification.positive_detection_rate,
        negative_false_positive_rate: summary.classification.negative_false_positive_rate,
        pre_onset_detection_rate: pre_onset_detection_rate(summary),
        positive_scenarios: summary.classification.total_positive_scenarios,
        negative_scenarios: summary.classification.total_negative_scenarios,
        onset_cases: summary.lead_time.total_cases,
        by_threat: summary
            .calibration
            .by_threat
            .iter()
            .map(|threat| ThreatCalibrationSnapshot {
                threat_type: threat_label(threat.threat_type),
                count: threat.count,
                brier_score: threat.brier_score,
                expected_calibration_error: threat.expected_calibration_error,
            })
            .collect(),
    }
}

fn policy_release_snapshot(
    summary: &PolicyActionSummary,
    gates: &ScenarioGateReport,
) -> PolicyReleaseSnapshot {
    PolicyReleaseSnapshot {
        metrics: policy_metrics_from_summary(summary),
        gates: gate_report_snapshot(gates),
    }
}

fn policy_metrics_from_summary(summary: &PolicyActionSummary) -> PolicyMetricsSnapshot {
    PolicyMetricsSnapshot {
        total_scenarios: summary.total_scenarios,
        passed_scenarios: summary.passed_scenarios,
        failed_scenarios: summary.failed_scenarios,
        scenario_pass_rate: summary.scenario_pass_rate,
        required_any_coverage: summary.required_any_coverage,
        required_by_onset_coverage: summary.required_by_onset_coverage,
        forbidden_violation_rate: summary.forbidden_violation_rate,
    }
}

fn gate_report_snapshot(report: &ScenarioGateReport) -> GateReportSnapshot {
    GateReportSnapshot {
        passed: report.passed,
        checks: report.checks.iter().map(gate_check_snapshot).collect(),
    }
}

fn gate_check_snapshot(check: &ScenarioGateCheck) -> GateCheckSnapshot {
    GateCheckSnapshot {
        name: check.name.clone(),
        comparison: comparison_label(check.comparison).to_string(),
        actual: finite_value(check.actual),
        threshold: check.threshold,
        passed: check.passed,
    }
}

fn pre_onset_detection_rate(summary: &ScenarioEvaluationSummary) -> Option<f32> {
    if summary.lead_time.total_cases == 0 {
        None
    } else {
        Some(
            summary.lead_time.detected_before_onset_cases as f32
                / summary.lead_time.total_cases as f32,
        )
    }
}

fn comparison_label(comparison: GateComparison) -> &'static str {
    match comparison {
        GateComparison::AtMost => "at_most",
        GateComparison::AtLeast => "at_least",
    }
}

fn finite_value(value: f32) -> Option<f32> {
    value.is_finite().then_some(value)
}

fn threat_label(threat_type: ThreatType) -> String {
    format!("{threat_type:?}")
}

fn status_from_gate_and_support(
    evaluation_gates: &ScenarioGateReport,
    policy_gates: Option<&ScenarioGateReport>,
    support: &SupportAssessmentSnapshot,
) -> ReleaseStatus {
    if !evaluation_gates.passed || policy_gates.is_some_and(|report| !report.passed) {
        ReleaseStatus::Fail
    } else if !support.release_blocking_ready {
        ReleaseStatus::InsufficientSupport
    } else {
        ReleaseStatus::Pass
    }
}

fn suite_status(
    evaluation_gates: &ScenarioGateReport,
    policy_gates: Option<&ScenarioGateReport>,
    slices: &[SliceReleaseReport],
    missing_required_slices: &[String],
) -> ReleaseStatus {
    let gate_status =
        if !evaluation_gates.passed || policy_gates.is_some_and(|report| !report.passed) {
            ReleaseStatus::Fail
        } else {
            ReleaseStatus::Pass
        };
    let missing_required_status =
        (!missing_required_slices.is_empty()).then_some(ReleaseStatus::InsufficientSupport);
    combine_statuses(
        std::iter::once(gate_status)
            .chain(missing_required_status)
            .chain(
                slices
                    .iter()
                    .filter(|slice| {
                        matches!(
                            slice.support_enforcement,
                            SupportEnforcement::ReleaseBlocking
                        )
                    })
                    .map(|slice| slice.status),
            ),
    )
}

fn combine_statuses(statuses: impl IntoIterator<Item = ReleaseStatus>) -> ReleaseStatus {
    let mut combined = ReleaseStatus::Pass;
    for status in statuses {
        combined = match (combined, status) {
            (_, ReleaseStatus::Blocked) | (ReleaseStatus::Blocked, _) => ReleaseStatus::Blocked,
            (_, ReleaseStatus::Fail) | (ReleaseStatus::Fail, _) => ReleaseStatus::Fail,
            (_, ReleaseStatus::InsufficientSupport) | (ReleaseStatus::InsufficientSupport, _) => {
                ReleaseStatus::InsufficientSupport
            }
            _ => ReleaseStatus::Pass,
        };
    }
    combined
}

fn finalize_suite_status(status: ReleaseStatus, lookup_failed: bool) -> ReleaseStatus {
    combine_statuses(std::iter::once(status).chain(lookup_failed.then_some(ReleaseStatus::Blocked)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_assessment_tracks_reportable_and_blocking_thresholds() {
        let summary = ScenarioEvaluationSummary {
            calibration: crate::CalibrationReport {
                count: 13,
                brier_score: 0.1,
                expected_calibration_error: 0.1,
                bins: Vec::new(),
                by_threat: Vec::new(),
            },
            lead_time: crate::LeadTimeSummary {
                total_cases: 2,
                detected_cases: 2,
                detected_before_onset_cases: 1,
                missed_cases: 0,
                mean_lead_time_ms: None,
                median_lead_time_ms: None,
            },
            classification: crate::ScenarioClassificationSummary {
                total_positive_scenarios: 3,
                detected_positive_scenarios: 3,
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

        let support =
            support_assessment_from_summary(&summary, default_release_support_thresholds());

        assert!(support.reportable);
        assert!(!support.release_blocking_ready);
        assert!(support
            .missing_release_blocking
            .iter()
            .any(|requirement| requirement.requirement == "min_blocking_negative_scenarios"));
    }

    #[test]
    fn status_prefers_fail_over_support_shortfall() {
        let failing_gates = ScenarioGateReport {
            passed: false,
            checks: vec![ScenarioGateCheck {
                name: "max_brier_score".to_string(),
                comparison: GateComparison::AtMost,
                actual: 0.4,
                threshold: 0.2,
                passed: false,
            }],
        };
        let support = SupportAssessmentSnapshot {
            calibration_examples: 4,
            positive_scenarios: 1,
            negative_scenarios: 0,
            onset_cases: 0,
            reportable: false,
            release_blocking_ready: false,
            reportable_basis: Vec::new(),
            missing_release_blocking: vec![support_requirement(
                "min_blocking_calibration_examples",
                4,
                24,
            )],
        };

        assert_eq!(
            status_from_gate_and_support(&failing_gates, None, &support),
            ReleaseStatus::Fail
        );
    }

    #[test]
    fn support_aware_slice_gates_keep_reportable_per_threat_checks() {
        let summary = ScenarioEvaluationSummary {
            calibration: crate::CalibrationReport {
                count: 18,
                brier_score: 0.09,
                expected_calibration_error: 0.08,
                bins: Vec::new(),
                by_threat: vec![crate::ThreatCalibrationReport {
                    threat_type: ThreatType::Manipulation,
                    count: 12,
                    brier_score: 0.11,
                    expected_calibration_error: 0.10,
                    bins: Vec::new(),
                }],
            },
            lead_time: crate::LeadTimeSummary {
                total_cases: 8,
                detected_cases: 8,
                detected_before_onset_cases: 6,
                missed_cases: 0,
                mean_lead_time_ms: Some(2_500.0),
                median_lead_time_ms: Some(2_000),
            },
            classification: crate::ScenarioClassificationSummary {
                total_positive_scenarios: 8,
                detected_positive_scenarios: 8,
                missed_positive_scenarios: 0,
                positive_detection_rate: 1.0,
                total_negative_scenarios: 8,
                clean_negative_scenarios: 8,
                false_positive_scenarios: 0,
                negative_false_positive_rate: 0.0,
                scenarios: Vec::new(),
            },
            language_slices: Vec::new(),
            scenarios: Vec::new(),
        };
        let gates = ScenarioQualityGates {
            max_brier_score: Some(0.2),
            max_expected_calibration_error: Some(0.2),
            min_positive_detection_rate: Some(0.8),
            max_negative_false_positive_rate: Some(0.1),
            min_pre_onset_detection_rate: Some(0.5),
            per_threat: vec![crate::ThreatCalibrationGate {
                threat_type: ThreatType::Manipulation,
                min_example_count: Some(20),
                max_brier_score: Some(0.2),
                max_expected_calibration_error: Some(0.2),
            }],
        };

        let adapted =
            support_aware_slice_gates(&summary, &gates, default_release_support_thresholds());

        assert_eq!(adapted.per_threat.len(), 1);
        assert_eq!(adapted.per_threat[0].threat_type, ThreatType::Manipulation);
        assert_eq!(adapted.per_threat[0].min_example_count, Some(12));
    }

    #[test]
    fn suite_status_ignores_report_only_slice_support_shortfalls() {
        let gates = ScenarioGateReport {
            passed: true,
            checks: Vec::new(),
        };
        let slice = SliceReleaseReport {
            group: "language".to_string(),
            slice_id: "ru".to_string(),
            support_enforcement: SupportEnforcement::ReportOnly,
            status: ReleaseStatus::InsufficientSupport,
            support: SupportAssessmentSnapshot {
                calibration_examples: 4,
                positive_scenarios: 1,
                negative_scenarios: 0,
                onset_cases: 1,
                reportable: false,
                release_blocking_ready: false,
                reportable_basis: Vec::new(),
                missing_release_blocking: vec![support_requirement(
                    "min_blocking_calibration_examples",
                    4,
                    24,
                )],
            },
            evaluation: EvaluationMetricsSnapshot {
                calibration_count: 4,
                brier_score: 0.0,
                expected_calibration_error: 0.0,
                positive_detection_rate: 1.0,
                negative_false_positive_rate: 0.0,
                pre_onset_detection_rate: Some(1.0),
                positive_scenarios: 1,
                negative_scenarios: 0,
                onset_cases: 1,
                by_threat: Vec::new(),
            },
            evaluation_gates: GateReportSnapshot {
                passed: true,
                checks: Vec::new(),
            },
            policy: None,
        };

        assert_eq!(
            suite_status(&gates, None, &[slice], &[]),
            ReleaseStatus::Pass
        );
    }

    #[test]
    fn suite_status_requires_release_blocking_slice_support() {
        let gates = ScenarioGateReport {
            passed: true,
            checks: Vec::new(),
        };
        let slice = SliceReleaseReport {
            group: "relationship".to_string(),
            slice_id: "trusted_adult".to_string(),
            support_enforcement: SupportEnforcement::ReleaseBlocking,
            status: ReleaseStatus::InsufficientSupport,
            support: SupportAssessmentSnapshot {
                calibration_examples: 12,
                positive_scenarios: 1,
                negative_scenarios: 1,
                onset_cases: 1,
                reportable: true,
                release_blocking_ready: false,
                reportable_basis: vec!["calibration_examples".to_string()],
                missing_release_blocking: vec![support_requirement(
                    "min_blocking_positive_scenarios",
                    1,
                    8,
                )],
            },
            evaluation: EvaluationMetricsSnapshot {
                calibration_count: 12,
                brier_score: 0.0,
                expected_calibration_error: 0.0,
                positive_detection_rate: 1.0,
                negative_false_positive_rate: 0.0,
                pre_onset_detection_rate: Some(1.0),
                positive_scenarios: 1,
                negative_scenarios: 1,
                onset_cases: 1,
                by_threat: Vec::new(),
            },
            evaluation_gates: GateReportSnapshot {
                passed: true,
                checks: Vec::new(),
            },
            policy: None,
        };

        assert_eq!(
            suite_status(&gates, None, &[slice], &[]),
            ReleaseStatus::InsufficientSupport
        );
    }

    #[test]
    fn suite_status_flags_missing_required_slices() {
        let gates = ScenarioGateReport {
            passed: true,
            checks: Vec::new(),
        };

        assert_eq!(
            suite_status(
                &gates,
                None,
                &[],
                &[
                    "language:ru".to_string(),
                    "relationship:trusted_adult".to_string()
                ],
            ),
            ReleaseStatus::InsufficientSupport
        );
    }

    #[test]
    fn drift_status_requires_blocking_ready_for_hard_failures() {
        let failing_gates = ScenarioGateReport {
            passed: false,
            checks: vec![ScenarioGateCheck {
                name: "max_expected_calibration_error_delta".to_string(),
                comparison: GateComparison::AtMost,
                actual: 0.08,
                threshold: 0.05,
                passed: false,
            }],
        };

        assert_eq!(
            drift_status(&failing_gates, false),
            ReleaseStatus::InsufficientSupport
        );
        assert_eq!(drift_status(&failing_gates, true), ReleaseStatus::Fail);
    }

    #[test]
    fn pre_release_report_serializes_and_lists_critical_suites() {
        let db = PatternDatabase::default_mvp();
        let report = run_pre_release_report(&db, 5);
        let json = serde_json::to_string(&report).expect("release report json");

        assert!(json.contains("canonical_messenger"));
        assert!(json.contains("realistic_chat"));
        assert!(json.contains("external_curated_gold"));
        assert!(json.contains("external_mixed_vs_gold"));
        assert!(json.contains("support_enforcement"));
        assert!(json.contains("missing_required_slices"));
        assert!(json.contains("release_blocking_ready"));
        assert_eq!(report.schema_version, RELEASE_REPORT_SCHEMA_VERSION);
    }
}
