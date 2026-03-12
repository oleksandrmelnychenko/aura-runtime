use aura_core::{
    evaluate_external_curated_policy_suite, evaluate_external_curated_suite,
    pre_release_external_curated_gates_for_manifest, pre_release_external_curated_policy_gates,
    run_external_curated_gold_suite, run_external_curated_suite, ExternalCuratedSliceSummary,
    ExternalCuratedSuiteSummary, GateComparison, ScenarioGateReport,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let mixed_summary = run_external_curated_suite(&db, 6);
    print_suite("AURA external curated corpus evaluation", &mixed_summary);

    println!();
    let gold_summary = run_external_curated_gold_suite(&db, 6);
    print_suite("AURA external curated gold-only evaluation", &gold_summary);
}

fn print_suite(title: &str, summary: &ExternalCuratedSuiteSummary) {
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

    println!("{title}");
    println!(
        "  dataset: id={} label=\"{}\" schema={} curation_status={} maintainer={}",
        summary.manifest.dataset_id,
        summary.manifest.dataset_label,
        summary.manifest.schema_version,
        summary.manifest.curation_status,
        summary.manifest.maintainer
    );
    println!(
        "  calibration: count={} brier={:.4} ece={:.4}",
        summary.evaluation.calibration.count,
        summary.evaluation.calibration.brier_score,
        summary.evaluation.calibration.expected_calibration_error
    );
    println!(
        "  classification: positive_detect_rate={:.2} negative_fp_rate={:.2}",
        summary.evaluation.classification.positive_detection_rate,
        summary
            .evaluation
            .classification
            .negative_false_positive_rate
    );
    println!(
        "  lead-time: total={} detected={} before_onset={} missed={}",
        summary.evaluation.lead_time.total_cases,
        summary.evaluation.lead_time.detected_cases,
        summary.evaluation.lead_time.detected_before_onset_cases,
        summary.evaluation.lead_time.missed_cases
    );
    println!(
        "  policy: pass_rate={:.2} required_any={:.2} required_by_onset={:.2} forbidden_violation_rate={:.2}",
        summary.policy.scenario_pass_rate,
        summary.policy.required_any_coverage,
        summary.policy.required_by_onset_coverage,
        summary.policy.forbidden_violation_rate
    );

    println!();
    print_gate_report("External curated gates", &overall_eval);
    println!();
    print_gate_report("External curated policy gates", &overall_policy);

    print_slice_group(
        "By source family",
        &summary.by_source_family,
        &by_source_family_eval,
        &by_source_family_policy,
    );
    print_slice_group(
        "By review status",
        &summary.by_review_status,
        &by_review_status_eval,
        &by_review_status_policy,
    );
    print_slice_group(
        "By language",
        &summary.by_language,
        &by_language_eval,
        &by_language_policy,
    );
    print_slice_group(
        "By relationship",
        &summary.by_relationship,
        &by_relationship_eval,
        &by_relationship_policy,
    );
    print_slice_group(
        "By age band",
        &summary.by_age_band,
        &by_age_eval,
        &by_age_policy,
    );
}

fn print_gate_report(title: &str, report: &ScenarioGateReport) {
    println!("{title}: {}", if report.passed { "PASS" } else { "FAIL" });
    for check in &report.checks {
        let op = match check.comparison {
            GateComparison::AtMost => "<=",
            GateComparison::AtLeast => ">=",
        };
        println!(
            "  {}: actual={:.4} {} threshold={:.4} => {}",
            check.name,
            check.actual,
            op,
            check.threshold,
            if check.passed { "pass" } else { "fail" }
        );
    }
}

fn print_slice_group(
    title: &str,
    slices: &[ExternalCuratedSliceSummary],
    eval_reports: &[(String, ScenarioGateReport)],
    policy_reports: &[(String, ScenarioGateReport)],
) {
    println!();
    println!("{title}");
    for slice in slices {
        let eval_report = eval_reports
            .iter()
            .find(|(slice_id, _)| slice_id == &slice.slice_id)
            .map(|(_, report)| report)
            .expect("matching eval report");
        let policy_report = policy_reports
            .iter()
            .find(|(slice_id, _)| slice_id == &slice.slice_id)
            .map(|(_, report)| report);

        println!(
            "  {} -> cases={} calib={} positives={} negatives={} onset={} brier={:.4} ece={:.4} pos_detect={:.2} neg_fp={:.2} eval_gates={} policy_gates={} policy_pass_rate={}",
            slice.slice_id,
            slice.case_count,
            slice.evaluation.calibration.count,
            slice.evaluation.classification.total_positive_scenarios,
            slice.evaluation.classification.total_negative_scenarios,
            slice.evaluation.lead_time.total_cases,
            slice.evaluation.calibration.brier_score,
            slice.evaluation.calibration.expected_calibration_error,
            slice.evaluation.classification.positive_detection_rate,
            slice.evaluation.classification.negative_false_positive_rate,
            if eval_report.passed { "PASS" } else { "FAIL" },
            policy_report
                .map(|report| if report.passed { "PASS" } else { "FAIL" })
                .unwrap_or("N/A"),
            policy_report
                .map(|_| format!("{:.2}", slice.policy.scenario_pass_rate))
                .unwrap_or_else(|| "N/A".to_string())
        );
    }
}
