use aura_core::{
    evaluate_realistic_chat_policy_suite, evaluate_realistic_chat_suite,
    pre_release_realistic_chat_gates, pre_release_realistic_chat_policy_gates,
    run_realistic_chat_suite, GateComparison,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let summary = run_realistic_chat_suite(&db, 6);
    let (overall_eval, by_language_eval, by_relationship_eval, by_age_eval) =
        evaluate_realistic_chat_suite(&summary, &pre_release_realistic_chat_gates());
    let (overall_policy, by_language_policy, by_relationship_policy, by_age_policy) =
        evaluate_realistic_chat_policy_suite(&summary, &pre_release_realistic_chat_policy_gates());

    println!("AURA realistic chat evaluation");
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
    println!(
        "Realistic gates: {}",
        if overall_eval.passed { "PASS" } else { "FAIL" }
    );
    for check in &overall_eval.checks {
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

    println!();
    println!(
        "Realistic policy gates: {}",
        if overall_policy.passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    for check in &overall_policy.checks {
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
    if !overall_policy.passed {
        for scenario in summary
            .policy
            .scenarios
            .iter()
            .filter(|scenario| !scenario.passed)
        {
            println!(
                "  policy fail: run={} expectation={} all={:?} missing_any={:?} missing_by_onset={:?} forbidden={:?}",
                scenario.scenario_name,
                scenario.expectation_name,
                scenario.all_actions,
                scenario.missing_required_any,
                scenario.missing_required_by_onset,
                scenario.forbidden_actions_present
            );
        }
    }

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

fn print_slice_group(
    title: &str,
    slices: &[aura_core::RealisticChatSliceSummary],
    eval_reports: &[(String, aura_core::ScenarioGateReport)],
    policy_reports: &[(String, aura_core::ScenarioGateReport)],
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
            .map(|(_, report)| report)
            .expect("matching policy report");

        println!(
            "  {} -> cases={} calib={} positives={} negatives={} onset={} brier={:.4} ece={:.4} pos_detect={:.2} neg_fp={:.2} eval_gates={} policy_gates={} policy_pass_rate={:.2}",
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
            if policy_report.passed { "PASS" } else { "FAIL" },
            slice.policy.scenario_pass_rate
        );
        if !policy_report.passed {
            for scenario in slice
                .policy
                .scenarios
                .iter()
                .filter(|scenario| !scenario.passed)
            {
                println!(
                    "    policy fail: run={} expectation={} all={:?} missing_any={:?} missing_by_onset={:?} forbidden={:?}",
                    scenario.scenario_name,
                    scenario.expectation_name,
                    scenario.all_actions,
                    scenario.missing_required_any,
                    scenario.missing_required_by_onset,
                    scenario.forbidden_actions_present
                );
            }
        }
    }
}
