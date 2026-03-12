use aura_core::{
    canonical_social_context_seed_scenarios, default_social_context_profiles,
    evaluate_social_context_policy_suite, evaluate_social_context_suite,
    pre_release_social_context_gates, pre_release_social_context_policy_gates,
    run_social_context_suite, GateComparison,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let summary = run_social_context_suite(
        &db,
        &canonical_social_context_seed_scenarios(),
        &default_social_context_profiles(),
        6,
    );
    let (overall_gate_report, cohort_gate_reports) =
        evaluate_social_context_suite(&summary, &pre_release_social_context_gates());
    let (overall_policy_report, cohort_policy_reports) =
        evaluate_social_context_policy_suite(&summary, &pre_release_social_context_policy_gates());

    println!("AURA social-context evaluation");
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
        "Social-context gates: {}",
        if overall_gate_report.passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    for check in &overall_gate_report.checks {
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
        "Social-context policy gates: {}",
        if overall_policy_report.passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    for check in &overall_policy_report.checks {
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
    println!("Per-cohort slices");
    for cohort in &summary.cohorts {
        let gate_report = cohort_gate_reports
            .iter()
            .find(|(candidate, _)| candidate == &cohort.cohort_id)
            .map(|(_, report)| report)
            .expect("matching cohort report");
        let policy_report = cohort_policy_reports
            .iter()
            .find(|(candidate, _)| candidate == &cohort.cohort_id)
            .map(|(_, report)| report)
            .expect("matching cohort policy report");
        println!(
            "  {} -> variants={} base_cases={} profiles={} brier={:.4} ece={:.4} pos_detect={:.2} neg_fp={:.2} eval_gates={} policy_gates={} policy_pass_rate={:.2}",
            cohort.cohort_id,
            cohort.variant_count,
            cohort.base_cases.join(","),
            cohort.style_profiles.join(","),
            cohort.evaluation.calibration.brier_score,
            cohort.evaluation.calibration.expected_calibration_error,
            cohort.evaluation.classification.positive_detection_rate,
            cohort.evaluation.classification.negative_false_positive_rate,
            if gate_report.passed { "PASS" } else { "FAIL" },
            if policy_report.passed { "PASS" } else { "FAIL" },
            cohort.policy.scenario_pass_rate
        );
        if !policy_report.passed {
            for scenario in cohort
                .policy
                .scenarios
                .iter()
                .filter(|scenario| !scenario.passed)
            {
                println!(
                    "    policy fail: run={} expectation={} missing_any={:?} missing_by_onset={:?} forbidden={:?}",
                    scenario.scenario_name,
                    scenario.expectation_name,
                    scenario.missing_required_any,
                    scenario.missing_required_by_onset,
                    scenario.forbidden_actions_present
                );
            }
        }
        for check in &gate_report.checks {
            let op = match check.comparison {
                GateComparison::AtMost => "<=",
                GateComparison::AtLeast => ">=",
            };
            println!(
                "    {}: actual={:.4} {} threshold={:.4} => {}",
                check.name,
                check.actual,
                op,
                check.threshold,
                if check.passed { "pass" } else { "fail" }
            );
        }
    }
}
