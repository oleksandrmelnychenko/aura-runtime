use aura_core::{
    canonical_corpus_seed_scenarios, default_corpus_style_profiles,
    evaluate_corpus_style_policy_suite, evaluate_corpus_style_suite,
    pre_release_corpus_policy_gates, pre_release_corpus_style_gates, run_corpus_style_suite,
    GateComparison,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let seeds = canonical_corpus_seed_scenarios();
    let profiles = default_corpus_style_profiles();
    let summary = run_corpus_style_suite(&db, &seeds, &profiles, 6);
    let gates = pre_release_corpus_style_gates();
    let (overall_gate_report, profile_gate_reports) = evaluate_corpus_style_suite(&summary, &gates);
    let (overall_policy_report, profile_policy_reports) =
        evaluate_corpus_style_policy_suite(&summary, &pre_release_corpus_policy_gates());

    println!("AURA corpus-style evaluation");
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
        "Corpus-style gates: {}",
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
        "Corpus policy gates: {}",
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
    println!("Per-style slices");
    for profile in &summary.profiles {
        let gate_report = profile_gate_reports
            .iter()
            .find(|(candidate, _)| candidate == &profile.profile)
            .map(|(_, report)| report)
            .expect("matching profile report");
        let policy_report = profile_policy_reports
            .iter()
            .find(|(candidate, _)| candidate == &profile.profile)
            .map(|(_, report)| report);
        println!(
            "  {} -> variants={} mutated_steps={} brier={:.4} ece={:.4} pos_detect={:.2} neg_fp={:.2} eval_gates={} policy_gates={} policy_pass_rate={:.2}",
            profile.profile.label(),
            profile.variant_count,
            profile.mutated_steps,
            profile.evaluation.calibration.brier_score,
            profile.evaluation.calibration.expected_calibration_error,
            profile.evaluation.classification.positive_detection_rate,
            profile.evaluation.classification.negative_false_positive_rate,
            if gate_report.passed { "PASS" } else { "FAIL" },
            policy_report
                .map(|report| if report.passed { "PASS" } else { "FAIL" })
                .unwrap_or("N/A"),
            profile.policy.scenario_pass_rate
        );
        if policy_report.is_some_and(|report| !report.passed) {
            for scenario in profile
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
    }

    println!();
    println!("Variant coverage");
    for variant in &summary.variants {
        println!(
            "  {} -> base_case={} base_variant={} profile={} mutated_steps={}",
            variant.variant_name,
            variant.base_case_name,
            variant.base_variant_name,
            variant.profile.label(),
            variant.mutated_steps
        );
    }
}
