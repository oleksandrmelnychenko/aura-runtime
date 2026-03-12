use aura_core::{
    canonical_robustness_seed_scenarios, default_robustness_profiles, evaluate_robustness_suite,
    pre_release_robustness_gates, run_robustness_suite, GateComparison,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let seeds = canonical_robustness_seed_scenarios();
    let profiles = default_robustness_profiles();
    let summary = run_robustness_suite(&db, &seeds, &profiles, 6);
    let gates = pre_release_robustness_gates();
    let (overall_gate_report, profile_gate_reports) = evaluate_robustness_suite(&summary, &gates);

    println!("AURA robustness evaluation");
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

    println!();
    println!(
        "Robustness gates: {}",
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
    println!("Per-profile slices");
    for profile in &summary.profiles {
        let gate_report = profile_gate_reports
            .iter()
            .find(|(candidate, _)| candidate == &profile.profile)
            .map(|(_, report)| report)
            .expect("matching profile report");
        println!(
            "  {} -> variants={} mutated_steps={} brier={:.4} ece={:.4} pos_detect={:.2} neg_fp={:.2} gates={}",
            profile.profile.label(),
            profile.variant_count,
            profile.mutated_steps,
            profile.evaluation.calibration.brier_score,
            profile.evaluation.calibration.expected_calibration_error,
            profile.evaluation.classification.positive_detection_rate,
            profile.evaluation.classification.negative_false_positive_rate,
            if gate_report.passed { "PASS" } else { "FAIL" }
        );
    }

    println!();
    println!("Variant coverage");
    for variant in &summary.variants {
        println!(
            "  {} -> base={} profile={} mutated_steps={}",
            variant.variant_name,
            variant.base_case_name,
            variant.profile.label(),
            variant.mutated_steps
        );
    }
}
