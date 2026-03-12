use aura_core::{
    canonical_manipulation_scenarios, evaluate_scenario_quality_gates,
    pre_release_manipulation_gates, run_scenario_case, summarize_scenario_runs, GateComparison,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let pack = canonical_manipulation_scenarios();
    let runs: Vec<_> = pack
        .iter()
        .map(|case| run_scenario_case(&db, case))
        .collect();
    let summary = summarize_scenario_runs(&runs, 6);
    let gates = pre_release_manipulation_gates();
    let gate_report = evaluate_scenario_quality_gates(&summary, &gates);

    println!("AURA manipulation-track evaluation");
    println!(
        "  calibration: count={} brier={:.4} ece={:.4}",
        summary.calibration.count,
        summary.calibration.brier_score,
        summary.calibration.expected_calibration_error
    );
    println!(
        "  classification: positive_detect_rate={:.2} negative_fp_rate={:.2}",
        summary.classification.positive_detection_rate,
        summary.classification.negative_false_positive_rate
    );
    println!(
        "  lead-time: total={} detected={} before_onset={} missed={}",
        summary.lead_time.total_cases,
        summary.lead_time.detected_cases,
        summary.lead_time.detected_before_onset_cases,
        summary.lead_time.missed_cases
    );

    println!();
    println!(
        "Manipulation-track gates: {}",
        if gate_report.passed { "PASS" } else { "FAIL" }
    );
    for check in &gate_report.checks {
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
    println!("Per-scenario classification");
    for scenario in &summary.classification.scenarios {
        println!(
            "  {} -> peak_score={:.2} detected={} false_positive={} first_detection_step={:?}",
            scenario.name,
            scenario.peak_score,
            scenario.detected,
            scenario.false_positive,
            scenario.first_detection_step
        );
    }

    println!();
    println!("Per-threat calibration");
    for threat in &summary.calibration.by_threat {
        println!(
            "  {:?}: count={} brier={:.4} ece={:.4}",
            threat.threat_type, threat.count, threat.brier_score, threat.expected_calibration_error
        );
    }
}
