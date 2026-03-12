use aura_core::{
    canonical_messenger_scenarios, evaluate_scenario_quality_gates, pre_release_child_safety_gates,
    run_scenario_case, summarize_scenario_runs,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let pack = canonical_messenger_scenarios();
    let runs: Vec<_> = pack
        .iter()
        .map(|case| run_scenario_case(&db, case))
        .collect();
    let summary = summarize_scenario_runs(&runs, 6);

    println!("AURA canonical scenario evaluation");
    println!(
        "  calibration: count={} brier={:.4} ece={:.4}",
        summary.calibration.count,
        summary.calibration.brier_score,
        summary.calibration.expected_calibration_error
    );
    println!(
        "  lead-time: total={} detected={} before_onset={} missed={} mean_lead_ms={:?}",
        summary.lead_time.total_cases,
        summary.lead_time.detected_cases,
        summary.lead_time.detected_before_onset_cases,
        summary.lead_time.missed_cases,
        summary.lead_time.mean_lead_time_ms
    );

    println!();
    println!("Per-scenario lead time");
    for scenario in &summary.scenarios {
        println!(
            "  {} -> first_detection={:?} lead_time_ms={:?} delay_after_onset_ms={:?}",
            scenario.name,
            scenario.result.first_detection_ms,
            scenario.result.lead_time_ms,
            scenario.result.delay_after_onset_ms
        );
    }

    println!();
    println!(
        "Classification: positive_detect_rate={:.2} negative_fp_rate={:.2} positives={}/{} negatives_fp={}/{}",
        summary.classification.positive_detection_rate,
        summary.classification.negative_false_positive_rate,
        summary.classification.detected_positive_scenarios,
        summary.classification.total_positive_scenarios,
        summary.classification.false_positive_scenarios,
        summary.classification.total_negative_scenarios
    );

    let gates = pre_release_child_safety_gates();
    let gate_report = evaluate_scenario_quality_gates(&summary, &gates);
    println!();
    println!(
        "Pre-release child-safety gates: {}",
        if gate_report.passed { "PASS" } else { "FAIL" }
    );
    for check in &gate_report.checks {
        let op = match check.comparison {
            aura_core::GateComparison::AtMost => "<=",
            aura_core::GateComparison::AtLeast => ">=",
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
    println!("Scenario classification");
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
