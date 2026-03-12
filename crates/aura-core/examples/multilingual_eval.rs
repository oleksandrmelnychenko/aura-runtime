use aura_core::{canonical_multilingual_scenarios, run_scenario_case, summarize_scenario_runs};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let pack = canonical_multilingual_scenarios();
    let runs: Vec<_> = pack
        .iter()
        .map(|case| run_scenario_case(&db, case))
        .collect();
    let summary = summarize_scenario_runs(&runs, 6);

    println!("AURA multilingual scenario evaluation");
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
    println!("Per-language slices");
    for slice in &summary.language_slices {
        println!(
            "  {} -> scenarios={} examples={} brier={:.4} ece={:.4} pos_detect={:.2} neg_fp={:.2}",
            slice.language,
            slice.scenario_count,
            slice.calibration.count,
            slice.calibration.brier_score,
            slice.calibration.expected_calibration_error,
            slice.classification.positive_detection_rate,
            slice.classification.negative_false_positive_rate
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
}
