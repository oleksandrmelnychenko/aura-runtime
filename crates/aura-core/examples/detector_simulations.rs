//! Run every registered detector pack through the eval harness and print a
//! per-detector report (calibration / lead-time / classification / gates).
//!
//! Usage: `cargo run -p aura-core --example detector_simulations`

use aura_core::scenario_packs::{pack_index, DetectorPack};
use aura_core::{
    evaluate_scenario_quality_gates, summarize_scenario_runs, GateComparison, ScenarioCaseRunner,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let mut runner = ScenarioCaseRunner::new(&db);
    let packs = pack_index();
    let mut overall_pass = 0usize;
    let mut overall_total = 0usize;

    println!("AURA detector simulation suite ({} packs)\n", packs.len());

    for pack in &packs {
        report_pack(&mut runner, pack, &mut overall_pass, &mut overall_total);
    }

    println!(
        "\n=== overall: {}/{} quality gates passing ===",
        overall_pass, overall_total
    );
    println!(
        "Analyzer config buckets reused: {}",
        runner.analyzer_count()
    );
}

fn report_pack(
    runner: &mut ScenarioCaseRunner<'_>,
    pack: &DetectorPack,
    overall_pass: &mut usize,
    overall_total: &mut usize,
) {
    let cases = pack.all_scenarios();
    if cases.is_empty() {
        println!("[{:>20}] (no scenarios registered)", pack.name);
        return;
    }
    let runs: Vec<_> = cases.iter().map(|c| runner.run(c)).collect();
    let summary = summarize_scenario_runs(&runs, 6);
    let gates = (pack.gates)();
    let report = evaluate_scenario_quality_gates(&summary, &gates);

    println!(
        "[{:>20}] cases={:<3} pos_detect={:.2} neg_fp={:.2} brier={:.3} ece={:.3} mean_lead_ms={:?}",
        pack.name,
        cases.len(),
        summary.classification.positive_detection_rate,
        summary.classification.negative_false_positive_rate,
        summary.calibration.brier_score,
        summary.calibration.expected_calibration_error,
        summary.lead_time.mean_lead_time_ms,
    );

    let pack_pass = report.checks.iter().filter(|c| c.passed).count();
    let pack_total = report.checks.len();
    *overall_pass += pack_pass;
    *overall_total += pack_total;
    println!(
        "                      gates={}/{} {}",
        pack_pass,
        pack_total,
        if report.passed { "PASS" } else { "FAIL" },
    );
    if !report.passed {
        for check in &report.checks {
            if !check.passed {
                let op = match check.comparison {
                    GateComparison::AtMost => "<=",
                    GateComparison::AtLeast => ">=",
                };
                println!(
                    "                        - {}: {:.4} {} {:.4}",
                    check.name, check.actual, op, check.threshold
                );
            }
        }
    }
}
