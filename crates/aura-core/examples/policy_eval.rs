use aura_core::{
    canonical_messenger_scenarios, canonical_policy_action_expectations,
    evaluate_policy_action_gates, pre_release_policy_action_gates, run_scenario_case,
    summarize_policy_actions,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let runs = canonical_messenger_scenarios()
        .iter()
        .map(|case| run_scenario_case(&db, case))
        .collect::<Vec<_>>();
    let summary = summarize_policy_actions(&runs, &canonical_policy_action_expectations());
    let report = evaluate_policy_action_gates(&summary, &pre_release_policy_action_gates());

    println!(
        "Policy action summary: pass_rate={:.2}, required_any={:.2}, required_by_onset={:.2}, forbidden_violation_rate={:.2}",
        summary.scenario_pass_rate,
        summary.required_any_coverage,
        summary.required_by_onset_coverage,
        summary.forbidden_violation_rate
    );
    println!(
        "Policy action gates: {}",
        if report.passed { "PASS" } else { "FAIL" }
    );

    for check in &report.checks {
        println!(
            "  - {}: actual={:.3} threshold={:.3} {:?} -> {}",
            check.name,
            check.actual,
            check.threshold,
            check.comparison,
            if check.passed { "PASS" } else { "FAIL" }
        );
    }

    for scenario in summary.scenarios.iter().filter(|scenario| !scenario.passed) {
        println!(
            "Scenario {} failed: all={:?} by_onset={:?} missing_any={:?} missing_by_onset={:?} forbidden={:?}",
            scenario.scenario_name,
            scenario.all_actions,
            scenario.actions_by_onset,
            scenario.missing_required_any,
            scenario.missing_required_by_onset,
            scenario.forbidden_actions_present
        );
    }
}
