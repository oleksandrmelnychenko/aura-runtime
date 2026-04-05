use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_core::{
    external_curated_gold_bundle, realistic_chat_bundle, run_external_curated_gold_suite,
    run_realistic_chat_suite, run_scenario_case, ExternalCuratedSliceSummary,
    ExternalCuratedSuiteSummary, RealisticChatSliceSummary, RealisticChatSuiteSummary,
    ScenarioClassificationRecord, ScenarioPolicyRecord,
};
use aura_patterns::PatternDatabase;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ReleaseReport {
    suites: Vec<ReleaseSuite>,
}

#[derive(Debug, Deserialize)]
struct ReleaseSuite {
    suite_id: String,
    status: String,
    slices: Vec<ReleaseSlice>,
}

#[derive(Debug, Deserialize)]
struct ReleaseSlice {
    group: String,
    slice_id: String,
    status: String,
    evaluation_gates: GateReportSnapshot,
    policy: Option<PolicyGateSnapshot>,
}

#[derive(Debug, Deserialize)]
struct PolicyGateSnapshot {
    gates: GateReportSnapshot,
}

#[derive(Debug, Deserialize)]
struct GateReportSnapshot {
    checks: Vec<GateCheckSnapshot>,
}

#[derive(Debug, Deserialize)]
struct GateCheckSnapshot {
    name: String,
    actual: Option<f32>,
    threshold: f32,
    passed: bool,
}

fn default_report_path() -> PathBuf {
    PathBuf::from("artifacts/promotion-rehearsal-smoke/release-report.json")
}

fn parse_args() -> Result<(PathBuf, Option<String>), String> {
    let mut args = env::args().skip(1);
    let mut path = default_report_path();
    let mut trace_scenario = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--release-report" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing path after --release-report".to_string())?;
                path = PathBuf::from(value);
            }
            "--trace-scenario" => {
                trace_scenario = Some(
                    args.next()
                        .ok_or_else(|| "missing scenario id after --trace-scenario".to_string())?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "usage: cargo run --example release_gate_diagnostics -p aura-core -- [--release-report PATH] [--trace-scenario ID]"
                );
                process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok((path, trace_scenario))
}

fn realistic_slice_map(
    summary: &RealisticChatSuiteSummary,
) -> BTreeMap<(String, String), &RealisticChatSliceSummary> {
    let mut map = BTreeMap::new();
    for slice in &summary.by_language {
        map.insert(("language".to_string(), slice.slice_id.clone()), slice);
    }
    for slice in &summary.by_relationship {
        map.insert(("relationship".to_string(), slice.slice_id.clone()), slice);
    }
    for slice in &summary.by_age_band {
        map.insert(("age_band".to_string(), slice.slice_id.clone()), slice);
    }
    map
}

fn external_slice_map(
    summary: &ExternalCuratedSuiteSummary,
) -> BTreeMap<(String, String), &ExternalCuratedSliceSummary> {
    let mut map = BTreeMap::new();
    for slice in &summary.by_source_family {
        map.insert(("source_family".to_string(), slice.slice_id.clone()), slice);
    }
    for slice in &summary.by_review_status {
        map.insert(("review_status".to_string(), slice.slice_id.clone()), slice);
    }
    for slice in &summary.by_language {
        map.insert(("language".to_string(), slice.slice_id.clone()), slice);
    }
    for slice in &summary.by_relationship {
        map.insert(("relationship".to_string(), slice.slice_id.clone()), slice);
    }
    for slice in &summary.by_age_band {
        map.insert(("age_band".to_string(), slice.slice_id.clone()), slice);
    }
    map
}

fn print_gate_failures(checks: &[GateCheckSnapshot], prefix: &str) {
    for check in checks.iter().filter(|check| !check.passed) {
        println!(
            "  {prefix} {} actual={} threshold={}",
            check.name,
            check
                .actual
                .map(|value| format!("{value:.6}"))
                .unwrap_or_else(|| "n/a".to_string()),
            check.threshold
        );
    }
}

fn print_classification_records(records: &[ScenarioClassificationRecord]) {
    let false_positives = records
        .iter()
        .filter(|record| record.false_positive)
        .collect::<Vec<_>>();
    let missed_positives = records
        .iter()
        .filter(|record| record.primary_threat.is_some() && !record.detected)
        .collect::<Vec<_>>();

    if !false_positives.is_empty() {
        println!("  false_positives:");
        for record in false_positives {
            println!(
                "    {} peak_score={:.3} threshold={:.3}",
                record.name, record.peak_score, record.threshold
            );
        }
    }
    if !missed_positives.is_empty() {
        println!("  missed_positives:");
        for record in missed_positives {
            println!(
                "    {} peak_score={:.3} threshold={:.3}",
                record.name, record.peak_score, record.threshold
            );
        }
    }
}

fn print_policy_failures(records: &[ScenarioPolicyRecord]) {
    let failed = records
        .iter()
        .filter(|record| !record.passed)
        .collect::<Vec<_>>();
    if failed.is_empty() {
        return;
    }

    println!("  failed_policy_scenarios:");
    for record in failed {
        println!(
            "    {} via {} missing_any={:?} missing_by_onset={:?} forbidden={:?}",
            record.scenario_name,
            record.expectation_name,
            record.missing_required_any,
            record.missing_required_by_onset,
            record.forbidden_actions_present
        );
    }
}

fn print_realistic_suite(report: &ReleaseSuite, summary: &RealisticChatSuiteSummary) {
    let map = realistic_slice_map(summary);
    let fail_slices = report
        .slices
        .iter()
        .filter(|slice| slice.status == "fail")
        .collect::<Vec<_>>();
    let support_only = report
        .slices
        .iter()
        .filter(|slice| slice.status == "insufficient_support")
        .count();

    println!(
        "## {} status={} fail_slices={} insufficient_support_slices={}",
        report.suite_id,
        report.status,
        fail_slices.len(),
        support_only
    );

    for slice in fail_slices {
        println!();
        println!(
            "slice {}:{} status={}",
            slice.group, slice.slice_id, slice.status
        );
        print_gate_failures(&slice.evaluation_gates.checks, "eval_fail");
        if let Some(policy) = slice.policy.as_ref() {
            print_gate_failures(&policy.gates.checks, "policy_fail");
        }
        if let Some(summary_slice) = map.get(&(slice.group.clone(), slice.slice_id.clone())) {
            println!(
                "  scenarios={} [{}]",
                summary_slice.case_count,
                summary_slice.scenario_names.join(", ")
            );
            print_classification_records(&summary_slice.evaluation.classification.scenarios);
            print_policy_failures(&summary_slice.policy.scenarios);
        }
    }
    println!();
}

fn print_external_suite(report: &ReleaseSuite, summary: &ExternalCuratedSuiteSummary) {
    let map = external_slice_map(summary);
    let fail_slices = report
        .slices
        .iter()
        .filter(|slice| slice.status == "fail")
        .collect::<Vec<_>>();
    let support_only = report
        .slices
        .iter()
        .filter(|slice| slice.status == "insufficient_support")
        .count();

    println!(
        "## {} status={} fail_slices={} insufficient_support_slices={}",
        report.suite_id,
        report.status,
        fail_slices.len(),
        support_only
    );

    for slice in fail_slices {
        println!();
        println!(
            "slice {}:{} status={}",
            slice.group, slice.slice_id, slice.status
        );
        print_gate_failures(&slice.evaluation_gates.checks, "eval_fail");
        if let Some(policy) = slice.policy.as_ref() {
            print_gate_failures(&policy.gates.checks, "policy_fail");
        }
        if let Some(summary_slice) = map.get(&(slice.group.clone(), slice.slice_id.clone())) {
            println!(
                "  scenarios={} [{}]",
                summary_slice.case_count,
                summary_slice.scenario_names.join(", ")
            );
            print_classification_records(&summary_slice.evaluation.classification.scenarios);
            print_policy_failures(&summary_slice.policy.scenarios);
        }
    }
    println!();
}

fn print_trace(db: &PatternDatabase, scenario_id: &str) {
    let realistic = realistic_chat_bundle();
    if let Some(scenario) = realistic
        .scenarios
        .iter()
        .find(|scenario| scenario.metadata.scenario_name == scenario_id)
    {
        let run = run_scenario_case(db, &scenario.case);
        println!("## trace {} (realistic_chat)", scenario_id);
        for (index, result) in run.step_results.iter().enumerate() {
            println!(
                "step={} threat={:?} score={:.3} action={:?}",
                index + 1,
                result.threat_type,
                result.score,
                result.action
            );
            if let Some(recommendation) = result.recommended_action.as_ref() {
                println!(
                    "  ui_actions={:?} alert={:?}",
                    recommendation.ui_actions, recommendation.parent_alert
                );
            }
            if !result.reason_codes.is_empty() {
                println!("  reason_codes={:?}", result.reason_codes);
            }
            if !result.context_markers.is_empty() {
                println!("  context_markers={:?}", result.context_markers);
            }
            if !result.inference.latent_states.is_empty() {
                println!(
                    "  inference horizon={:?} escalation_24h={:.3} latent_states={:?}",
                    result.inference.risk_horizon,
                    result.inference.escalation_likelihood_24h,
                    result.inference.latent_states
                );
            }
        }
        return;
    }

    let external = external_curated_gold_bundle();
    if let Some(scenario) = external
        .scenarios
        .iter()
        .find(|scenario| scenario.metadata.scenario_name == scenario_id)
    {
        let run = run_scenario_case(db, &scenario.case);
        println!("## trace {} (external_curated_gold)", scenario_id);
        for (index, result) in run.step_results.iter().enumerate() {
            println!(
                "step={} threat={:?} score={:.3} action={:?}",
                index + 1,
                result.threat_type,
                result.score,
                result.action
            );
            if let Some(recommendation) = result.recommended_action.as_ref() {
                println!(
                    "  ui_actions={:?} alert={:?}",
                    recommendation.ui_actions, recommendation.parent_alert
                );
            }
            if !result.reason_codes.is_empty() {
                println!("  reason_codes={:?}", result.reason_codes);
            }
            if !result.context_markers.is_empty() {
                println!("  context_markers={:?}", result.context_markers);
            }
        }
        return;
    }

    eprintln!("scenario not found in realistic_chat or external_curated_gold: {scenario_id}");
    process::exit(2);
}

fn main() {
    let (report_path, trace_scenario) = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let db = PatternDatabase::default_mvp();
    if let Some(scenario_id) = trace_scenario.as_deref() {
        print_trace(&db, scenario_id);
        return;
    }

    let report_json = fs::read_to_string(&report_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", report_path.display()));
    let report: ReleaseReport =
        serde_json::from_str(&report_json).expect("valid release report json");
    let realistic_summary = run_realistic_chat_suite(&db, 5);
    let external_gold_summary = run_external_curated_gold_suite(&db, 5);

    if let Some(realistic_report) = report
        .suites
        .iter()
        .find(|suite| suite.suite_id == "realistic_chat")
    {
        print_realistic_suite(realistic_report, &realistic_summary);
    }

    if let Some(external_report) = report
        .suites
        .iter()
        .find(|suite| suite.suite_id == "external_curated_gold")
    {
        print_external_suite(external_report, &external_gold_summary);
    }
}
