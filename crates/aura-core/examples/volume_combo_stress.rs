//! Combo perturbation stress suite.
//!
//! This is heavier than `volume_scaling`: each scenario is mutated by ordered
//! pairs like `leetspeak + emoji_padding`. It is intended for adversarial
//! robustness work, not as the fastest smoke test.

mod common;

use aura_core::scenario_packs::pack_index;
use aura_core::scenario_packs::volume::{default_combo_set, perturb_pack_sequences};
use aura_core::{
    predicted_score_for_threat, run_scenario_cases_parallel, ScenarioCase, ScenarioRunResult,
    ScenarioStep, ThreatType,
};
use aura_patterns::PatternDatabase;
use common::volume_ci::{
    build_volume_report, finalize_volume_report, IssueReport, MetricRow, OutcomeReport,
};
use std::collections::BTreeMap;
use std::time::Instant;

#[derive(Debug, Default, Clone, Copy)]
struct Outcome {
    positives: usize,
    positives_detected: usize,
    negatives: usize,
    negatives_fired: usize,
}

impl Outcome {
    fn record(&mut self, positive: bool, detected: bool) {
        if positive {
            self.positives += 1;
            if detected {
                self.positives_detected += 1;
            }
        } else {
            self.negatives += 1;
            if detected {
                self.negatives_fired += 1;
            }
        }
    }

    fn merge(&mut self, other: Self) {
        self.positives += other.positives;
        self.positives_detected += other.positives_detected;
        self.negatives += other.negatives;
        self.negatives_fired += other.negatives_fired;
    }

    fn total(&self) -> usize {
        self.positives + self.negatives
    }

    fn pos_percent(&self) -> f32 {
        if self.positives == 0 {
            0.0
        } else {
            100.0 * self.positives_detected as f32 / self.positives as f32
        }
    }

    fn fp_percent(&self) -> f32 {
        if self.negatives == 0 {
            0.0
        } else {
            100.0 * self.negatives_fired as f32 / self.negatives as f32
        }
    }
}

#[derive(Debug)]
struct IssueRecord {
    kind: &'static str,
    pack: &'static str,
    combo: String,
    case_name: String,
    peak: f32,
    threshold: f32,
    snippet: String,
}

#[derive(Debug, Clone, Copy)]
struct VariantMeta {
    pack_idx: usize,
    pack: &'static str,
    fallback_threat: ThreatType,
}

fn main() {
    let started = Instant::now();
    let issue_limit = std::env::var("AURA_COMBO_ISSUES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(50);

    let db = PatternDatabase::default_mvp();
    let packs = pack_index();
    let sequences = default_combo_set();
    let worker_count = scenario_worker_count("AURA_COMBO_THREADS");

    println!(
        "AURA combo perturbation stress suite ({} packs x {} combos, long-context excluded)\n",
        packs.len(),
        sequences.len()
    );

    println!(
        "{:<22} {:>8} {:>8} {:>9} {:>9}",
        "pack", "pos%", "fp%", "variants", "issues"
    );
    println!("{}", "-".repeat(62));

    let mut cases = Vec::new();
    let mut metas = Vec::new();
    for (pack_idx, pack) in packs.iter().enumerate() {
        let mut base: Vec<ScenarioCase> = (pack.canonical)();
        base.extend((pack.adversarial)());
        base.extend((pack.false_positive)());

        for case in perturb_pack_sequences(&base, &sequences) {
            metas.push(VariantMeta {
                pack_idx,
                pack: pack.name,
                fallback_threat: pack.threat,
            });
            cases.push(case);
        }
    }

    let batch = run_scenario_cases_parallel(&db, &cases, worker_count);
    let mut pack_outcomes = vec![Outcome::default(); packs.len()];
    let mut pack_issues = vec![0usize; packs.len()];
    let mut combo_outcomes: BTreeMap<String, Outcome> = BTreeMap::new();
    let mut issues = Vec::new();

    for ((case, run), meta) in cases.iter().zip(batch.runs.iter()).zip(metas.iter()) {
        let combo = combo_label(case);
        let (peak, detected, first_hit_step) = score_run(run, case, meta.fallback_threat);
        let positive = case.primary_threat.is_some();

        pack_outcomes[meta.pack_idx].record(positive, detected);
        combo_outcomes
            .entry(combo.clone())
            .or_default()
            .record(positive, detected);

        if positive && !detected {
            pack_issues[meta.pack_idx] += 1;
            issues.push(IssueRecord {
                kind: "MISS",
                pack: meta.pack,
                combo,
                case_name: base_case_name(case),
                peak,
                threshold: case.detection_threshold,
                snippet: positive_snippet(case, meta.fallback_threat),
            });
        } else if !positive && detected {
            pack_issues[meta.pack_idx] += 1;
            issues.push(IssueRecord {
                kind: "FP",
                pack: meta.pack,
                combo,
                case_name: base_case_name(case),
                peak,
                threshold: case.detection_threshold,
                snippet: step_snippet(case, first_hit_step),
            });
        }
    }

    let mut grand = Outcome::default();
    for (idx, pack) in packs.iter().enumerate() {
        let pack_outcome = pack_outcomes[idx];
        grand.merge(pack_outcome);
        println!(
            "{:<22} {:>7.1}% {:>7.1}% {:>9} {:>9}",
            pack.name,
            pack_outcome.pos_percent(),
            pack_outcome.fp_percent(),
            pack_outcome.total(),
            pack_issues[idx]
        );
    }

    println!();
    println!(
        "Total: {} variants run across {} packs",
        grand.total(),
        packs.len()
    );
    println!("Scenario worker threads: {}", worker_count);
    println!(
        "Analyzer instances initialized across workers: {}",
        batch.analyzer_instances
    );
    println!(
        "Aggregate pos_detect={:.1}%  fp_rate={:.1}%  (positives {}/{}, fp {}/{})",
        grand.pos_percent(),
        grand.fp_percent(),
        grand.positives_detected,
        grand.positives,
        grand.negatives_fired,
        grand.negatives
    );

    println!();
    println!(
        "{:<34} {:>8} {:>8} {:>9}",
        "combo", "pos%", "fp%", "variants"
    );
    println!("{}", "-".repeat(62));
    for (combo, outcome) in &combo_outcomes {
        println!(
            "{:<34} {:>7.1}% {:>7.1}% {:>9}",
            combo,
            outcome.pos_percent(),
            outcome.fp_percent(),
            outcome.total()
        );
    }

    println!();
    if issues.is_empty() {
        println!("No misses or false positives in combo stress.");
    } else {
        println!("First {} issues:", issue_limit.min(issues.len()));
        println!(
            "{:<5} {:<22} {:<34} {:<46} {:>6} {:>6} text",
            "kind", "pack", "combo", "case", "peak", "thr"
        );
        println!("{}", "-".repeat(145));
        for issue in issues.iter().take(issue_limit) {
            println!(
                "{:<5} {:<22} {:<34} {:<46} {:>6.2} {:>6.2} {}",
                issue.kind,
                issue.pack,
                issue.combo,
                issue.case_name,
                issue.peak,
                issue.threshold,
                issue.snippet
            );
        }
    }

    let report = build_volume_report(
        "AURA_COMBO",
        "volume_combo_stress",
        worker_count,
        batch.analyzer_instances,
        started.elapsed().as_millis(),
        outcome_report(grand),
        packs
            .iter()
            .enumerate()
            .map(|(idx, pack)| MetricRow::new(pack.name, outcome_report(pack_outcomes[idx])))
            .collect(),
        combo_outcomes
            .iter()
            .map(|(combo, outcome)| MetricRow::new(combo.clone(), outcome_report(*outcome)))
            .collect(),
        issues
            .iter()
            .map(|issue| {
                IssueReport::new(
                    issue.kind,
                    issue.pack,
                    issue.combo.clone(),
                    issue.case_name.clone(),
                    issue.peak,
                    issue.threshold,
                    issue.snippet.clone(),
                )
            })
            .collect(),
    );
    finalize_volume_report("AURA_COMBO", &report);
}

fn score_run(
    run: &ScenarioRunResult,
    case: &ScenarioCase,
    fallback_threat: ThreatType,
) -> (f32, bool, Option<usize>) {
    let tracked_threats = if case.tracked_threats.is_empty() {
        vec![fallback_threat]
    } else {
        case.tracked_threats.clone()
    };

    let mut peak = 0.0_f32;
    let mut first_hit_step = None;
    for (step_idx, step_result) in run.step_results.iter().enumerate() {
        let mut step_peak = 0.0_f32;
        for threat in &tracked_threats {
            step_peak = step_peak.max(predicted_score_for_threat(step_result, *threat));
        }
        peak = peak.max(step_peak);
        if first_hit_step.is_none() && step_peak >= case.detection_threshold {
            first_hit_step = Some(step_idx);
        }
    }

    (peak, peak >= case.detection_threshold, first_hit_step)
}

fn scenario_worker_count(env_name: &str) -> usize {
    std::env::var(env_name)
        .or_else(|_| std::env::var("AURA_SCENARIO_THREADS"))
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(default_worker_count)
}

fn default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .map(|count| count.min(16))
        .unwrap_or(1)
}

fn outcome_report(outcome: Outcome) -> OutcomeReport {
    OutcomeReport::new(
        outcome.positives,
        outcome.positives_detected,
        outcome.negatives,
        outcome.negatives_fired,
    )
}

fn combo_label(case: &ScenarioCase) -> String {
    case.name
        .rsplit_once("__")
        .map(|(_, suffix)| suffix.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn base_case_name(case: &ScenarioCase) -> String {
    case.name
        .rsplit_once("__")
        .map(|(base, _)| base.to_string())
        .unwrap_or_else(|| case.name.clone())
}

fn positive_snippet(case: &ScenarioCase, fallback_threat: ThreatType) -> String {
    case.steps
        .iter()
        .find(|step| step.observed_threats.contains(&fallback_threat))
        .and_then(step_text)
        .map(compact_text)
        .or_else(|| case.steps.iter().find_map(step_text).map(compact_text))
        .unwrap_or_default()
}

fn step_snippet(case: &ScenarioCase, step_idx: Option<usize>) -> String {
    step_idx
        .and_then(|idx| case.steps.get(idx))
        .and_then(step_text)
        .map(compact_text)
        .or_else(|| case.steps.iter().find_map(step_text).map(compact_text))
        .unwrap_or_default()
}

fn step_text(step: &ScenarioStep) -> Option<&str> {
    step.input.text.as_deref()
}

fn compact_text(text: &str) -> String {
    let cleaned = text.replace('\u{200B}', "");
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let max_chars = 120usize;
    let mut snippet = collapsed.chars().take(max_chars).collect::<String>();
    if collapsed.chars().count() > max_chars {
        snippet.push_str("...");
    }
    snippet
}
