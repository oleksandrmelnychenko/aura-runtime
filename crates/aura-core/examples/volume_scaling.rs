//! Volume-scaled simulation suite (fast variant).
//!
//! Each detector pack contributes `canonical + adversarial + false_positive`
//! (long-context cases are excluded — they're slow and produce one variant
//! per pack which doesn't change the matrix shape). For every case, we
//! generate 8 perturbations and run them through the harness in one pass.

mod common;

use aura_core::scenario_packs::pack_index;
use aura_core::scenario_packs::volume::{perturb_pack, PerturbationKind};
use aura_core::{
    predicted_score_for_threat, run_scenario_cases_parallel, ScenarioCase, ScenarioRunResult,
    ScenarioStep, ThreatType,
};
use aura_patterns::PatternDatabase;
use common::volume_ci::{
    build_volume_report, finalize_volume_report, IssueReport, MetricRow, OutcomeReport,
};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
struct VariantMeta {
    pack_idx: usize,
    pack: &'static str,
    kind: PerturbationKind,
    fallback_threat: ThreatType,
}

#[derive(Debug)]
struct IssueRecord {
    kind: &'static str,
    pack: &'static str,
    perturbation: &'static str,
    case_name: String,
    peak: f32,
    threshold: f32,
    snippet: String,
}

#[derive(Debug, Default)]
struct PackStats {
    variants: usize,
    per_kind: HashMap<PerturbationKind, (usize, usize, usize, usize)>,
    total_pos_hits: usize,
    total_pos_tot: usize,
    total_neg_fired: usize,
    total_neg_tot: usize,
}

fn main() {
    let started = Instant::now();
    let issue_limit = std::env::var("AURA_VOLUME_ISSUES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(50);

    let db = PatternDatabase::default_mvp();
    let packs = pack_index();
    let kinds = PerturbationKind::default_set();
    let worker_count = scenario_worker_count("AURA_VOLUME_THREADS");

    println!(
        "AURA volume-scaled simulation suite ({} packs × {} perturbations, long-context excluded)\n",
        packs.len(),
        kinds.len()
    );

    let header_kinds = kinds
        .iter()
        .map(|k| format!("{:>11}", k.label()))
        .collect::<Vec<_>>()
        .join("");
    println!(
        "{:<22} {:>7} {:>7} {:>8}{}",
        "pack", "pos%", "fp%", "variants", header_kinds
    );
    println!("{}", "-".repeat(22 + 25 + kinds.len() * 11));

    let mut cases = Vec::new();
    let mut metas = Vec::new();
    for (pack_idx, pack) in packs.iter().enumerate() {
        let mut base: Vec<ScenarioCase> = (pack.canonical)();
        base.extend((pack.adversarial)());
        base.extend((pack.false_positive)());

        for case in perturb_pack(&base, kinds) {
            let suffix = case.name.rsplit_once("__").map(|(_, s)| s).unwrap_or("");
            let Some(kind) = kinds.iter().find(|k| k.label() == suffix).copied() else {
                continue;
            };
            metas.push(VariantMeta {
                pack_idx,
                pack: pack.name,
                kind,
                fallback_threat: pack.threat,
            });
            cases.push(case);
        }
    }

    let batch = run_scenario_cases_parallel(&db, &cases, worker_count);
    let mut pack_stats = (0..packs.len())
        .map(|_| PackStats::default())
        .collect::<Vec<_>>();
    let mut issues = Vec::new();

    for ((case, run), meta) in cases.iter().zip(batch.runs.iter()).zip(metas.iter()) {
        let stats = &mut pack_stats[meta.pack_idx];
        stats.variants += 1;

        let (peak, detected, first_hit_step) = score_run(run, case, meta.fallback_threat);
        let bucket = stats.per_kind.entry(meta.kind).or_insert((0, 0, 0, 0));
        if case.primary_threat.is_some() {
            bucket.1 += 1;
            stats.total_pos_tot += 1;
            if detected {
                bucket.0 += 1;
                stats.total_pos_hits += 1;
            } else {
                issues.push(IssueRecord {
                    kind: "MISS",
                    pack: meta.pack,
                    perturbation: meta.kind.label(),
                    case_name: base_case_name(case),
                    peak,
                    threshold: case.detection_threshold,
                    snippet: positive_snippet(case, meta.fallback_threat),
                });
            }
        } else {
            bucket.3 += 1;
            stats.total_neg_tot += 1;
            if detected {
                bucket.2 += 1;
                stats.total_neg_fired += 1;
                issues.push(IssueRecord {
                    kind: "FP",
                    pack: meta.pack,
                    perturbation: meta.kind.label(),
                    case_name: base_case_name(case),
                    peak,
                    threshold: case.detection_threshold,
                    snippet: step_snippet(case, first_hit_step),
                });
            }
        }
    }

    let mut grand_variants = 0usize;
    let mut grand_pos_hits = 0usize;
    let mut grand_pos_tot = 0usize;
    let mut grand_neg_fired = 0usize;
    let mut grand_neg_tot = 0usize;

    for (idx, pack) in packs.iter().enumerate() {
        let stats = &pack_stats[idx];
        let kind_str = kinds
            .iter()
            .map(|kind| {
                let (pos_hits, pos_tot, neg_fired, neg_tot) =
                    stats.per_kind.get(kind).copied().unwrap_or((0, 0, 0, 0));
                let pos = if pos_tot == 0 {
                    0.0
                } else {
                    pos_hits as f32 / pos_tot as f32
                };
                let fp = if neg_tot == 0 {
                    0.0
                } else {
                    neg_fired as f32 / neg_tot as f32
                };
                format!(" {:>5.0}|{:<4.0}", pos * 100.0, fp * 100.0)
            })
            .collect::<Vec<_>>()
            .join("");

        let aggregate_pos = if stats.total_pos_tot == 0 {
            0.0
        } else {
            stats.total_pos_hits as f32 / stats.total_pos_tot as f32
        };
        let aggregate_fp = if stats.total_neg_tot == 0 {
            0.0
        } else {
            stats.total_neg_fired as f32 / stats.total_neg_tot as f32
        };
        grand_variants += stats.variants;
        grand_pos_hits += stats.total_pos_hits;
        grand_pos_tot += stats.total_pos_tot;
        grand_neg_fired += stats.total_neg_fired;
        grand_neg_tot += stats.total_neg_tot;

        println!(
            "{:<22} {:>6.0}% {:>6.0}% {:>8}{}",
            pack.name,
            aggregate_pos * 100.0,
            aggregate_fp * 100.0,
            stats.variants,
            kind_str
        );
    }

    println!();
    println!(
        "Total: {} variants run across {} packs",
        grand_variants,
        packs.len()
    );
    println!("Scenario worker threads: {}", worker_count);
    println!(
        "Analyzer instances initialized across workers: {}",
        batch.analyzer_instances
    );
    println!(
        "Aggregate pos_detect={:.1}%  fp_rate={:.1}%  (positives {}/{}, fp {}/{})",
        if grand_pos_tot == 0 {
            0.0
        } else {
            100.0 * grand_pos_hits as f32 / grand_pos_tot as f32
        },
        if grand_neg_tot == 0 {
            0.0
        } else {
            100.0 * grand_neg_fired as f32 / grand_neg_tot as f32
        },
        grand_pos_hits,
        grand_pos_tot,
        grand_neg_fired,
        grand_neg_tot,
    );

    println!();
    if issues.is_empty() {
        println!("No misses or false positives in volume scaling.");
    } else {
        println!("First {} issues:", issue_limit.min(issues.len()));
        println!(
            "{:<5} {:<22} {:<18} {:<46} {:>6} {:>6} text",
            "kind", "pack", "perturbation", "case", "peak", "thr"
        );
        println!("{}", "-".repeat(129));
        for issue in issues.iter().take(issue_limit) {
            println!(
                "{:<5} {:<22} {:<18} {:<46} {:>6.2} {:>6.2} {}",
                issue.kind,
                issue.pack,
                issue.perturbation,
                issue.case_name,
                issue.peak,
                issue.threshold,
                issue.snippet
            );
        }
    }

    let report = build_volume_report(
        "AURA_VOLUME",
        "volume_scaling",
        worker_count,
        batch.analyzer_instances,
        started.elapsed().as_millis(),
        OutcomeReport::new(
            grand_pos_tot,
            grand_pos_hits,
            grand_neg_tot,
            grand_neg_fired,
        ),
        packs
            .iter()
            .enumerate()
            .map(|(idx, pack)| {
                let stats = &pack_stats[idx];
                MetricRow::new(
                    pack.name,
                    OutcomeReport::new(
                        stats.total_pos_tot,
                        stats.total_pos_hits,
                        stats.total_neg_tot,
                        stats.total_neg_fired,
                    ),
                )
            })
            .collect(),
        kinds
            .iter()
            .map(|kind| {
                let mut pos_hits = 0usize;
                let mut pos_tot = 0usize;
                let mut neg_fired = 0usize;
                let mut neg_tot = 0usize;
                for stats in &pack_stats {
                    let (kind_pos_hits, kind_pos_tot, kind_neg_fired, kind_neg_tot) =
                        stats.per_kind.get(kind).copied().unwrap_or((0, 0, 0, 0));
                    pos_hits += kind_pos_hits;
                    pos_tot += kind_pos_tot;
                    neg_fired += kind_neg_fired;
                    neg_tot += kind_neg_tot;
                }
                MetricRow::new(
                    kind.label(),
                    OutcomeReport::new(pos_tot, pos_hits, neg_tot, neg_fired),
                )
            })
            .collect(),
        issues
            .iter()
            .map(|issue| {
                IssueReport::new(
                    issue.kind,
                    issue.pack,
                    issue.perturbation,
                    issue.case_name.clone(),
                    issue.peak,
                    issue.threshold,
                    issue.snippet.clone(),
                )
            })
            .collect(),
    );
    finalize_volume_report("AURA_VOLUME", &report);
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
