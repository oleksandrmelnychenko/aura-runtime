//! Per-case diagnostic for PII_LEAKAGE pack.

use aura_core::scenario_packs::pii_leakage::{
    adversarial_pii_leakage_scenarios, canonical_pii_leakage_scenarios,
    false_positive_pii_leakage_scenarios, long_context_pii_leakage_scenarios,
};
use aura_core::scenario_packs::volume::{perturb_pack, PerturbationKind};
use aura_core::{predicted_score_for_threat, ScenarioCaseRunner, ThreatType};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let mut base = canonical_pii_leakage_scenarios();
    base.extend(adversarial_pii_leakage_scenarios());
    base.extend(long_context_pii_leakage_scenarios());
    base.extend(false_positive_pii_leakage_scenarios());

    let all = if std::env::var_os("PII_VOLUME").is_some() {
        perturb_pack(&base, PerturbationKind::default_set())
    } else {
        base
    };
    let debug_signals = std::env::var_os("PII_DEBUG_SIGNALS").is_some();
    let mut runner = ScenarioCaseRunner::new(&db);

    println!(
        "{:<46} {:>12} {:>6} {:>6} {:>10}",
        "case", "label", "peak", "first", "fired_on"
    );
    println!("{}", "-".repeat(86));

    let mut pos_hits = 0;
    let mut pos_total = 0;
    let mut neg_fp = 0;
    let mut neg_total = 0;

    for case in &all {
        let run = runner.run(case);
        let mut peak = 0.0_f32;
        let mut first_hit: Option<usize> = None;
        let mut fired_step_text: Option<String> = None;
        for (idx, step_result) in run.step_results.iter().enumerate() {
            let score = predicted_score_for_threat(step_result, ThreatType::PiiLeakage);
            if score > peak {
                peak = score;
            }
            if score >= case.detection_threshold && first_hit.is_none() {
                first_hit = Some(idx);
                let s = case.steps[idx].input.text.as_deref().unwrap_or("");
                let trim: String = s.chars().take(64).collect();
                fired_step_text = Some(trim);
            }
        }

        let label = match case.primary_threat {
            Some(ThreatType::PiiLeakage) => "POS",
            Some(_) => "POS-other",
            None => "NEG",
        };
        let detected = first_hit.is_some();
        if case.primary_threat == Some(ThreatType::PiiLeakage) {
            pos_total += 1;
            if detected {
                pos_hits += 1;
            }
        } else if case.primary_threat.is_none() {
            neg_total += 1;
            if detected {
                neg_fp += 1;
            }
        }
        let outcome = match (case.primary_threat.is_some(), detected) {
            (true, true) => "OK",
            (true, false) => "MISS",
            (false, true) => "FP!",
            (false, false) => "ok",
        };

        println!(
            "{:<46} {:>12} {:>6.2} {:>6} {:>10}  {}",
            truncate(&case.name, 46),
            format!("{label}({outcome})"),
            peak,
            first_hit.map(|i| i.to_string()).unwrap_or("-".into()),
            outcome,
            fired_step_text
                .as_deref()
                .or_else(|| {
                    case.steps
                        .iter()
                        .find(|step| step.observed_threats.contains(&ThreatType::PiiLeakage))
                        .and_then(|step| step.input.text.as_deref())
                })
                .or_else(|| case
                    .steps
                    .first()
                    .and_then(|step| step.input.text.as_deref()))
                .unwrap_or("")
        );
        if debug_signals && !detected {
            for (idx, step_result) in run.step_results.iter().enumerate() {
                if !step_result.signals.is_empty() || !step_result.reason_codes.is_empty() {
                    println!(
                        "    step {idx}: threat={:?} score={:.2} detected={:?} reasons={:?}",
                        step_result.threat_type,
                        step_result.score,
                        step_result.detected_threats,
                        step_result.reason_codes
                    );
                    for signal in &step_result.signals {
                        println!(
                            "        {:?} {:.2} {}",
                            signal.threat_type, signal.score, signal.reason_code
                        );
                    }
                }
            }
        }
    }

    println!();
    println!(
        "Summary: pos {}/{} detected, neg_fp {}/{} fired",
        pos_hits, pos_total, neg_fp, neg_total
    );
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).chain(std::iter::once('…')).collect()
    }
}
