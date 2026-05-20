use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: &str = "aura.volume_stress_report.v1";
const COMMON_PREFIX: &str = "AURA_STRESS";

#[derive(Debug, Clone, Copy, Serialize)]
pub struct OutcomeReport {
    pub variants: usize,
    pub positives: usize,
    pub positives_detected: usize,
    pub negatives: usize,
    pub negatives_fired: usize,
    pub pos_rate: f32,
    pub fp_rate: f32,
}

impl OutcomeReport {
    pub fn new(
        positives: usize,
        positives_detected: usize,
        negatives: usize,
        negatives_fired: usize,
    ) -> Self {
        Self {
            variants: positives + negatives,
            positives,
            positives_detected,
            negatives,
            negatives_fired,
            pos_rate: rate(positives_detected, positives),
            fp_rate: rate(negatives_fired, negatives),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricRow {
    pub name: String,
    pub outcome: OutcomeReport,
}

impl MetricRow {
    pub fn new(name: impl Into<String>, outcome: OutcomeReport) -> Self {
        Self {
            name: name.into(),
            outcome,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueReport {
    pub kind: String,
    pub pack: String,
    pub dimension: String,
    pub case_name: String,
    pub peak: f32,
    pub threshold: f32,
    pub snippet: String,
}

impl IssueReport {
    pub fn new(
        kind: impl Into<String>,
        pack: impl Into<String>,
        dimension: impl Into<String>,
        case_name: impl Into<String>,
        peak: f32,
        threshold: f32,
        snippet: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            pack: pack.into(),
            dimension: dimension.into(),
            case_name: case_name.into(),
            peak,
            threshold,
            snippet: snippet.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateComparison {
    AtLeast,
    AtMost,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateCheck {
    pub name: String,
    pub comparison: GateComparison,
    pub actual: f64,
    pub threshold: f64,
    pub unit: &'static str,
    pub passed: bool,
}

impl GateCheck {
    fn at_least(name: impl Into<String>, actual: f64, threshold: f64, unit: &'static str) -> Self {
        Self {
            name: name.into(),
            comparison: GateComparison::AtLeast,
            actual,
            threshold,
            unit,
            passed: actual >= threshold,
        }
    }

    fn at_most(name: impl Into<String>, actual: f64, threshold: f64, unit: &'static str) -> Self {
        Self {
            name: name.into(),
            comparison: GateComparison::AtMost,
            actual,
            threshold,
            unit,
            passed: actual <= threshold,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GateReport {
    pub passed: bool,
    pub fail_on_gate: bool,
    pub checks: Vec<GateCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeStressReport {
    pub schema_version: &'static str,
    pub suite: String,
    pub generated_at_unix_ms: u128,
    pub worker_count: usize,
    pub analyzer_instances: usize,
    pub elapsed_ms: u128,
    pub total: OutcomeReport,
    pub packs: Vec<MetricRow>,
    pub dimensions: Vec<MetricRow>,
    pub issues: Vec<IssueReport>,
    pub gates: GateReport,
}

#[derive(Debug, Clone, Copy)]
struct GateConfig {
    min_pos_rate: f64,
    max_fp_rate: f64,
    max_elapsed_ms: Option<u128>,
    fail_on_gate: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn build_volume_report(
    prefix: &str,
    suite: impl Into<String>,
    worker_count: usize,
    analyzer_instances: usize,
    elapsed_ms: u128,
    total: OutcomeReport,
    packs: Vec<MetricRow>,
    dimensions: Vec<MetricRow>,
    issues: Vec<IssueReport>,
) -> VolumeStressReport {
    let gates = evaluate_gates(prefix, total, elapsed_ms);
    VolumeStressReport {
        schema_version: SCHEMA_VERSION,
        suite: suite.into(),
        generated_at_unix_ms: generated_at_unix_ms(),
        worker_count,
        analyzer_instances,
        elapsed_ms,
        total,
        packs,
        dimensions,
        issues,
        gates,
    }
}

pub fn finalize_volume_report(prefix: &str, report: &VolumeStressReport) {
    print_gate_summary(&report.gates);

    if let Err(err) = write_report_outputs(prefix, report) {
        eprintln!("Failed to write volume stress report: {err}");
        process::exit(2);
    }

    if !report.gates.passed && report.gates.fail_on_gate {
        eprintln!("AURA volume stress gates failed:");
        for check in report.gates.checks.iter().filter(|check| !check.passed) {
            eprintln!(
                "  - {}: actual {} must be {} {}",
                check.name,
                format_value(check.actual, check.unit),
                comparison_symbol(check.comparison),
                format_value(check.threshold, check.unit)
            );
        }
        process::exit(1);
    }
}

fn evaluate_gates(prefix: &str, total: OutcomeReport, elapsed_ms: u128) -> GateReport {
    let config = load_gate_config(prefix);
    let mut checks = vec![
        GateCheck::at_least(
            "min_pos_detect",
            total.pos_rate as f64,
            config.min_pos_rate,
            "rate",
        ),
        GateCheck::at_most(
            "max_fp_rate",
            total.fp_rate as f64,
            config.max_fp_rate,
            "rate",
        ),
    ];

    if let Some(max_elapsed_ms) = config.max_elapsed_ms {
        checks.push(GateCheck::at_most(
            "max_elapsed_ms",
            elapsed_ms as f64,
            max_elapsed_ms as f64,
            "ms",
        ));
    }

    let passed = checks.iter().all(|check| check.passed);
    GateReport {
        passed,
        fail_on_gate: config.fail_on_gate,
        checks,
    }
}

fn load_gate_config(prefix: &str) -> GateConfig {
    GateConfig {
        min_pos_rate: env_rate(prefix, "MIN_POS_DETECT").unwrap_or(1.0),
        max_fp_rate: env_rate(prefix, "MAX_FP_RATE").unwrap_or(0.0),
        max_elapsed_ms: env_u128(prefix, "MAX_ELAPSED_MS"),
        fail_on_gate: env_bool(prefix, "FAIL_ON_GATE").unwrap_or(true),
    }
}

fn write_report_outputs(prefix: &str, report: &VolumeStressReport) -> Result<(), String> {
    if let Some(path) = env_path(prefix, "JSON") {
        ensure_parent_dir(&path)?;
        let json = serde_json::to_string_pretty(report).map_err(|err| err.to_string())?;
        fs::write(&path, json).map_err(|err| format!("{}: {err}", path.display()))?;
        println!("Wrote JSON report: {}", path.display());
    }

    if let Some(path) = env_path(prefix, "NDJSON") {
        ensure_parent_dir(&path)?;
        let json = serde_json::to_string(report).map_err(|err| err.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        writeln!(file, "{json}").map_err(|err| format!("{}: {err}", path.display()))?;
        println!("Appended NDJSON report: {}", path.display());
    }

    if env_bool(prefix, "JSON_STDOUT").unwrap_or(false) {
        let json = serde_json::to_string_pretty(report).map_err(|err| err.to_string())?;
        println!("{json}");
    }

    Ok(())
}

fn print_gate_summary(gates: &GateReport) {
    println!();
    println!("CI gates: {}", if gates.passed { "PASS" } else { "FAIL" });
    for check in &gates.checks {
        println!(
            "  {:<18} {:>8} {} {:<8} {}",
            check.name,
            format_value(check.actual, check.unit),
            comparison_symbol(check.comparison),
            format_value(check.threshold, check.unit),
            if check.passed { "ok" } else { "failed" }
        );
    }
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    Ok(())
}

fn env_path(prefix: &str, key: &str) -> Option<PathBuf> {
    scoped_env(prefix, key)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn env_rate(prefix: &str, key: &str) -> Option<f64> {
    scoped_env(prefix, key)
        .and_then(|raw| raw.parse::<f64>().ok())
        .map(|value| if value > 1.0 { value / 100.0 } else { value })
}

fn env_u128(prefix: &str, key: &str) -> Option<u128> {
    scoped_env(prefix, key).and_then(|raw| raw.parse::<u128>().ok())
}

fn env_bool(prefix: &str, key: &str) -> Option<bool> {
    scoped_env(prefix, key).and_then(|raw| match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    })
}

fn scoped_env(prefix: &str, key: &str) -> Option<String> {
    [
        format!("{prefix}_{key}"),
        format!("{COMMON_PREFIX}_{key}"),
        format!("AURA_{key}"),
    ]
    .into_iter()
    .find_map(|name| std::env::var(name).ok())
}

fn rate(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}

fn generated_at_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn format_value(value: f64, unit: &str) -> String {
    match unit {
        "rate" => format!("{:.1}%", value * 100.0),
        "ms" => format!("{value:.0}ms"),
        _ => format!("{value:.3}"),
    }
}

fn comparison_symbol(comparison: GateComparison) -> &'static str {
    match comparison {
        GateComparison::AtLeast => ">=",
        GateComparison::AtMost => "<=",
    }
}
