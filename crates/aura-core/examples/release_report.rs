use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use aura_core::{
    run_pre_release_report, world_simulation_release_snapshot_from_value, ReleaseStatus,
    WorldSimulationReleaseSnapshot,
};
use aura_patterns::PatternDatabase;

struct CliArgs {
    output: Option<PathBuf>,
    world_lifecycle_report: Option<PathBuf>,
    require_pass: bool,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

fn status_label(status: ReleaseStatus) -> &'static str {
    match status {
        ReleaseStatus::Pass => "pass",
        ReleaseStatus::Fail => "fail",
        ReleaseStatus::InsufficientSupport => "insufficient_support",
        ReleaseStatus::Blocked => "blocked",
    }
}

fn usage() -> &'static str {
    "usage: cargo run --example release_report -p aura-core -- [--output PATH] [--world-lifecycle-report PATH] [--require-pass]"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);
    let mut output = None;
    let mut world_lifecycle_report = None;
    let mut require_pass = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --output".to_string())?;
                output = Some(PathBuf::from(path));
            }
            "--world-lifecycle-report" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --world-lifecycle-report".to_string())?;
                world_lifecycle_report = Some(PathBuf::from(path));
            }
            "--require-pass" => require_pass = true,
            "--help" | "-h" => return Ok(ParseArgsResult::Help),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(ParseArgsResult::Run(CliArgs {
        output,
        world_lifecycle_report,
        require_pass,
    }))
}

fn load_world_lifecycle_snapshot(path: &Path) -> Result<WorldSimulationReleaseSnapshot, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("read world lifecycle report {}: {err}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| format!("parse world lifecycle report {}: {err}", path.display()))?;
    world_simulation_release_snapshot_from_value(&value)
        .map_err(|err| format!("load world lifecycle report {}: {err}", path.display()))
}

fn world_lifecycle_report_path(args: &CliArgs) -> Option<(PathBuf, bool)> {
    if let Some(path) = args.world_lifecycle_report.clone() {
        return Some((path, true));
    }

    let path = env::var_os("AURA_WORLD_LIFECYCLE_REPORT_PATH")
        .filter(|value| !value.as_os_str().is_empty())
        .map(PathBuf::from)?;
    path.exists().then_some((path, false))
}

fn main() {
    let args = match parse_args() {
        Ok(ParseArgsResult::Run(args)) => args,
        Ok(ParseArgsResult::Help) => {
            println!("{}", usage());
            process::exit(0);
        }
        Err(message) => {
            eprintln!("{message}\n{}", usage());
            process::exit(2);
        }
    };

    let db = PatternDatabase::default_mvp();
    let mut report = run_pre_release_report(&db, 6);
    if let Some((path, explicit)) = world_lifecycle_report_path(&args) {
        match load_world_lifecycle_snapshot(&path) {
            Ok(snapshot) => {
                report.world_simulation = Some(snapshot);
                eprintln!("world lifecycle metrics embedded from {}", path.display());
            }
            Err(message) if explicit => {
                eprintln!("{message}");
                process::exit(2);
            }
            Err(message) => eprintln!("skipping optional world lifecycle metrics: {message}"),
        }
    }
    let json = serde_json::to_string_pretty(&report).expect("serializable release report");

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).expect("create release report directory");
            }
        }
        fs::write(&path, &json).expect("write release report");
        eprintln!(
            "release report written to {} (overall_status={})",
            path.display(),
            status_label(report.overall_status)
        );
        for line in &report.operator_summary {
            eprintln!("summary: {line}");
        }
    } else {
        println!("{json}");
    }

    if args.require_pass && report.overall_status != ReleaseStatus::Pass {
        eprintln!(
            "pre-release report status was {:?}; --require-pass expects pass",
            report.overall_status
        );
        process::exit(1);
    }
}
