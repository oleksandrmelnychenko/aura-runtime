use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_core::{
    parse_kids_memory_health_snapshot, parse_kids_preprod_dry_run_snapshot,
    parse_pilot_regression_snapshot, parse_pilot_release_snapshot, parse_pilot_review_signoffs,
    parse_pilot_shadow_snapshot, run_pilot_gate, PilotGateConfig, PilotGateStatus,
    PilotReviewInput,
};

struct CliArgs {
    release_report: PathBuf,
    pilot_regression_report: PathBuf,
    shadow_bundles: Vec<PathBuf>,
    review_signoffs: PathBuf,
    release_revision: String,
    kids_memory_health_report: Option<PathBuf>,
    kids_preprod_dry_run_report: Option<PathBuf>,
    output: Option<PathBuf>,
    require_pass: bool,
    require_kids_memory_pass: bool,
    require_kids_preprod_dry_run_pass: bool,
    min_shadow_runs: Option<usize>,
    min_shadow_total_events: Option<usize>,
}

enum ParseArgsResult {
    Run(Box<CliArgs>),
    Help,
}

fn usage() -> &'static str {
    "usage: cargo run --example pilot_gate -p aura-core -- --release-report PATH --pilot-regression-report PATH --shadow-bundle PATH [--shadow-bundle PATH ...] --review-signoffs PATH --release-revision FULL_SHA [--kids-memory-health-report PATH] [--kids-preprod-dry-run-report PATH] [--output PATH] [--require-pass] [--require-kids-memory-pass] [--require-kids-preprod-dry-run-pass] [--min-shadow-runs N] [--min-shadow-total-events N]"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);

    let mut release_report = None;
    let mut pilot_regression_report = None;
    let mut shadow_bundles = Vec::new();
    let mut review_signoffs = None;
    let mut release_revision = None;
    let mut kids_memory_health_report = None;
    let mut kids_preprod_dry_run_report = None;
    let mut output = None;
    let mut require_pass = false;
    let mut require_kids_memory_pass = false;
    let mut require_kids_preprod_dry_run_pass = false;
    let mut min_shadow_runs = None;
    let mut min_shadow_total_events = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--release-report" => {
                release_report =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "missing path after --release-report".to_string()
                    })?));
            }
            "--pilot-regression-report" => {
                pilot_regression_report =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "missing path after --pilot-regression-report".to_string()
                    })?));
            }
            "--shadow-bundle" => {
                shadow_bundles
                    .push(PathBuf::from(args.next().ok_or_else(|| {
                        "missing path after --shadow-bundle".to_string()
                    })?));
            }
            "--review-signoffs" => {
                review_signoffs =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "missing path after --review-signoffs".to_string()
                    })?));
            }
            "--release-revision" => {
                release_revision = Some(
                    args.next()
                        .ok_or_else(|| "missing value after --release-revision".to_string())?,
                );
            }
            "--kids-memory-health-report" => {
                kids_memory_health_report = Some(PathBuf::from(args.next().ok_or_else(|| {
                    "missing path after --kids-memory-health-report".to_string()
                })?));
            }
            "--kids-preprod-dry-run-report" => {
                kids_preprod_dry_run_report =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "missing path after --kids-preprod-dry-run-report".to_string()
                    })?));
            }
            "--output" => {
                output = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "missing path after --output".to_string())?,
                ));
            }
            "--require-pass" => require_pass = true,
            "--require-kids-memory-pass" => require_kids_memory_pass = true,
            "--require-kids-preprod-dry-run-pass" => require_kids_preprod_dry_run_pass = true,
            "--min-shadow-runs" => {
                min_shadow_runs = Some(
                    args.next()
                        .ok_or_else(|| "missing value after --min-shadow-runs".to_string())?
                        .parse()
                        .map_err(|_| "invalid --min-shadow-runs value".to_string())?,
                );
            }
            "--min-shadow-total-events" => {
                min_shadow_total_events = Some(
                    args.next()
                        .ok_or_else(|| "missing value after --min-shadow-total-events".to_string())?
                        .parse()
                        .map_err(|_| "invalid --min-shadow-total-events value".to_string())?,
                );
            }
            "--help" | "-h" => return Ok(ParseArgsResult::Help),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let args = CliArgs {
        release_report: release_report
            .ok_or_else(|| "missing required --release-report".to_string())?,
        pilot_regression_report: pilot_regression_report
            .ok_or_else(|| "missing required --pilot-regression-report".to_string())?,
        shadow_bundles,
        review_signoffs: review_signoffs
            .ok_or_else(|| "missing required --review-signoffs".to_string())?,
        release_revision: release_revision
            .ok_or_else(|| "missing required --release-revision".to_string())?,
        kids_memory_health_report,
        kids_preprod_dry_run_report,
        output,
        require_pass,
        require_kids_memory_pass,
        require_kids_preprod_dry_run_pass,
        min_shadow_runs,
        min_shadow_total_events,
    };

    if args.shadow_bundles.is_empty() {
        return Err("at least one --shadow-bundle is required".to_string());
    }

    Ok(ParseArgsResult::Run(Box::new(args)))
}

fn status_label(status: PilotGateStatus) -> &'static str {
    match status {
        PilotGateStatus::Pass => "pass",
        PilotGateStatus::Fail => "fail",
        PilotGateStatus::Blocked => "blocked",
    }
}

fn main() {
    let args = match parse_args() {
        Ok(ParseArgsResult::Run(args)) => *args,
        Ok(ParseArgsResult::Help) => {
            println!("{}", usage());
            process::exit(0);
        }
        Err(message) => {
            eprintln!("{message}\n{}", usage());
            process::exit(2);
        }
    };

    let release = parse_pilot_release_snapshot(
        &fs::read_to_string(&args.release_report).unwrap_or_else(|err| {
            panic!(
                "failed to read release report {}: {err}",
                args.release_report.display()
            )
        }),
    )
    .unwrap_or_else(|err| panic!("invalid release report: {err}"));
    let pilot_regression = parse_pilot_regression_snapshot(
        &fs::read_to_string(&args.pilot_regression_report).unwrap_or_else(|err| {
            panic!(
                "failed to read pilot regression report {}: {err}",
                args.pilot_regression_report.display()
            )
        }),
    )
    .unwrap_or_else(|err| panic!("invalid pilot regression report: {err}"));
    let shadow_runs = args
        .shadow_bundles
        .iter()
        .map(|path| {
            parse_pilot_shadow_snapshot(&fs::read_to_string(path).unwrap_or_else(|err| {
                panic!("failed to read shadow bundle {}: {err}", path.display())
            }))
            .unwrap_or_else(|err| panic!("invalid shadow bundle {}: {err}", path.display()))
        })
        .collect::<Vec<_>>();
    let signoffs = parse_pilot_review_signoffs(
        &fs::read_to_string(&args.review_signoffs).unwrap_or_else(|err| {
            panic!(
                "failed to read review signoffs {}: {err}",
                args.review_signoffs.display()
            )
        }),
    )
    .unwrap_or_else(|err| panic!("invalid review signoffs: {err}"));
    let kids_memory_health = args.kids_memory_health_report.as_ref().map(|path| {
        parse_kids_memory_health_snapshot(&fs::read_to_string(path).unwrap_or_else(|err| {
            panic!(
                "failed to read kids memory health report {}: {err}",
                path.display()
            )
        }))
        .unwrap_or_else(|err| panic!("invalid kids memory health report: {err}"))
    });
    let kids_preprod_dry_run = args.kids_preprod_dry_run_report.as_ref().map(|path| {
        parse_kids_preprod_dry_run_snapshot(&fs::read_to_string(path).unwrap_or_else(|err| {
            panic!(
                "failed to read kids preprod dry-run report {}: {err}",
                path.display()
            )
        }))
        .unwrap_or_else(|err| panic!("invalid kids preprod dry-run report: {err}"))
    });

    let mut config = PilotGateConfig {
        require_kids_memory_pass: args.require_kids_memory_pass,
        require_kids_preprod_dry_run_pass: args.require_kids_preprod_dry_run_pass,
        ..PilotGateConfig::default()
    };
    if let Some(value) = args.min_shadow_runs {
        config.min_shadow_runs = value;
    }
    if let Some(value) = args.min_shadow_total_events {
        config.min_shadow_total_events = value;
    }

    let report = run_pilot_gate(
        config,
        release,
        pilot_regression,
        shadow_runs,
        kids_memory_health,
        kids_preprod_dry_run,
        PilotReviewInput {
            expected_release_revision: args.release_revision,
            signoffs,
        },
    );
    let json = serde_json::to_string_pretty(&report).expect("serialize pilot gate report");

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).expect("create pilot gate output directory");
            }
        }
        fs::write(&path, &json).expect("write pilot gate report");
        eprintln!(
            "pilot gate report written to {} (overall_status={})",
            path.display(),
            status_label(report.overall_status)
        );
    } else {
        println!("{json}");
    }

    if args.require_pass && report.overall_status != PilotGateStatus::Pass {
        eprintln!(
            "pilot gate status was {}; --require-pass expects pass",
            status_label(report.overall_status)
        );
        process::exit(1);
    }
}
