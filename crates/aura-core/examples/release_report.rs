use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_core::{run_pre_release_report, ReleaseStatus};
use aura_patterns::PatternDatabase;

struct CliArgs {
    output: Option<PathBuf>,
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
    "usage: cargo run --example release_report -p aura-core -- [--output PATH] [--require-pass]"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);
    let mut output = None;
    let mut require_pass = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --output".to_string())?;
                output = Some(PathBuf::from(path));
            }
            "--require-pass" => require_pass = true,
            "--help" | "-h" => return Ok(ParseArgsResult::Help),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(ParseArgsResult::Run(CliArgs {
        output,
        require_pass,
    }))
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
    let report = run_pre_release_report(&db, 6);
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
