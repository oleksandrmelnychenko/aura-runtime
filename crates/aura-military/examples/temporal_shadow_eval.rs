use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_military::temporal_eval::run_embedded_temporal_shadow_report;

struct CliArgs {
    output: Option<PathBuf>,
    require_pass: bool,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

fn usage() -> &'static str {
    "usage: cargo run -p aura-military --features evaluation --example temporal_shadow_eval -- [--output PATH] [--require-pass]"
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

fn run() -> Result<i32, String> {
    let args = match parse_args()? {
        ParseArgsResult::Run(args) => args,
        ParseArgsResult::Help => {
            println!("{}", usage());
            return Ok(0);
        }
    };
    let report = run_embedded_temporal_shadow_report().map_err(|err| err.to_string())?;
    let json = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("serialize temporal Shadow report: {err}"))?;

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "create temporal Shadow output directory {}: {err}",
                        parent.display()
                    )
                })?;
            }
        }
        fs::write(&path, &json)
            .map_err(|err| format!("write temporal Shadow report {}: {err}", path.display()))?;
        eprintln!(
            "temporal Shadow report written to {} (overall_status={})",
            path.display(),
            report.overall_status
        );
    } else {
        println!("{json}");
    }

    if args.require_pass && report.overall_status != "pass" {
        eprintln!(
            "temporal Shadow status was {}; --require-pass expects pass",
            report.overall_status
        );
        Ok(1)
    } else {
        Ok(0)
    }
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(message) => {
            eprintln!("{message}\n{}", usage());
            process::exit(2);
        }
    }
}
