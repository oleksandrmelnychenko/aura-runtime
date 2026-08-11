use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_military::temporal_shadow_telemetry::evaluate_temporal_shadow_telemetry_batch;

struct CliArgs {
    input: PathBuf,
    output: Option<PathBuf>,
    require_pass: bool,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

fn usage() -> &'static str {
    "usage: cargo run -p aura-military --features shadow-telemetry --example temporal_shadow_telemetry -- --input PATH [--output PATH] [--require-pass]"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);
    let mut input = None;
    let mut output = None;
    let mut require_pass = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --input".to_string())?;
                input = Some(PathBuf::from(path));
            }
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

    let input = input.ok_or_else(|| "--input is required".to_string())?;
    Ok(ParseArgsResult::Run(CliArgs {
        input,
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
    let raw = fs::read_to_string(&args.input)
        .map_err(|err| format!("read temporal Shadow batch {}: {err}", args.input.display()))?;
    let report = evaluate_temporal_shadow_telemetry_batch(&raw).map_err(|err| err.to_string())?;
    let json = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("serialize temporal Shadow telemetry report: {err}"))?;

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "create temporal telemetry output directory {}: {err}",
                        parent.display()
                    )
                })?;
            }
        }
        fs::write(&path, &json).map_err(|err| {
            format!(
                "write temporal Shadow telemetry report {}: {err}",
                path.display()
            )
        })?;
        eprintln!(
            "temporal Shadow telemetry written to {} (overall_status={})",
            path.display(),
            report.overall_status
        );
    } else {
        println!("{json}");
    }

    if args.require_pass && report.overall_status != "pass" {
        eprintln!(
            "temporal Shadow telemetry status was {}; --require-pass expects pass",
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
