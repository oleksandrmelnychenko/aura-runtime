use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_military::temporal_eval::run_embedded_temporal_shadow_telemetry_report;
use aura_military::temporal_shadow_telemetry::{
    TemporalShadowDeployment, TemporalShadowTelemetryReport,
};
use serde::Serialize;

#[derive(Serialize)]
struct TelemetryValidationReport {
    schema_version: &'static str,
    overall_status: &'static str,
    on_prem: TemporalShadowTelemetryReport,
    adk: TemporalShadowTelemetryReport,
}

struct CliArgs {
    output: Option<PathBuf>,
    require_pass: bool,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

fn usage() -> &'static str {
    "usage: cargo run -p aura-military --features evaluation --example temporal_shadow_telemetry_validation -- [--output PATH] [--require-pass]"
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
    let on_prem = run_embedded_temporal_shadow_telemetry_report(TemporalShadowDeployment::OnPrem)
        .map_err(|err| err.to_string())?;
    let adk = run_embedded_temporal_shadow_telemetry_report(TemporalShadowDeployment::Adk)
        .map_err(|err| err.to_string())?;
    let overall_status = if on_prem.overall_status == "pass" && adk.overall_status == "pass" {
        "pass"
    } else {
        "fail"
    };
    let report = TelemetryValidationReport {
        schema_version: "aura.military.temporal_shadow_telemetry_validation.v1",
        overall_status,
        on_prem,
        adk,
    };
    let json = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("serialize temporal Shadow telemetry validation: {err}"))?;

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "create temporal telemetry validation directory {}: {err}",
                        parent.display()
                    )
                })?;
            }
        }
        fs::write(&path, &json).map_err(|err| {
            format!(
                "write temporal Shadow telemetry validation {}: {err}",
                path.display()
            )
        })?;
        eprintln!(
            "temporal Shadow telemetry validation written to {} (overall_status={overall_status})",
            path.display()
        );
    } else {
        println!("{json}");
    }

    if args.require_pass && overall_status != "pass" {
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
