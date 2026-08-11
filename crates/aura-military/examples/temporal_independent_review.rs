use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_military::temporal_review::evaluate_embedded_temporal_review;
use aura_military::temporal_review_packet::evaluate_embedded_temporal_blind_review;

const MAX_REVIEW_FILE_BYTES: u64 = 16 * 1024 * 1024;

struct CliArgs {
    review_bundle: PathBuf,
    blind_packet: Option<PathBuf>,
    coordinator_map: Option<PathBuf>,
    output: Option<PathBuf>,
    require_pass: bool,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

fn usage() -> &'static str {
    "usage: cargo run -p aura-military --features evaluation --example temporal_independent_review -- --review-bundle PATH [--blind-packet PATH --coordinator-map PATH] [--output PATH] [--require-pass]"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);
    let mut review_bundle = None;
    let mut blind_packet = None;
    let mut coordinator_map = None;
    let mut output = None;
    let mut require_pass = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--review-bundle" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --review-bundle".to_string())?;
                review_bundle = Some(PathBuf::from(path));
            }
            "--blind-packet" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --blind-packet".to_string())?;
                blind_packet = Some(PathBuf::from(path));
            }
            "--coordinator-map" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --coordinator-map".to_string())?;
                coordinator_map = Some(PathBuf::from(path));
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

    let review_bundle = review_bundle.ok_or_else(|| "--review-bundle is required".to_string())?;
    if blind_packet.is_some() != coordinator_map.is_some() {
        return Err("--blind-packet and --coordinator-map must be supplied together".to_string());
    }
    Ok(ParseArgsResult::Run(CliArgs {
        review_bundle,
        blind_packet,
        coordinator_map,
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
    let raw = read_bounded_text(&args.review_bundle, "temporal independent-review bundle")?;
    let report = match (&args.blind_packet, &args.coordinator_map) {
        (Some(packet_path), Some(map_path)) => {
            let packet = read_bounded_text(packet_path, "temporal blind-review packet")?;
            let coordinator_map = read_bounded_text(map_path, "temporal coordinator map")?;
            evaluate_embedded_temporal_blind_review(&packet, &coordinator_map, &raw)
                .map_err(|err| err.to_string())?
        }
        (None, None) => evaluate_embedded_temporal_review(&raw).map_err(|err| err.to_string())?,
        _ => return Err("blind review paths are incomplete".to_string()),
    };
    let json = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("serialize temporal independent-review report: {err}"))?;

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "create temporal review output directory {}: {err}",
                        parent.display()
                    )
                })?;
            }
        }
        fs::write(&path, &json)
            .map_err(|err| format!("write temporal review report {}: {err}", path.display()))?;
        eprintln!(
            "temporal independent-review report written to {} (overall_status={})",
            path.display(),
            report.overall_status
        );
    } else {
        println!("{json}");
    }

    if args.require_pass && report.overall_status != "pass" {
        eprintln!(
            "temporal independent-review status was {}; --require-pass expects pass",
            report.overall_status
        );
        Ok(1)
    } else {
        Ok(0)
    }
}

fn read_bounded_text(path: &PathBuf, label: &str) -> Result<String, String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("read {label} metadata {}: {err}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_REVIEW_FILE_BYTES {
        return Err(format!(
            "{label} size must be within 1..={MAX_REVIEW_FILE_BYTES} bytes"
        ));
    }
    fs::read_to_string(path).map_err(|err| format!("read {label} {}: {err}", path.display()))
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
