use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use aura_military::temporal_review_packet::{
    generate_embedded_temporal_blind_review_materials, generate_temporal_blind_review_materials,
};
use serde::Serialize;

const MAX_CORPUS_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PREREGISTRATION_FILE_BYTES: u64 = 1024 * 1024;

struct CliArgs {
    packet_id: String,
    corpus: Option<PathBuf>,
    preregistration: PathBuf,
    blinding_key: PathBuf,
    packet_output: PathBuf,
    coordinator_map_output: PathBuf,
    review_template_output: PathBuf,
    study_commitment_output: PathBuf,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

fn usage() -> &'static str {
    "usage: cargo run -p aura-military --features evaluation --example temporal_blind_review_packet -- --packet-id TOKEN [--corpus PATH] --preregistration PATH --blinding-key PATH --packet-output PATH --coordinator-map-output PATH --review-template-output PATH --study-commitment-output PATH"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);
    let mut packet_id = None;
    let mut corpus = None;
    let mut preregistration = None;
    let mut blinding_key = None;
    let mut packet_output = None;
    let mut coordinator_map_output = None;
    let mut review_template_output = None;
    let mut study_commitment_output = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--packet-id" => packet_id = Some(next_value(&mut args, "--packet-id")?),
            "--corpus" => corpus = Some(PathBuf::from(next_value(&mut args, "--corpus")?)),
            "--preregistration" => {
                preregistration = Some(PathBuf::from(next_value(&mut args, "--preregistration")?));
            }
            "--blinding-key" => {
                blinding_key = Some(PathBuf::from(next_value(&mut args, "--blinding-key")?));
            }
            "--packet-output" => {
                packet_output = Some(PathBuf::from(next_value(&mut args, "--packet-output")?));
            }
            "--coordinator-map-output" => {
                coordinator_map_output = Some(PathBuf::from(next_value(
                    &mut args,
                    "--coordinator-map-output",
                )?));
            }
            "--review-template-output" => {
                review_template_output = Some(PathBuf::from(next_value(
                    &mut args,
                    "--review-template-output",
                )?));
            }
            "--study-commitment-output" => {
                study_commitment_output = Some(PathBuf::from(next_value(
                    &mut args,
                    "--study-commitment-output",
                )?));
            }
            "--help" | "-h" => return Ok(ParseArgsResult::Help),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(ParseArgsResult::Run(CliArgs {
        packet_id: packet_id.ok_or_else(|| "--packet-id is required".to_string())?,
        corpus,
        preregistration: preregistration
            .ok_or_else(|| "--preregistration is required".to_string())?,
        blinding_key: blinding_key.ok_or_else(|| "--blinding-key is required".to_string())?,
        packet_output: packet_output.ok_or_else(|| "--packet-output is required".to_string())?,
        coordinator_map_output: coordinator_map_output
            .ok_or_else(|| "--coordinator-map-output is required".to_string())?,
        review_template_output: review_template_output
            .ok_or_else(|| "--review-template-output is required".to_string())?,
        study_commitment_output: study_commitment_output
            .ok_or_else(|| "--study-commitment-output is required".to_string())?,
    }))
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("missing value after {name}"))
}

fn run() -> Result<i32, String> {
    let args = match parse_args()? {
        ParseArgsResult::Run(args) => args,
        ParseArgsResult::Help => {
            println!("{}", usage());
            return Ok(0);
        }
    };
    validate_distinct_paths(&args)?;
    let blinding_key = read_blinding_key(&args.blinding_key)?;
    let preregistration = read_bounded_text(
        &args.preregistration,
        "temporal review preregistration",
        MAX_PREREGISTRATION_FILE_BYTES,
    )?;
    let materials = if let Some(path) = &args.corpus {
        let corpus = read_bounded_text(path, "temporal review corpus", MAX_CORPUS_FILE_BYTES)?;
        generate_temporal_blind_review_materials(
            &corpus,
            &preregistration,
            &args.packet_id,
            &blinding_key,
        )
    } else {
        generate_embedded_temporal_blind_review_materials(
            &preregistration,
            &args.packet_id,
            &blinding_key,
        )
    }
    .map_err(|error| error.to_string())?;

    write_json_atomic(&args.packet_output, &materials.packet, false)?;
    write_json_atomic(
        &args.coordinator_map_output,
        &materials.coordinator_map,
        true,
    )?;
    write_json_atomic(
        &args.review_template_output,
        &materials.review_template,
        false,
    )?;
    write_json_atomic(
        &args.study_commitment_output,
        &materials.study_commitment,
        false,
    )?;
    eprintln!(
        "blind review packet written to {} (cases={}, packet_sha256={})",
        args.packet_output.display(),
        materials.packet.cases.len(),
        materials.coordinator_map.packet_canonical_sha256
    );
    eprintln!(
        "coordinator-only mapping written to {}",
        args.coordinator_map_output.display()
    );
    eprintln!(
        "blank packet-bound review bundle written to {}",
        args.review_template_output.display()
    );
    eprintln!(
        "public study commitment written to {}",
        args.study_commitment_output.display()
    );
    Ok(0)
}

fn read_blinding_key(path: &Path) -> Result<[u8; 32], String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read blinding key metadata {}: {error}", path.display()))?;
    if path_metadata.file_type().is_symlink() {
        return Err("blinding key must not be a symbolic link".to_string());
    }
    let file = File::open(path)
        .map_err(|error| format!("open blinding key {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("read blinding key metadata {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err("blinding key must be a regular file containing exactly 32 bytes".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "blinding key permissions must not allow group or world access".to_string(),
            );
        }
    }
    let mut bytes = Vec::with_capacity(33);
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read blinding key {}: {error}", path.display()))?;
    bytes
        .try_into()
        .map_err(|_| "blinding key must contain exactly 32 bytes".to_string())
}

fn read_bounded_text(path: &Path, label: &str, max_bytes: u64) -> Result<String, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("read {label} metadata {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(format!("{label} size must be within 1..={max_bytes} bytes"));
    }
    fs::read_to_string(path).map_err(|error| format!("read {label} {}: {error}", path.display()))
}

fn validate_distinct_paths(args: &CliArgs) -> Result<(), String> {
    let mut protected = vec![normalized_path(&args.blinding_key)?];
    protected.push(normalized_path(&args.preregistration)?);
    if let Some(corpus) = &args.corpus {
        protected.push(normalized_path(corpus)?);
    }
    let outputs = [
        normalized_path(&args.packet_output)?,
        normalized_path(&args.coordinator_map_output)?,
        normalized_path(&args.review_template_output)?,
        normalized_path(&args.study_commitment_output)?,
    ];
    if outputs
        .iter()
        .any(|output| protected.iter().any(|input| output == input))
    {
        return Err("an output path must not overwrite an input file".to_string());
    }
    if outputs.iter().collect::<HashSet<_>>().len() != outputs.len() {
        return Err("blind review output paths must be distinct".to_string());
    }
    for output in &outputs {
        if output
            .try_exists()
            .map_err(|error| format!("inspect output path {}: {error}", output.display()))?
        {
            return Err(format!(
                "blind review output already exists: {}",
                output.display()
            ));
        }
    }
    Ok(())
}

fn normalized_path(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("resolve current directory: {error}"))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let file_name = absolute
        .file_name()
        .ok_or_else(|| format!("path has no file name: {}", path.display()))?;
    let canonical_parent = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    Ok(canonical_parent.join(file_name))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T, owner_only: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("create output directory {}: {error}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid output file name: {}", path.display()))?;
    let temporary_path = parent.join(format!(".{file_name}.{}.tmp", process::id()));
    let result = write_temporary_json(&temporary_path, value, owner_only).and_then(|()| {
        fs::rename(&temporary_path, path).map_err(|error| {
            format!(
                "replace blind review output {} with {}: {error}",
                path.display(),
                temporary_path.display()
            )
        })
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn write_temporary_json<T: Serialize>(
    path: &Path,
    value: &T,
    owner_only: bool,
) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(if owner_only { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("create temporary output {}: {error}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|error| format!("serialize blind review output {}: {error}", path.display()))?;
    file.write_all(b"\n")
        .map_err(|error| format!("finish blind review output {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync blind review output {}: {error}", path.display()))
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
