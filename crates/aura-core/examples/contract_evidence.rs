use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use aura_core::context::{
    builtin_context_rule_pack_evidence, tracker::TRACKER_STATE_VERSION, ContextRulePackEvidence,
};
use aura_core::AuraDomainRuntime;
use aura_domain::DomainModuleEvidence;
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};

const PROTO_RELATIVE_PATH: &str = "proto/aura/messenger/v1/messenger.proto";
const FFI_HEADER_RELATIVE_PATH: &str = "include/aura_ffi.h";
const FFI_EXPORT_ALLOWLIST_RELATIVE_PATH: &str = "include/aura_ffi.exports";
const FFI_SMOKE_SOURCE_RELATIVE_PATH: &str = "ci/ffi_header_smoke.c";
const FFI_SOURCE_RELATIVE_PATH: &str = "crates/aura-agent-ffi/src/lib.rs";
const FFI_LIFECYCLE_SOURCE_RELATIVE_PATH: &str = "crates/aura-agent-ffi/src/lifecycle.rs";
const FFI_BUFFER_SOURCE_RELATIVE_PATH: &str = "crates/aura-agent-ffi/src/lifecycle/buffers.rs";

struct CliArgs {
    output: Option<PathBuf>,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

#[derive(Serialize)]
struct ContractEvidenceReport {
    generated_at_utc: String,
    runtime_release_version: String,
    wire: WireContractEvidence,
    persisted_state: PersistedStateEvidence,
    context_rule_packs: ContextRulePackEvidence,
    domain_modules: Vec<DomainModuleEvidence>,
    abi: AbiContractEvidence,
    files: Vec<FileDigestEvidence>,
}

#[derive(Serialize)]
struct WireContractEvidence {
    proto_path: String,
    proto_package: String,
    wire_major_version: u32,
}

#[derive(Serialize)]
struct PersistedStateEvidence {
    schema_version: u32,
    schema_anchor_message: String,
    schema_field_name: String,
    schema_field_number: u32,
}

#[derive(Serialize)]
struct AbiContractEvidence {
    header_path: String,
    export_allowlist_path: String,
    source_path: String,
    implementation_source_paths: Vec<String>,
    smoke_source_path: String,
    exported_functions: Vec<String>,
    aura_buffer_layout: AuraBufferLayoutEvidence,
    request_limits_bytes: Vec<RequestLimitEvidence>,
}

#[derive(Serialize)]
struct AuraBufferLayoutEvidence {
    size_bytes: usize,
    align_bytes: usize,
    pointer_width_bits: u32,
    field_order: Vec<String>,
}

#[derive(Serialize)]
struct FileDigestEvidence {
    path: String,
    sha256: String,
    bytes: usize,
}

#[derive(Serialize)]
struct RequestLimitEvidence {
    constant_name: String,
    request_kind: String,
    max_bytes: usize,
}

#[repr(C)]
struct AuraBufferLayout {
    ptr: *mut u8,
    len: usize,
}

fn usage() -> &'static str {
    "usage: cargo run --example contract_evidence -p aura-core -- [--output PATH]"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);
    let mut output = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --output".to_string())?;
                output = Some(PathBuf::from(path));
            }
            "--help" | "-h" => return Ok(ParseArgsResult::Help),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(ParseArgsResult::Run(CliArgs { output }))
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

    let report = build_contract_evidence().unwrap_or_else(|error| {
        eprintln!("failed to build contract evidence: {error}");
        process::exit(1);
    });
    let json = serde_json::to_string_pretty(&report).expect("serializable contract evidence");

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).expect("create contract evidence directory");
            }
        }
        fs::write(&path, &json).expect("write contract evidence");
        eprintln!("contract evidence written to {}", path.display());
    } else {
        println!("{json}");
    }
}

fn build_contract_evidence() -> Result<ContractEvidenceReport, String> {
    let workspace_root = workspace_root()?;
    let proto_path = workspace_root.join(PROTO_RELATIVE_PATH);
    let ffi_header_path = workspace_root.join(FFI_HEADER_RELATIVE_PATH);
    let ffi_export_allowlist_path = workspace_root.join(FFI_EXPORT_ALLOWLIST_RELATIVE_PATH);
    let ffi_smoke_source_path = workspace_root.join(FFI_SMOKE_SOURCE_RELATIVE_PATH);
    let ffi_source_path = workspace_root.join(FFI_SOURCE_RELATIVE_PATH);
    let ffi_lifecycle_source_path = workspace_root.join(FFI_LIFECYCLE_SOURCE_RELATIVE_PATH);
    let ffi_buffer_source_path = workspace_root.join(FFI_BUFFER_SOURCE_RELATIVE_PATH);

    let proto_contents = fs::read_to_string(&proto_path)
        .map_err(|error| format!("read {}: {error}", proto_path.display()))?;
    let ffi_header_contents = fs::read_to_string(&ffi_header_path)
        .map_err(|error| format!("read {}: {error}", ffi_header_path.display()))?;
    let ffi_export_allowlist_contents = fs::read_to_string(&ffi_export_allowlist_path)
        .map_err(|error| format!("read {}: {error}", ffi_export_allowlist_path.display()))?;
    let ffi_smoke_source_bytes = fs::read(&ffi_smoke_source_path)
        .map_err(|error| format!("read {}: {error}", ffi_smoke_source_path.display()))?;
    let ffi_source_contents = fs::read_to_string(&ffi_source_path)
        .map_err(|error| format!("read {}: {error}", ffi_source_path.display()))?;
    let ffi_lifecycle_source_contents = fs::read_to_string(&ffi_lifecycle_source_path)
        .map_err(|error| format!("read {}: {error}", ffi_lifecycle_source_path.display()))?;
    let ffi_buffer_source_bytes = fs::read(&ffi_buffer_source_path)
        .map_err(|error| format!("read {}: {error}", ffi_buffer_source_path.display()))?;

    let proto_package = parse_proto_package(&proto_contents)?;
    let wire_major_version = parse_wire_major_version(&proto_package)?;
    let exported_functions = parse_exported_functions(&ffi_header_contents)?;
    let export_allowlist = parse_export_allowlist(&ffi_export_allowlist_contents)?;
    if exported_functions.iter().collect::<BTreeSet<_>>()
        != export_allowlist.iter().collect::<BTreeSet<_>>()
    {
        return Err(format!(
            "FFI header exports differ from {}",
            FFI_EXPORT_ALLOWLIST_RELATIVE_PATH
        ));
    }
    let request_limits_bytes = parse_request_limits(&ffi_lifecycle_source_contents)?;
    let context_rule_packs = builtin_context_rule_pack_evidence()
        .map_err(|error| format!("validate bundled context rule packs: {error}"))?;
    let domain_modules = AuraDomainRuntime::new().module_evidence();
    if domain_modules.len() != 2 {
        return Err(format!(
            "expected Kids and Military domain evidence, found {} modules",
            domain_modules.len()
        ));
    }

    Ok(ContractEvidenceReport {
        generated_at_utc: Utc::now().to_rfc3339(),
        runtime_release_version: env!("CARGO_PKG_VERSION").to_string(),
        wire: WireContractEvidence {
            proto_path: PROTO_RELATIVE_PATH.to_string(),
            proto_package,
            wire_major_version,
        },
        persisted_state: PersistedStateEvidence {
            schema_version: TRACKER_STATE_VERSION,
            schema_anchor_message: "TrackerState".to_string(),
            schema_field_name: "schema_version".to_string(),
            schema_field_number: 1,
        },
        context_rule_packs,
        domain_modules,
        abi: AbiContractEvidence {
            header_path: FFI_HEADER_RELATIVE_PATH.to_string(),
            export_allowlist_path: FFI_EXPORT_ALLOWLIST_RELATIVE_PATH.to_string(),
            source_path: FFI_SOURCE_RELATIVE_PATH.to_string(),
            implementation_source_paths: vec![
                FFI_LIFECYCLE_SOURCE_RELATIVE_PATH.to_string(),
                FFI_BUFFER_SOURCE_RELATIVE_PATH.to_string(),
            ],
            smoke_source_path: FFI_SMOKE_SOURCE_RELATIVE_PATH.to_string(),
            exported_functions,
            aura_buffer_layout: AuraBufferLayoutEvidence {
                size_bytes: std::mem::size_of::<AuraBufferLayout>(),
                align_bytes: std::mem::align_of::<AuraBufferLayout>(),
                pointer_width_bits: usize::BITS,
                field_order: vec!["ptr".to_string(), "len".to_string()],
            },
            request_limits_bytes,
        },
        files: vec![
            file_digest(PROTO_RELATIVE_PATH, proto_contents.as_bytes()),
            file_digest(FFI_HEADER_RELATIVE_PATH, ffi_header_contents.as_bytes()),
            file_digest(FFI_SMOKE_SOURCE_RELATIVE_PATH, &ffi_smoke_source_bytes),
            file_digest(FFI_SOURCE_RELATIVE_PATH, ffi_source_contents.as_bytes()),
            file_digest(
                FFI_LIFECYCLE_SOURCE_RELATIVE_PATH,
                ffi_lifecycle_source_contents.as_bytes(),
            ),
            file_digest(FFI_BUFFER_SOURCE_RELATIVE_PATH, &ffi_buffer_source_bytes),
            file_digest(
                FFI_EXPORT_ALLOWLIST_RELATIVE_PATH,
                ffi_export_allowlist_contents.as_bytes(),
            ),
        ],
    })
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../..").canonicalize().map_err(|error| {
        format!(
            "resolve workspace root from {}: {error}",
            manifest_dir.display()
        )
    })
}

fn parse_proto_package(proto: &str) -> Result<String, String> {
    proto
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("package "))
        .map(|line| line.trim_end_matches(';').to_string())
        .ok_or_else(|| "missing protobuf package declaration".to_string())
}

fn parse_wire_major_version(package: &str) -> Result<u32, String> {
    let version = package
        .rsplit('.')
        .next()
        .ok_or_else(|| format!("missing version segment in protobuf package {package}"))?;
    let major = version
        .strip_prefix('v')
        .ok_or_else(|| format!("protobuf package version segment is not vN: {version}"))?;
    major
        .parse::<u32>()
        .map_err(|error| format!("parse protobuf major version from {version}: {error}"))
}

fn parse_exported_functions(header: &str) -> Result<Vec<String>, String> {
    let mut functions = Vec::new();

    for line in header.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("///")
            || trimmed.starts_with("typedef")
            || trimmed == "}"
            || !trimmed.ends_with(';')
            || !trimmed.contains('(')
        {
            continue;
        }

        let signature = trimmed
            .split('(')
            .next()
            .ok_or_else(|| format!("invalid header signature: {trimmed}"))?
            .trim();
        let function_name = signature
            .split_whitespace()
            .last()
            .ok_or_else(|| format!("missing function name in signature: {trimmed}"))?
            .trim_start_matches('*');

        functions.push(function_name.to_string());
    }

    if functions.is_empty() {
        return Err("no exported functions found in aura_ffi.h".to_string());
    }

    Ok(functions)
}

fn parse_export_allowlist(contents: &str) -> Result<Vec<String>, String> {
    let functions = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect::<Vec<_>>();
    if functions.is_empty() {
        return Err("FFI export allowlist is empty".to_string());
    }
    if functions.iter().collect::<BTreeSet<_>>().len() != functions.len() {
        return Err("FFI export allowlist contains duplicates".to_string());
    }
    if functions
        .iter()
        .any(|function| !function.starts_with("aura_"))
    {
        return Err("FFI export allowlist contains a non-Aura symbol".to_string());
    }
    Ok(functions)
}

fn parse_request_limits(source: &str) -> Result<Vec<RequestLimitEvidence>, String> {
    let tracked_limits = [
        ("MAX_CONFIG_REQUEST_BYTES", "config"),
        ("MAX_IMPORT_CONTEXT_REQUEST_BYTES", "import_context request"),
        (
            "MAX_CANONICAL_SAFETY_REQUEST_BYTES",
            "canonical safety request",
        ),
        ("MAX_SMALL_CONTROL_REQUEST_BYTES", "small control request"),
    ];

    let mut limits = Vec::with_capacity(tracked_limits.len());
    for (constant_name, request_kind) in tracked_limits {
        let max_bytes = parse_usize_constant(source, constant_name)?;
        limits.push(RequestLimitEvidence {
            constant_name: constant_name.to_string(),
            request_kind: request_kind.to_string(),
            max_bytes,
        });
    }

    Ok(limits)
}

fn parse_usize_constant(source: &str, constant_name: &str) -> Result<usize, String> {
    let prefix = format!("const {constant_name}: usize = ");
    let expression = source
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing constant {constant_name} in aura-agent-ffi source"))?
        .trim_end_matches(';')
        .trim();

    parse_usize_expression(expression)
        .map_err(|error| format!("parse {constant_name} expression `{expression}`: {error}"))
}

fn parse_usize_expression(expression: &str) -> Result<usize, String> {
    let mut value = 1_usize;
    for factor in expression.split('*') {
        let trimmed = factor.trim();
        if trimmed.is_empty() {
            return Err("empty factor".to_string());
        }
        let parsed = trimmed
            .parse::<usize>()
            .map_err(|error| format!("invalid factor `{trimmed}`: {error}"))?;
        value = value
            .checked_mul(parsed)
            .ok_or_else(|| format!("overflow while evaluating `{expression}`"))?;
    }
    Ok(value)
}

fn file_digest(path: &str, bytes: &[u8]) -> FileDigestEvidence {
    FileDigestEvidence {
        path: path.to_string(),
        sha256: sha256_hex(bytes),
        bytes: bytes.len(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();

    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_limits_are_read_from_decomposed_ffi_lifecycle_source() {
        let source = include_str!("../../aura-agent-ffi/src/lifecycle.rs");

        let limits = parse_request_limits(source).expect("FFI request limits should parse");

        assert_eq!(
            limits
                .iter()
                .map(|limit| (limit.constant_name.as_str(), limit.max_bytes))
                .collect::<Vec<_>>(),
            vec![
                ("MAX_CONFIG_REQUEST_BYTES", 64 * 1024),
                ("MAX_IMPORT_CONTEXT_REQUEST_BYTES", 4 * 1024 * 1024),
                ("MAX_CANONICAL_SAFETY_REQUEST_BYTES", 1024 * 1024),
                ("MAX_SMALL_CONTROL_REQUEST_BYTES", 16 * 1024),
            ]
        );
    }

    #[test]
    fn ffi_export_allowlist_matches_public_header() {
        let header = include_str!("../../../include/aura_ffi.h");
        let allowlist = include_str!("../../../include/aura_ffi.exports");

        let exported = parse_exported_functions(header).expect("header exports should parse");
        let allowed = parse_export_allowlist(allowlist).expect("allowlist should parse");

        assert_eq!(
            exported.into_iter().collect::<BTreeSet<_>>(),
            allowed.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn contract_evidence_binds_both_registered_domain_packs() {
        let evidence = AuraDomainRuntime::new().module_evidence();

        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0].module_id, aura_domain::DomainModuleId::Kids);
        assert_eq!(evidence[1].module_id, aura_domain::DomainModuleId::Military);
        assert!(
            !evidence[1]
                .temporal_policy
                .as_ref()
                .expect("military temporal policy")
                .runtime_enabled
        );
    }
}
