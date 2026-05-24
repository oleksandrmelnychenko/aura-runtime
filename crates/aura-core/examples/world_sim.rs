use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use aura_core::{
    build_shadow_mode_event, AccountType, Action, AlertPriority, AnalysisResult, Analyzer,
    AuraConfig, ContactSnapshot, ConversationType, DomainMode, ProtectionLevel,
    RelationshipTrustSource, SenderRelationship, ShadowModeBundle, ShadowModeEventInput,
    ShadowModeExpectation, ShadowModeFinding,
};
use aura_patterns::PatternDatabase;
use aura_proto::messenger::v1 as proto;
use chrono::{DateTime, Duration, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};

const DEFAULT_WORLD_PATH: &str = "crates/aura-core/data/world_sim_demo.json";

fn main() {
    let mut args = Args::default();
    if let Err(err) = args.parse(env::args().skip(1)) {
        eprintln!("error: {err}");
        print_help();
        std::process::exit(2);
    }

    if args.help {
        print_help();
        return;
    }

    let input_path = args
        .input
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WORLD_PATH));

    if input_path.is_dir() {
        if args.shadow_output.is_some() || args.shadow_output_proto.is_some() {
            eprintln!("error: shadow output is only supported for a single world input");
            std::process::exit(2);
        }

        let suite_report =
            run_world_suite(&input_path, args.repeat_multiplier).unwrap_or_else(|err| {
                eprintln!("error: failed to run simulation suite: {err}");
                std::process::exit(1);
            });

        if !args.summary_only {
            for report in &suite_report.reports {
                print_event_log(report);
                print_summary(report, args.top_contacts);
                println!();
            }
        }
        print_suite_summary(&suite_report);

        if let Some(path) = args.output.as_deref() {
            write_json_report(
                &suite_report,
                path,
                "suite report",
                args.redact_text,
                args.omit_event_log,
            );
        }

        if args.require_clean && suite_report.total_findings != 0 {
            eprintln!(
                "simulation suite produced {} finding(s); --require-clean expects zero",
                suite_report.total_findings
            );
            std::process::exit(1);
        }
        fail_on_metric_gate_violations(&suite_report.metrics.overall, &args, "simulation suite");

        return;
    }

    let world = load_world(&input_path).unwrap_or_else(|err| {
        eprintln!("error: failed to load simulation world: {err}");
        std::process::exit(1);
    });

    let report =
        run_world_simulation(&world, &input_path, args.repeat_multiplier).unwrap_or_else(|err| {
            eprintln!("error: failed to run simulation: {err}");
            std::process::exit(1);
        });

    if !args.summary_only {
        print_event_log(&report);
    }
    print_summary(&report, args.top_contacts);

    if let Some(path) = args.output.as_deref() {
        write_json_report(
            &report,
            path,
            "JSON report",
            args.redact_text,
            args.omit_event_log,
        );
    }

    if args.shadow_output.is_some() || args.shadow_output_proto.is_some() {
        let shadow_bundle = build_shadow_bundle(&report, &input_path);
        if let Some(path) = args.shadow_output.as_deref() {
            write_shadow_bundle_json(&shadow_bundle, path);
        }
        if let Some(path) = args.shadow_output_proto.as_deref() {
            write_shadow_bundle_proto(&shadow_bundle, path);
        }
    }

    if args.require_clean && !report.findings.is_empty() {
        eprintln!(
            "simulation produced {} finding(s); --require-clean expects zero",
            report.findings.len()
        );
        std::process::exit(1);
    }
    fail_on_metric_gate_violations(&report.metrics.overall, &args, "simulation");
}

#[derive(Debug, Default)]
struct Args {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    shadow_output: Option<PathBuf>,
    shadow_output_proto: Option<PathBuf>,
    summary_only: bool,
    top_contacts: usize,
    repeat_multiplier: usize,
    require_clean: bool,
    min_labeled_recall: Option<f64>,
    max_clean_fp_rate: Option<f64>,
    redact_text: bool,
    omit_event_log: bool,
    help: bool,
}

impl Args {
    fn parse<I>(&mut self, mut args: I) -> Result<(), String>
    where
        I: Iterator<Item = String>,
    {
        self.top_contacts = 8;
        self.repeat_multiplier = 1;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input" => self.input = Some(PathBuf::from(next_arg(&mut args, "--input")?)),
                "--output" => self.output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                "--shadow-output" => {
                    self.shadow_output =
                        Some(PathBuf::from(next_arg(&mut args, "--shadow-output")?))
                }
                "--shadow-output-proto" => {
                    self.shadow_output_proto =
                        Some(PathBuf::from(next_arg(&mut args, "--shadow-output-proto")?))
                }
                "--summary-only" => self.summary_only = true,
                "--require-clean" => self.require_clean = true,
                "--min-labeled-recall" => {
                    self.min_labeled_recall =
                        Some(parse_rate_arg(&mut args, "--min-labeled-recall")?)
                }
                "--max-clean-fp-rate" => {
                    self.max_clean_fp_rate = Some(parse_rate_arg(&mut args, "--max-clean-fp-rate")?)
                }
                "--repeat-multiplier" => {
                    let raw = next_arg(&mut args, "--repeat-multiplier")?;
                    self.repeat_multiplier = raw
                        .parse::<usize>()
                        .map_err(|_| format!("invalid --repeat-multiplier value: {raw}"))?;
                    if self.repeat_multiplier == 0 {
                        return Err("--repeat-multiplier must be >= 1".to_string());
                    }
                }
                "--top-contacts" => {
                    let raw = next_arg(&mut args, "--top-contacts")?;
                    self.top_contacts = raw
                        .parse::<usize>()
                        .map_err(|_| format!("invalid --top-contacts value: {raw}"))?;
                }
                "--redact-text" => self.redact_text = true,
                "--omit-event-log" => self.omit_event_log = true,
                "--help" | "-h" => self.help = true,
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(())
    }
}

fn next_arg<I>(args: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_rate_arg<I>(args: &mut I, flag: &str) -> Result<f64, String>
where
    I: Iterator<Item = String>,
{
    let raw = next_arg(args, flag)?;
    let value = raw
        .parse::<f64>()
        .map_err(|_| format!("invalid {flag} value: {raw}"))?;
    if !(0.0..=1.0).contains(&value) {
        return Err(format!("{flag} must be between 0.0 and 1.0, got {raw}"));
    }
    Ok(value)
}

fn print_help() {
    println!("Usage:");
    println!("  cargo run --example world_sim -p aura-core -- [options]");
    println!();
    println!("Options:");
    println!("  --input <path>         simulation world JSON or suite directory (default: {DEFAULT_WORLD_PATH})");
    println!("  --output <path>        write machine-readable JSON report");
    println!("  --shadow-output <path> write plaintext-free shadow replay bundle");
    println!("  --shadow-output-proto <path> write protobuf shadow replay bundle");
    println!("  --summary-only         skip per-event log, print only summary");
    println!("  --top-contacts <n>     number of risky contacts to print (default: 8)");
    println!("  --repeat-multiplier <n> scale generated_batches day_repeats by n (default: 1)");
    println!("  --require-clean        exit non-zero if simulation produced findings");
    println!("  --min-labeled-recall <rate> fail if labeled positive recall is below rate");
    println!(
        "  --max-clean-fp-rate <rate> fail if clean labeled false-positive rate is above rate"
    );
    println!("  --redact-text          replace event text in JSON reports with a redaction marker");
    println!("  --omit-event-log       omit full event_log arrays from JSON reports");
    println!("  --help                 show this message");
}

#[derive(Debug, Clone, Deserialize)]
struct SimulationWorld {
    label: String,
    #[serde(default)]
    description: Option<String>,
    owner: WorldOwner,
    #[serde(default)]
    config: WorldConfigOverrides,
    #[serde(default)]
    actors: Vec<WorldActor>,
    #[serde(default)]
    conversations: Vec<WorldConversation>,
    #[serde(default)]
    events: Vec<WorldEvent>,
    #[serde(default)]
    generated_batches: Vec<GeneratedBatch>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorldOwner {
    id: String,
    display_name: String,
    #[serde(default)]
    age: Option<u16>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WorldConfigOverrides {
    #[serde(default)]
    account_type: Option<AccountType>,
    #[serde(default)]
    protection_level: Option<ProtectionLevel>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    account_holder_age: Option<u16>,
    #[serde(default)]
    ttl_days: Option<u32>,
    #[serde(default)]
    timezone_offset_minutes: Option<i32>,
    #[serde(default)]
    domain_mode: Option<DomainMode>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorldActor {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    trusted: bool,
    #[serde(default)]
    sender_relationship: SenderRelationship,
    #[serde(default)]
    relationship_trust_source: RelationshipTrustSource,
}

#[derive(Debug, Clone, Deserialize)]
struct WorldConversation {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    conversation_type: Option<ConversationType>,
    #[serde(default)]
    member_count: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorldEvent {
    at: String,
    sender_id: String,
    conversation_id: String,
    text: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    conversation_type: Option<ConversationType>,
    #[serde(default)]
    member_count: Option<u32>,
    #[serde(default)]
    sender_relationship: Option<SenderRelationship>,
    #[serde(default)]
    relationship_trust_source: Option<RelationshipTrustSource>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    expect_clean: bool,
    #[serde(default)]
    expect_threat: Option<aura_core::ThreatType>,
    #[serde(default)]
    expect_min_action: Option<Action>,
    #[serde(default)]
    expect_min_alert: Option<AlertPriority>,
}

#[derive(Debug, Clone, Deserialize)]
struct GeneratedBatch {
    label: String,
    start_at: String,
    count: usize,
    interval_minutes: u64,
    #[serde(default = "default_day_repeats")]
    day_repeats: usize,
    #[serde(default = "default_day_stride_days")]
    day_stride_days: u64,
    sender_ids: Vec<String>,
    conversation_ids: Vec<String>,
    texts: Vec<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    conversation_type: Option<ConversationType>,
    #[serde(default)]
    member_count: Option<u32>,
    #[serde(default)]
    sender_relationship: Option<SenderRelationship>,
    #[serde(default)]
    relationship_trust_source: Option<RelationshipTrustSource>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    expect_clean: bool,
    #[serde(default)]
    expect_threat: Option<aura_core::ThreatType>,
    #[serde(default)]
    expect_min_action: Option<Action>,
    #[serde(default)]
    expect_min_alert: Option<AlertPriority>,
}

fn default_day_repeats() -> usize {
    1
}

fn default_day_stride_days() -> u64 {
    1
}

#[derive(Debug, Serialize)]
struct WorldSimReport {
    schema_version: &'static str,
    label: String,
    description: Option<String>,
    owner: OwnerReport,
    config: AuraConfig,
    input_path: String,
    started_at: String,
    ended_at: String,
    total_events: usize,
    threat_events: usize,
    warn_events: usize,
    block_events: usize,
    action_counts: BTreeMap<String, usize>,
    threat_counts: BTreeMap<String, usize>,
    alert_counts: BTreeMap<String, usize>,
    metrics: WorldMetricsReport,
    context_store: WorldContextStoreSummary,
    findings: Vec<SimulationFinding>,
    event_log: Vec<EventOutcome>,
    conversations: Vec<ConversationSummary>,
    top_risky_contacts: Vec<ContactRiskSummary>,
}

#[derive(Debug, Serialize)]
struct WorldSuiteReport {
    schema_version: &'static str,
    label: String,
    input_path: String,
    total_worlds: usize,
    total_events: usize,
    threat_events: usize,
    warn_events: usize,
    block_events: usize,
    total_findings: usize,
    action_counts: BTreeMap<String, usize>,
    threat_counts: BTreeMap<String, usize>,
    alert_counts: BTreeMap<String, usize>,
    metrics: WorldMetricsReport,
    reports: Vec<WorldSimReport>,
}

#[derive(Debug, Serialize)]
struct OwnerReport {
    id: String,
    display_name: String,
    age: Option<u16>,
}

#[derive(Debug, Serialize)]
struct EventOutcome {
    sequence: usize,
    at: String,
    timestamp_ms: u64,
    sender_id: String,
    sender_name: String,
    conversation_id: String,
    conversation_name: String,
    language: String,
    conversation_type: ConversationType,
    member_count: Option<u32>,
    sender_relationship: SenderRelationship,
    relationship_trust_source: RelationshipTrustSource,
    note: Option<String>,
    expectation: Option<EventExpectation>,
    text: String,
    result: AnalysisResult,
}

#[derive(Debug, Clone, Serialize)]
struct EventExpectation {
    expect_clean: bool,
    expect_threat: Option<aura_core::ThreatType>,
    expect_min_action: Option<Action>,
    expect_min_alert: Option<AlertPriority>,
}

#[derive(Debug, Serialize)]
struct ConversationSummary {
    conversation_id: String,
    display_name: String,
    conversation_type: ConversationType,
    member_count: Option<u32>,
    total_messages: usize,
    unique_senders: usize,
    threat_messages: usize,
    warn_messages: usize,
    block_messages: usize,
    max_score: f32,
    action_counts: BTreeMap<String, usize>,
    threat_counts: BTreeMap<String, usize>,
    alert_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct ContactRiskSummary {
    sender_id: String,
    display_name: String,
    risk_score: f32,
    rating: f32,
    trust_level: f32,
    total_messages: u64,
    grooming_event_count: u64,
    bullying_event_count: u64,
    manipulation_event_count: u64,
    inferred_age: Option<u16>,
    is_trusted: bool,
    snapshot: ContactSnapshot,
}

#[derive(Debug, Clone, Serialize)]
struct WorldMetricsReport {
    overall: WorldMetricCounts,
    by_relationship: Vec<WorldMetricSlice>,
    by_surface: Vec<WorldMetricSlice>,
    by_language: Vec<WorldMetricSlice>,
    by_expected_threat: Vec<WorldMetricSlice>,
}

#[derive(Debug, Clone, Serialize)]
struct WorldContextStoreSummary {
    timeline_count: usize,
    total_timeline_events: usize,
    max_timeline_events: usize,
    contact_profile_count: usize,
    max_contact_conversations: usize,
    max_contact_messages: u64,
}

#[derive(Debug, Clone, Serialize)]
struct WorldMetricSlice {
    slice_id: String,
    counts: WorldMetricCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
struct WorldMetricCounts {
    labeled_events: usize,
    labeled_positive_events: usize,
    labeled_clean_events: usize,
    true_positive_events: usize,
    false_negative_events: usize,
    wrong_threat_events: usize,
    true_negative_events: usize,
    false_positive_events: usize,
    positive_precision: Option<f64>,
    positive_recall: Option<f64>,
    clean_false_positive_rate: Option<f64>,
}

#[derive(Debug, Clone, Default)]
struct MetricAccumulator {
    labeled_positive_events: usize,
    labeled_clean_events: usize,
    true_positive_events: usize,
    false_negative_events: usize,
    wrong_threat_events: usize,
    true_negative_events: usize,
    false_positive_events: usize,
}

#[derive(Debug, Serialize)]
struct SimulationFinding {
    severity: FindingSeverity,
    event_sequence: usize,
    at: String,
    sender_id: String,
    conversation_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FindingSeverity {
    Warning,
}

#[derive(Debug)]
struct ResolvedEvent {
    source_index: usize,
    timestamp_ms: u64,
    at: String,
    sender_id: String,
    sender_name: String,
    conversation_id: String,
    conversation_name: String,
    conversation_type: ConversationType,
    member_count: Option<u32>,
    sender_relationship: SenderRelationship,
    relationship_trust_source: RelationshipTrustSource,
    language: String,
    note: Option<String>,
    expectation: Option<EventExpectation>,
    text: String,
    sender_trusted: bool,
}

#[derive(Debug, Clone)]
struct ResolvedEventSeed {
    at: String,
    timestamp_ms: u64,
    sender_id: String,
    conversation_id: String,
    conversation_type: Option<ConversationType>,
    member_count: Option<u32>,
    sender_relationship: Option<SenderRelationship>,
    relationship_trust_source: Option<RelationshipTrustSource>,
    language: Option<String>,
    note: Option<String>,
    expectation: Option<EventExpectation>,
    text: String,
}

fn run_world_suite(input_dir: &Path, repeat_multiplier: usize) -> Result<WorldSuiteReport, String> {
    let input_paths = load_suite_paths(input_dir)?;
    let mut reports = Vec::with_capacity(input_paths.len());

    for input_path in input_paths {
        let world = load_world(&input_path)?;
        let report = run_world_simulation(&world, &input_path, repeat_multiplier)?;
        reports.push(report);
    }

    let mut action_counts = BTreeMap::new();
    let mut threat_counts = BTreeMap::new();
    let mut alert_counts = BTreeMap::new();
    let mut total_events = 0;
    let mut threat_events = 0;
    let mut warn_events = 0;
    let mut block_events = 0;
    let mut total_findings = 0;

    for report in &reports {
        total_events += report.total_events;
        threat_events += report.threat_events;
        warn_events += report.warn_events;
        block_events += report.block_events;
        total_findings += report.findings.len();
        merge_counts(&mut action_counts, &report.action_counts);
        merge_counts(&mut threat_counts, &report.threat_counts);
        merge_counts(&mut alert_counts, &report.alert_counts);
    }
    let metrics = build_metrics_report(reports.iter().flat_map(|report| report.event_log.iter()));

    Ok(WorldSuiteReport {
        schema_version: "world_suite.v1",
        label: input_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("world_suite")
            .to_string(),
        input_path: input_dir.display().to_string(),
        total_worlds: reports.len(),
        total_events,
        threat_events,
        warn_events,
        block_events,
        total_findings,
        action_counts,
        threat_counts,
        alert_counts,
        metrics,
        reports,
    })
}

fn load_suite_paths(input_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut input_paths = fs::read_dir(input_dir)
        .map_err(|err| format!("read suite directory {}: {err}", input_dir.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|err| format!("read suite directory entry: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    input_paths.retain(|path| {
        path.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    });
    input_paths.sort();

    if input_paths.is_empty() {
        return Err(format!(
            "suite directory {} does not contain any JSON worlds",
            input_dir.display()
        ));
    }

    Ok(input_paths)
}

fn load_world(path: &Path) -> Result<SimulationWorld, String> {
    let raw = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut world: SimulationWorld =
        serde_json::from_str(&raw).map_err(|err| format!("parse {}: {err}", path.display()))?;
    if world.events.is_empty() && world.generated_batches.is_empty() {
        return Err("simulation world must contain events or generated_batches".to_string());
    }
    if !world.actors.iter().any(|actor| actor.id == world.owner.id) {
        world.actors.push(WorldActor {
            id: world.owner.id.clone(),
            display_name: Some(world.owner.display_name.clone()),
            trusted: false,
            sender_relationship: SenderRelationship::Unknown,
            relationship_trust_source: RelationshipTrustSource::Unknown,
        });
    }
    Ok(world)
}

fn run_world_simulation(
    world: &SimulationWorld,
    input_path: &Path,
    repeat_multiplier: usize,
) -> Result<WorldSimReport, String> {
    let mut config = AuraConfig::default();
    config.account_type = world.config.account_type.unwrap_or(AccountType::Child);
    config.protection_level = world
        .config
        .protection_level
        .unwrap_or(ProtectionLevel::High);
    config.language = world
        .config
        .language
        .clone()
        .unwrap_or_else(|| "uk".to_string());
    config.enabled = world.config.enabled.unwrap_or(true);
    config.account_holder_age = world.config.account_holder_age.or(world.owner.age);
    config.protected_account_id = Some(world.owner.id.clone());
    config.ttl_days = world.config.ttl_days.unwrap_or(30);
    config.timezone_offset_minutes = world.config.timezone_offset_minutes.unwrap_or(120);
    config.domain_mode = world.config.domain_mode.unwrap_or(DomainMode::None);
    config
        .validate()
        .map_err(|err| format!("invalid config in world file: {err}"))?;

    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(config.clone(), &db);

    let actor_lookup: HashMap<_, _> = world
        .actors
        .iter()
        .map(|actor| (actor.id.clone(), actor.clone()))
        .collect();
    let conversation_lookup: HashMap<_, _> = world
        .conversations
        .iter()
        .map(|conversation| (conversation.id.clone(), conversation.clone()))
        .collect();

    let mut resolved_events = Vec::new();

    for event in &world.events {
        let seed = event_seed_from_event(event)?;
        resolved_events.push(resolve_seed(
            resolved_events.len(),
            seed,
            world,
            &actor_lookup,
            &conversation_lookup,
        )?);
    }

    for batch in &world.generated_batches {
        for seed in expand_generated_batch(batch, repeat_multiplier)? {
            resolved_events.push(resolve_seed(
                resolved_events.len(),
                seed,
                world,
                &actor_lookup,
                &conversation_lookup,
            )?);
        }
    }

    resolved_events.sort_by_key(|event| (event.timestamp_ms, event.source_index));

    let mut event_log = Vec::with_capacity(resolved_events.len());
    let mut findings = Vec::new();
    for (sequence, event) in resolved_events.iter().enumerate() {
        let input = aura_core::MessageInput {
            content_type: aura_core::ContentType::Text,
            text: Some(event.text.clone()),
            image_data: None,
            sender_id: event.sender_id.as_str().into(),
            conversation_id: event.conversation_id.as_str().into(),
            language: Some(event.language.clone()),
            conversation_type: event.conversation_type,
            member_count: event.member_count,
            server_sender_risk_hint: None,
            sender_relationship: event.sender_relationship,
            relationship_trust_source: event.relationship_trust_source,
        };

        let result = analyzer.analyze_with_context(&input, event.timestamp_ms);

        if event.sender_trusted {
            analyzer.mark_contact_trusted(&event.sender_id);
        }

        event_log.push(EventOutcome {
            sequence: sequence + 1,
            at: event.at.clone(),
            timestamp_ms: event.timestamp_ms,
            sender_id: event.sender_id.clone(),
            sender_name: event.sender_name.clone(),
            conversation_id: event.conversation_id.clone(),
            conversation_name: event.conversation_name.clone(),
            language: event.language.clone(),
            conversation_type: event.conversation_type,
            member_count: event.member_count,
            sender_relationship: event.sender_relationship,
            relationship_trust_source: event.relationship_trust_source,
            note: event.note.clone(),
            expectation: event.expectation.clone(),
            text: event.text.clone(),
            result,
        });

        let outcome = event_log.last().expect("just pushed event outcome");
        findings.extend(evaluate_findings(world, outcome));
    }

    let mut action_counts = BTreeMap::new();
    let mut threat_counts = BTreeMap::new();
    let mut alert_counts = BTreeMap::new();
    let mut threat_events = 0_usize;
    let mut warn_events = 0_usize;
    let mut block_events = 0_usize;

    for outcome in &event_log {
        bump_count(&mut action_counts, enum_key(&outcome.result.action));
        if outcome.result.is_threat() {
            threat_events += 1;
            bump_count(&mut threat_counts, enum_key(&outcome.result.threat_type));
        }
        if outcome.result.action == Action::Warn {
            warn_events += 1;
        }
        if outcome.result.action == Action::Block {
            block_events += 1;
        }
        if let Some(recommendation) = &outcome.result.recommended_action {
            bump_count(&mut alert_counts, enum_key(&recommendation.parent_alert));
        }
    }

    let conversations = build_conversation_summaries(&event_log);
    let top_risky_contacts = build_contact_summaries(
        world,
        &actor_lookup,
        analyzer.context_tracker().contact_profiler(),
    );
    let metrics = build_metrics_report(event_log.iter());
    let context_store = build_context_store_summary(&analyzer);

    let started_at = resolved_events
        .first()
        .map(|event| event.at.clone())
        .unwrap_or_default();
    let ended_at = resolved_events
        .last()
        .map(|event| event.at.clone())
        .unwrap_or_default();

    Ok(WorldSimReport {
        schema_version: "world_sim.v1",
        label: world.label.clone(),
        description: world.description.clone(),
        owner: OwnerReport {
            id: world.owner.id.clone(),
            display_name: world.owner.display_name.clone(),
            age: world.owner.age,
        },
        config,
        input_path: input_path.display().to_string(),
        started_at,
        ended_at,
        total_events: event_log.len(),
        threat_events,
        warn_events,
        block_events,
        action_counts,
        threat_counts,
        alert_counts,
        metrics,
        context_store,
        findings,
        event_log,
        conversations,
        top_risky_contacts,
    })
}

fn event_seed_from_event(event: &WorldEvent) -> Result<ResolvedEventSeed, String> {
    let timestamp = DateTime::parse_from_rfc3339(&event.at)
        .map_err(|err| format!("invalid RFC3339 timestamp '{}': {err}", event.at))?;
    let timestamp_ms = timestamp.with_timezone(&Utc).timestamp_millis();
    if timestamp_ms < 0 {
        return Err(format!("negative timestamp not supported: {}", event.at));
    }

    Ok(ResolvedEventSeed {
        at: event.at.clone(),
        timestamp_ms: timestamp_ms as u64,
        sender_id: event.sender_id.clone(),
        conversation_id: event.conversation_id.clone(),
        conversation_type: event.conversation_type,
        member_count: event.member_count,
        sender_relationship: event.sender_relationship,
        relationship_trust_source: event.relationship_trust_source,
        language: event.language.clone(),
        note: event.note.clone(),
        expectation: expectation_from_parts(
            event.expect_clean,
            event.expect_threat,
            event.expect_min_action,
            event.expect_min_alert,
        ),
        text: event.text.clone(),
    })
}

fn expand_generated_batch(
    batch: &GeneratedBatch,
    repeat_multiplier: usize,
) -> Result<Vec<ResolvedEventSeed>, String> {
    if batch.count == 0 {
        return Err(format!(
            "generated batch '{}' must have count > 0",
            batch.label
        ));
    }
    if batch.interval_minutes == 0 {
        return Err(format!(
            "generated batch '{}' must have interval_minutes > 0",
            batch.label
        ));
    }
    if batch.day_repeats == 0 {
        return Err(format!(
            "generated batch '{}' must have day_repeats > 0",
            batch.label
        ));
    }
    if repeat_multiplier == 0 {
        return Err("repeat_multiplier must be >= 1".to_string());
    }
    if batch.sender_ids.is_empty() {
        return Err(format!(
            "generated batch '{}' must include sender_ids",
            batch.label
        ));
    }
    if batch.conversation_ids.is_empty() {
        return Err(format!(
            "generated batch '{}' must include conversation_ids",
            batch.label
        ));
    }
    if batch.texts.is_empty() {
        return Err(format!(
            "generated batch '{}' must include texts",
            batch.label
        ));
    }

    let start = DateTime::parse_from_rfc3339(&batch.start_at).map_err(|err| {
        format!(
            "generated batch '{}' has invalid RFC3339 timestamp '{}': {err}",
            batch.label, batch.start_at
        )
    })?;

    let interval = Duration::minutes(batch.interval_minutes as i64);
    let day_stride = Duration::days(batch.day_stride_days as i64);
    let effective_day_repeats = batch.day_repeats * repeat_multiplier;
    let mut seeds = Vec::with_capacity(batch.count * effective_day_repeats);

    for day_index in 0..effective_day_repeats {
        let day_base = start + day_stride * day_index as i32;
        for event_index in 0..batch.count {
            let absolute_index = day_index * batch.count + event_index;
            let at = day_base + interval * event_index as i32;
            let timestamp_ms = at.with_timezone(&Utc).timestamp_millis();
            if timestamp_ms < 0 {
                return Err(format!(
                    "generated batch '{}' produced negative timestamp",
                    batch.label
                ));
            }

            let note = batch.note.as_ref().map(|note| {
                format!(
                    "{note} | batch={} day={} event={}",
                    batch.label,
                    day_index + 1,
                    event_index + 1
                )
            });

            seeds.push(ResolvedEventSeed {
                at: at.to_rfc3339(),
                timestamp_ms: timestamp_ms as u64,
                sender_id: batch.sender_ids[absolute_index % batch.sender_ids.len()].clone(),
                conversation_id: batch.conversation_ids
                    [absolute_index % batch.conversation_ids.len()]
                .clone(),
                conversation_type: batch.conversation_type,
                member_count: batch.member_count,
                sender_relationship: batch.sender_relationship,
                relationship_trust_source: batch.relationship_trust_source,
                language: batch.language.clone(),
                note,
                expectation: expectation_from_parts(
                    batch.expect_clean,
                    batch.expect_threat,
                    batch.expect_min_action,
                    batch.expect_min_alert,
                ),
                text: batch.texts[absolute_index % batch.texts.len()].clone(),
            });
        }
    }

    Ok(seeds)
}

fn expectation_from_parts(
    expect_clean: bool,
    expect_threat: Option<aura_core::ThreatType>,
    expect_min_action: Option<Action>,
    expect_min_alert: Option<AlertPriority>,
) -> Option<EventExpectation> {
    if expect_clean
        || expect_threat.is_some()
        || expect_min_action.is_some()
        || expect_min_alert.is_some()
    {
        Some(EventExpectation {
            expect_clean,
            expect_threat,
            expect_min_action,
            expect_min_alert,
        })
    } else {
        None
    }
}

fn resolve_seed(
    index: usize,
    seed: ResolvedEventSeed,
    world: &SimulationWorld,
    actor_lookup: &HashMap<String, WorldActor>,
    conversation_lookup: &HashMap<String, WorldConversation>,
) -> Result<ResolvedEvent, String> {
    let actor = actor_lookup.get(&seed.sender_id);
    let sender_name = actor
        .and_then(|actor| actor.display_name.clone())
        .unwrap_or_else(|| seed.sender_id.clone());
    let sender_trusted = actor.map(|actor| actor.trusted).unwrap_or(false);

    let conversation = conversation_lookup.get(&seed.conversation_id);
    let conversation_name = conversation
        .and_then(|conversation| conversation.display_name.clone())
        .unwrap_or_else(|| seed.conversation_id.clone());

    let conversation_type = seed
        .conversation_type
        .or_else(|| conversation.and_then(|conversation| conversation.conversation_type))
        .unwrap_or(ConversationType::Direct);

    let member_count = seed
        .member_count
        .or_else(|| conversation.and_then(|conversation| conversation.member_count));
    let sender_relationship = seed
        .sender_relationship
        .or_else(|| actor.map(|actor| actor.sender_relationship))
        .unwrap_or_default();
    let relationship_trust_source = seed
        .relationship_trust_source
        .or_else(|| actor.map(|actor| actor.relationship_trust_source))
        .unwrap_or_default();

    Ok(ResolvedEvent {
        source_index: index,
        timestamp_ms: seed.timestamp_ms,
        at: seed.at,
        sender_id: seed.sender_id,
        sender_name,
        conversation_id: seed.conversation_id,
        conversation_name,
        conversation_type,
        member_count,
        sender_relationship,
        relationship_trust_source,
        language: seed.language.unwrap_or_else(|| {
            world
                .config
                .language
                .clone()
                .unwrap_or_else(|| "uk".to_string())
        }),
        note: seed.note,
        expectation: seed.expectation,
        text: seed.text,
        sender_trusted,
    })
}

fn build_conversation_summaries(event_log: &[EventOutcome]) -> Vec<ConversationSummary> {
    let mut grouped: BTreeMap<String, Vec<&EventOutcome>> = BTreeMap::new();
    for outcome in event_log {
        grouped
            .entry(outcome.conversation_id.clone())
            .or_default()
            .push(outcome);
    }

    grouped
        .into_values()
        .map(|events| {
            let first = events[0];
            let mut senders = BTreeSet::new();
            let mut action_counts = BTreeMap::new();
            let mut threat_counts = BTreeMap::new();
            let mut alert_counts = BTreeMap::new();
            let mut threat_messages = 0;
            let mut warn_messages = 0;
            let mut block_messages = 0;
            let mut max_score = 0.0_f32;

            for outcome in &events {
                senders.insert(outcome.sender_id.clone());
                max_score = max_score.max(outcome.result.score);
                bump_count(&mut action_counts, enum_key(&outcome.result.action));

                if outcome.result.is_threat() {
                    threat_messages += 1;
                    bump_count(&mut threat_counts, enum_key(&outcome.result.threat_type));
                }
                if outcome.result.action == Action::Warn {
                    warn_messages += 1;
                }
                if outcome.result.action == Action::Block {
                    block_messages += 1;
                }
                if let Some(recommendation) = &outcome.result.recommended_action {
                    bump_count(&mut alert_counts, enum_key(&recommendation.parent_alert));
                }
            }

            ConversationSummary {
                conversation_id: first.conversation_id.clone(),
                display_name: first.conversation_name.clone(),
                conversation_type: first.conversation_type,
                member_count: first.member_count,
                total_messages: events.len(),
                unique_senders: senders.len(),
                threat_messages,
                warn_messages,
                block_messages,
                max_score,
                action_counts,
                threat_counts,
                alert_counts,
            }
        })
        .collect()
}

fn build_contact_summaries(
    world: &SimulationWorld,
    actor_lookup: &HashMap<String, WorldActor>,
    profiler: &aura_core::context::contact::ContactProfiler,
) -> Vec<ContactRiskSummary> {
    profiler
        .contacts_by_risk()
        .into_iter()
        .filter(|profile| profile.sender_id != world.owner.id.as_str())
        .filter_map(|profile| {
            let snapshot = profiler.snapshot(&profile.sender_id)?;
            Some(ContactRiskSummary {
                sender_id: profile.sender_id.to_string(),
                display_name: actor_lookup
                    .get(&*profile.sender_id)
                    .and_then(|actor| actor.display_name.clone())
                    .unwrap_or_else(|| profile.sender_id.to_string()),
                risk_score: profile.risk_score(),
                rating: profile.rating,
                trust_level: profile.trust_level,
                total_messages: profile.total_messages,
                grooming_event_count: profile.grooming_event_count,
                bullying_event_count: profile.bullying_event_count,
                manipulation_event_count: profile.manipulation_event_count,
                inferred_age: profile.inferred_age,
                is_trusted: profile.is_trusted,
                snapshot,
            })
        })
        .collect()
}

fn build_context_store_summary(analyzer: &Analyzer) -> WorldContextStoreSummary {
    let state = analyzer.export_context_state();
    let total_timeline_events = state
        .timelines
        .iter()
        .map(|timeline| timeline.events.len())
        .sum();
    let max_timeline_events = state
        .timelines
        .iter()
        .map(|timeline| timeline.events.len())
        .max()
        .unwrap_or(0);
    let max_contact_conversations = state
        .contact_profiler
        .profiles
        .iter()
        .map(|profile| profile.conversations.len())
        .max()
        .unwrap_or(0);
    let max_contact_messages = state
        .contact_profiler
        .profiles
        .iter()
        .map(|profile| profile.total_messages)
        .max()
        .unwrap_or(0);

    WorldContextStoreSummary {
        timeline_count: state.timelines.len(),
        total_timeline_events,
        max_timeline_events,
        contact_profile_count: state.contact_profiler.profiles.len(),
        max_contact_conversations,
        max_contact_messages,
    }
}

fn build_metrics_report<'a, I>(events: I) -> WorldMetricsReport
where
    I: IntoIterator<Item = &'a EventOutcome>,
{
    let mut overall = MetricAccumulator::default();
    let mut by_relationship = BTreeMap::<String, MetricAccumulator>::new();
    let mut by_surface = BTreeMap::<String, MetricAccumulator>::new();
    let mut by_language = BTreeMap::<String, MetricAccumulator>::new();
    let mut by_expected_threat = BTreeMap::<String, MetricAccumulator>::new();

    for event in events {
        if !event_has_metric_label(event) {
            continue;
        }

        overall.observe(event);
        by_relationship
            .entry(enum_key(&event.sender_relationship))
            .or_default()
            .observe(event);
        by_surface
            .entry(enum_key(&event.conversation_type))
            .or_default()
            .observe(event);
        by_language
            .entry(event.language.clone())
            .or_default()
            .observe(event);

        if let Some(expected_threat) = event
            .expectation
            .as_ref()
            .and_then(|expectation| expectation.expect_threat)
        {
            by_expected_threat
                .entry(enum_key(&expected_threat))
                .or_default()
                .observe(event);
        }
    }

    WorldMetricsReport {
        overall: overall.finish(),
        by_relationship: finish_metric_slices(by_relationship),
        by_surface: finish_metric_slices(by_surface),
        by_language: finish_metric_slices(by_language),
        by_expected_threat: finish_metric_slices(by_expected_threat),
    }
}

impl MetricAccumulator {
    fn observe(&mut self, event: &EventOutcome) {
        let Some(expectation) = &event.expectation else {
            return;
        };

        if let Some(expected_threat) = expectation.expect_threat {
            self.labeled_positive_events += 1;
            if result_contains_threat(&event.result, expected_threat) {
                self.true_positive_events += 1;
            } else {
                self.false_negative_events += 1;
                if event.result.is_threat() {
                    self.wrong_threat_events += 1;
                }
            }
        }

        if expectation.expect_clean {
            self.labeled_clean_events += 1;
            if clean_expectation_violated(event) {
                self.false_positive_events += 1;
            } else {
                self.true_negative_events += 1;
            }
        }
    }

    fn finish(self) -> WorldMetricCounts {
        let labeled_events = self.labeled_positive_events + self.labeled_clean_events;
        let positive_predictions =
            self.true_positive_events + self.false_positive_events + self.wrong_threat_events;

        WorldMetricCounts {
            labeled_events,
            labeled_positive_events: self.labeled_positive_events,
            labeled_clean_events: self.labeled_clean_events,
            true_positive_events: self.true_positive_events,
            false_negative_events: self.false_negative_events,
            wrong_threat_events: self.wrong_threat_events,
            true_negative_events: self.true_negative_events,
            false_positive_events: self.false_positive_events,
            positive_precision: rate(self.true_positive_events, positive_predictions),
            positive_recall: rate(self.true_positive_events, self.labeled_positive_events),
            clean_false_positive_rate: rate(self.false_positive_events, self.labeled_clean_events),
        }
    }
}

fn finish_metric_slices(slices: BTreeMap<String, MetricAccumulator>) -> Vec<WorldMetricSlice> {
    slices
        .into_iter()
        .map(|(slice_id, accumulator)| WorldMetricSlice {
            slice_id,
            counts: accumulator.finish(),
        })
        .collect()
}

fn event_has_metric_label(event: &EventOutcome) -> bool {
    event
        .expectation
        .as_ref()
        .is_some_and(|expectation| expectation.expect_clean || expectation.expect_threat.is_some())
}

fn rate(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn print_event_log(report: &WorldSimReport) {
    println!("Simulation: {}", report.label);
    if let Some(description) = &report.description {
        println!("{description}");
    }
    println!(
        "Window: {} -> {} | events={} | owner={}",
        report.started_at, report.ended_at, report.total_events, report.owner.display_name
    );
    println!();

    for event in &report.event_log {
        let alert = event
            .result
            .recommended_action
            .as_ref()
            .map(|rec| enum_key(&rec.parent_alert))
            .unwrap_or_else(|| enum_key(&AlertPriority::None));

        println!(
            "[{}] {} / {} -> threat={} action={} score={:.2} alert={}",
            event.at,
            event.conversation_name,
            event.sender_name,
            enum_key(&event.result.threat_type),
            enum_key(&event.result.action),
            event.result.score,
            alert
        );
        println!("  text: {}", event.text);
        if let Some(note) = &event.note {
            println!("  note: {note}");
        }
        if !event.result.reason_codes.is_empty() {
            println!("  reason_codes: {}", event.result.reason_codes.join(", "));
        }
        if let Some(recommendation) = &event.result.recommended_action {
            println!(
                "  ui_actions: {}",
                recommendation
                    .ui_actions
                    .iter()
                    .map(enum_key)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!();
    }
}

fn print_summary(report: &WorldSimReport, top_contacts: usize) {
    println!("Summary");
    println!(
        "  threat_events={} warn_events={} block_events={}",
        report.threat_events, report.warn_events, report.block_events
    );
    println!("  action_counts={}", format_counts(&report.action_counts));
    println!("  threat_counts={}", format_counts(&report.threat_counts));
    println!("  alert_counts={}", format_counts(&report.alert_counts));
    println!("  findings={}", report.findings.len());
    println!();

    print_metrics_summary(&report.metrics);
    println!();

    println!("Conversation Summary");
    for conversation in &report.conversations {
        println!(
            "  {}: msgs={} senders={} threats={} warn={} block={} max_score={:.2}",
            conversation.display_name,
            conversation.total_messages,
            conversation.unique_senders,
            conversation.threat_messages,
            conversation.warn_messages,
            conversation.block_messages,
            conversation.max_score
        );
        if !conversation.threat_counts.is_empty() {
            println!("    threats={}", format_counts(&conversation.threat_counts));
        }
        if !conversation.alert_counts.is_empty() {
            println!("    alerts={}", format_counts(&conversation.alert_counts));
        }
    }
    println!();

    println!("Top Risky Contacts");
    for contact in report.top_risky_contacts.iter().take(top_contacts) {
        println!(
            "  {}: risk={:.2} rating={:.1} trust={:.2} tier={} trend={} msgs={} trusted={}",
            contact.display_name,
            contact.risk_score,
            contact.rating,
            contact.trust_level,
            enum_key(&contact.snapshot.circle_tier),
            enum_key(&contact.snapshot.trend),
            contact.total_messages,
            contact.is_trusted
        );
        println!(
            "    groom={} bully={} manip={} inferred_age={}",
            contact.grooming_event_count,
            contact.bullying_event_count,
            contact.manipulation_event_count,
            contact
                .inferred_age
                .map(|age| age.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
    }

    if !report.findings.is_empty() {
        println!();
        println!("Findings");
        for finding in &report.findings {
            println!(
                "  [{}] {} / {}: {}",
                finding.at, finding.conversation_id, finding.sender_id, finding.message
            );
        }
    }
}

fn print_suite_summary(report: &WorldSuiteReport) {
    println!("Suite Summary");
    println!(
        "  worlds={} events={} threat_events={} warn_events={} block_events={} findings={}",
        report.total_worlds,
        report.total_events,
        report.threat_events,
        report.warn_events,
        report.block_events,
        report.total_findings
    );
    println!("  action_counts={}", format_counts(&report.action_counts));
    println!("  threat_counts={}", format_counts(&report.threat_counts));
    println!("  alert_counts={}", format_counts(&report.alert_counts));
    print_metric_counts("  metrics", &report.metrics.overall);
    println!();

    println!("World Results");
    for world in &report.reports {
        println!(
            "  {}: events={} threats={} warn={} block={} findings={}",
            world.label,
            world.total_events,
            world.threat_events,
            world.warn_events,
            world.block_events,
            world.findings.len()
        );
        if !world.threat_counts.is_empty() {
            println!("    threats={}", format_counts(&world.threat_counts));
        }
        print_metric_counts("    metrics", &world.metrics.overall);
        if !world.findings.is_empty() {
            for finding in world.findings.iter().take(3) {
                println!(
                    "    finding [{}] {} / {}: {}",
                    finding.at, finding.conversation_id, finding.sender_id, finding.message
                );
            }
            if world.findings.len() > 3 {
                println!("    ... {} more finding(s)", world.findings.len() - 3);
            }
        }
    }
}

fn print_metrics_summary(metrics: &WorldMetricsReport) {
    println!("Quality Metrics");
    print_metric_counts("  overall", &metrics.overall);
    print_metric_rows("  by_relationship", &metrics.by_relationship);
    print_metric_rows("  by_surface", &metrics.by_surface);
    print_metric_rows("  by_language", &metrics.by_language);
    print_metric_rows("  by_expected_threat", &metrics.by_expected_threat);
}

fn print_metric_rows(label: &str, rows: &[WorldMetricSlice]) {
    if rows.is_empty() {
        println!("{label}: -");
        return;
    }

    println!("{label}:");
    for row in rows {
        print_metric_counts(&format!("    {}", row.slice_id), &row.counts);
    }
}

fn print_metric_counts(label: &str, counts: &WorldMetricCounts) {
    println!(
        "{label}: labeled={} pos={} clean={} tp={} fn={} wrong={} fp={} recall={} precision={} clean_fp={}",
        counts.labeled_events,
        counts.labeled_positive_events,
        counts.labeled_clean_events,
        counts.true_positive_events,
        counts.false_negative_events,
        counts.wrong_threat_events,
        counts.false_positive_events,
        format_rate(counts.positive_recall),
        format_rate(counts.positive_precision),
        format_rate(counts.clean_false_positive_rate)
    );
}

fn format_rate(rate: Option<f64>) -> String {
    rate.map(|value| format!("{:.1}%", value * 100.0))
        .unwrap_or_else(|| "-".to_string())
}

fn fail_on_metric_gate_violations(metrics: &WorldMetricCounts, args: &Args, label: &str) {
    let failures = metric_gate_violations(metrics, args);
    if failures.is_empty() {
        return;
    }

    eprintln!("{label} failed quality metric gate(s):");
    for failure in failures {
        eprintln!("  - {failure}");
    }
    std::process::exit(1);
}

fn metric_gate_violations(metrics: &WorldMetricCounts, args: &Args) -> Vec<String> {
    let mut failures = Vec::new();

    if let Some(min_recall) = args.min_labeled_recall {
        match metrics.positive_recall {
            Some(actual) if actual < min_recall => failures.push(format!(
                "positive recall {} is below required {}",
                format_rate(Some(actual)),
                format_rate(Some(min_recall))
            )),
            None => failures.push(
                "positive recall is unavailable because there are no labeled positive events"
                    .to_string(),
            ),
            _ => {}
        }
    }

    if let Some(max_fp_rate) = args.max_clean_fp_rate {
        match metrics.clean_false_positive_rate {
            Some(actual) if actual > max_fp_rate => failures.push(format!(
                "clean false-positive rate {} is above allowed {}",
                format_rate(Some(actual)),
                format_rate(Some(max_fp_rate))
            )),
            None => failures.push(
                "clean false-positive rate is unavailable because there are no labeled clean events"
                    .to_string(),
            ),
            _ => {}
        }
    }

    failures
}

fn build_shadow_bundle(report: &WorldSimReport, input_path: &Path) -> ShadowModeBundle {
    let events = report
        .event_log
        .iter()
        .map(|event| {
            let request_id = format!("world_sim:{}:{}", report.label, event.sequence);
            build_shadow_mode_event(ShadowModeEventInput {
                request_id: &request_id,
                sequence: event.sequence,
                timestamp_ms: event.timestamp_ms,
                sender_id: &event.sender_id,
                conversation_id: &event.conversation_id,
                language: &event.language,
                conversation_type: event.conversation_type,
                member_count: event.member_count,
                expectation: event
                    .expectation
                    .as_ref()
                    .map(|expectation| ShadowModeExpectation {
                        expect_threat: expectation.expect_threat,
                        expect_min_action: expectation.expect_min_action,
                        expect_min_alert: expectation.expect_min_alert,
                    }),
                protection_level: report.config.protection_level,
                result: &event.result,
            })
        })
        .collect::<Vec<_>>();

    let findings = report
        .findings
        .iter()
        .map(|finding| ShadowModeFinding {
            severity: enum_key(&finding.severity),
            event_sequence: finding.event_sequence,
            request_id: format!("world_sim:{}:{}", report.label, finding.event_sequence),
            timestamp_ms: report
                .event_log
                .get(finding.event_sequence.saturating_sub(1))
                .map(|event| event.timestamp_ms)
                .unwrap_or_default(),
            message: finding.message.clone(),
        })
        .collect::<Vec<_>>();

    ShadowModeBundle::from_events(
        "world_sim",
        report.label.clone(),
        input_path.display().to_string(),
        &report.owner.id,
        report.config.protection_level,
        findings,
        events,
    )
}

fn write_json_report<T: Serialize>(
    report: &T,
    output_path: &Path,
    label: &str,
    redact_text: bool,
    omit_event_log: bool,
) {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).expect("create output directory");
        }
    }
    let json = if redact_text || omit_event_log {
        let mut value = serde_json::to_value(report).expect("serializable world sim report");
        sanitize_json_report(&mut value, redact_text, omit_event_log);
        serde_json::to_string_pretty(&value).expect("serializable sanitized world sim report")
    } else {
        serde_json::to_string_pretty(report).expect("serializable world sim report")
    };
    fs::write(output_path, json).expect("write world sim report");
    println!();
    println!("Wrote {label} to {}", output_path.display());
}

fn sanitize_json_report(value: &mut serde_json::Value, redact_text: bool, omit_event_log: bool) {
    match value {
        serde_json::Value::Object(map) => {
            if omit_event_log {
                map.remove("event_log");
            }
            for (key, value) in map {
                if redact_text && key == "text" {
                    *value = serde_json::Value::String("[redacted]".to_string());
                } else {
                    sanitize_json_report(value, redact_text, omit_event_log);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sanitize_json_report(value, redact_text, omit_event_log);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
fn redact_text_fields(value: &mut serde_json::Value) {
    sanitize_json_report(value, true, false);
}

fn write_shadow_bundle_json(bundle: &ShadowModeBundle, output_path: &Path) {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).expect("create shadow bundle directory");
        }
    }
    let json = serde_json::to_string_pretty(&bundle).expect("serializable shadow mode bundle");
    fs::write(output_path, json).expect("write shadow mode bundle");
    println!();
    println!("Wrote shadow bundle to {}", output_path.display());
}

fn write_shadow_bundle_proto(bundle: &ShadowModeBundle, output_path: &Path) {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).expect("create shadow bundle proto directory");
        }
    }
    let proto_bundle = shadow_mode_bundle_to_proto(bundle);
    fs::write(output_path, proto_bundle.encode_to_vec()).expect("write shadow mode proto bundle");
    println!();
    println!("Wrote shadow bundle protobuf to {}", output_path.display());
}

fn shadow_mode_bundle_to_proto(bundle: &ShadowModeBundle) -> proto::ShadowModeBundle {
    let kids_memory_reason_counts = kids_memory_reason_counts_from_events(&bundle.events);
    proto::ShadowModeBundle {
        schema_version: bundle.schema_version.clone(),
        generated_at_utc: bundle.generated_at_utc.clone(),
        source_kind: bundle.source_kind.clone(),
        source_label: bundle.source_label.clone(),
        source_input: bundle.source_input.clone(),
        owner_token: Some(protected_identifier_to_proto(&bundle.owner_token)),
        runtime_version: bundle.runtime_version.clone(),
        wire_package: bundle.wire_package.clone(),
        state_schema_version: bundle.state_schema_version,
        protection_level: proto_protection_level(bundle.protection_level) as i32,
        privacy: Some(shadow_mode_privacy_to_proto(&bundle.privacy)),
        summary: Some(shadow_mode_summary_to_proto(
            &bundle.summary,
            kids_memory_reason_counts,
        )),
        findings: bundle
            .findings
            .iter()
            .map(shadow_mode_finding_to_proto)
            .collect(),
        events: bundle
            .events
            .iter()
            .map(shadow_mode_event_to_proto)
            .collect(),
    }
}

const MANDATORY_KIDS_MEMORY_REASON_CODES: &[&str] = &[
    "kids.memory.grooming_progression",
    "kids.memory.sustained_sextortion",
    "kids.memory.bullying_cascade_selfharm",
    "kids.memory.sender_risk_accumulation",
    "kids.memory.new_sender_fast_escalation",
    "kids.memory.cross_conversation_repeat_offender",
    "kids.memory.victim_vulnerability_targeting",
];

fn normalized_reason_code(reason_code: &str) -> &str {
    reason_code.strip_prefix("domain.").unwrap_or(reason_code)
}

fn kids_memory_reason_codes(reason_codes: &[String]) -> Vec<String> {
    let mut filtered = Vec::new();
    for reason_code in reason_codes {
        let reason_code = normalized_reason_code(reason_code);
        if !reason_code.starts_with("kids.memory.") {
            continue;
        }
        if filtered.iter().any(|existing| existing == reason_code) {
            continue;
        }
        filtered.push(reason_code.to_string());
    }
    filtered
}

fn has_mandatory_kids_memory_reason(reason_codes: &[String]) -> bool {
    for reason_code in reason_codes {
        for mandatory in MANDATORY_KIDS_MEMORY_REASON_CODES {
            if reason_code == mandatory {
                return true;
            }
        }
    }
    false
}

fn kids_memory_explainability_to_proto(
    reason_codes: &[String],
) -> Option<proto::KidsMemoryExplainability> {
    let reason_codes = kids_memory_reason_codes(reason_codes);
    if reason_codes.is_empty() {
        return None;
    }
    Some(proto::KidsMemoryExplainability {
        reason_codes: reason_codes.clone(),
        mandatory_guardian_escalation: has_mandatory_kids_memory_reason(&reason_codes),
        conversation_risk_score: 0.0,
        sender_risk_score: 0.0,
        escalation_message_count: 0,
    })
}

fn kids_memory_reason_counts_from_events(
    events: &[aura_core::ShadowModeEvent],
) -> std::collections::HashMap<String, u64> {
    let mut counts = std::collections::HashMap::new();
    for event in events {
        let reason_codes = kids_memory_reason_codes(&event.decision.reason_codes);
        for reason_code in reason_codes {
            let entry = counts.entry(reason_code).or_insert(0u64);
            *entry = (*entry).saturating_add(1);
        }
    }
    counts
}

fn protected_identifier_to_proto(
    identifier: &aura_core::ProtectedIdentifier,
) -> proto::ProtectedIdentifier {
    proto::ProtectedIdentifier {
        token: identifier.token.clone(),
        scheme: identifier.scheme.clone(),
    }
}

fn audit_threat_score_to_proto(score: &aura_core::AuditThreatScore) -> proto::AuditThreatScore {
    proto::AuditThreatScore {
        threat_type: proto_threat_type(score.threat_type) as i32,
        score: score.score,
    }
}

fn audit_record_to_proto(record: &aura_core::AuditRecord) -> proto::AuditRecord {
    proto::AuditRecord {
        schema_version: record.schema_version.clone(),
        event_timestamp_ms: record.event_timestamp_ms,
        runtime_version: record.runtime_version.clone(),
        wire_package: record.wire_package.clone(),
        state_schema_version: record.state_schema_version,
        protection_level: proto_protection_level(record.protection_level) as i32,
        threat_type: proto_threat_type(record.threat_type) as i32,
        primary_score: record.primary_score,
        top_threat_scores: record
            .top_threat_scores
            .iter()
            .map(audit_threat_score_to_proto)
            .collect(),
        reason_codes: record.reason_codes.clone(),
        ui_actions: record
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        parent_alert: proto_alert_priority(record.parent_alert) as i32,
        follow_ups: record
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        crisis_resources: record.crisis_resources,
        contact_trend: record
            .contact_trend
            .map(|trend| proto_behavioral_trend(trend) as i32)
            .unwrap_or(proto::BehavioralTrend::Unspecified as i32),
        contact_circle_tier: record
            .contact_circle_tier
            .map(|tier| proto_circle_tier(tier) as i32)
            .unwrap_or(proto::CircleTier::Unspecified as i32),
        request_id: record.request_id.clone(),
        sender_token: record
            .sender_token
            .as_ref()
            .map(protected_identifier_to_proto),
        conversation_token: record
            .conversation_token
            .as_ref()
            .map(protected_identifier_to_proto),
        kids_memory: kids_memory_explainability_to_proto(&record.reason_codes),
    }
}

fn shadow_mode_privacy_to_proto(
    privacy: &aura_core::ShadowModePrivacy,
) -> proto::ShadowModePrivacy {
    proto::ShadowModePrivacy {
        identifier_scheme: privacy.identifier_scheme.clone(),
        raw_text_present: privacy.raw_text_present,
        raw_identifier_fields_present: privacy.raw_identifier_fields_present,
    }
}

fn shadow_mode_summary_to_proto(
    summary: &aura_core::ShadowModeSummary,
    kids_memory_reason_counts: std::collections::HashMap<String, u64>,
) -> proto::ShadowModeSummary {
    proto::ShadowModeSummary {
        total_events: summary.total_events as u64,
        threat_events: summary.threat_events as u64,
        blocked_events: summary.blocked_events as u64,
        action_counts: summary
            .action_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value as u64))
            .collect(),
        threat_counts: summary
            .threat_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value as u64))
            .collect(),
        alert_counts: summary
            .alert_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value as u64))
            .collect(),
        finding_count: summary.finding_count as u64,
        kids_memory_reason_counts,
    }
}

fn shadow_mode_expectation_to_proto(
    expectation: &aura_core::ShadowModeExpectation,
) -> proto::ShadowModeExpectation {
    proto::ShadowModeExpectation {
        expect_threat: expectation
            .expect_threat
            .map(|threat| proto_threat_type(threat) as i32)
            .unwrap_or(proto::ThreatType::Unspecified as i32),
        expect_min_action: expectation
            .expect_min_action
            .map(|action| proto_action(action) as i32)
            .unwrap_or(proto::Action::Unspecified as i32),
        expect_min_alert: expectation
            .expect_min_alert
            .map(|alert| proto_alert_priority(alert) as i32)
            .unwrap_or(proto::AlertPriority::Unspecified as i32),
    }
}

fn shadow_mode_mirror_to_proto(mirror: &aura_core::ShadowModeMirror) -> proto::ShadowModeMirror {
    proto::ShadowModeMirror {
        would_surface_to_child: mirror.would_surface_to_child,
        would_alert_guardian: mirror.would_alert_guardian,
        would_open_review: mirror.would_open_review,
        would_block_message: mirror.would_block_message,
    }
}

fn shadow_mode_contact_summary_to_proto(
    contact: &aura_core::ShadowModeContactSummary,
) -> proto::ShadowModeContactSummary {
    proto::ShadowModeContactSummary {
        sender_token: Some(protected_identifier_to_proto(&contact.sender_token)),
        rating: contact.rating,
        trust_level: contact.trust_level,
        circle_tier: proto_circle_tier(contact.circle_tier) as i32,
        trend: proto_behavioral_trend(contact.trend) as i32,
        is_trusted: contact.is_trusted,
        is_new_contact: contact.is_new_contact,
        conversation_count: contact.conversation_count as u64,
    }
}

fn shadow_mode_decision_to_proto(
    decision: &aura_core::ShadowModeDecision,
) -> proto::ShadowModeDecision {
    proto::ShadowModeDecision {
        threat_type: proto_threat_type(decision.threat_type) as i32,
        confidence: proto_confidence(decision.confidence) as i32,
        action: proto_action(decision.action) as i32,
        score: decision.score,
        reason_codes: decision.reason_codes.clone(),
        top_threat_scores: decision
            .top_threat_scores
            .iter()
            .map(audit_threat_score_to_proto)
            .collect(),
        risk_breakdown: Some(risk_breakdown_to_proto(&decision.risk_breakdown)),
        inference: Some(inference_summary_to_proto(&decision.inference)),
        parent_alert: proto_alert_priority(decision.parent_alert) as i32,
        follow_ups: decision
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        crisis_resources: decision.crisis_resources,
        ui_actions: decision
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        contact: decision
            .contact
            .as_ref()
            .map(shadow_mode_contact_summary_to_proto),
        mirror: Some(shadow_mode_mirror_to_proto(&decision.mirror)),
        product_surface: Some(product_decision_surface_to_proto(&decision.product_surface)),
        kids_memory: kids_memory_explainability_to_proto(&decision.reason_codes),
    }
}

fn shadow_mode_finding_to_proto(
    finding: &aura_core::ShadowModeFinding,
) -> proto::ShadowModeFinding {
    proto::ShadowModeFinding {
        severity: finding.severity.clone(),
        event_sequence: finding.event_sequence as u64,
        request_id: finding.request_id.clone(),
        timestamp_ms: finding.timestamp_ms,
        message: finding.message.clone(),
    }
}

fn shadow_mode_event_to_proto(event: &aura_core::ShadowModeEvent) -> proto::ShadowModeEvent {
    proto::ShadowModeEvent {
        request_id: event.request_id.clone(),
        sequence: event.sequence as u64,
        timestamp_ms: event.timestamp_ms,
        sender_token: Some(protected_identifier_to_proto(&event.sender_token)),
        conversation_token: Some(protected_identifier_to_proto(&event.conversation_token)),
        language: event.language.clone(),
        conversation_type: proto_conversation_type(event.conversation_type) as i32,
        member_count: event.member_count,
        expectation: event
            .expectation
            .as_ref()
            .map(shadow_mode_expectation_to_proto),
        audit_record: Some(audit_record_to_proto(&event.audit_record)),
        decision: Some(shadow_mode_decision_to_proto(&event.decision)),
    }
}

fn risk_breakdown_to_proto(breakdown: &aura_core::RiskBreakdown) -> proto::RiskBreakdown {
    proto::RiskBreakdown {
        content: breakdown.content,
        conversation: breakdown.conversation,
        link: breakdown.link,
        abuse: breakdown.abuse,
    }
}

fn inference_summary_to_proto(summary: &aura_core::InferenceSummary) -> proto::InferenceSummary {
    proto::InferenceSummary {
        uncertainty: proto_uncertainty_level(summary.uncertainty) as i32,
        risk_horizon: proto_risk_horizon(summary.risk_horizon) as i32,
        escalation_likelihood_24h: summary.escalation_likelihood_24h,
        protective_factor_strength: summary.protective_factor_strength,
        latent_states: summary
            .latent_states
            .iter()
            .map(latent_state_evidence_to_proto)
            .collect(),
    }
}

fn product_decision_surface_to_proto(
    surface: &aura_core::ProductDecisionSurface,
) -> proto::ProductDecisionSurface {
    proto::ProductDecisionSurface {
        schema_version: surface.schema_version.clone(),
        rollout_mode: proto_product_rollout_mode(surface.rollout_mode) as i32,
        threat_type: proto_threat_type(surface.threat_type) as i32,
        action: proto_action(surface.action) as i32,
        score: surface.score,
        child: Some(product_child_surface_to_proto(&surface.child)),
        guardian: Some(product_guardian_surface_to_proto(&surface.guardian)),
        review: Some(product_review_surface_to_proto(&surface.review)),
        uncertainty_disposition: proto_product_uncertainty_disposition(
            surface.uncertainty_disposition,
        ) as i32,
    }
}

fn product_child_surface_to_proto(
    surface: &aura_core::ProductChildSurface,
) -> proto::ProductChildSurface {
    proto::ProductChildSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        visible: surface.visible,
        intervention: proto_product_child_intervention(surface.intervention) as i32,
        ui_actions: surface
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        reason_codes: surface.reason_codes.clone(),
    }
}

fn product_guardian_surface_to_proto(
    surface: &aura_core::ProductGuardianSurface,
) -> proto::ProductGuardianSurface {
    proto::ProductGuardianSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        notify: surface.notify,
        priority: proto_alert_priority(surface.priority) as i32,
        follow_ups: surface
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        reason_codes: surface.reason_codes.clone(),
    }
}

fn product_review_surface_to_proto(
    surface: &aura_core::ProductReviewSurface,
) -> proto::ProductReviewSurface {
    proto::ProductReviewSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        open_review: surface.open_review,
        urgency: proto_product_review_urgency(surface.urgency) as i32,
        reason_codes: surface.reason_codes.clone(),
        latent_states: surface
            .latent_states
            .iter()
            .map(|kind| proto_latent_state_kind(*kind) as i32)
            .collect(),
    }
}

fn latent_state_evidence_to_proto(
    evidence: &aura_core::LatentStateEvidence,
) -> proto::LatentStateEvidence {
    proto::LatentStateEvidence {
        kind: proto_latent_state_kind(evidence.kind) as i32,
        score: evidence.score,
        reason_codes: evidence.reason_codes.clone(),
    }
}

fn proto_protection_level(value: ProtectionLevel) -> proto::ProtectionLevel {
    match value {
        ProtectionLevel::Off => proto::ProtectionLevel::Off,
        ProtectionLevel::Low => proto::ProtectionLevel::Low,
        ProtectionLevel::Medium => proto::ProtectionLevel::Medium,
        ProtectionLevel::High => proto::ProtectionLevel::High,
    }
}

fn proto_conversation_type(value: ConversationType) -> proto::ConversationType {
    match value {
        ConversationType::Direct => proto::ConversationType::Direct,
        ConversationType::Group => proto::ConversationType::Group,
    }
}

fn proto_threat_type(value: aura_core::ThreatType) -> proto::ThreatType {
    match value {
        aura_core::ThreatType::None => proto::ThreatType::None,
        aura_core::ThreatType::Bullying => proto::ThreatType::Bullying,
        aura_core::ThreatType::Grooming => proto::ThreatType::Grooming,
        aura_core::ThreatType::Explicit => proto::ThreatType::Explicit,
        aura_core::ThreatType::Threat => proto::ThreatType::Threat,
        aura_core::ThreatType::SelfHarm => proto::ThreatType::SelfHarm,
        aura_core::ThreatType::Spam => proto::ThreatType::Spam,
        aura_core::ThreatType::Scam => proto::ThreatType::Scam,
        aura_core::ThreatType::Phishing => proto::ThreatType::Phishing,
        aura_core::ThreatType::Manipulation => proto::ThreatType::Manipulation,
        aura_core::ThreatType::Nsfw => proto::ThreatType::Nsfw,
        aura_core::ThreatType::HateSpeech => proto::ThreatType::HateSpeech,
        aura_core::ThreatType::Doxxing => proto::ThreatType::Doxxing,
        aura_core::ThreatType::PiiLeakage => proto::ThreatType::PiiLeakage,
        aura_core::ThreatType::Propaganda => proto::ThreatType::Propaganda,
        aura_core::ThreatType::OpsecViolation => proto::ThreatType::OpsecViolation,
        aura_core::ThreatType::Psyops => proto::ThreatType::Psyops,
        aura_core::ThreatType::MilitarySocialEng => proto::ThreatType::MilitarySocialEng,
        aura_core::ThreatType::CoordinateLeak => proto::ThreatType::CoordinateLeak,
    }
}

fn proto_action(value: Action) -> proto::Action {
    match value {
        Action::Allow => proto::Action::Allow,
        Action::Mark => proto::Action::Mark,
        Action::Blur => proto::Action::Blur,
        Action::Warn => proto::Action::Warn,
        Action::Block => proto::Action::Block,
    }
}

fn proto_alert_priority(value: AlertPriority) -> proto::AlertPriority {
    match value {
        AlertPriority::None => proto::AlertPriority::None,
        AlertPriority::Low => proto::AlertPriority::Low,
        AlertPriority::Medium => proto::AlertPriority::Medium,
        AlertPriority::High => proto::AlertPriority::High,
        AlertPriority::Urgent => proto::AlertPriority::Urgent,
    }
}

fn proto_confidence(value: aura_core::Confidence) -> proto::Confidence {
    match value {
        aura_core::Confidence::Low => proto::Confidence::Low,
        aura_core::Confidence::Medium => proto::Confidence::Medium,
        aura_core::Confidence::High => proto::Confidence::High,
    }
}

fn proto_follow_up_action(value: aura_core::FollowUpAction) -> proto::FollowUpAction {
    match value {
        aura_core::FollowUpAction::MonitorConversation => {
            proto::FollowUpAction::MonitorConversation
        }
        aura_core::FollowUpAction::BlockSuggested => proto::FollowUpAction::BlockSuggested,
        aura_core::FollowUpAction::ReviewContactProfile => {
            proto::FollowUpAction::ReviewContactProfile
        }
        aura_core::FollowUpAction::ReportToAuthorities => {
            proto::FollowUpAction::ReportToAuthorities
        }
    }
}

fn proto_product_rollout_mode(value: aura_core::ProductRolloutMode) -> proto::ProductRolloutMode {
    match value {
        aura_core::ProductRolloutMode::Shadow => proto::ProductRolloutMode::Shadow,
        aura_core::ProductRolloutMode::StagingPilot => proto::ProductRolloutMode::StagingPilot,
        aura_core::ProductRolloutMode::GuardianEnabled => {
            proto::ProductRolloutMode::GuardianEnabled
        }
    }
}

fn proto_product_delivery_mode(
    value: aura_core::ProductDeliveryMode,
) -> proto::ProductDeliveryMode {
    match value {
        aura_core::ProductDeliveryMode::Suppress => proto::ProductDeliveryMode::Suppress,
        aura_core::ProductDeliveryMode::MirrorOnly => proto::ProductDeliveryMode::MirrorOnly,
        aura_core::ProductDeliveryMode::Apply => proto::ProductDeliveryMode::Apply,
    }
}

fn proto_product_child_intervention(
    value: aura_core::ProductChildIntervention,
) -> proto::ProductChildIntervention {
    match value {
        aura_core::ProductChildIntervention::None => proto::ProductChildIntervention::None,
        aura_core::ProductChildIntervention::Mark => proto::ProductChildIntervention::Mark,
        aura_core::ProductChildIntervention::Blur => proto::ProductChildIntervention::Blur,
        aura_core::ProductChildIntervention::Warn => proto::ProductChildIntervention::Warn,
        aura_core::ProductChildIntervention::Block => proto::ProductChildIntervention::Block,
    }
}

fn proto_product_review_urgency(
    value: aura_core::ProductReviewUrgency,
) -> proto::ProductReviewUrgency {
    match value {
        aura_core::ProductReviewUrgency::None => proto::ProductReviewUrgency::None,
        aura_core::ProductReviewUrgency::Standard => proto::ProductReviewUrgency::Standard,
        aura_core::ProductReviewUrgency::High => proto::ProductReviewUrgency::High,
        aura_core::ProductReviewUrgency::Urgent => proto::ProductReviewUrgency::Urgent,
    }
}

fn proto_product_uncertainty_disposition(
    value: aura_core::ProductUncertaintyDisposition,
) -> proto::ProductUncertaintyDisposition {
    match value {
        aura_core::ProductUncertaintyDisposition::Normal => {
            proto::ProductUncertaintyDisposition::Normal
        }
        aura_core::ProductUncertaintyDisposition::MirrorOnly => {
            proto::ProductUncertaintyDisposition::MirrorOnly
        }
        aura_core::ProductUncertaintyDisposition::RequireReview => {
            proto::ProductUncertaintyDisposition::RequireReview
        }
        aura_core::ProductUncertaintyDisposition::GuardianPriority => {
            proto::ProductUncertaintyDisposition::GuardianPriority
        }
    }
}

fn proto_ui_action(value: aura_core::UiAction) -> proto::UiAction {
    match value {
        aura_core::UiAction::WarnBeforeSend => proto::UiAction::WarnBeforeSend,
        aura_core::UiAction::WarnBeforeDisplay => proto::UiAction::WarnBeforeDisplay,
        aura_core::UiAction::BlurUntilTap => proto::UiAction::BlurUntilTap,
        aura_core::UiAction::ConfirmBeforeOpenLink => proto::UiAction::ConfirmBeforeOpenLink,
        aura_core::UiAction::SuggestBlockContact => proto::UiAction::SuggestBlockContact,
        aura_core::UiAction::SuggestReport => proto::UiAction::SuggestReport,
        aura_core::UiAction::RestrictUnknownContact => proto::UiAction::RestrictUnknownContact,
        aura_core::UiAction::SlowDownConversation => proto::UiAction::SlowDownConversation,
        aura_core::UiAction::ShowCrisisSupport => proto::UiAction::ShowCrisisSupport,
        aura_core::UiAction::EscalateToGuardian => proto::UiAction::EscalateToGuardian,
    }
}

fn proto_circle_tier(value: aura_core::CircleTier) -> proto::CircleTier {
    match value {
        aura_core::CircleTier::Inner => proto::CircleTier::Inner,
        aura_core::CircleTier::Regular => proto::CircleTier::Regular,
        aura_core::CircleTier::Occasional => proto::CircleTier::Occasional,
        aura_core::CircleTier::New => proto::CircleTier::New,
    }
}

fn proto_behavioral_trend(value: aura_core::BehavioralTrend) -> proto::BehavioralTrend {
    match value {
        aura_core::BehavioralTrend::Stable => proto::BehavioralTrend::Stable,
        aura_core::BehavioralTrend::Improving => proto::BehavioralTrend::Improving,
        aura_core::BehavioralTrend::GradualWorsening => proto::BehavioralTrend::GradualWorsening,
        aura_core::BehavioralTrend::RapidWorsening => proto::BehavioralTrend::RapidWorsening,
        aura_core::BehavioralTrend::RoleReversal => proto::BehavioralTrend::RoleReversal,
    }
}

fn proto_uncertainty_level(value: aura_core::UncertaintyLevel) -> proto::UncertaintyLevel {
    match value {
        aura_core::UncertaintyLevel::Low => proto::UncertaintyLevel::Low,
        aura_core::UncertaintyLevel::Medium => proto::UncertaintyLevel::Medium,
        aura_core::UncertaintyLevel::High => proto::UncertaintyLevel::High,
    }
}

fn proto_risk_horizon(value: aura_core::RiskHorizon) -> proto::RiskHorizon {
    match value {
        aura_core::RiskHorizon::Unknown => proto::RiskHorizon::Unknown,
        aura_core::RiskHorizon::Immediate => proto::RiskHorizon::Immediate,
        aura_core::RiskHorizon::ShortTerm => proto::RiskHorizon::ShortTerm,
        aura_core::RiskHorizon::Sustained => proto::RiskHorizon::Sustained,
    }
}

fn proto_latent_state_kind(value: aura_core::LatentStateKind) -> proto::LatentStateKind {
    match value {
        aura_core::LatentStateKind::DependencyBuilding => {
            proto::LatentStateKind::DependencyBuilding
        }
        aura_core::LatentStateKind::IsolationPressure => proto::LatentStateKind::IsolationPressure,
        aura_core::LatentStateKind::CoerciveControl => proto::LatentStateKind::CoerciveControl,
        aura_core::LatentStateKind::Humiliation => proto::LatentStateKind::Humiliation,
        aura_core::LatentStateKind::CrisisVulnerability => {
            proto::LatentStateKind::CrisisVulnerability
        }
        aura_core::LatentStateKind::ProtectiveSupport => proto::LatentStateKind::ProtectiveSupport,
        aura_core::LatentStateKind::GroupEscalation => proto::LatentStateKind::GroupEscalation,
    }
}

fn bump_count(map: &mut BTreeMap<String, usize>, key: String) {
    *map.entry(key).or_default() += 1;
}

fn merge_counts(target: &mut BTreeMap<String, usize>, source: &BTreeMap<String, usize>) {
    for (key, value) in source {
        *target.entry(key.clone()).or_default() += *value;
    }
}

fn format_counts(map: &BTreeMap<String, usize>) -> String {
    if map.is_empty() {
        return "-".to_string();
    }
    map.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn enum_key<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .expect("serializable enum")
        .trim_matches('"')
        .to_string()
}

fn clean_expectation_violated(outcome: &EventOutcome) -> bool {
    outcome.result.is_threat() || outcome.result.action != Action::Allow
}

fn result_contains_threat(result: &AnalysisResult, expected_threat: aura_core::ThreatType) -> bool {
    result.threat_type == expected_threat
        || result
            .detected_threats
            .iter()
            .any(|(threat, _)| *threat == expected_threat)
}

fn evaluate_findings(world: &SimulationWorld, outcome: &EventOutcome) -> Vec<SimulationFinding> {
    let mut findings = Vec::new();

    if let Some(expectation) = &outcome.expectation {
        if expectation.expect_clean && clean_expectation_violated(outcome) {
            findings.push(SimulationFinding {
                severity: FindingSeverity::Warning,
                event_sequence: outcome.sequence,
                at: outcome.at.clone(),
                sender_id: outcome.sender_id.clone(),
                conversation_id: outcome.conversation_id.clone(),
                message: format!(
                    "expected clean allow but runtime returned threat='{}' action='{}'",
                    enum_key(&outcome.result.threat_type),
                    enum_key(&outcome.result.action)
                ),
            });
        }

        if let Some(expected_threat) = expectation.expect_threat {
            if !result_contains_threat(&outcome.result, expected_threat) {
                findings.push(SimulationFinding {
                    severity: FindingSeverity::Warning,
                    event_sequence: outcome.sequence,
                    at: outcome.at.clone(),
                    sender_id: outcome.sender_id.clone(),
                    conversation_id: outcome.conversation_id.clone(),
                    message: format!(
                        "expected threat '{}' but runtime returned '{}'",
                        enum_key(&expected_threat),
                        enum_key(&outcome.result.threat_type)
                    ),
                });
            }
        }

        if let Some(expected_action) = expectation.expect_min_action {
            if outcome.result.action < expected_action {
                findings.push(SimulationFinding {
                    severity: FindingSeverity::Warning,
                    event_sequence: outcome.sequence,
                    at: outcome.at.clone(),
                    sender_id: outcome.sender_id.clone(),
                    conversation_id: outcome.conversation_id.clone(),
                    message: format!(
                        "expected action >= '{}' but runtime returned '{}'",
                        enum_key(&expected_action),
                        enum_key(&outcome.result.action)
                    ),
                });
            }
        }

        if let Some(expected_alert) = expectation.expect_min_alert {
            let actual_alert = outcome
                .result
                .recommended_action
                .as_ref()
                .map(|rec| rec.parent_alert)
                .unwrap_or(AlertPriority::None);
            if actual_alert < expected_alert {
                findings.push(SimulationFinding {
                    severity: FindingSeverity::Warning,
                    event_sequence: outcome.sequence,
                    at: outcome.at.clone(),
                    sender_id: outcome.sender_id.clone(),
                    conversation_id: outcome.conversation_id.clone(),
                    message: format!(
                        "expected alert >= '{}' but runtime returned '{}'",
                        enum_key(&expected_alert),
                        enum_key(&actual_alert)
                    ),
                });
            }
        }
    }

    if outcome.sender_id == world.owner.id {
        if let Some(code) = outcome
            .result
            .reason_codes
            .iter()
            .find(|code| code.starts_with("conversation.contact."))
        {
            findings.push(SimulationFinding {
                severity: FindingSeverity::Warning,
                event_sequence: outcome.sequence,
                at: outcome.at.clone(),
                sender_id: outcome.sender_id.clone(),
                conversation_id: outcome.conversation_id.clone(),
                message: format!(
                    "owner-authored message triggered contact-risk reason code: {code}"
                ),
            });
        }
    }

    if outcome.sender_id == world.owner.id
        && outcome
            .result
            .reason_codes
            .iter()
            .any(|code| code == "conversation.timing.late_night_minor_contact")
    {
        findings.push(SimulationFinding {
            severity: FindingSeverity::Warning,
            event_sequence: outcome.sequence,
            at: outcome.at.clone(),
            sender_id: outcome.sender_id.clone(),
            conversation_id: outcome.conversation_id.clone(),
            message:
                "owner-authored message triggered 'conversation.timing.late_night_minor_contact'"
                    .to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn expect_clean_allows_clean_owner_event() {
        let world = test_world(vec![WorldEvent {
            at: "2026-01-01T12:00:00Z".to_string(),
            sender_id: "child".to_string(),
            conversation_id: "family".to_string(),
            text: "I finished homework and I am home.".to_string(),
            language: Some("en".to_string()),
            conversation_type: Some(ConversationType::Direct),
            member_count: None,
            sender_relationship: None,
            relationship_trust_source: None,
            note: None,
            expect_clean: true,
            expect_threat: None,
            expect_min_action: None,
            expect_min_alert: None,
        }]);

        let report = run_world_simulation(&world, Path::new("unit-clean.json"), 1)
            .expect("clean world should run");

        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.total_events, 1);
        assert_eq!(report.action_counts.get("allow"), Some(&1));
    }

    #[test]
    fn expect_clean_flags_risky_runtime_result() {
        let world = test_world(vec![WorldEvent {
            at: "2026-01-01T12:00:00Z".to_string(),
            sender_id: "peer".to_string(),
            conversation_id: "class_chat".to_string(),
            text: "you're pathetic, kill yourself loser".to_string(),
            language: Some("en".to_string()),
            conversation_type: Some(ConversationType::Group),
            member_count: Some(12),
            sender_relationship: None,
            relationship_trust_source: None,
            note: None,
            expect_clean: true,
            expect_threat: None,
            expect_min_action: None,
            expect_min_alert: None,
        }]);

        let report = run_world_simulation(&world, Path::new("unit-risky-clean.json"), 1)
            .expect("risky world should run");

        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(
            report.findings[0].message.contains("expected clean allow"),
            "{:?}",
            report.findings[0]
        );
    }

    #[test]
    fn actor_relationship_metadata_is_passed_to_analyzer() {
        let mut world = test_world(vec![WorldEvent {
            at: "2026-01-01T22:00:00Z".to_string(),
            sender_id: "stranger".to_string(),
            conversation_id: "stranger_dm".to_string(),
            text: "Don't tell your parents about our chats.".to_string(),
            language: Some("en".to_string()),
            conversation_type: Some(ConversationType::Direct),
            member_count: None,
            sender_relationship: None,
            relationship_trust_source: None,
            note: None,
            expect_clean: false,
            expect_threat: Some(aura_core::ThreatType::Grooming),
            expect_min_action: Some(Action::Mark),
            expect_min_alert: None,
        }]);
        world.actors.push(WorldActor {
            id: "stranger".to_string(),
            display_name: Some("Stranger".to_string()),
            trusted: false,
            sender_relationship: SenderRelationship::UnknownAdult,
            relationship_trust_source: RelationshipTrustSource::ServerReputation,
        });

        let report = run_world_simulation(&world, Path::new("unit-relationship.json"), 1)
            .expect("relationship world should run");
        let outcome = &report.event_log[0];

        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(
            outcome.sender_relationship,
            SenderRelationship::UnknownAdult
        );
        assert_eq!(
            outcome.relationship_trust_source,
            RelationshipTrustSource::ServerReputation
        );
        assert!(outcome
            .result
            .context_markers
            .contains(&"context.relationship.unknown_adult_minor".to_string()));
        assert!(outcome
            .result
            .reason_codes
            .contains(&"context.relationship.unknown_adult_minor".to_string()));
        assert_eq!(report.metrics.overall.labeled_positive_events, 1);
        assert_eq!(report.metrics.overall.true_positive_events, 1);
        assert_eq!(report.metrics.overall.positive_recall, Some(1.0));
    }

    #[test]
    fn six_month_fixture_stays_clean_with_relationship_metadata() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/world_sim_13yo_6mo.json");
        let world = load_world(&path).expect("six-month fixture should load");
        let report = run_world_simulation(&world, &path, 1).expect("six-month fixture should run");

        assert_eq!(report.label, "sofia_13_six_month_lifecycle");
        assert!(
            report.total_events >= 400,
            "fixture should keep substantial background volume: {}",
            report.total_events
        );
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(
            report
                .threat_counts
                .get("grooming")
                .copied()
                .unwrap_or_default()
                >= 8,
            "{:?}",
            report.threat_counts
        );

        let coach_loop = report
            .conversations
            .iter()
            .find(|conversation| conversation.conversation_id == "coach_parent_loop")
            .expect("fixture should include parent-visible coach loop");
        assert_eq!(
            coach_loop.threat_messages, 0,
            "verified parent-visible adult logistics should stay clean"
        );

        assert!(report.event_log.iter().any(|event| {
            event.sender_id == "max_19"
                && event.sender_relationship == SenderRelationship::UnknownAdult
                && event
                    .result
                    .context_markers
                    .contains(&"context.relationship.unknown_adult_minor".to_string())
        }));

        assert_eq!(report.metrics.overall.false_negative_events, 0);
        assert_eq!(report.metrics.overall.false_positive_events, 0);
        assert_eq!(report.metrics.overall.positive_recall, Some(1.0));
        assert_eq!(report.metrics.overall.clean_false_positive_rate, Some(0.0));
        assert!(report.metrics.by_relationship.iter().any(|slice| {
            slice.slice_id == "unknown_adult"
                && slice.counts.labeled_positive_events >= 5
                && slice.counts.positive_recall == Some(1.0)
        }));
        assert!(report.metrics.by_surface.iter().any(|slice| {
            slice.slice_id == "group"
                && slice.counts.labeled_clean_events > 100
                && slice.counts.clean_false_positive_rate == Some(0.0)
        }));
    }

    #[test]
    fn two_year_dense_fixture_passes_quality_gates() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("data/world_lifecycle_suite/sofia_13_to_15_dense_2y.json");
        let world = load_world(&path).expect("two-year dense fixture should load");
        let report =
            run_world_simulation(&world, &path, 1).expect("two-year dense fixture should run");

        assert_eq!(report.label, "sofia_13_to_15_dense_2y");
        assert!(
            world.actors.len() >= 50,
            "fixture should include many actors: {}",
            world.actors.len()
        );
        assert!(
            report.total_events >= 6_500,
            "fixture should keep dense two-year volume: {}",
            report.total_events
        );
        assert!(
            report.conversations.len() >= 20,
            "fixture should cover many conversations: {}",
            report.conversations.len()
        );
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.metrics.overall.false_negative_events, 0);
        assert_eq!(report.metrics.overall.false_positive_events, 0);
        assert_eq!(report.metrics.overall.positive_recall, Some(1.0));
        assert_eq!(report.metrics.overall.clean_false_positive_rate, Some(0.0));
        assert!(
            report
                .threat_counts
                .get("grooming")
                .copied()
                .unwrap_or_default()
                >= 10,
            "{:?}",
            report.threat_counts
        );
        assert_eq!(report.threat_counts.get("doxxing"), Some(&1));
        assert_eq!(report.threat_counts.get("phishing"), Some(&3));

        for clean_conversation_id in [
            "family_group",
            "coach_parent_loop",
            "language_club",
            "volunteer_group",
        ] {
            let conversation = report
                .conversations
                .iter()
                .find(|conversation| conversation.conversation_id == clean_conversation_id)
                .expect("clean conversation should be present");
            assert_eq!(
                conversation.threat_messages, 0,
                "{clean_conversation_id} should stay clean"
            );
        }

        assert!(report.metrics.by_relationship.iter().any(|slice| {
            slice.slice_id == "unknown_adult"
                && slice.counts.labeled_positive_events >= 10
                && slice.counts.positive_recall == Some(1.0)
        }));
        assert!(report.metrics.by_relationship.iter().any(|slice| {
            slice.slice_id == "peer"
                && slice.counts.labeled_clean_events > 2_000
                && slice.counts.clean_false_positive_rate == Some(0.0)
        }));
    }

    #[test]
    fn recruitment_pressure_fixture_passes_quality_gates() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("data/world_lifecycle_suite/kateryna_16_recruitment_pressure_9mo.json");
        let world = load_world(&path).expect("recruitment fixture should load");
        let report =
            run_world_simulation(&world, &path, 1).expect("recruitment fixture should run");

        assert_eq!(report.label, "kateryna_16_recruitment_pressure_9mo");
        assert!(
            report.total_events >= 300,
            "fixture should keep substantial recruitment pressure volume: {}",
            report.total_events
        );
        assert!(
            report.conversations.len() >= 10,
            "fixture should cover public, private, family, school, and closed-group surfaces: {}",
            report.conversations.len()
        );
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.metrics.overall.false_negative_events, 0);
        assert_eq!(report.metrics.overall.false_positive_events, 0);
        assert_eq!(report.metrics.overall.positive_recall, Some(1.0));
        assert_eq!(report.metrics.overall.clean_false_positive_rate, Some(0.0));
        assert!(
            report
                .threat_counts
                .get("grooming")
                .copied()
                .unwrap_or_default()
                >= 10,
            "{:?}",
            report.threat_counts
        );
        assert!(
            report
                .threat_counts
                .get("propaganda")
                .copied()
                .unwrap_or_default()
                >= 10,
            "{:?}",
            report.threat_counts
        );
        assert!(
            report
                .threat_counts
                .get("manipulation")
                .copied()
                .unwrap_or_default()
                >= 2,
            "{:?}",
            report.threat_counts
        );
        assert_eq!(report.threat_counts.get("phishing"), Some(&1));

        for clean_conversation_id in [
            "family_group",
            "class_10b",
            "debate_club",
            "volunteer_parent_loop",
        ] {
            let conversation = report
                .conversations
                .iter()
                .find(|conversation| conversation.conversation_id == clean_conversation_id)
                .expect("clean conversation should be present");
            assert_eq!(
                conversation.threat_messages, 0,
                "{clean_conversation_id} should stay clean"
            );
        }

        assert!(report.metrics.by_relationship.iter().any(|slice| {
            slice.slice_id == "unknown_adult"
                && slice.counts.labeled_positive_events >= 5
                && slice.counts.positive_recall == Some(1.0)
        }));
        assert!(report.metrics.by_surface.iter().any(|slice| {
            slice.slice_id == "group"
                && slice.counts.labeled_clean_events > 200
                && slice.counts.clean_false_positive_rate == Some(0.0)
        }));
    }

    #[test]
    fn adult_recruitment_fixtures_pass_quality_gates() {
        let cases = [
            (
                "olena_32_spec_service_recruitment_simple_4mo.json",
                "olena_32_spec_service_recruitment_simple_4mo",
                &[
                    ("manipulation", 1usize),
                    ("phishing", 1usize),
                    ("propaganda", 2usize),
                ][..],
                DomainMode::None,
            ),
            (
                "serhiy_24_gang_recruitment_simple_3mo.json",
                "serhiy_24_gang_recruitment_simple_3mo",
                &[
                    ("manipulation", 1usize),
                    ("phishing", 1usize),
                    ("threat", 1usize),
                ][..],
                DomainMode::None,
            ),
            (
                "andrii_36_military_fake_recruiter_simple_4mo.json",
                "andrii_36_military_fake_recruiter_simple_4mo",
                &[("military_social_eng", 4usize), ("psyops", 2usize)][..],
                DomainMode::Military,
            ),
        ];

        for (file_name, label, expected_threats, expected_domain_mode) in cases {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("data/world_lifecycle_suite")
                .join(file_name);
            let world = load_world(&path).expect("adult recruitment fixture should load");
            let report = run_world_simulation(&world, &path, 1)
                .expect("adult recruitment fixture should run");

            assert_eq!(report.label, label);
            assert_eq!(world.config.account_type, Some(AccountType::Adult));
            assert_eq!(
                world.config.domain_mode.unwrap_or(DomainMode::None),
                expected_domain_mode
            );
            assert!(
                report.total_events >= 45,
                "{label}: {}",
                report.total_events
            );
            assert!(report.findings.is_empty(), "{label}: {:?}", report.findings);
            assert_eq!(report.metrics.overall.false_negative_events, 0, "{label}");
            assert_eq!(report.metrics.overall.false_positive_events, 0, "{label}");
            assert_eq!(report.metrics.overall.positive_recall, Some(1.0), "{label}");
            assert_eq!(
                report.metrics.overall.clean_false_positive_rate,
                Some(0.0),
                "{label}"
            );

            for (threat, min_count) in expected_threats {
                assert!(
                    report
                        .threat_counts
                        .get(*threat)
                        .copied()
                        .unwrap_or_default()
                        >= *min_count,
                    "{label}: {:?}",
                    report.threat_counts
                );
            }
        }
    }

    #[test]
    fn metric_gates_report_recall_and_clean_fp_failures() {
        let metrics = MetricAccumulator {
            labeled_positive_events: 2,
            labeled_clean_events: 2,
            true_positive_events: 1,
            false_negative_events: 1,
            wrong_threat_events: 0,
            true_negative_events: 1,
            false_positive_events: 1,
        }
        .finish();
        let args = Args {
            min_labeled_recall: Some(0.75),
            max_clean_fp_rate: Some(0.25),
            ..Args::default()
        };

        let failures = metric_gate_violations(&metrics, &args);

        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("positive recall")),
            "{failures:?}"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("clean false-positive rate")),
            "{failures:?}"
        );
    }

    #[test]
    fn suite_directory_aggregates_json_worlds() {
        let dir = unique_temp_dir("suite_aggregates");
        fs::create_dir_all(&dir).expect("create temp suite dir");
        fs::write(dir.join("ignore.txt"), "not a world").expect("write ignored file");
        fs::write(dir.join("a_world.json"), suite_world_json("a_world"))
            .expect("write first world");
        fs::write(dir.join("b_world.json"), suite_world_json("b_world"))
            .expect("write second world");

        let report = run_world_suite(&dir, 1).expect("suite should run");
        fs::remove_dir_all(&dir).expect("cleanup temp suite dir");

        assert_eq!(report.total_worlds, 2);
        assert_eq!(report.total_events, 2);
        assert_eq!(report.total_findings, 0);
        assert_eq!(report.action_counts.get("allow"), Some(&2));
        assert_eq!(
            report
                .reports
                .iter()
                .map(|report| report.label.as_str())
                .collect::<Vec<_>>(),
            vec!["a_world", "b_world"]
        );
    }

    #[test]
    fn suite_directory_rejects_empty_json_set() {
        let dir = unique_temp_dir("suite_empty");
        fs::create_dir_all(&dir).expect("create temp suite dir");
        fs::write(dir.join("ignore.txt"), "not a world").expect("write ignored file");

        let err = run_world_suite(&dir, 1).expect_err("empty suite should fail");
        fs::remove_dir_all(&dir).expect("cleanup temp suite dir");

        assert!(err.contains("does not contain any JSON worlds"), "{err}");
    }

    #[test]
    fn redacted_json_report_removes_event_text() {
        let world = test_world(vec![WorldEvent {
            at: "2026-01-01T12:00:00Z".to_string(),
            sender_id: "child".to_string(),
            conversation_id: "family".to_string(),
            text: "I finished homework and I am home.".to_string(),
            language: Some("en".to_string()),
            conversation_type: Some(ConversationType::Direct),
            member_count: None,
            sender_relationship: None,
            relationship_trust_source: None,
            note: None,
            expect_clean: true,
            expect_threat: None,
            expect_min_action: None,
            expect_min_alert: None,
        }]);
        let report = run_world_simulation(&world, Path::new("unit-redacted.json"), 1)
            .expect("world should run");
        let path = unique_temp_dir("redacted_report").with_extension("json");

        write_json_report(&report, &path, "unit report", true, false);
        let json = fs::read_to_string(&path).expect("read redacted report");
        fs::remove_file(&path).expect("cleanup redacted report");

        assert!(!json.contains("I finished homework"), "{json}");
        assert!(json.contains("[redacted]"), "{json}");
    }

    #[test]
    fn redact_text_fields_recurses_into_nested_suite_reports() {
        let mut value = serde_json::json!({
            "reports": [
                {
                    "event_log": [
                        { "text": "raw nested text", "result": { "text": "raw result text" } }
                    ]
                }
            ],
            "summary": { "text": "raw summary text" }
        });

        redact_text_fields(&mut value);

        let json = serde_json::to_string(&value).expect("serialize redacted value");
        assert!(!json.contains("raw nested text"), "{json}");
        assert!(!json.contains("raw result text"), "{json}");
        assert!(!json.contains("raw summary text"), "{json}");
        assert_eq!(json.matches("[redacted]").count(), 3);
    }

    #[test]
    fn sanitized_json_report_can_omit_nested_event_logs() {
        let mut value = serde_json::json!({
            "reports": [
                {
                    "event_log": [
                        { "text": "raw nested text" }
                    ],
                    "context_store": { "timeline_count": 1 }
                }
            ],
            "event_log": [
                { "text": "raw top-level text" }
            ]
        });

        sanitize_json_report(&mut value, true, true);

        let json = serde_json::to_string(&value).expect("serialize sanitized value");
        assert!(!json.contains("event_log"), "{json}");
        assert!(!json.contains("raw nested text"), "{json}");
        assert!(!json.contains("raw top-level text"), "{json}");
        assert!(json.contains("context_store"), "{json}");
    }

    fn test_world(events: Vec<WorldEvent>) -> SimulationWorld {
        SimulationWorld {
            label: "unit_world".to_string(),
            description: None,
            owner: WorldOwner {
                id: "child".to_string(),
                display_name: "Child".to_string(),
                age: Some(13),
            },
            config: WorldConfigOverrides {
                language: Some("en".to_string()),
                account_holder_age: Some(13),
                timezone_offset_minutes: Some(0),
                ..WorldConfigOverrides::default()
            },
            actors: vec![
                WorldActor {
                    id: "child".to_string(),
                    display_name: Some("Child".to_string()),
                    trusted: false,
                    sender_relationship: SenderRelationship::Unknown,
                    relationship_trust_source: RelationshipTrustSource::Unknown,
                },
                WorldActor {
                    id: "peer".to_string(),
                    display_name: Some("Peer".to_string()),
                    trusted: false,
                    sender_relationship: SenderRelationship::Peer,
                    relationship_trust_source: RelationshipTrustSource::UserVerified,
                },
            ],
            conversations: vec![
                WorldConversation {
                    id: "family".to_string(),
                    display_name: Some("Family".to_string()),
                    conversation_type: Some(ConversationType::Direct),
                    member_count: None,
                },
                WorldConversation {
                    id: "class_chat".to_string(),
                    display_name: Some("Class Chat".to_string()),
                    conversation_type: Some(ConversationType::Group),
                    member_count: Some(12),
                },
            ],
            events,
            generated_batches: Vec::new(),
        }
    }

    fn suite_world_json(label: &str) -> String {
        format!(
            r#"{{
  "label": "{label}",
  "owner": {{
    "id": "child",
    "display_name": "Child",
    "age": 13
  }},
  "config": {{
    "language": "en",
    "account_holder_age": 13,
    "timezone_offset_minutes": 0
  }},
  "actors": [
    {{
      "id": "child",
      "display_name": "Child"
    }}
  ],
  "conversations": [
    {{
      "id": "family",
      "display_name": "Family",
      "conversation_type": "direct"
    }}
  ],
  "events": [
    {{
      "at": "2026-01-01T12:00:00Z",
      "sender_id": "child",
      "conversation_id": "family",
      "text": "I finished homework and I am home.",
      "language": "en",
      "expect_clean": true
    }}
  ]
}}"#
        )
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "aura_world_sim_{label}_{}_{}",
            std::process::id(),
            nanos
        ))
    }
}
