use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use aura_core::{
    AccountType, Action, AlertPriority, AnalysisResult, Analyzer, AuraConfig, ContactSnapshot,
    ConversationType, ProtectionLevel,
};
use aura_patterns::PatternDatabase;
use chrono::{DateTime, Duration, Utc};
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

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create output directory");
        }
        let json = serde_json::to_string_pretty(&report).expect("serializable world sim report");
        fs::write(&path, json).expect("write world sim report");
        println!();
        println!("Wrote JSON report to {}", path.display());
    }
}

#[derive(Debug, Default)]
struct Args {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    summary_only: bool,
    top_contacts: usize,
    repeat_multiplier: usize,
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
                "--summary-only" => self.summary_only = true,
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

fn print_help() {
    println!("Usage:");
    println!("  cargo run --example world_sim -p aura-core -- [options]");
    println!();
    println!("Options:");
    println!("  --input <path>         simulation world JSON (default: {DEFAULT_WORLD_PATH})");
    println!("  --output <path>        write machine-readable JSON report");
    println!("  --summary-only         skip per-event log, print only summary");
    println!("  --top-contacts <n>     number of risky contacts to print (default: 8)");
    println!("  --repeat-multiplier <n> scale generated_batches day_repeats by n (default: 1)");
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
}

#[derive(Debug, Clone, Deserialize)]
struct WorldActor {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    trusted: bool,
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
    note: Option<String>,
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
    note: Option<String>,
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
    findings: Vec<SimulationFinding>,
    event_log: Vec<EventOutcome>,
    conversations: Vec<ConversationSummary>,
    top_risky_contacts: Vec<ContactRiskSummary>,
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
    conversation_type: ConversationType,
    member_count: Option<u32>,
    note: Option<String>,
    expectation: Option<EventExpectation>,
    text: String,
    result: AnalysisResult,
}

#[derive(Debug, Clone, Serialize)]
struct EventExpectation {
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
    language: Option<String>,
    note: Option<String>,
    expectation: Option<EventExpectation>,
    text: String,
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
    config.ttl_days = world.config.ttl_days.unwrap_or(30);
    config.timezone_offset_minutes = world.config.timezone_offset_minutes.unwrap_or(120);
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
            conversation_type: event.conversation_type,
            member_count: event.member_count,
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
        language: event.language.clone(),
        note: event.note.clone(),
        expectation: expectation_from_parts(
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
                language: batch.language.clone(),
                note,
                expectation: expectation_from_parts(
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
    expect_threat: Option<aura_core::ThreatType>,
    expect_min_action: Option<Action>,
    expect_min_alert: Option<AlertPriority>,
) -> Option<EventExpectation> {
    if expect_threat.is_some() || expect_min_action.is_some() || expect_min_alert.is_some() {
        Some(EventExpectation {
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

fn bump_count(map: &mut BTreeMap<String, usize>, key: String) {
    *map.entry(key).or_default() += 1;
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

fn evaluate_findings(world: &SimulationWorld, outcome: &EventOutcome) -> Vec<SimulationFinding> {
    let mut findings = Vec::new();

    if let Some(expectation) = &outcome.expectation {
        if let Some(expected_threat) = expectation.expect_threat {
            let threat_present = outcome.result.threat_type == expected_threat
                || outcome
                    .result
                    .detected_threats
                    .iter()
                    .any(|(threat, _)| *threat == expected_threat);
            if !threat_present {
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

    if outcome.sender_id == world.owner.id
        && outcome
            .result
            .reason_codes
            .iter()
            .any(|code| code == "conversation.contact.new_risky_contact")
    {
        findings.push(SimulationFinding {
            severity: FindingSeverity::Warning,
            event_sequence: outcome.sequence,
            at: outcome.at.clone(),
            sender_id: outcome.sender_id.clone(),
            conversation_id: outcome.conversation_id.clone(),
            message: "owner-authored message triggered 'conversation.contact.new_risky_contact'"
                .to_string(),
        });
    }

    findings
}
