//! Component-side runtime hardening harness.
//!
//! This exercises the embeddable `AgentRuntime` the way a client SDK would use
//! it: initialize once per local account, process a long mixed stream, export
//! and import local state, and gate latency/detection/state growth.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use aura_agent_core::{
    AccountType, AgentRuntime, AuraConfig, ContentType, ConversationType, DomainMode, MessageInput,
    ProtectionLevel, SenderId, ThreatType,
};
use aura_patterns::PatternDatabase;
use serde::Serialize;

const BASE_TS_MS: u64 = 1_778_652_000_000;
const STEP_MS: u64 = 45_000;
const DEFAULT_SESSIONS: usize = 3;
const DEFAULT_EVENTS_PER_SESSION: usize = 90;
const DEFAULT_MIN_POSITIVE_DETECT_RATE: f64 = 0.85;
const DEFAULT_MAX_SAFE_FP_RATE: f64 = 0.05;
const DEFAULT_MAX_AVG_LATENCY_MS: f64 = 100.0;
const DEFAULT_MAX_P95_LATENCY_MS: f64 = 250.0;
const DEFAULT_MAX_STATE_DEBUG_BYTES: usize = 2_000_000;
const DEFAULT_MAX_STATE_FOOTPRINT_UNITS: usize = 20_000;
const MEMORY_REASON_PREFIXES: &[&str] = &["domain.kids.memory.", "kids.memory."];

#[derive(Debug, Clone)]
struct Args {
    profile: Option<RunProfile>,
    sessions: usize,
    events_per_session: usize,
    json: Option<PathBuf>,
    fail_on_gate: bool,
    min_positive_detect_rate: f64,
    max_safe_fp_rate: f64,
    max_avg_latency_ms: f64,
    max_p95_latency_ms: f64,
    max_state_debug_bytes: usize,
    max_state_footprint_units: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunProfile {
    Quick,
    Standard,
    Stress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum EventKind {
    Safe,
    Grooming,
    Bullying,
    Manipulation,
    PiiLeakage,
    Phishing,
    SelfHarm,
}

#[derive(Debug, Clone)]
struct SyntheticEvent {
    text: &'static str,
    kind: EventKind,
    expected_threat: Option<ThreatType>,
    sender_id: String,
    conversation_id: String,
    conversation_type: ConversationType,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeHardeningReport {
    schema_version: &'static str,
    profile: Option<String>,
    sessions: usize,
    events_per_session: usize,
    total_events: usize,
    init_ms: LatencyStats,
    analyze_ms: LatencyStats,
    throughput_per_second: f64,
    positives: DetectionStats,
    safe: SafeStats,
    memory_reason_hits: usize,
    import_roundtrips: usize,
    post_import_memory_hits: usize,
    max_state_footprint: StateFootprint,
    by_kind: BTreeMap<EventKind, KindStats>,
    gates: Vec<GateCheck>,
    passed: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct LatencyStats {
    count: usize,
    avg_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct DetectionStats {
    total: usize,
    detected: usize,
    detect_rate: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct SafeStats {
    total: usize,
    false_positive: usize,
    false_positive_rate: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct KindStats {
    events: usize,
    detected: usize,
    safe_false_positive: usize,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct StateFootprint {
    core_timelines: usize,
    core_events: usize,
    contact_profiles: usize,
    kids_conversations: usize,
    kids_snapshots: usize,
    kids_senders: usize,
    debug_bytes: usize,
    footprint_units: usize,
}

#[derive(Debug, Clone, Serialize)]
struct GateCheck {
    name: &'static str,
    actual: f64,
    threshold: f64,
    passed: bool,
}

fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            print_usage();
            std::process::exit(2);
        }
    };

    let report = run_harness(&args);
    print_report(&report);

    if let Some(path) = &args.json {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).unwrap_or_else(|error| {
                panic!(
                    "failed to create report directory {}: {error}",
                    parent.display()
                )
            });
        }
        let bytes = serde_json::to_vec_pretty(&report).expect("runtime report serializes");
        fs::write(path, bytes)
            .unwrap_or_else(|error| panic!("failed to write report {}: {error}", path.display()));
    }

    if args.fail_on_gate && !report.passed {
        std::process::exit(1);
    }
}

fn run_harness(args: &Args) -> RuntimeHardeningReport {
    let total_started = Instant::now();
    let pattern_db = PatternDatabase::default_mvp();
    let mut init_samples = Vec::with_capacity(args.sessions);
    let mut analyze_samples = Vec::with_capacity(args.sessions * args.events_per_session);
    let mut positives = DetectionStats::default();
    let mut safe = SafeStats::default();
    let mut by_kind: BTreeMap<EventKind, KindStats> = BTreeMap::new();
    let mut memory_reason_hits = 0usize;
    let mut import_roundtrips = 0usize;
    let mut post_import_memory_hits = 0usize;
    let mut max_state_footprint = StateFootprint::default();

    for session in 0..args.sessions {
        let init_started = Instant::now();
        let mut runtime = AgentRuntime::new(child_config(), &pattern_db);
        init_samples.push(init_started.elapsed().as_secs_f64() * 1000.0);

        let import_index = args.events_per_session / 2;
        let mut imported_once = false;

        for index in 0..args.events_per_session {
            if index == import_index && !imported_once {
                let core_state = runtime.export_context_state();
                let kids_state = runtime.export_kids_memory_state();
                max_state_footprint = max_footprint(
                    max_state_footprint,
                    state_footprint(&core_state, &kids_state),
                );

                let mut replacement = AgentRuntime::new(child_config(), &pattern_db);
                replacement
                    .import_context_state(core_state)
                    .expect("exported runtime context imports into fresh runtime");
                replacement.import_kids_memory_state(&kids_state);
                runtime = replacement;
                imported_once = true;
                import_roundtrips += 1;
            }

            let event = synthetic_event(session, index);
            let input = message_input(&event);
            let timestamp_ms = BASE_TS_MS
                .saturating_add(session as u64 * 24 * 60 * 60 * 1_000)
                .saturating_add(index as u64 * STEP_MS);

            let analyze_started = Instant::now();
            let result = runtime.analyze_local_with_context(&input, timestamp_ms);
            analyze_samples.push(analyze_started.elapsed().as_secs_f64() * 1000.0);

            let kind_stats = by_kind.entry(event.kind).or_default();
            kind_stats.events += 1;

            if event.expected_threat.is_some() {
                positives.total += 1;
                if detected_expected_threat(&result, event.expected_threat) {
                    positives.detected += 1;
                    kind_stats.detected += 1;
                }
            } else {
                safe.total += 1;
                if is_safe_false_positive(&result) {
                    safe.false_positive += 1;
                    kind_stats.safe_false_positive += 1;
                }
            }

            if has_kids_memory_reason(&result.reason_codes) {
                memory_reason_hits += 1;
                if imported_once && index > import_index {
                    post_import_memory_hits += 1;
                }
            }

            if index % 25 == 0 || index + 1 == args.events_per_session {
                let core_state = runtime.export_context_state();
                let kids_state = runtime.export_kids_memory_state();
                max_state_footprint = max_footprint(
                    max_state_footprint,
                    state_footprint(&core_state, &kids_state),
                );
                runtime.cleanup_context(timestamp_ms);
            }
        }
    }

    positives.detect_rate = rate(positives.detected, positives.total);
    safe.false_positive_rate = rate(safe.false_positive, safe.total);

    let elapsed_s = total_started.elapsed().as_secs_f64();
    let total_events = args.sessions * args.events_per_session;
    let mut report = RuntimeHardeningReport {
        schema_version: "aura.agent_runtime_hardening.v1",
        profile: args.profile.map(|profile| profile.as_str().to_string()),
        sessions: args.sessions,
        events_per_session: args.events_per_session,
        total_events,
        init_ms: latency_stats(init_samples),
        analyze_ms: latency_stats(analyze_samples),
        throughput_per_second: if elapsed_s > 0.0 {
            total_events as f64 / elapsed_s
        } else {
            0.0
        },
        positives,
        safe,
        memory_reason_hits,
        import_roundtrips,
        post_import_memory_hits,
        max_state_footprint,
        by_kind,
        gates: Vec::new(),
        passed: false,
    };

    report.gates = evaluate_gates(&report, args);
    report.passed = report.gates.iter().all(|gate| gate.passed);
    report
}

fn evaluate_gates(report: &RuntimeHardeningReport, args: &Args) -> Vec<GateCheck> {
    vec![
        GateCheck {
            name: "min_positive_detect_rate",
            actual: report.positives.detect_rate,
            threshold: args.min_positive_detect_rate,
            passed: report.positives.detect_rate >= args.min_positive_detect_rate,
        },
        GateCheck {
            name: "max_safe_false_positive_rate",
            actual: report.safe.false_positive_rate,
            threshold: args.max_safe_fp_rate,
            passed: report.safe.false_positive_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "max_avg_latency_ms",
            actual: report.analyze_ms.avg_ms,
            threshold: args.max_avg_latency_ms,
            passed: report.analyze_ms.avg_ms <= args.max_avg_latency_ms,
        },
        GateCheck {
            name: "max_p95_latency_ms",
            actual: report.analyze_ms.p95_ms,
            threshold: args.max_p95_latency_ms,
            passed: report.analyze_ms.p95_ms <= args.max_p95_latency_ms,
        },
        GateCheck {
            name: "max_state_debug_bytes",
            actual: report.max_state_footprint.debug_bytes as f64,
            threshold: args.max_state_debug_bytes as f64,
            passed: report.max_state_footprint.debug_bytes <= args.max_state_debug_bytes,
        },
        GateCheck {
            name: "max_state_footprint_units",
            actual: report.max_state_footprint.footprint_units as f64,
            threshold: args.max_state_footprint_units as f64,
            passed: report.max_state_footprint.footprint_units <= args.max_state_footprint_units,
        },
        GateCheck {
            name: "min_import_roundtrips",
            actual: report.import_roundtrips as f64,
            threshold: report.sessions as f64,
            passed: report.import_roundtrips >= report.sessions,
        },
        GateCheck {
            name: "min_post_import_memory_hits",
            actual: report.post_import_memory_hits as f64,
            threshold: 1.0,
            passed: report.post_import_memory_hits >= 1,
        },
    ]
}

fn synthetic_event(session: usize, index: usize) -> SyntheticEvent {
    let conv_slot = (index / 3) % 7;
    let (kind, expected_threat, text) = match index % 12 {
        0 | 5 => (
            EventKind::Grooming,
            Some(ThreatType::Grooming),
            "our little secret. don't tell your parents.",
        ),
        1 => (
            EventKind::Manipulation,
            Some(ThreatType::Manipulation),
            "if you were a real friend, you would keep this secret for me",
        ),
        2 => (
            EventKind::PiiLeakage,
            Some(ThreatType::PiiLeakage),
            "my address is 42 Maple Street and my school is North Middle",
        ),
        3 => (
            EventKind::Bullying,
            Some(ThreatType::Bullying),
            "you're worthless. nobody likes you.",
        ),
        4 => (
            EventKind::Phishing,
            Some(ThreatType::Phishing),
            "claim your free game skin now at login-verify.example and enter your password",
        ),
        8 => (
            EventKind::SelfHarm,
            Some(ThreatType::SelfHarm),
            "i'm going to hurt myself tonight and I do not feel safe alone",
        ),
        _ => (
            EventKind::Safe,
            None,
            "thanks for the homework help, see you in the group project tomorrow",
        ),
    };
    let (sender_id, conversation_id, conversation_type) = match kind {
        EventKind::Grooming | EventKind::Manipulation => (
            format!("sdk_risky_groomer_{session}"),
            format!("sdk_grooming_conv_{session}"),
            ConversationType::Direct,
        ),
        EventKind::Bullying | EventKind::SelfHarm => (
            format!("sdk_group_bully_{session}_{}", index % 3),
            format!("sdk_bullying_group_{session}"),
            ConversationType::Group,
        ),
        _ => (
            format!("sdk_sender_{session}_{}", index % 9),
            format!("sdk_conv_{session}_{conv_slot}"),
            if conv_slot.is_multiple_of(3) {
                ConversationType::Group
            } else {
                ConversationType::Direct
            },
        ),
    };

    SyntheticEvent {
        text,
        kind,
        expected_threat,
        sender_id,
        conversation_id,
        conversation_type,
    }
}

fn message_input(event: &SyntheticEvent) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(event.text.to_string()),
        image_data: None,
        sender_id: SenderId::from(event.sender_id.as_str()),
        conversation_id: event.conversation_id.as_str().into(),
        language: Some("en".to_string()),
        conversation_type: event.conversation_type,
        member_count: matches!(event.conversation_type, ConversationType::Group).then_some(8),
        server_sender_risk_hint: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    }
}

fn child_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        domain_mode: DomainMode::Kids,
        ttl_days: 30,
        ..AuraConfig::default()
    }
}

fn detected_expected_threat(
    result: &aura_agent_core::AnalysisResult,
    expected: Option<ThreatType>,
) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    if result.threat_type == expected && result.score >= 0.35 {
        return true;
    }
    result
        .detected_threats
        .iter()
        .any(|(threat, score)| *threat == expected && *score >= 0.35)
}

fn is_safe_false_positive(result: &aura_agent_core::AnalysisResult) -> bool {
    result.threat_type != ThreatType::None && result.score >= 0.50
}

fn has_kids_memory_reason(reason_codes: &[String]) -> bool {
    reason_codes.iter().any(|reason| {
        MEMORY_REASON_PREFIXES
            .iter()
            .any(|prefix| reason.starts_with(prefix))
    })
}

fn state_footprint(
    core_state: &aura_agent_core::context::tracker::TrackerWireState,
    kids_state: &aura_agent_core::aura_kids::pipeline::ExportedKidsMemoryState,
) -> StateFootprint {
    let core_events = core_state
        .timelines
        .iter()
        .map(|timeline| timeline.events.len())
        .sum::<usize>();
    let kids_snapshots = kids_state
        .conversations
        .iter()
        .map(|conversation| conversation.entries.len())
        .sum::<usize>();
    let debug_bytes = format!("{core_state:?}").len() + format!("{kids_state:?}").len();
    let contact_profiles = core_state.contact_profiler.profiles.len();
    let footprint_units = core_events
        + kids_snapshots
        + core_state.timelines.len()
        + contact_profiles
        + kids_state.conversations.len()
        + kids_state.senders.len();

    StateFootprint {
        core_timelines: core_state.timelines.len(),
        core_events,
        contact_profiles,
        kids_conversations: kids_state.conversations.len(),
        kids_snapshots,
        kids_senders: kids_state.senders.len(),
        debug_bytes,
        footprint_units,
    }
}

fn max_footprint(left: StateFootprint, right: StateFootprint) -> StateFootprint {
    if right.footprint_units > left.footprint_units {
        right
    } else {
        left
    }
}

fn latency_stats(mut samples: Vec<f64>) -> LatencyStats {
    if samples.is_empty() {
        return LatencyStats {
            count: 0,
            avg_ms: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            max_ms: 0.0,
        };
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let sum = samples.iter().sum::<f64>();
    let count = samples.len();
    LatencyStats {
        count,
        avg_ms: sum / count as f64,
        p50_ms: percentile(&samples, 0.50),
        p95_ms: percentile(&samples, 0.95),
        max_ms: *samples.last().unwrap_or(&0.0),
    }
}

fn percentile(samples: &[f64], pct: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let index = ((samples.len() - 1) as f64 * pct).round() as usize;
    samples[index.min(samples.len() - 1)]
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn print_report(report: &RuntimeHardeningReport) {
    println!("AURA agent runtime hardening");
    println!(
        "  profile={} sessions={} events_per_session={} total_events={} throughput={:.0}/s",
        report.profile.as_deref().unwrap_or("custom"),
        report.sessions,
        report.events_per_session,
        report.total_events,
        report.throughput_per_second
    );
    println!(
        "  init avg={:.2}ms p95={:.2}ms max={:.2}ms",
        report.init_ms.avg_ms, report.init_ms.p95_ms, report.init_ms.max_ms
    );
    println!(
        "  analyze avg={:.2}ms p50={:.2}ms p95={:.2}ms max={:.2}ms",
        report.analyze_ms.avg_ms,
        report.analyze_ms.p50_ms,
        report.analyze_ms.p95_ms,
        report.analyze_ms.max_ms
    );
    println!(
        "  positives={}/{} ({:.1}%) safe_fp={}/{} ({:.1}%)",
        report.positives.detected,
        report.positives.total,
        report.positives.detect_rate * 100.0,
        report.safe.false_positive,
        report.safe.total,
        report.safe.false_positive_rate * 100.0
    );
    println!(
        "  memory_reason_hits={} post_import_memory_hits={} import_roundtrips={}",
        report.memory_reason_hits, report.post_import_memory_hits, report.import_roundtrips
    );
    println!(
        "  state timelines={} events={} contacts={} kids_convs={} kids_senders={} debug_bytes={} units={}",
        report.max_state_footprint.core_timelines,
        report.max_state_footprint.core_events,
        report.max_state_footprint.contact_profiles,
        report.max_state_footprint.kids_conversations,
        report.max_state_footprint.kids_senders,
        report.max_state_footprint.debug_bytes,
        report.max_state_footprint.footprint_units
    );
    println!("  gates={}", if report.passed { "PASS" } else { "FAIL" });
    for gate in &report.gates {
        let op = if gate.name.starts_with("max_") {
            "<="
        } else {
            ">="
        };
        println!(
            "    {} actual={:.3} {} threshold={:.3} {}",
            gate.name,
            gate.actual,
            op,
            gate.threshold,
            if gate.passed { "ok" } else { "FAIL" }
        );
    }
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self::default();
        let mut iter = env::args().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--profile" => {
                    let profile = iter
                        .next()
                        .ok_or_else(|| "missing value after --profile".to_string())?;
                    args.apply_profile(RunProfile::parse(&profile)?);
                }
                "--sessions" => args.sessions = parse_next(&mut iter, "--sessions")?,
                "--events-per-session" => {
                    args.events_per_session = parse_next(&mut iter, "--events-per-session")?
                }
                "--json" => {
                    args.json = Some(PathBuf::from(
                        iter.next()
                            .ok_or_else(|| "missing value after --json".to_string())?,
                    ))
                }
                "--fail-on-gate" => args.fail_on_gate = true,
                "--min-positive-detect-rate" => {
                    args.min_positive_detect_rate =
                        parse_next(&mut iter, "--min-positive-detect-rate")?
                }
                "--max-safe-fp-rate" => {
                    args.max_safe_fp_rate = parse_next(&mut iter, "--max-safe-fp-rate")?
                }
                "--max-avg-latency-ms" => {
                    args.max_avg_latency_ms = parse_next(&mut iter, "--max-avg-latency-ms")?
                }
                "--max-p95-latency-ms" => {
                    args.max_p95_latency_ms = parse_next(&mut iter, "--max-p95-latency-ms")?
                }
                "--max-state-debug-bytes" => {
                    args.max_state_debug_bytes = parse_next(&mut iter, "--max-state-debug-bytes")?
                }
                "--max-state-footprint-units" => {
                    args.max_state_footprint_units =
                        parse_next(&mut iter, "--max-state-footprint-units")?
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        args.validate()?;
        Ok(args)
    }

    fn apply_profile(&mut self, profile: RunProfile) {
        self.profile = Some(profile);
        match profile {
            RunProfile::Quick => {
                self.sessions = 2;
                self.events_per_session = 45;
            }
            RunProfile::Standard => {
                self.sessions = 4;
                self.events_per_session = 160;
            }
            RunProfile::Stress => {
                self.sessions = 8;
                self.events_per_session = 600;
            }
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.sessions == 0 {
            return Err("--sessions must be greater than zero".to_string());
        }
        if self.events_per_session < 4 {
            return Err("--events-per-session must be at least 4".to_string());
        }
        Ok(())
    }
}

impl Default for Args {
    fn default() -> Self {
        Self {
            profile: None,
            sessions: DEFAULT_SESSIONS,
            events_per_session: DEFAULT_EVENTS_PER_SESSION,
            json: None,
            fail_on_gate: false,
            min_positive_detect_rate: DEFAULT_MIN_POSITIVE_DETECT_RATE,
            max_safe_fp_rate: DEFAULT_MAX_SAFE_FP_RATE,
            max_avg_latency_ms: DEFAULT_MAX_AVG_LATENCY_MS,
            max_p95_latency_ms: DEFAULT_MAX_P95_LATENCY_MS,
            max_state_debug_bytes: DEFAULT_MAX_STATE_DEBUG_BYTES,
            max_state_footprint_units: DEFAULT_MAX_STATE_FOOTPRINT_UNITS,
        }
    }
}

impl RunProfile {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "quick" => Ok(Self::Quick),
            "standard" => Ok(Self::Standard),
            "stress" => Ok(Self::Stress),
            other => Err(format!(
                "unknown profile {other:?}; expected quick|standard|stress"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Stress => "stress",
        }
    }
}

fn parse_next<T: std::str::FromStr>(
    iter: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> Result<T, String> {
    let value = iter
        .next()
        .ok_or_else(|| format!("missing value after {flag}"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value {value:?} for {flag}"))
}

fn print_usage() {
    println!("Usage: cargo run -p aura-agent-core --example runtime_hardening -- [options]");
    println!("  --profile <quick|standard|stress>");
    println!("  --sessions <n>");
    println!("  --events-per-session <n>");
    println!("  --json <path>");
    println!("  --fail-on-gate");
    println!("  --min-positive-detect-rate <0..1>");
    println!("  --max-safe-fp-rate <0..1>");
    println!("  --max-avg-latency-ms <ms>");
    println!("  --max-p95-latency-ms <ms>");
    println!("  --max-state-debug-bytes <bytes>");
    println!("  --max-state-footprint-units <units>");
}
