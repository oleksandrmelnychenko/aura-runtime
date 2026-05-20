//! Multi-surface community simulation.
//!
//! This runner models what a child or teen account actually sees across direct
//! messages, group chats, public post comments, and livestream comments. It is
//! intentionally between the small hand-authored `world_sim` fixtures and the
//! very large `world_200k` throughput stress test: enough volume and actors to
//! exercise contact/conversation context, but still small enough for CI-style
//! iteration and JSON artifacts.

use aura_core::{
    predicted_score_for_threat, AccountType, Action, Analyzer, AuraConfig, ContentType,
    ConversationType, MessageInput, ProtectionLevel, ThreatType,
};
use aura_patterns::PatternDatabase;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_CHILDREN: usize = 16;
const DEFAULT_EVENTS_PER_CHILD: usize = 180;
const DEFAULT_SEED: u64 = 42;
const DEFAULT_MIN_DETECT_RATE: f64 = 0.65;
const DEFAULT_MAX_SAFE_FP_RATE: f64 = 0.08;
const DEFAULT_MAX_DETECT_RATE_DROP: f64 = 0.02;
const DEFAULT_MAX_FP_RATE_RISE: f64 = 0.01;
const DEFAULT_HISTORY_WINDOW: usize = 20;
const BASE_TS_MS: u64 = 1_778_652_000_000;
const ENV_PREFIX: &str = "AURA_COMMUNITY";
const COMMON_PREFIX: &str = "AURA_STRESS";
const MAX_SEED_MATRIX: usize = 32;
const REQUIRED_POSITIVE_KIND_LABELS: &[&str] = &[
    "grooming",
    "bullying",
    "manipulation",
    "self_harm",
    "phishing",
    "pii_leakage",
];
const REQUIRED_SURFACE_LABELS: &[&str] = &[
    "direct_message",
    "group_chat",
    "public_comment",
    "livestream_comment",
];
const REQUIRED_SCENARIO_LABELS: &[&str] = &[
    "ambient",
    "trusted_adult_support",
    "slow_trust_grooming",
    "surface_hop_grooming",
    "cross_child_repeat_offender",
    "pile_on_bullying",
    "coercive_manipulation",
    "self_harm_after_bullying",
    "phishing_blast",
    "pii_after_trust",
];
const SERVER_HINTED_LABELS: &[&str] = &["low", "medium", "high"];
const EMOJI_PADDING_TOKENS: &[&str] = &["🎮", "✨", "💬", "🔥", "🫶", "🙂"];

#[derive(Debug, Clone)]
struct Args {
    profile: Option<RunProfile>,
    children: usize,
    events_per_child: usize,
    seed: u64,
    seeds: Vec<u64>,
    jobs: usize,
    text_variants: Vec<TextVariant>,
    json: Option<PathBuf>,
    baseline_json: Option<PathBuf>,
    history_ndjson: Option<PathBuf>,
    history_window: usize,
    history_gate: bool,
    fail_on_gate: bool,
    min_detect_rate: f64,
    max_safe_fp_rate: f64,
    max_detect_rate_drop: f64,
    max_fp_rate_rise: f64,
    max_elapsed_ms: Option<u128>,
    verbose: bool,
}

impl Args {
    fn from_env() -> Result<Self, String> {
        let mut args = Self::default_values();

        if let Some(profile) = env_profile("PROFILE")? {
            apply_profile_defaults(&mut args, profile);
        }
        if let Some(children) = env_usize("CHILDREN") {
            args.children = children;
        }
        if let Some(events_per_child) = env_usize("EVENTS_PER_CHILD") {
            args.events_per_child = events_per_child;
        }
        if let Some(seed) = env_u64("SEED") {
            args.seed = seed;
            args.seeds = vec![seed];
        }
        if let Some(seeds) = env_seed_list("SEEDS")? {
            args.seed = seeds[0];
            args.seeds = seeds;
        }
        if let Some(jobs) = env_usize("JOBS") {
            args.jobs = jobs;
        }
        if env_bool("ADVERSARIAL").unwrap_or(false) {
            args.text_variants = TextVariant::adversarial_suite();
        }
        if let Some(text_variants) = env_text_variant_list("TEXT_VARIANTS")? {
            args.text_variants = text_variants;
        }
        if let Some(path) = env_path("JSON") {
            args.json = Some(path);
        }
        if let Some(path) = env_path("BASELINE_JSON") {
            args.baseline_json = Some(path);
        }
        if let Some(path) = env_path("HISTORY_NDJSON") {
            args.history_ndjson = Some(path);
        }
        if let Some(history_window) = env_usize("HISTORY_WINDOW") {
            args.history_window = history_window;
        }
        if let Some(history_gate) = env_bool("HISTORY_GATE") {
            args.history_gate = history_gate;
        }
        if let Some(fail_on_gate) = env_bool("FAIL_ON_GATE") {
            args.fail_on_gate = fail_on_gate;
        }
        if let Some(min_detect_rate) = env_rate("MIN_DETECT_RATE") {
            args.min_detect_rate = min_detect_rate;
        }
        if let Some(max_safe_fp_rate) = env_rate("MAX_SAFE_FP_RATE") {
            args.max_safe_fp_rate = max_safe_fp_rate;
        }
        if let Some(max_detect_rate_drop) = env_rate("MAX_DETECT_RATE_DROP") {
            args.max_detect_rate_drop = max_detect_rate_drop;
        }
        if let Some(max_fp_rate_rise) = env_rate("MAX_FP_RATE_RISE") {
            args.max_fp_rate_rise = max_fp_rate_rise;
        }
        if let Some(max_elapsed_ms) = env_u128("MAX_ELAPSED_MS") {
            args.max_elapsed_ms = Some(max_elapsed_ms);
        }
        if let Some(verbose) = env_bool("VERBOSE") {
            args.verbose = verbose;
        }

        Ok(args)
    }

    fn default_values() -> Self {
        Self {
            profile: None,
            children: DEFAULT_CHILDREN,
            events_per_child: DEFAULT_EVENTS_PER_CHILD,
            seed: DEFAULT_SEED,
            seeds: vec![DEFAULT_SEED],
            jobs: 0,
            text_variants: vec![TextVariant::Clean],
            json: None,
            baseline_json: None,
            history_ndjson: None,
            history_window: DEFAULT_HISTORY_WINDOW,
            history_gate: false,
            fail_on_gate: false,
            min_detect_rate: DEFAULT_MIN_DETECT_RATE,
            max_safe_fp_rate: DEFAULT_MAX_SAFE_FP_RATE,
            max_detect_rate_drop: DEFAULT_MAX_DETECT_RATE_DROP,
            max_fp_rate_rise: DEFAULT_MAX_FP_RATE_RISE,
            max_elapsed_ms: None,
            verbose: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RunProfile {
    Quick,
    Ci,
    Nightly,
}

impl RunProfile {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "quick" | "smoke" => Ok(Self::Quick),
            "ci" => Ok(Self::Ci),
            "nightly" | "holdout" => Ok(Self::Nightly),
            other => Err(format!(
                "unknown profile: {other}; expected quick, ci, or nightly"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Ci => "ci",
            Self::Nightly => "nightly",
        }
    }
}

#[derive(Debug, Clone)]
struct ChildProfile {
    id: String,
    display_name: String,
    age: u8,
    language: &'static str,
    trusted_family: String,
    peers: Vec<String>,
    groomer: String,
    manipulator: String,
    bully_pack: Vec<String>,
    spammer: String,
}

#[derive(Debug, Default)]
struct ChildTrajectory {
    grooming_stage: usize,
    bullying_stage: usize,
    manipulation_stage: usize,
    selfharm_stage: usize,
    phishing_stage: usize,
    pii_stage: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum Surface {
    DirectMessage,
    GroupChat,
    PublicComment,
    LivestreamComment,
}

impl Surface {
    fn label(self) -> &'static str {
        match self {
            Surface::DirectMessage => "direct_message",
            Surface::GroupChat => "group_chat",
            Surface::PublicComment => "public_comment",
            Surface::LivestreamComment => "livestream_comment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum EventKind {
    Safe,
    SupportSafe,
    MildConflict,
    Grooming,
    Bullying,
    Manipulation,
    SelfHarm,
    Phishing,
    PiiLeakage,
}

impl EventKind {
    fn label(self) -> &'static str {
        match self {
            EventKind::Safe => "safe",
            EventKind::SupportSafe => "support_safe",
            EventKind::MildConflict => "mild_conflict",
            EventKind::Grooming => "grooming",
            EventKind::Bullying => "bullying",
            EventKind::Manipulation => "manipulation",
            EventKind::SelfHarm => "self_harm",
            EventKind::Phishing => "phishing",
            EventKind::PiiLeakage => "pii_leakage",
        }
    }

    fn expected_threat(self) -> Option<ThreatType> {
        match self {
            EventKind::Safe | EventKind::SupportSafe | EventKind::MildConflict => None,
            EventKind::Grooming => Some(ThreatType::Grooming),
            EventKind::Bullying => Some(ThreatType::Bullying),
            EventKind::Manipulation => Some(ThreatType::Manipulation),
            EventKind::SelfHarm => Some(ThreatType::SelfHarm),
            EventKind::Phishing => Some(ThreatType::Phishing),
            EventKind::PiiLeakage => Some(ThreatType::PiiLeakage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioKind {
    Ambient,
    TrustedAdultSupport,
    SlowTrustGrooming,
    SurfaceHopGrooming,
    CrossChildRepeatOffender,
    PileOnBullying,
    CoerciveManipulation,
    SelfHarmAfterBullying,
    PhishingBlast,
    PiiAfterTrust,
}

impl ScenarioKind {
    fn label(self) -> &'static str {
        match self {
            Self::Ambient => "ambient",
            Self::TrustedAdultSupport => "trusted_adult_support",
            Self::SlowTrustGrooming => "slow_trust_grooming",
            Self::SurfaceHopGrooming => "surface_hop_grooming",
            Self::CrossChildRepeatOffender => "cross_child_repeat_offender",
            Self::PileOnBullying => "pile_on_bullying",
            Self::CoerciveManipulation => "coercive_manipulation",
            Self::SelfHarmAfterBullying => "self_harm_after_bullying",
            Self::PhishingBlast => "phishing_blast",
            Self::PiiAfterTrust => "pii_after_trust",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum TextVariant {
    Clean,
    Zwsp,
    EmojiPadding,
    Leetspeak,
    TypoDrop,
    TypoSwap,
    PunctStrip,
    Spongebob,
}

impl TextVariant {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "clean" | "none" => Ok(Self::Clean),
            "zwsp" | "zero_width" | "zero_width_space" => Ok(Self::Zwsp),
            "emoji" | "emoji_padding" => Ok(Self::EmojiPadding),
            "leet" | "leetspeak" => Ok(Self::Leetspeak),
            "typo_drop" | "drop" => Ok(Self::TypoDrop),
            "typo_swap" | "swap" => Ok(Self::TypoSwap),
            "punct_strip" | "punctuation_strip" | "strip_punct" => Ok(Self::PunctStrip),
            "spongebob" | "mixed_case" => Ok(Self::Spongebob),
            other => Err(format!(
                "unknown text variant: {other}; expected clean, zwsp, emoji_padding, leetspeak, typo_drop, typo_swap, punct_strip, or spongebob"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Zwsp => "zwsp",
            Self::EmojiPadding => "emoji_padding",
            Self::Leetspeak => "leetspeak",
            Self::TypoDrop => "typo_drop",
            Self::TypoSwap => "typo_swap",
            Self::PunctStrip => "punct_strip",
            Self::Spongebob => "spongebob",
        }
    }

    fn quick_suite() -> Vec<Self> {
        vec![
            Self::Clean,
            Self::Zwsp,
            Self::EmojiPadding,
            Self::Leetspeak,
            Self::TypoDrop,
        ]
    }

    fn adversarial_suite() -> Vec<Self> {
        vec![
            Self::Clean,
            Self::Zwsp,
            Self::EmojiPadding,
            Self::Leetspeak,
            Self::TypoDrop,
            Self::TypoSwap,
            Self::PunctStrip,
            Self::Spongebob,
        ]
    }
}

#[derive(Debug, Clone)]
struct SimEvent {
    sequence: usize,
    child_id: String,
    child_language: &'static str,
    timestamp_ms: u64,
    surface: Surface,
    kind: EventKind,
    scenario: ScenarioKind,
    text_variant: TextVariant,
    expected_threat: Option<ThreatType>,
    sender_id: String,
    conversation_id: String,
    conversation_type: ConversationType,
    member_count: Option<u32>,
    server_sender_risk_hint: Option<f32>,
    text: String,
}

#[derive(Debug, Default, Clone, Serialize)]
struct MetricCounts {
    events: usize,
    positives: usize,
    positives_detected: usize,
    negatives: usize,
    false_positives: usize,
    wrong_threat_positives: usize,
    detect_rate: f64,
    fp_rate: f64,
}

impl MetricCounts {
    fn record(
        &mut self,
        expected_threat: Option<ThreatType>,
        expected_detected: bool,
        wrong_threat_positive: bool,
        false_positive: bool,
    ) {
        self.events += 1;
        if expected_threat.is_some() {
            self.positives += 1;
            if expected_detected {
                self.positives_detected += 1;
            }
            if wrong_threat_positive {
                self.wrong_threat_positives += 1;
            }
        } else {
            self.negatives += 1;
            if false_positive {
                self.false_positives += 1;
            }
        }
        self.recompute();
    }

    fn recompute(&mut self) {
        self.detect_rate = if self.positives == 0 {
            0.0
        } else {
            self.positives_detected as f64 / self.positives as f64
        };
        self.fp_rate = if self.negatives == 0 {
            0.0
        } else {
            self.false_positives as f64 / self.negatives as f64
        };
    }

    fn merge(&mut self, other: &MetricCounts) {
        self.events += other.events;
        self.positives += other.positives;
        self.positives_detected += other.positives_detected;
        self.negatives += other.negatives;
        self.false_positives += other.false_positives;
        self.wrong_threat_positives += other.wrong_threat_positives;
        self.recompute();
    }
}

#[derive(Debug, Serialize)]
struct MetricRow {
    name: String,
    counts: MetricCounts,
}

#[derive(Debug, Default, Clone, Serialize)]
struct SenderRiskRow {
    sender_id: String,
    events: usize,
    positives: usize,
    positives_detected: usize,
    false_positives: usize,
    threat_events: usize,
    max_score: f32,
    surfaces: BTreeMap<String, usize>,
    threats: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
struct Finding {
    kind: String,
    sequence: usize,
    child_id: String,
    surface: Surface,
    event_kind: EventKind,
    scenario: ScenarioKind,
    text_variant: TextVariant,
    server_sender_risk_hint: Option<f32>,
    expected_threat: Option<ThreatType>,
    detected_threat: ThreatType,
    action: Action,
    score: f32,
    expected_score: Option<f32>,
    expected_threshold: Option<f32>,
    detected_score: f32,
    reason_codes: Vec<String>,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
struct GateCheck {
    name: String,
    actual: f64,
    threshold: f64,
    comparison: String,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct GateReport {
    passed: bool,
    fail_on_gate: bool,
    checks: Vec<GateCheck>,
}

#[derive(Debug, Clone, Serialize)]
struct SliceBaselineDelta {
    name: String,
    baseline_rate: f64,
    current_rate: f64,
    delta: f64,
}

#[derive(Debug, Clone, Serialize)]
struct BaselineComparison {
    path: String,
    schema_version: Option<String>,
    baseline_total_events: Option<usize>,
    baseline_detect_rate: f64,
    current_detect_rate: f64,
    detect_rate_drop: f64,
    max_detect_rate_drop: f64,
    baseline_fp_rate: f64,
    current_fp_rate: f64,
    fp_rate_rise: f64,
    max_fp_rate_rise: f64,
    worst_event_kind_detect_drop: Option<SliceBaselineDelta>,
    worst_surface_fp_rate_rise: Option<SliceBaselineDelta>,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct HistoryRunSummary {
    schema_version: Option<String>,
    generated_at_unix_ms: Option<u128>,
    profile: Option<String>,
    total_events: usize,
    detect_rate: f64,
    fp_rate: f64,
    finding_count: usize,
    gates_passed: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct HistorySummary {
    path: String,
    window_size: usize,
    gate_enabled: bool,
    gate_passed: Option<bool>,
    max_detect_rate_drop: f64,
    max_fp_rate_rise: f64,
    loaded_runs: usize,
    avg_detect_rate: f64,
    avg_fp_rate: f64,
    min_detect_rate: f64,
    max_fp_rate: f64,
    current_detect_rate: f64,
    current_fp_rate: f64,
    current_vs_latest_detect_delta: Option<f64>,
    current_vs_latest_fp_delta: Option<f64>,
    current_vs_window_avg_detect_delta: Option<f64>,
    current_vs_window_avg_fp_delta: Option<f64>,
    recent_gate_failures: usize,
    recent_runs: Vec<HistoryRunSummary>,
}

#[derive(Debug, Serialize)]
struct CommunitySimReport {
    schema_version: &'static str,
    generated_at_unix_ms: u128,
    profile: Option<RunProfile>,
    seed: u64,
    children: usize,
    events_per_child: usize,
    text_variants: Vec<TextVariant>,
    total_events: usize,
    elapsed_ms: u128,
    events_per_second: f64,
    total: MetricCounts,
    by_surface: Vec<MetricRow>,
    by_kind: Vec<MetricRow>,
    by_scenario: Vec<MetricRow>,
    by_text_variant: Vec<MetricRow>,
    by_server_hint: Vec<MetricRow>,
    by_language: Vec<MetricRow>,
    by_expected_threat: Vec<MetricRow>,
    action_counts: BTreeMap<String, usize>,
    detected_threat_counts: BTreeMap<String, usize>,
    top_senders: Vec<SenderRiskRow>,
    findings: Vec<Finding>,
    baseline: Option<BaselineComparison>,
    history: Option<HistorySummary>,
    gates: GateReport,
}

#[derive(Debug, Clone, Serialize)]
struct SeedMatrixRow {
    seed: u64,
    total_events: usize,
    elapsed_ms: u128,
    events_per_second: f64,
    positives: usize,
    positives_detected: usize,
    detect_rate: f64,
    negatives: usize,
    false_positives: usize,
    fp_rate: f64,
    wrong_threat_positives: usize,
    finding_count: usize,
    gates_passed: bool,
}

#[derive(Debug, Serialize)]
struct MatrixFinding {
    seed: u64,
    finding: Finding,
}

#[derive(Debug, Serialize)]
struct CommunityMatrixReport {
    schema_version: &'static str,
    generated_at_unix_ms: u128,
    profile: Option<RunProfile>,
    seeds: Vec<u64>,
    jobs: usize,
    children: usize,
    events_per_child: usize,
    text_variants: Vec<TextVariant>,
    total_events: usize,
    elapsed_ms: u128,
    events_per_second: f64,
    total: MetricCounts,
    by_surface: Vec<MetricRow>,
    by_kind: Vec<MetricRow>,
    by_scenario: Vec<MetricRow>,
    by_text_variant: Vec<MetricRow>,
    by_server_hint: Vec<MetricRow>,
    by_language: Vec<MetricRow>,
    by_expected_threat: Vec<MetricRow>,
    seed_reports: Vec<SeedMatrixRow>,
    worst_detect_seed: Option<SeedMatrixRow>,
    worst_fp_seed: Option<SeedMatrixRow>,
    findings: Vec<MatrixFinding>,
    baseline: Option<BaselineComparison>,
    history: Option<HistorySummary>,
    gates: GateReport,
}

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        lo + (self.next_u64() as usize % (hi - lo))
    }
}

#[derive(Debug, Default)]
struct ServerReputationAggregator {
    senders: HashMap<String, ServerSenderReputation>,
}

#[derive(Debug, Default)]
struct ServerSenderReputation {
    telemetry_events: usize,
    medium_or_high_confidence_events: usize,
    high_confidence_events: usize,
    protected_accounts: BTreeSet<String>,
    surfaces: BTreeSet<&'static str>,
    threats: BTreeMap<String, usize>,
    actions: BTreeMap<String, usize>,
    last_timestamp_hour: u64,
}

#[derive(Debug, Clone)]
struct ClientSafetyTelemetryEvent {
    sender_token: String,
    protected_account_token: String,
    surface: &'static str,
    threat_type: ThreatType,
    severity: TelemetrySeverityBucket,
    confidence: TelemetryConfidenceBucket,
    timestamp_hour: u64,
    action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelemetrySeverityBucket {
    Low,
    Medium,
    High,
    Critical,
}

impl TelemetrySeverityBucket {
    fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TelemetryConfidenceBucket {
    Low,
    Medium,
    High,
}

impl TelemetryConfidenceBucket {
    fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl ServerReputationAggregator {
    fn hint(&self, sender_id: &str) -> Option<f32> {
        let sender = self.senders.get(sender_id)?;
        if sender.telemetry_events == 0 {
            return None;
        }

        let cross_child = sender.protected_accounts.len() >= 2;
        let cross_surface = sender.surfaces.len() >= 2;
        let score = if sender.high_confidence_events >= 3 && cross_child {
            0.90
        } else if sender.medium_or_high_confidence_events >= 2 && (cross_child || cross_surface) {
            0.72
        } else if sender.high_confidence_events >= 1 && cross_surface {
            0.55
        } else {
            return None;
        };
        Some(score)
    }

    fn record(&mut self, telemetry: ClientSafetyTelemetryEvent) {
        let sender = self.senders.entry(telemetry.sender_token).or_default();
        sender.telemetry_events += 1;
        if telemetry.confidence >= TelemetryConfidenceBucket::Medium {
            sender.medium_or_high_confidence_events += 1;
        }
        if telemetry.confidence == TelemetryConfidenceBucket::High {
            sender.high_confidence_events += 1;
        }
        sender
            .protected_accounts
            .insert(telemetry.protected_account_token);
        sender.surfaces.insert(telemetry.surface);
        sender.last_timestamp_hour = sender.last_timestamp_hour.max(telemetry.timestamp_hour);
        *sender
            .threats
            .entry(format!("{:?}", telemetry.threat_type))
            .or_default() += 1;
        *sender
            .actions
            .entry(format!("{:?}", telemetry.action))
            .or_default() += 1;
        *sender
            .actions
            .entry(format!("severity.{}", telemetry.severity.label()))
            .or_default() += 1;
        *sender
            .actions
            .entry(format!("confidence.{}", telemetry.confidence.label()))
            .or_default() += 1;
    }
}

fn main() {
    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("error: {err}");
        print_help();
        std::process::exit(2);
    });

    if args.seeds.len() > 1 {
        let mut report = run_seed_matrix(&args);
        apply_baseline_to_matrix_report(&mut report, &args).unwrap_or_else(|err| {
            eprintln!("failed to compare baseline: {err}");
            std::process::exit(2);
        });
        apply_history_to_matrix_report(&mut report, &args).unwrap_or_else(|err| {
            eprintln!("failed to summarize history: {err}");
            std::process::exit(2);
        });
        print_matrix_report(&report);

        write_matrix_report_outputs(&args, &report).unwrap_or_else(|err| {
            eprintln!("failed to write matrix report outputs: {err}");
            std::process::exit(2);
        });

        if args.fail_on_gate && !report.gates.passed {
            eprintln!("community surface seed matrix gates failed");
            std::process::exit(1);
        }
    } else {
        let mut report = run_simulation(&args);
        apply_baseline_to_sim_report(&mut report, &args).unwrap_or_else(|err| {
            eprintln!("failed to compare baseline: {err}");
            std::process::exit(2);
        });
        apply_history_to_sim_report(&mut report, &args).unwrap_or_else(|err| {
            eprintln!("failed to summarize history: {err}");
            std::process::exit(2);
        });
        print_report(&report);

        write_report_outputs(&args, &report).unwrap_or_else(|err| {
            eprintln!("failed to write report outputs: {err}");
            std::process::exit(2);
        });

        if args.fail_on_gate && !report.gates.passed {
            eprintln!("community surface simulation gates failed");
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::from_env()?;
    let mut iter = env::args().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--profile" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing value for --profile".to_string())?;
                let profile = RunProfile::parse(&raw)?;
                apply_profile_defaults(&mut args, profile);
            }
            "--children" => {
                args.children = parse_next(&mut iter, "--children")?;
                if args.children == 0 {
                    return Err("--children must be >= 1".to_string());
                }
            }
            "--events-per-child" => {
                args.events_per_child = parse_next(&mut iter, "--events-per-child")?;
                if args.events_per_child == 0 {
                    return Err("--events-per-child must be >= 1".to_string());
                }
            }
            "--seed" => {
                args.seed = parse_next(&mut iter, "--seed")?;
                args.seeds = vec![args.seed];
            }
            "--seeds" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing value for --seeds".to_string())?;
                args.seeds = parse_seed_list(&raw)?;
                args.seed = args.seeds[0];
            }
            "--json" => {
                let path = iter
                    .next()
                    .ok_or_else(|| "missing value for --json".to_string())?;
                args.json = Some(PathBuf::from(path));
            }
            "--baseline-json" => {
                let path = iter
                    .next()
                    .ok_or_else(|| "missing value for --baseline-json".to_string())?;
                args.baseline_json = Some(PathBuf::from(path));
            }
            "--history-ndjson" => {
                let path = iter
                    .next()
                    .ok_or_else(|| "missing value for --history-ndjson".to_string())?;
                args.history_ndjson = Some(PathBuf::from(path));
            }
            "--history-window" => args.history_window = parse_next(&mut iter, "--history-window")?,
            "--history-gate" => args.history_gate = true,
            "--fail-on-gate" => args.fail_on_gate = true,
            "--min-detect-rate" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing value for --min-detect-rate".to_string())?;
                args.min_detect_rate = parse_rate(&raw)?;
            }
            "--max-safe-fp-rate" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing value for --max-safe-fp-rate".to_string())?;
                args.max_safe_fp_rate = parse_rate(&raw)?;
            }
            "--max-detect-rate-drop" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing value for --max-detect-rate-drop".to_string())?;
                args.max_detect_rate_drop = parse_rate(&raw)?;
            }
            "--max-fp-rate-rise" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing value for --max-fp-rate-rise".to_string())?;
                args.max_fp_rate_rise = parse_rate(&raw)?;
            }
            "--max-elapsed-ms" => {
                args.max_elapsed_ms = Some(parse_next(&mut iter, "--max-elapsed-ms")?)
            }
            "--jobs" => args.jobs = parse_next(&mut iter, "--jobs")?,
            "--text-variants" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing value for --text-variants".to_string())?;
                args.text_variants = parse_text_variant_list(&raw)?;
            }
            "--adversarial" => args.text_variants = TextVariant::adversarial_suite(),
            "--verbose" | "-v" => args.verbose = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    if args.seeds.is_empty() {
        return Err("at least one seed is required".to_string());
    }
    if args.children == 0 {
        return Err("--children must be >= 1".to_string());
    }
    if args.events_per_child == 0 {
        return Err("--events-per-child must be >= 1".to_string());
    }
    if args.history_window == 0 {
        return Err("--history-window must be >= 1".to_string());
    }
    if args.seeds.len() > MAX_SEED_MATRIX {
        return Err(format!(
            "seed matrix is capped at {MAX_SEED_MATRIX} seeds; got {}",
            args.seeds.len()
        ));
    }
    if args.text_variants.is_empty() {
        return Err("at least one text variant is required".to_string());
    }
    args.seed = args.seeds[0];
    args.jobs = normalize_jobs(args.jobs, args.seeds.len());

    Ok(args)
}

fn apply_profile_defaults(args: &mut Args, profile: RunProfile) {
    args.profile = Some(profile);
    args.jobs = 0;
    args.max_elapsed_ms = None;
    args.verbose = false;

    match profile {
        RunProfile::Quick => {
            args.children = 3;
            args.events_per_child = 45;
            args.seeds = vec![42, 43];
            args.seed = args.seeds[0];
            args.text_variants = TextVariant::quick_suite();
            args.fail_on_gate = false;
            args.min_detect_rate = DEFAULT_MIN_DETECT_RATE;
            args.max_safe_fp_rate = DEFAULT_MAX_SAFE_FP_RATE;
        }
        RunProfile::Ci => {
            args.children = DEFAULT_CHILDREN;
            args.events_per_child = DEFAULT_EVENTS_PER_CHILD;
            args.seeds = vec![42, 43];
            args.seed = args.seeds[0];
            args.text_variants = TextVariant::adversarial_suite();
            args.fail_on_gate = true;
            args.min_detect_rate = DEFAULT_MIN_DETECT_RATE;
            args.max_safe_fp_rate = DEFAULT_MAX_SAFE_FP_RATE;
        }
        RunProfile::Nightly => {
            args.children = DEFAULT_CHILDREN;
            args.events_per_child = DEFAULT_EVENTS_PER_CHILD;
            args.seeds = (42..50).collect();
            args.seed = args.seeds[0];
            args.text_variants = TextVariant::adversarial_suite();
            args.fail_on_gate = true;
            args.min_detect_rate = DEFAULT_MIN_DETECT_RATE;
            args.max_safe_fp_rate = DEFAULT_MAX_SAFE_FP_RATE;
        }
    }
}

fn parse_next<T>(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    let raw = iter
        .next()
        .ok_or_else(|| format!("missing value for {flag}"))?;
    raw.parse::<T>()
        .map_err(|_| format!("invalid value for {flag}: {raw}"))
}

fn parse_rate(raw: &str) -> Result<f64, String> {
    let value = raw
        .parse::<f64>()
        .map_err(|_| format!("invalid rate: {raw}"))?;
    Ok(if value > 1.0 { value / 100.0 } else { value })
}

fn parse_seed_list(raw: &str) -> Result<Vec<u64>, String> {
    let mut seeds = Vec::new();
    for token in raw
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        parse_seed_token(token, &mut seeds)?;
    }

    seeds.sort_unstable();
    seeds.dedup();

    if seeds.is_empty() {
        return Err("seed list must contain at least one seed".to_string());
    }
    if seeds.len() > MAX_SEED_MATRIX {
        return Err(format!(
            "seed matrix is capped at {MAX_SEED_MATRIX} seeds; got {}",
            seeds.len()
        ));
    }
    Ok(seeds)
}

fn parse_text_variant_list(raw: &str) -> Result<Vec<TextVariant>, String> {
    let mut variants = Vec::new();
    for token in raw
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        match token.to_ascii_lowercase().as_str() {
            "all" | "adversarial" => {
                push_unique_text_variants(&mut variants, TextVariant::adversarial_suite());
            }
            "quick" => push_unique_text_variants(&mut variants, TextVariant::quick_suite()),
            _ => push_unique_text_variant(&mut variants, TextVariant::parse(token)?),
        }
    }

    if variants.is_empty() {
        return Err("text variant list must contain at least one variant".to_string());
    }
    Ok(variants)
}

fn push_unique_text_variants(target: &mut Vec<TextVariant>, variants: Vec<TextVariant>) {
    for variant in variants {
        push_unique_text_variant(target, variant);
    }
}

fn push_unique_text_variant(target: &mut Vec<TextVariant>, variant: TextVariant) {
    if !target.contains(&variant) {
        target.push(variant);
    }
}

fn parse_seed_token(token: &str, seeds: &mut Vec<u64>) -> Result<(), String> {
    if let Some((start, end)) = token.split_once("..=") {
        let start = parse_seed_value(start, token)?;
        let end = parse_seed_value(end, token)?;
        if end < start {
            return Err(format!("invalid descending seed range: {token}"));
        }
        seeds.extend(start..=end);
    } else if let Some((start, end)) = token.split_once("..") {
        let start = parse_seed_value(start, token)?;
        let end = parse_seed_value(end, token)?;
        if end <= start {
            return Err(format!("invalid empty seed range: {token}"));
        }
        seeds.extend(start..end);
    } else {
        seeds.push(parse_seed_value(token, token)?);
    }
    Ok(())
}

fn parse_seed_value(raw: &str, token: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|_| format!("invalid seed token: {token}"))
}

fn normalize_jobs(raw_jobs: usize, seed_count: usize) -> usize {
    let seed_count = seed_count.max(1);
    let available = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let requested = if raw_jobs == 0 { available } else { raw_jobs };
    requested.max(1).min(seed_count)
}

fn print_help() {
    println!("Usage: cargo run --example community_surface_sim -p aura-core -- [options]");
    println!();
    println!("Options:");
    println!("  --profile <name>           preset: quick, ci, nightly");
    println!(
        "  --children <n>             protected accounts to simulate (default {DEFAULT_CHILDREN})"
    );
    println!(
        "  --events-per-child <n>     visible events per protected account (default {DEFAULT_EVENTS_PER_CHILD})"
    );
    println!("  --seed <n>                 deterministic RNG seed (default {DEFAULT_SEED})");
    println!("  --seeds <list>             comma/space/range seed matrix, e.g. 42,43,44 or 42..45");
    println!(
        "  --jobs <n>                 parallel seed workers for matrix mode, 0=auto (default)"
    );
    println!(
        "  --text-variants <list>     clean/adversarial text variants, e.g. clean,zwsp,leetspeak"
    );
    println!("  --adversarial              shorthand for the full adversarial text variant suite");
    println!("  --json <path>              write machine-readable JSON report");
    println!("  --fail-on-gate             exit non-zero if quality gates fail");
    println!(
        "  --min-detect-rate <rate>   positive detection gate, 0..1 or percent (default {DEFAULT_MIN_DETECT_RATE})"
    );
    println!(
        "  --max-safe-fp-rate <rate>  safe false-positive gate, 0..1 or percent (default {DEFAULT_MAX_SAFE_FP_RATE})"
    );
    println!("  --baseline-json <path>     compare current totals with a previous JSON report");
    println!(
        "  --history-ndjson <path>    summarize recent NDJSON reports before appending this run"
    );
    println!(
        "  --history-window <n>       recent history rows to summarize (default {DEFAULT_HISTORY_WINDOW})"
    );
    println!(
        "  --history-gate             add blocking gates against latest/window history deltas"
    );
    println!(
        "  --max-detect-rate-drop <r> allowed drop vs baseline, 0..1 or percent (default {DEFAULT_MAX_DETECT_RATE_DROP})"
    );
    println!(
        "  --max-fp-rate-rise <r>     allowed FP-rate rise vs baseline, 0..1 or percent (default {DEFAULT_MAX_FP_RATE_RISE})"
    );
    println!("  --max-elapsed-ms <ms>      optional runtime gate");
    println!("  --verbose                  print per-child progress");
    println!();
    println!("Environment overrides:");
    println!(
        "  {ENV_PREFIX}_PROFILE, {ENV_PREFIX}_JSON, {ENV_PREFIX}_NDJSON, {ENV_PREFIX}_JSON_STDOUT, {ENV_PREFIX}_FAIL_ON_GATE"
    );
    println!("  {ENV_PREFIX}_CHILDREN, {ENV_PREFIX}_EVENTS_PER_CHILD, {ENV_PREFIX}_SEED, {ENV_PREFIX}_SEEDS");
    println!("  {ENV_PREFIX}_JOBS, {ENV_PREFIX}_TEXT_VARIANTS, {ENV_PREFIX}_ADVERSARIAL");
    println!(
        "  {ENV_PREFIX}_BASELINE_JSON, {ENV_PREFIX}_MAX_DETECT_RATE_DROP, {ENV_PREFIX}_MAX_FP_RATE_RISE"
    );
    println!(
        "  {ENV_PREFIX}_HISTORY_NDJSON, {ENV_PREFIX}_HISTORY_WINDOW, {ENV_PREFIX}_HISTORY_GATE"
    );
    println!(
        "  {ENV_PREFIX}_MIN_DETECT_RATE, {ENV_PREFIX}_MAX_SAFE_FP_RATE, {ENV_PREFIX}_MAX_ELAPSED_MS"
    );
}

fn run_simulation(args: &Args) -> CommunitySimReport {
    let started = Instant::now();
    let mut rng = Rng::new(args.seed);
    let children = build_children(args.children, &mut rng);
    let db = PatternDatabase::default_mvp();

    let mut total = MetricCounts::default();
    let mut by_surface = BTreeMap::<String, MetricCounts>::new();
    let mut by_kind = BTreeMap::<String, MetricCounts>::new();
    let mut by_scenario = BTreeMap::<String, MetricCounts>::new();
    let mut by_text_variant = BTreeMap::<String, MetricCounts>::new();
    let mut by_server_hint = BTreeMap::<String, MetricCounts>::new();
    let mut by_language = BTreeMap::<String, MetricCounts>::new();
    let mut by_expected_threat = BTreeMap::<String, MetricCounts>::new();
    let mut action_counts = BTreeMap::<String, usize>::new();
    let mut detected_threat_counts = BTreeMap::<String, usize>::new();
    let mut senders = HashMap::<String, SenderRiskRow>::new();
    let mut server_reputation = ServerReputationAggregator::default();
    let mut findings = Vec::new();
    let mut sequence = 1usize;

    for (child_index, child) in children.iter().enumerate() {
        let mut analyzer = Analyzer::new(config_for_child(child), &db);
        let mut trajectory = ChildTrajectory::default();

        for event_index in 0..args.events_per_child {
            let mut event = build_event(
                sequence,
                child_index,
                child,
                event_index,
                &mut trajectory,
                &args.text_variants,
                &mut rng,
            );
            event.server_sender_risk_hint = server_reputation.hint(&event.sender_id);
            sequence += 1;

            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some(event.text.clone()),
                image_data: None,
                sender_id: event.sender_id.as_str().into(),
                conversation_id: event.conversation_id.as_str().into(),
                language: Some(event.child_language.to_string()),
                conversation_type: event.conversation_type,
                member_count: event.member_count,
                server_sender_risk_hint: event.server_sender_risk_hint,
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            };
            let result = analyzer.analyze_with_context(&input, event.timestamp_ms);

            let expected_score = event
                .expected_threat
                .map(|threat| predicted_score_for_threat(&result, threat));
            let expected_threshold = event.expected_threat.map(threshold_for);
            let expected_detected = event.expected_threat.is_some_and(|threat| {
                expected_score.unwrap_or(0.0) >= threshold_for(threat)
                    || (result.threat_type == threat && result.action != Action::Allow)
            });
            let detected_score = if result.threat_type == ThreatType::None {
                0.0
            } else {
                predicted_score_for_threat(&result, result.threat_type)
            };
            let false_positive = event.expected_threat.is_none()
                && result.is_threat()
                && result.action != Action::Allow;
            let wrong_threat_positive = event.expected_threat.is_some()
                && !expected_detected
                && result.is_threat()
                && Some(result.threat_type) != event.expected_threat;

            total.record(
                event.expected_threat,
                expected_detected,
                wrong_threat_positive,
                false_positive,
            );
            by_surface
                .entry(event.surface.label().to_string())
                .or_default()
                .record(
                    event.expected_threat,
                    expected_detected,
                    wrong_threat_positive,
                    false_positive,
                );
            by_kind
                .entry(event.kind.label().to_string())
                .or_default()
                .record(
                    event.expected_threat,
                    expected_detected,
                    wrong_threat_positive,
                    false_positive,
                );
            by_scenario
                .entry(event.scenario.label().to_string())
                .or_default()
                .record(
                    event.expected_threat,
                    expected_detected,
                    wrong_threat_positive,
                    false_positive,
                );
            by_text_variant
                .entry(event.text_variant.label().to_string())
                .or_default()
                .record(
                    event.expected_threat,
                    expected_detected,
                    wrong_threat_positive,
                    false_positive,
                );
            by_server_hint
                .entry(server_hint_label(event.server_sender_risk_hint).to_string())
                .or_default()
                .record(
                    event.expected_threat,
                    expected_detected,
                    wrong_threat_positive,
                    false_positive,
                );
            by_language
                .entry(event.child_language.to_string())
                .or_default()
                .record(
                    event.expected_threat,
                    expected_detected,
                    wrong_threat_positive,
                    false_positive,
                );
            by_expected_threat
                .entry(
                    event
                        .expected_threat
                        .map(|threat| format!("{threat:?}"))
                        .unwrap_or_else(|| "None".to_string()),
                )
                .or_default()
                .record(
                    event.expected_threat,
                    expected_detected,
                    wrong_threat_positive,
                    false_positive,
                );

            *action_counts
                .entry(format!("{:?}", result.action))
                .or_default() += 1;
            if result.is_threat() {
                *detected_threat_counts
                    .entry(format!("{:?}", result.threat_type))
                    .or_default() += 1;
            }

            record_sender(
                &mut senders,
                &event,
                &result,
                expected_detected,
                false_positive,
            );
            if let Some(telemetry) =
                client_safety_telemetry_from_result(&event, &result, detected_score)
            {
                server_reputation.record(telemetry);
            }

            if event.expected_threat.is_some() && !expected_detected {
                findings.push(Finding {
                    kind: if wrong_threat_positive {
                        "wrong_threat".to_string()
                    } else {
                        "miss".to_string()
                    },
                    sequence: event.sequence,
                    child_id: event.child_id.clone(),
                    surface: event.surface,
                    event_kind: event.kind,
                    scenario: event.scenario,
                    text_variant: event.text_variant,
                    server_sender_risk_hint: event.server_sender_risk_hint,
                    expected_threat: event.expected_threat,
                    detected_threat: result.threat_type,
                    action: result.action,
                    score: result.score,
                    expected_score,
                    expected_threshold,
                    detected_score,
                    reason_codes: top_reason_codes(&result),
                    text: event.text.clone(),
                });
            } else if false_positive {
                findings.push(Finding {
                    kind: "false_positive".to_string(),
                    sequence: event.sequence,
                    child_id: event.child_id.clone(),
                    surface: event.surface,
                    event_kind: event.kind,
                    scenario: event.scenario,
                    text_variant: event.text_variant,
                    server_sender_risk_hint: event.server_sender_risk_hint,
                    expected_threat: None,
                    detected_threat: result.threat_type,
                    action: result.action,
                    score: result.score,
                    expected_score: None,
                    expected_threshold: None,
                    detected_score,
                    reason_codes: top_reason_codes(&result),
                    text: event.text.clone(),
                });
            }
        }

        if args.verbose {
            println!(
                "child {}/{} {} age={} lang={} done",
                child_index + 1,
                children.len(),
                child.display_name,
                child.age,
                child.language
            );
        }
    }

    let elapsed_ms = started.elapsed().as_millis();
    let events_per_second = if elapsed_ms == 0 {
        0.0
    } else {
        total.events as f64 / (elapsed_ms as f64 / 1000.0)
    };
    let gates = evaluate_gates(
        &total,
        &by_kind,
        &by_surface,
        &by_scenario,
        &by_text_variant,
        &by_server_hint,
        args,
    );
    let mut report = CommunitySimReport {
        schema_version: "aura.community_surface_sim.v1",
        generated_at_unix_ms: generated_at_unix_ms(),
        profile: args.profile,
        seed: args.seed,
        children: args.children,
        events_per_child: args.events_per_child,
        text_variants: args.text_variants.clone(),
        total_events: total.events,
        elapsed_ms,
        events_per_second,
        total,
        by_surface: metric_rows(by_surface),
        by_kind: metric_rows(by_kind),
        by_scenario: metric_rows(by_scenario),
        by_text_variant: metric_rows(by_text_variant),
        by_server_hint: metric_rows(by_server_hint),
        by_language: metric_rows(by_language),
        by_expected_threat: metric_rows(by_expected_threat),
        action_counts,
        detected_threat_counts,
        top_senders: top_senders(senders),
        findings,
        baseline: None,
        history: None,
        gates,
    };
    evaluate_runtime_gate(&mut report, args);
    report
}

fn run_seed_matrix(args: &Args) -> CommunityMatrixReport {
    let started = Instant::now();
    let mut total = MetricCounts::default();
    let mut by_surface = BTreeMap::<String, MetricCounts>::new();
    let mut by_kind = BTreeMap::<String, MetricCounts>::new();
    let mut by_scenario = BTreeMap::<String, MetricCounts>::new();
    let mut by_text_variant = BTreeMap::<String, MetricCounts>::new();
    let mut by_server_hint = BTreeMap::<String, MetricCounts>::new();
    let mut by_language = BTreeMap::<String, MetricCounts>::new();
    let mut by_expected_threat = BTreeMap::<String, MetricCounts>::new();
    let mut seed_reports = Vec::with_capacity(args.seeds.len());
    let mut findings = Vec::new();

    for report in run_seed_reports(args) {
        total.merge(&report.total);
        merge_metric_rows(&mut by_surface, &report.by_surface);
        merge_metric_rows(&mut by_kind, &report.by_kind);
        merge_metric_rows(&mut by_scenario, &report.by_scenario);
        merge_metric_rows(&mut by_text_variant, &report.by_text_variant);
        merge_metric_rows(&mut by_server_hint, &report.by_server_hint);
        merge_metric_rows(&mut by_language, &report.by_language);
        merge_metric_rows(&mut by_expected_threat, &report.by_expected_threat);
        findings.extend(
            report
                .findings
                .iter()
                .cloned()
                .map(|finding| MatrixFinding {
                    seed: report.seed,
                    finding,
                }),
        );
        seed_reports.push(seed_matrix_row(&report, args));
    }

    let elapsed_ms = started.elapsed().as_millis();
    let events_per_second = if elapsed_ms == 0 {
        0.0
    } else {
        total.events as f64 / (elapsed_ms as f64 / 1000.0)
    };
    let worst_detect_seed = seed_reports
        .iter()
        .min_by(|a, b| {
            a.detect_rate
                .total_cmp(&b.detect_rate)
                .then_with(|| b.finding_count.cmp(&a.finding_count))
                .then_with(|| a.seed.cmp(&b.seed))
        })
        .cloned();
    let worst_fp_seed = seed_reports
        .iter()
        .max_by(|a, b| {
            a.fp_rate
                .total_cmp(&b.fp_rate)
                .then_with(|| a.finding_count.cmp(&b.finding_count))
                .then_with(|| b.seed.cmp(&a.seed))
        })
        .cloned();
    let gates = evaluate_matrix_gates(
        &total,
        &seed_reports,
        &by_kind,
        &by_surface,
        &by_scenario,
        &by_text_variant,
        &by_server_hint,
        elapsed_ms,
        args,
    );

    CommunityMatrixReport {
        schema_version: "aura.community_surface_matrix.v1",
        generated_at_unix_ms: generated_at_unix_ms(),
        profile: args.profile,
        seeds: args.seeds.clone(),
        jobs: args.jobs,
        children: args.children,
        events_per_child: args.events_per_child,
        text_variants: args.text_variants.clone(),
        total_events: total.events,
        elapsed_ms,
        events_per_second,
        total,
        by_surface: metric_rows(by_surface),
        by_kind: metric_rows(by_kind),
        by_scenario: metric_rows(by_scenario),
        by_text_variant: metric_rows(by_text_variant),
        by_server_hint: metric_rows(by_server_hint),
        by_language: metric_rows(by_language),
        by_expected_threat: metric_rows(by_expected_threat),
        seed_reports,
        worst_detect_seed,
        worst_fp_seed,
        findings,
        baseline: None,
        history: None,
        gates,
    }
}

fn run_seed_reports(args: &Args) -> Vec<CommunitySimReport> {
    if args.jobs <= 1 || args.seeds.len() <= 1 {
        return args
            .seeds
            .iter()
            .map(|seed| run_seed_report(args, *seed))
            .collect();
    }

    let job_count = args.jobs.min(args.seeds.len());
    let mut work = vec![Vec::<(usize, u64)>::new(); job_count];
    for (idx, seed) in args.seeds.iter().copied().enumerate() {
        work[idx % job_count].push((idx, seed));
    }

    let mut reports: Vec<Option<CommunitySimReport>> =
        (0..args.seeds.len()).map(|_| None).collect();
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(job_count);
        for job_work in work {
            let base_args = args.clone();
            handles.push(scope.spawn(move || {
                job_work
                    .into_iter()
                    .map(|(idx, seed)| (idx, run_seed_report(&base_args, seed)))
                    .collect::<Vec<_>>()
            }));
        }

        for handle in handles {
            for (idx, report) in handle.join().expect("community seed worker panicked") {
                reports[idx] = Some(report);
            }
        }
    });

    reports
        .into_iter()
        .map(|report| report.expect("community seed worker did not return report"))
        .collect()
}

fn run_seed_report(args: &Args, seed: u64) -> CommunitySimReport {
    let mut seed_args = args.clone();
    seed_args.seed = seed;
    seed_args.seeds = vec![seed];
    seed_args.jobs = 1;
    run_simulation(&seed_args)
}

fn seed_matrix_row(report: &CommunitySimReport, args: &Args) -> SeedMatrixRow {
    let gates_passed = report.total.detect_rate >= args.min_detect_rate
        && report.total.fp_rate <= args.max_safe_fp_rate;
    SeedMatrixRow {
        seed: report.seed,
        total_events: report.total_events,
        elapsed_ms: report.elapsed_ms,
        events_per_second: report.events_per_second,
        positives: report.total.positives,
        positives_detected: report.total.positives_detected,
        detect_rate: report.total.detect_rate,
        negatives: report.total.negatives,
        false_positives: report.total.false_positives,
        fp_rate: report.total.fp_rate,
        wrong_threat_positives: report.total.wrong_threat_positives,
        finding_count: report.findings.len(),
        gates_passed,
    }
}

fn build_children(count: usize, rng: &mut Rng) -> Vec<ChildProfile> {
    let names = [
        ("uk", ["Олена", "Марія", "Софія", "Максим"]),
        ("en", ["Emma", "Mia", "Noah", "Grace"]),
        ("ru", ["Аня", "Маша", "Даня", "Лиза"]),
    ];

    (0..count)
        .map(|idx| {
            let (language, name_set) = &names[idx % names.len()];
            let display_name = name_set[idx % name_set.len()].to_string();
            let age = 10 + rng.range(0, 7) as u8;
            let prefix = format!("{}_{}", language, idx);
            ChildProfile {
                id: format!("child_{prefix}"),
                display_name,
                age,
                language,
                trusted_family: format!("family_{prefix}"),
                peers: (0..6).map(|peer| format!("peer_{prefix}_{peer}")).collect(),
                groomer: format!("groomer_{prefix}"),
                manipulator: format!("manip_{prefix}"),
                bully_pack: (0..5)
                    .map(|bully| format!("bully_{prefix}_{bully}"))
                    .collect(),
                spammer: format!("spammer_{prefix}"),
            }
        })
        .collect()
}

fn config_for_child(child: &ChildProfile) -> AuraConfig {
    AuraConfig {
        account_type: if child.age <= 12 {
            AccountType::Child
        } else {
            AccountType::Teen
        },
        protection_level: ProtectionLevel::High,
        language: child.language.to_string(),
        account_holder_age: Some(child.age as u16),
        timezone_offset_minutes: 120,
        ..AuraConfig::default()
    }
}

fn build_event(
    sequence: usize,
    child_index: usize,
    child: &ChildProfile,
    event_index: usize,
    trajectory: &mut ChildTrajectory,
    text_variants: &[TextVariant],
    rng: &mut Rng,
) -> SimEvent {
    let scenario = choose_scenario(event_index);
    let kind = choose_kind_for_scenario(scenario, rng);
    let surface = choose_surface_for_scenario(scenario, kind, event_index, rng);
    let text_variant = choose_text_variant(
        text_variants,
        sequence,
        child_index,
        event_index,
        kind,
        surface,
    );
    let (sender_id, clean_text) = text_for_event(child, kind, scenario, trajectory, rng);
    let text = apply_text_variant(clean_text.as_str(), text_variant, sequence);
    let conversation_id = conversation_id(child_index, surface, kind, scenario);
    let (conversation_type, member_count) = conversation_shape(surface);

    SimEvent {
        sequence,
        child_id: child.id.clone(),
        child_language: child.language,
        timestamp_ms: BASE_TS_MS
            + child_index as u64 * 14 * 86_400_000
            + event_index as u64 * 180_000
            + rng.range(0, 90_000) as u64,
        surface,
        kind,
        scenario,
        text_variant,
        expected_threat: kind.expected_threat(),
        sender_id,
        conversation_id,
        conversation_type,
        member_count,
        server_sender_risk_hint: None,
        text,
    }
}

fn choose_scenario(event_index: usize) -> ScenarioKind {
    match event_index % 20 {
        0 => ScenarioKind::TrustedAdultSupport,
        1 | 2 => ScenarioKind::SlowTrustGrooming,
        3 => ScenarioKind::SurfaceHopGrooming,
        4 | 11 => ScenarioKind::CrossChildRepeatOffender,
        5 | 6 => ScenarioKind::PileOnBullying,
        7 => ScenarioKind::CoerciveManipulation,
        8 => ScenarioKind::SelfHarmAfterBullying,
        9 => ScenarioKind::PhishingBlast,
        10 => ScenarioKind::PiiAfterTrust,
        _ => ScenarioKind::Ambient,
    }
}

fn choose_kind_for_scenario(scenario: ScenarioKind, rng: &mut Rng) -> EventKind {
    match scenario {
        ScenarioKind::Ambient => choose_kind(rng),
        ScenarioKind::TrustedAdultSupport => EventKind::SupportSafe,
        ScenarioKind::SlowTrustGrooming
        | ScenarioKind::SurfaceHopGrooming
        | ScenarioKind::CrossChildRepeatOffender => EventKind::Grooming,
        ScenarioKind::PileOnBullying => EventKind::Bullying,
        ScenarioKind::CoerciveManipulation => EventKind::Manipulation,
        ScenarioKind::SelfHarmAfterBullying => EventKind::SelfHarm,
        ScenarioKind::PhishingBlast => EventKind::Phishing,
        ScenarioKind::PiiAfterTrust => EventKind::PiiLeakage,
    }
}

fn choose_kind(rng: &mut Rng) -> EventKind {
    match rng.range(0, 100) {
        0..=49 => EventKind::Safe,
        50..=58 => EventKind::SupportSafe,
        59..=66 => EventKind::MildConflict,
        67..=76 => EventKind::Grooming,
        77..=84 => EventKind::Bullying,
        85..=89 => EventKind::Manipulation,
        90..=93 => EventKind::SelfHarm,
        94..=96 => EventKind::Phishing,
        _ => EventKind::PiiLeakage,
    }
}

fn choose_surface(kind: EventKind, rng: &mut Rng) -> Surface {
    match kind {
        EventKind::Grooming | EventKind::Manipulation | EventKind::SelfHarm => {
            if rng.range(0, 100) < 78 {
                Surface::DirectMessage
            } else {
                Surface::PublicComment
            }
        }
        EventKind::Bullying => match rng.range(0, 100) {
            0..=44 => Surface::GroupChat,
            45..=79 => Surface::PublicComment,
            _ => Surface::LivestreamComment,
        },
        EventKind::Phishing => {
            if rng.range(0, 100) < 65 {
                Surface::PublicComment
            } else {
                Surface::DirectMessage
            }
        }
        EventKind::PiiLeakage => match rng.range(0, 100) {
            0..=49 => Surface::DirectMessage,
            50..=79 => Surface::GroupChat,
            _ => Surface::PublicComment,
        },
        EventKind::Safe | EventKind::SupportSafe | EventKind::MildConflict => {
            match rng.range(0, 100) {
                0..=29 => Surface::DirectMessage,
                30..=59 => Surface::GroupChat,
                60..=84 => Surface::PublicComment,
                _ => Surface::LivestreamComment,
            }
        }
    }
}

fn choose_surface_for_scenario(
    scenario: ScenarioKind,
    kind: EventKind,
    event_index: usize,
    rng: &mut Rng,
) -> Surface {
    match scenario {
        ScenarioKind::Ambient => choose_surface(kind, rng),
        ScenarioKind::TrustedAdultSupport => {
            if event_index.is_multiple_of(2) {
                Surface::DirectMessage
            } else {
                Surface::GroupChat
            }
        }
        ScenarioKind::SlowTrustGrooming => Surface::DirectMessage,
        ScenarioKind::SurfaceHopGrooming => {
            if (event_index / 20).is_multiple_of(2) {
                Surface::PublicComment
            } else {
                Surface::DirectMessage
            }
        }
        ScenarioKind::CrossChildRepeatOffender => {
            if event_index.is_multiple_of(2) {
                Surface::DirectMessage
            } else {
                Surface::PublicComment
            }
        }
        ScenarioKind::PileOnBullying => {
            if event_index.is_multiple_of(2) {
                Surface::GroupChat
            } else {
                Surface::LivestreamComment
            }
        }
        ScenarioKind::CoerciveManipulation
        | ScenarioKind::SelfHarmAfterBullying
        | ScenarioKind::PiiAfterTrust => Surface::DirectMessage,
        ScenarioKind::PhishingBlast => Surface::PublicComment,
    }
}

fn choose_text_variant(
    variants: &[TextVariant],
    sequence: usize,
    child_index: usize,
    event_index: usize,
    kind: EventKind,
    surface: Surface,
) -> TextVariant {
    if variants.is_empty() {
        return TextVariant::Clean;
    }
    let mixed = sequence
        .wrapping_mul(17)
        .wrapping_add(child_index.wrapping_mul(31))
        .wrapping_add(event_index.wrapping_mul(13))
        .wrapping_add(event_kind_index(kind).wrapping_mul(7))
        .wrapping_add(surface_index(surface).wrapping_mul(11));
    variants[mixed % variants.len()]
}

fn event_kind_index(kind: EventKind) -> usize {
    match kind {
        EventKind::Safe => 0,
        EventKind::SupportSafe => 1,
        EventKind::MildConflict => 2,
        EventKind::Grooming => 3,
        EventKind::Bullying => 4,
        EventKind::Manipulation => 5,
        EventKind::SelfHarm => 6,
        EventKind::Phishing => 7,
        EventKind::PiiLeakage => 8,
    }
}

fn surface_index(surface: Surface) -> usize {
    match surface {
        Surface::DirectMessage => 0,
        Surface::GroupChat => 1,
        Surface::PublicComment => 2,
        Surface::LivestreamComment => 3,
    }
}

fn conversation_shape(surface: Surface) -> (ConversationType, Option<u32>) {
    match surface {
        Surface::DirectMessage => (ConversationType::Direct, None),
        Surface::GroupChat => (ConversationType::Group, Some(12)),
        Surface::PublicComment => (ConversationType::Group, Some(180)),
        Surface::LivestreamComment => (ConversationType::Group, Some(900)),
    }
}

fn conversation_id(
    child_index: usize,
    surface: Surface,
    kind: EventKind,
    scenario: ScenarioKind,
) -> String {
    match scenario {
        ScenarioKind::SlowTrustGrooming | ScenarioKind::SurfaceHopGrooming => {
            return format!("child_{child_index}_grooming_escalation_thread");
        }
        ScenarioKind::CrossChildRepeatOffender => {
            return format!("child_{child_index}_network_offender_thread");
        }
        ScenarioKind::PileOnBullying | ScenarioKind::SelfHarmAfterBullying => {
            return format!("child_{child_index}_pile_on_and_aftermath_group");
        }
        ScenarioKind::CoerciveManipulation => {
            return format!("child_{child_index}_coercive_control_dm");
        }
        ScenarioKind::PhishingBlast => {
            return format!("child_{child_index}_public_reward_comments");
        }
        ScenarioKind::PiiAfterTrust => {
            return format!("child_{child_index}_private_checkin_dm");
        }
        ScenarioKind::TrustedAdultSupport | ScenarioKind::Ambient => {}
    }

    let bucket = if kind.expected_threat().is_some() {
        "risk"
    } else {
        "safe"
    };
    match surface {
        Surface::DirectMessage => format!("child_{child_index}_dm_{}", kind.label()),
        Surface::GroupChat => format!("child_{child_index}_{bucket}_class_group"),
        Surface::PublicComment => format!("child_{child_index}_{bucket}_post_comments"),
        Surface::LivestreamComment => format!("child_{child_index}_{bucket}_livestream_chat"),
    }
}

fn text_for_event(
    child: &ChildProfile,
    kind: EventKind,
    scenario: ScenarioKind,
    trajectory: &mut ChildTrajectory,
    rng: &mut Rng,
) -> (String, String) {
    match scenario {
        ScenarioKind::TrustedAdultSupport => {
            return (
                child.trusted_family.clone(),
                pick(support_safe_texts(child.language), rng).to_string(),
            );
        }
        ScenarioKind::SlowTrustGrooming | ScenarioKind::SurfaceHopGrooming => {
            let text = pick_stage(grooming_stages(child.language), trajectory.grooming_stage);
            trajectory.grooming_stage += 1;
            return (child.groomer.clone(), text.to_string());
        }
        ScenarioKind::CrossChildRepeatOffender => {
            let text = pick_stage(grooming_stages(child.language), trajectory.grooming_stage);
            trajectory.grooming_stage += 1;
            return ("network_groomer_alpha".to_string(), text.to_string());
        }
        ScenarioKind::PileOnBullying => {
            let text = pick_stage(bullying_stages(child.language), trajectory.bullying_stage);
            trajectory.bullying_stage += 1;
            return (
                child.bully_pack[trajectory.bullying_stage % child.bully_pack.len()].clone(),
                text.to_string(),
            );
        }
        ScenarioKind::CoerciveManipulation => {
            let text = pick_stage(
                manipulation_stages(child.language),
                trajectory.manipulation_stage,
            );
            trajectory.manipulation_stage += 1;
            return (child.manipulator.clone(), text.to_string());
        }
        ScenarioKind::SelfHarmAfterBullying => {
            let text = pick_stage(selfharm_stages(child.language), trajectory.selfharm_stage);
            trajectory.selfharm_stage += 1;
            return (child.id.clone(), text.to_string());
        }
        ScenarioKind::PhishingBlast => {
            let text = pick_stage(phishing_stages(child.language), trajectory.phishing_stage);
            trajectory.phishing_stage += 1;
            return ("network_spammer_alpha".to_string(), text.to_string());
        }
        ScenarioKind::PiiAfterTrust => {
            let text = pick_stage(pii_stages(child.language), trajectory.pii_stage);
            trajectory.pii_stage += 1;
            return (child.id.clone(), text.to_string());
        }
        ScenarioKind::Ambient => {}
    }

    match kind {
        EventKind::Safe => {
            let sender = if rng.range(0, 100) < 25 {
                child.trusted_family.clone()
            } else {
                random_peer(child, rng)
            };
            (sender, pick(safe_texts(child.language), rng).to_string())
        }
        EventKind::SupportSafe => (
            random_peer(child, rng),
            pick(support_safe_texts(child.language), rng).to_string(),
        ),
        EventKind::MildConflict => (
            random_peer(child, rng),
            pick(mild_conflict_texts(child.language), rng).to_string(),
        ),
        EventKind::Grooming => {
            let text = pick_stage(grooming_stages(child.language), trajectory.grooming_stage);
            trajectory.grooming_stage += 1;
            (child.groomer.clone(), text.to_string())
        }
        EventKind::Bullying => {
            let text = pick_stage(bullying_stages(child.language), trajectory.bullying_stage);
            trajectory.bullying_stage += 1;
            (
                child.bully_pack[trajectory.bullying_stage % child.bully_pack.len()].clone(),
                text.to_string(),
            )
        }
        EventKind::Manipulation => {
            let text = pick_stage(
                manipulation_stages(child.language),
                trajectory.manipulation_stage,
            );
            trajectory.manipulation_stage += 1;
            (child.manipulator.clone(), text.to_string())
        }
        EventKind::SelfHarm => {
            let text = pick_stage(selfharm_stages(child.language), trajectory.selfharm_stage);
            trajectory.selfharm_stage += 1;
            (child.id.clone(), text.to_string())
        }
        EventKind::Phishing => {
            let text = pick_stage(phishing_stages(child.language), trajectory.phishing_stage);
            trajectory.phishing_stage += 1;
            (child.spammer.clone(), text.to_string())
        }
        EventKind::PiiLeakage => {
            let text = pick_stage(pii_stages(child.language), trajectory.pii_stage);
            trajectory.pii_stage += 1;
            (child.id.clone(), text.to_string())
        }
    }
}

fn random_peer(child: &ChildProfile, rng: &mut Rng) -> String {
    child.peers[rng.range(0, child.peers.len())].clone()
}

fn pick<'a>(values: &'a [&'a str], rng: &mut Rng) -> &'a str {
    values[rng.range(0, values.len())]
}

fn pick_stage(values: &'static [&'static str], stage: usize) -> &'static str {
    values[stage % values.len()]
}

fn apply_text_variant(text: &str, variant: TextVariant, salt: usize) -> String {
    match variant {
        TextVariant::Clean => text.to_string(),
        TextVariant::Zwsp => insert_zwsp(text),
        TextVariant::EmojiPadding => add_emoji_padding(text, salt),
        TextVariant::Leetspeak => leetspeak(text),
        TextVariant::TypoDrop => typo_drop(text),
        TextVariant::TypoSwap => typo_swap(text),
        TextVariant::PunctStrip => strip_punctuation(text),
        TextVariant::Spongebob => spongebob_case(text),
    }
}

fn insert_zwsp(text: &str) -> String {
    text.split_whitespace()
        .map(|token| {
            if token.chars().count() < 5 {
                token.to_string()
            } else {
                insert_every_n_chars(token, '\u{200B}', 3)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn insert_every_n_chars(token: &str, inserted: char, n: usize) -> String {
    let mut out = String::with_capacity(token.len() + token.len() / n);
    for (idx, ch) in token.chars().enumerate() {
        if idx > 0 && idx % n == 0 {
            out.push(inserted);
        }
        out.push(ch);
    }
    out
}

fn add_emoji_padding(text: &str, salt: usize) -> String {
    let mut out = Vec::new();
    for (idx, token) in text.split_whitespace().enumerate() {
        out.push(token.to_string());
        if idx % 2 == salt % 2 {
            out.push(EMOJI_PADDING_TOKENS[(salt + idx) % EMOJI_PADDING_TOKENS.len()].to_string());
        }
    }
    out.join(" ")
}

fn leetspeak(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            'a' | 'A' | 'а' | 'А' => '4',
            'e' | 'E' | 'е' | 'Е' | 'є' | 'Є' => '3',
            'i' | 'I' | 'і' | 'І' | 'ї' | 'Ї' | 'и' | 'И' => '1',
            'o' | 'O' | 'о' | 'О' => '0',
            's' | 'S' | 'с' | 'С' => '5',
            't' | 'T' | 'т' | 'Т' => '7',
            _ => ch,
        })
        .collect()
}

fn typo_drop(text: &str) -> String {
    mutate_every_other_word(text, drop_middle_char)
}

fn typo_swap(text: &str) -> String {
    mutate_every_other_word(text, swap_middle_chars)
}

fn mutate_every_other_word(text: &str, mutate: fn(&str) -> String) -> String {
    text.split_whitespace()
        .enumerate()
        .map(|(idx, token)| {
            if idx % 2 == 0
                && token.chars().count() > 5
                && token.chars().any(|ch| ch.is_alphabetic())
            {
                mutate(token)
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn drop_middle_char(token: &str) -> String {
    let chars = token.chars().collect::<Vec<_>>();
    let drop_idx = chars.len() / 2;
    chars
        .into_iter()
        .enumerate()
        .filter_map(|(idx, ch)| if idx == drop_idx { None } else { Some(ch) })
        .collect()
}

fn swap_middle_chars(token: &str) -> String {
    let mut chars = token.chars().collect::<Vec<_>>();
    let idx = chars.len() / 2;
    if idx > 0 {
        chars.swap(idx - 1, idx);
    }
    chars.into_iter().collect()
}

fn strip_punctuation(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_alphanumeric() || ch.is_whitespace() {
                ch
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn spongebob_case(text: &str) -> String {
    let mut upper = false;
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_alphabetic() {
            if upper {
                out.extend(ch.to_uppercase());
            } else {
                out.extend(ch.to_lowercase());
            }
            upper = !upper;
        } else {
            out.push(ch);
        }
    }
    out
}

fn safe_texts(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "не забудь домашку з математики на завтра",
            "зустрічаємось біля класу після уроку",
            "мама сказала що забере мене о шостій",
            "класний гол на тренуванні сьогодні",
            "хто бере маркери для проєкту",
        ],
        "ru" => &[
            "не забудь домашку по алгебре",
            "встречаемся у класса после урока",
            "мама сказала что заберет меня в шесть",
            "классный гол на тренировке сегодня",
            "кто возьмет маркеры для проекта",
        ],
        _ => &[
            "dont forget the math homework for tomorrow",
            "meet by the classroom after lunch",
            "my mom said she will pick me up at six",
            "great goal at practice today",
            "who is bringing markers for the project",
        ],
    }
}

fn support_safe_texts(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "мені шкода що тобі важко, давай поговоримо з дорослим разом",
            "я поруч, але це краще сказати мамі або психологу",
            "не треба тримати це в секреті, допомога поруч",
        ],
        "ru" => &[
            "мне жаль что тебе тяжело, давай скажем взрослому вместе",
            "я рядом, но лучше написать маме или психологу",
            "не надо держать это в секрете, помощь рядом",
        ],
        _ => &[
            "im sorry this is heavy, lets tell a trusted adult together",
            "im here with you, and we should message your counselor too",
            "you do not have to keep this secret, help is nearby",
        ],
    }
}

fn mild_conflict_texts(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "ти знову забув частину презентації, це дратує",
            "давайте без сварок, просто переробимо слайди",
            "я не згоден, але не треба кричати в чаті",
        ],
        "ru" => &[
            "ты опять забыл часть презентации, это бесит",
            "давайте без ссор, просто переделаем слайды",
            "я не согласен, но не надо кричать в чате",
        ],
        _ => &[
            "you forgot your part of the slides again and its annoying",
            "lets not fight, we can fix the project after class",
            "i disagree but we dont need to yell in chat",
        ],
    }
}

fn grooming_stages(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "ти дуже доросла для свого віку, не як інші діти",
            "я можу купити тобі скін, тільки не роби з цього шум",
            "не кажи батькам про наш чат, вони все зіпсують",
            "давай перейдем в телегу, тут усі все бачать",
            "скинь селфі там, щоб я знав що це точно ти",
            "видали цей чат після, краще щоб ніхто не бачив",
        ],
        "ru" => &[
            "ты очень взрослая для своего возраста, не как другие дети",
            "я могу купить тебе скин, только не шуми об этом",
            "не говори родителям про наш чат, они все испортят",
            "давай перейдем в телегу, тут все видно",
            "скинь селфи там, чтобы я знал что это точно ты",
            "удали этот чат после, лучше чтобы никто не видел",
        ],
        _ => &[
            "you seem way more mature than other kids your age",
            "i can buy you a game skin, just dont make it a big deal",
            "dont tell your parents about our chat, they will ruin it",
            "move this to telegram because this chat logs everything",
            "send a selfie there so i know its really you",
            "delete this thread after, nobody needs to see us talking",
        ],
    }
}

fn bullying_stages(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "ніхто тебе тут не хоче бачити",
            "всі сміються з твого відео",
            "ти нікому не потрібен, просто вийди",
            "завтра вся школа буде з тебе ржати",
        ],
        "ru" => &[
            "никто не хочет тебя тут видеть",
            "все смеются с твоего видео",
            "ты никому не нужен, просто выйди",
            "завтра вся школа будет над тобой смеяться",
        ],
        _ => &[
            "nobody wants you here anymore",
            "everyone is laughing at your video",
            "you are pathetic, just leave the chat",
            "tomorrow the whole school will laugh at you",
        ],
    }
}

fn manipulation_stages(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "я купив тобі подарунок, тепер ти мені винна",
            "скинь пароль на хвилину, не драматизуй",
            "якщо не зробиш як я кажу, я покажу всім скріни",
            "це буде твоя провина, ти сама мене змусила",
        ],
        "ru" => &[
            "я купил тебе подарок, теперь ты мне должна",
            "скинь пароль на минуту, не драматизируй",
            "если не сделаешь как я сказал, я покажу всем скрины",
            "это будет твоя вина, ты сама меня заставила",
        ],
        _ => &[
            "i bought you a gift, now you owe me",
            "send your password for a minute, dont be dramatic",
            "if you dont do what i say, ill show everyone screenshots",
            "this will be your fault because you made me do it",
        ],
    }
}

fn selfharm_stages(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "мені здається всім буде краще без мене",
            "я більше не хочу жити",
            "не бачу сенсу прокидатися завтра",
        ],
        "ru" => &[
            "мне кажется всем будет лучше без меня",
            "я больше не хочу жить",
            "не вижу смысла просыпаться завтра",
        ],
        _ => &[
            "everyone would be better off without me",
            "i dont want to live anymore",
            "i dont see a reason to wake up tomorrow",
        ],
    }
}

fn phishing_stages(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "безкоштовні скіни тут https://free-skins.example/claim",
            "акаунт заблокують за 10 хв, підтверди https://verify-login.example",
        ],
        "ru" => &[
            "бесплатные скины тут https://free-skins.example/claim",
            "аккаунт заблокируют через 10 мин, подтверди https://verify-login.example",
        ],
        _ => &[
            "free skins here https://free-skins.example/claim",
            "your account locks in 10 min, verify https://verify-login.example",
        ],
    }
}

fn pii_stages(language: &str) -> &'static [&'static str] {
    match language {
        "uk" => &[
            "мій номер 0671234567, подзвони після уроків",
            "я сама вдома до дев'ятої, мама на роботі",
            "я живу на Шевченка 15, квартира 42",
        ],
        "ru" => &[
            "мой номер 89161234567, позвони после уроков",
            "я одна дома до девяти, мама на работе",
            "я живу на Ленина 15, квартира 42",
        ],
        _ => &[
            "my number is 555-0123, call me after class",
            "im home alone until nine while mom is at work",
            "i live at 123 main street apartment 5",
        ],
    }
}

fn threshold_for(threat: ThreatType) -> f32 {
    match threat {
        ThreatType::SelfHarm => 0.70,
        ThreatType::Bullying => 0.55,
        ThreatType::Phishing | ThreatType::Scam | ThreatType::Spam => 0.60,
        ThreatType::PiiLeakage => 0.50,
        ThreatType::Grooming | ThreatType::Manipulation => 0.55,
        _ => 0.55,
    }
}

fn client_safety_telemetry_from_result(
    event: &SimEvent,
    result: &aura_core::AnalysisResult,
    detected_score: f32,
) -> Option<ClientSafetyTelemetryEvent> {
    if result.threat_type == ThreatType::None {
        return None;
    }

    let threshold = threshold_for(result.threat_type);
    if detected_score < threshold && result.action == Action::Allow {
        return None;
    }

    Some(ClientSafetyTelemetryEvent {
        // In production these are stable, privacy-preserving tokens, not raw
        // identifiers. The simulation keeps readable IDs so reports remain
        // debuggable.
        sender_token: event.sender_id.clone(),
        protected_account_token: event.child_id.clone(),
        surface: event.surface.label(),
        threat_type: result.threat_type,
        severity: telemetry_severity_bucket(result.action, detected_score),
        confidence: telemetry_confidence_bucket(result.action, detected_score),
        timestamp_hour: event.timestamp_ms / 3_600_000,
        action: result.action,
    })
}

fn telemetry_severity_bucket(action: Action, score: f32) -> TelemetrySeverityBucket {
    match action {
        Action::Block => TelemetrySeverityBucket::Critical,
        Action::Warn => TelemetrySeverityBucket::High,
        Action::Blur | Action::Mark => TelemetrySeverityBucket::Medium,
        Action::Allow if score >= 0.90 => TelemetrySeverityBucket::High,
        Action::Allow if score >= 0.65 => TelemetrySeverityBucket::Medium,
        Action::Allow => TelemetrySeverityBucket::Low,
    }
}

fn telemetry_confidence_bucket(action: Action, score: f32) -> TelemetryConfidenceBucket {
    match action {
        Action::Block | Action::Warn if score >= 0.75 => TelemetryConfidenceBucket::High,
        Action::Blur | Action::Mark if score >= 0.55 => TelemetryConfidenceBucket::Medium,
        _ if score >= 0.85 => TelemetryConfidenceBucket::High,
        _ if score >= 0.60 => TelemetryConfidenceBucket::Medium,
        _ => TelemetryConfidenceBucket::Low,
    }
}

fn server_hint_label(hint: Option<f32>) -> &'static str {
    match hint {
        Some(score) if score >= 0.70 => "high",
        Some(score) if score >= 0.40 => "medium",
        Some(score) if score > 0.0 => "low",
        _ => "none",
    }
}

fn record_sender(
    senders: &mut HashMap<String, SenderRiskRow>,
    event: &SimEvent,
    result: &aura_core::AnalysisResult,
    expected_detected: bool,
    false_positive: bool,
) {
    let row = senders
        .entry(event.sender_id.clone())
        .or_insert_with(|| SenderRiskRow {
            sender_id: event.sender_id.clone(),
            ..SenderRiskRow::default()
        });
    row.events += 1;
    row.max_score = row.max_score.max(result.score);
    *row.surfaces
        .entry(event.surface.label().to_string())
        .or_default() += 1;

    if event.expected_threat.is_some() {
        row.positives += 1;
        if expected_detected {
            row.positives_detected += 1;
        }
    }
    if false_positive {
        row.false_positives += 1;
    }
    if result.is_threat() {
        row.threat_events += 1;
        *row.threats
            .entry(format!("{:?}", result.threat_type))
            .or_default() += 1;
    }
}

fn top_reason_codes(result: &aura_core::AnalysisResult) -> Vec<String> {
    result.reason_codes.iter().take(8).cloned().collect()
}

fn metric_rows(map: BTreeMap<String, MetricCounts>) -> Vec<MetricRow> {
    map.into_iter()
        .map(|(name, counts)| MetricRow { name, counts })
        .collect()
}

fn merge_metric_rows(target: &mut BTreeMap<String, MetricCounts>, rows: &[MetricRow]) {
    for row in rows {
        target
            .entry(row.name.clone())
            .or_default()
            .merge(&row.counts);
    }
}

fn top_senders(senders: HashMap<String, SenderRiskRow>) -> Vec<SenderRiskRow> {
    let mut rows = senders.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        b.threat_events
            .cmp(&a.threat_events)
            .then_with(|| b.positives_detected.cmp(&a.positives_detected))
            .then_with(|| b.max_score.total_cmp(&a.max_score))
            .then_with(|| a.sender_id.cmp(&b.sender_id))
    });
    rows.truncate(25);
    rows
}

fn evaluate_gates(
    total: &MetricCounts,
    by_kind: &BTreeMap<String, MetricCounts>,
    by_surface: &BTreeMap<String, MetricCounts>,
    by_scenario: &BTreeMap<String, MetricCounts>,
    by_text_variant: &BTreeMap<String, MetricCounts>,
    by_server_hint: &BTreeMap<String, MetricCounts>,
    args: &Args,
) -> GateReport {
    let positive_kind_coverage = required_positive_kind_coverage(by_kind);
    let surface_coverage = required_surface_coverage(by_surface);
    let scenario_coverage = required_scenario_coverage(by_scenario);
    let min_scenario_detect_rate = min_positive_scenario_detect_rate(by_scenario);
    let max_scenario_fp_rate = max_scenario_fp_rate(by_scenario);
    let min_kind_detect_rate = min_required_positive_kind_detect_rate(by_kind);
    let max_surface_fp_rate = max_required_surface_fp_rate(by_surface);
    let text_variant_coverage = text_variant_coverage(by_text_variant, &args.text_variants);
    let text_variant_positive_coverage =
        text_variant_positive_coverage(by_text_variant, &args.text_variants);
    let min_text_variant_detect_rate =
        min_text_variant_detect_rate(by_text_variant, &args.text_variants);
    let max_text_variant_fp_rate = max_text_variant_fp_rate(by_text_variant, &args.text_variants);
    let server_hint_positive_events = server_hint_positive_events(by_server_hint);
    let server_hint_detect_rate = server_hint_detect_rate(by_server_hint);
    let server_hint_fp_rate = server_hint_fp_rate(by_server_hint);

    let mut checks = vec![
        GateCheck {
            name: "min_positive_detect_rate".to_string(),
            actual: total.detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: total.detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "max_safe_false_positive_rate".to_string(),
            actual: total.fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: total.fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "positive_event_kinds_covered".to_string(),
            actual: positive_kind_coverage as f64,
            threshold: REQUIRED_POSITIVE_KIND_LABELS.len() as f64,
            comparison: "at_least".to_string(),
            passed: positive_kind_coverage == REQUIRED_POSITIVE_KIND_LABELS.len(),
        },
        GateCheck {
            name: "surfaces_covered".to_string(),
            actual: surface_coverage as f64,
            threshold: REQUIRED_SURFACE_LABELS.len() as f64,
            comparison: "at_least".to_string(),
            passed: surface_coverage == REQUIRED_SURFACE_LABELS.len(),
        },
        GateCheck {
            name: "scenarios_covered".to_string(),
            actual: scenario_coverage as f64,
            threshold: REQUIRED_SCENARIO_LABELS.len() as f64,
            comparison: "at_least".to_string(),
            passed: scenario_coverage == REQUIRED_SCENARIO_LABELS.len(),
        },
        GateCheck {
            name: "min_event_kind_positive_detect_rate".to_string(),
            actual: min_kind_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: min_kind_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "min_scenario_positive_detect_rate".to_string(),
            actual: min_scenario_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: min_scenario_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "max_surface_safe_false_positive_rate".to_string(),
            actual: max_surface_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: max_surface_fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "max_scenario_safe_false_positive_rate".to_string(),
            actual: max_scenario_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: max_scenario_fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "text_variants_covered".to_string(),
            actual: text_variant_coverage as f64,
            threshold: args.text_variants.len() as f64,
            comparison: "at_least".to_string(),
            passed: text_variant_coverage == args.text_variants.len(),
        },
        GateCheck {
            name: "text_variants_with_positive_events".to_string(),
            actual: text_variant_positive_coverage as f64,
            threshold: args.text_variants.len() as f64,
            comparison: "at_least".to_string(),
            passed: text_variant_positive_coverage == args.text_variants.len(),
        },
        GateCheck {
            name: "min_text_variant_positive_detect_rate".to_string(),
            actual: min_text_variant_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: min_text_variant_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "max_text_variant_safe_false_positive_rate".to_string(),
            actual: max_text_variant_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: max_text_variant_fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "server_hint_positive_events".to_string(),
            actual: server_hint_positive_events as f64,
            threshold: 1.0,
            comparison: "at_least".to_string(),
            passed: server_hint_positive_events > 0,
        },
        GateCheck {
            name: "server_hint_positive_detect_rate".to_string(),
            actual: server_hint_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: server_hint_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "server_hint_safe_false_positive_rate".to_string(),
            actual: server_hint_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: server_hint_fp_rate <= args.max_safe_fp_rate,
        },
    ];
    if let Some(max_elapsed_ms) = args.max_elapsed_ms {
        checks.push(GateCheck {
            name: "max_elapsed_ms".to_string(),
            actual: 0.0,
            threshold: max_elapsed_ms as f64,
            comparison: "at_most".to_string(),
            passed: true,
        });
    }
    GateReport {
        passed: checks.iter().all(|check| check.passed),
        fail_on_gate: args.fail_on_gate,
        checks,
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_matrix_gates(
    total: &MetricCounts,
    seed_reports: &[SeedMatrixRow],
    by_kind: &BTreeMap<String, MetricCounts>,
    by_surface: &BTreeMap<String, MetricCounts>,
    by_scenario: &BTreeMap<String, MetricCounts>,
    by_text_variant: &BTreeMap<String, MetricCounts>,
    by_server_hint: &BTreeMap<String, MetricCounts>,
    elapsed_ms: u128,
    args: &Args,
) -> GateReport {
    let min_seed_detect_rate = seed_reports
        .iter()
        .map(|row| row.detect_rate)
        .fold(1.0, f64::min);
    let max_seed_fp_rate = seed_reports
        .iter()
        .map(|row| row.fp_rate)
        .fold(0.0, f64::max);
    let all_seed_gates_passed = seed_reports.iter().all(|row| row.gates_passed);
    let positive_kind_coverage = required_positive_kind_coverage(by_kind);
    let surface_coverage = required_surface_coverage(by_surface);
    let scenario_coverage = required_scenario_coverage(by_scenario);
    let min_scenario_detect_rate = min_positive_scenario_detect_rate(by_scenario);
    let max_scenario_fp_rate = max_scenario_fp_rate(by_scenario);
    let min_kind_detect_rate = min_required_positive_kind_detect_rate(by_kind);
    let max_surface_fp_rate = max_required_surface_fp_rate(by_surface);
    let text_variant_coverage = text_variant_coverage(by_text_variant, &args.text_variants);
    let text_variant_positive_coverage =
        text_variant_positive_coverage(by_text_variant, &args.text_variants);
    let min_text_variant_detect_rate =
        min_text_variant_detect_rate(by_text_variant, &args.text_variants);
    let max_text_variant_fp_rate = max_text_variant_fp_rate(by_text_variant, &args.text_variants);
    let server_hint_positive_events = server_hint_positive_events(by_server_hint);
    let server_hint_detect_rate = server_hint_detect_rate(by_server_hint);
    let server_hint_fp_rate = server_hint_fp_rate(by_server_hint);

    let mut checks = vec![
        GateCheck {
            name: "aggregate_min_positive_detect_rate".to_string(),
            actual: total.detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: total.detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "aggregate_max_safe_false_positive_rate".to_string(),
            actual: total.fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: total.fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "per_seed_min_positive_detect_rate".to_string(),
            actual: min_seed_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: min_seed_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "per_seed_max_safe_false_positive_rate".to_string(),
            actual: max_seed_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: max_seed_fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "all_seed_gates_pass".to_string(),
            actual: if all_seed_gates_passed { 1.0 } else { 0.0 },
            threshold: 1.0,
            comparison: "at_least".to_string(),
            passed: all_seed_gates_passed,
        },
        GateCheck {
            name: "positive_event_kinds_covered".to_string(),
            actual: positive_kind_coverage as f64,
            threshold: REQUIRED_POSITIVE_KIND_LABELS.len() as f64,
            comparison: "at_least".to_string(),
            passed: positive_kind_coverage == REQUIRED_POSITIVE_KIND_LABELS.len(),
        },
        GateCheck {
            name: "surfaces_covered".to_string(),
            actual: surface_coverage as f64,
            threshold: REQUIRED_SURFACE_LABELS.len() as f64,
            comparison: "at_least".to_string(),
            passed: surface_coverage == REQUIRED_SURFACE_LABELS.len(),
        },
        GateCheck {
            name: "scenarios_covered".to_string(),
            actual: scenario_coverage as f64,
            threshold: REQUIRED_SCENARIO_LABELS.len() as f64,
            comparison: "at_least".to_string(),
            passed: scenario_coverage == REQUIRED_SCENARIO_LABELS.len(),
        },
        GateCheck {
            name: "min_event_kind_positive_detect_rate".to_string(),
            actual: min_kind_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: min_kind_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "min_scenario_positive_detect_rate".to_string(),
            actual: min_scenario_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: min_scenario_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "max_surface_safe_false_positive_rate".to_string(),
            actual: max_surface_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: max_surface_fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "max_scenario_safe_false_positive_rate".to_string(),
            actual: max_scenario_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: max_scenario_fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "text_variants_covered".to_string(),
            actual: text_variant_coverage as f64,
            threshold: args.text_variants.len() as f64,
            comparison: "at_least".to_string(),
            passed: text_variant_coverage == args.text_variants.len(),
        },
        GateCheck {
            name: "text_variants_with_positive_events".to_string(),
            actual: text_variant_positive_coverage as f64,
            threshold: args.text_variants.len() as f64,
            comparison: "at_least".to_string(),
            passed: text_variant_positive_coverage == args.text_variants.len(),
        },
        GateCheck {
            name: "min_text_variant_positive_detect_rate".to_string(),
            actual: min_text_variant_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: min_text_variant_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "max_text_variant_safe_false_positive_rate".to_string(),
            actual: max_text_variant_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: max_text_variant_fp_rate <= args.max_safe_fp_rate,
        },
        GateCheck {
            name: "server_hint_positive_events".to_string(),
            actual: server_hint_positive_events as f64,
            threshold: 1.0,
            comparison: "at_least".to_string(),
            passed: server_hint_positive_events > 0,
        },
        GateCheck {
            name: "server_hint_positive_detect_rate".to_string(),
            actual: server_hint_detect_rate,
            threshold: args.min_detect_rate,
            comparison: "at_least".to_string(),
            passed: server_hint_detect_rate >= args.min_detect_rate,
        },
        GateCheck {
            name: "server_hint_safe_false_positive_rate".to_string(),
            actual: server_hint_fp_rate,
            threshold: args.max_safe_fp_rate,
            comparison: "at_most".to_string(),
            passed: server_hint_fp_rate <= args.max_safe_fp_rate,
        },
    ];

    if let Some(max_elapsed_ms) = args.max_elapsed_ms {
        checks.push(GateCheck {
            name: "max_matrix_elapsed_ms".to_string(),
            actual: elapsed_ms as f64,
            threshold: max_elapsed_ms as f64,
            comparison: "at_most".to_string(),
            passed: elapsed_ms <= max_elapsed_ms,
        });
    }

    GateReport {
        passed: checks.iter().all(|check| check.passed),
        fail_on_gate: args.fail_on_gate,
        checks,
    }
}

fn required_positive_kind_coverage(by_kind: &BTreeMap<String, MetricCounts>) -> usize {
    REQUIRED_POSITIVE_KIND_LABELS
        .iter()
        .filter(|kind| {
            by_kind
                .get(**kind)
                .is_some_and(|counts| counts.positives > 0)
        })
        .count()
}

fn required_surface_coverage(by_surface: &BTreeMap<String, MetricCounts>) -> usize {
    REQUIRED_SURFACE_LABELS
        .iter()
        .filter(|surface| {
            by_surface
                .get(**surface)
                .is_some_and(|counts| counts.events > 0)
        })
        .count()
}

fn required_scenario_coverage(by_scenario: &BTreeMap<String, MetricCounts>) -> usize {
    REQUIRED_SCENARIO_LABELS
        .iter()
        .filter(|scenario| {
            by_scenario
                .get(**scenario)
                .is_some_and(|counts| counts.events > 0)
        })
        .count()
}

fn min_required_positive_kind_detect_rate(by_kind: &BTreeMap<String, MetricCounts>) -> f64 {
    REQUIRED_POSITIVE_KIND_LABELS
        .iter()
        .map(|kind| {
            by_kind
                .get(*kind)
                .filter(|counts| counts.positives > 0)
                .map_or(0.0, |counts| counts.detect_rate)
        })
        .fold(1.0, f64::min)
}

fn min_positive_scenario_detect_rate(by_scenario: &BTreeMap<String, MetricCounts>) -> f64 {
    REQUIRED_SCENARIO_LABELS
        .iter()
        .filter_map(|scenario| {
            by_scenario
                .get(*scenario)
                .filter(|counts| counts.positives > 0)
                .map(|counts| counts.detect_rate)
        })
        .fold(1.0, f64::min)
}

fn max_required_surface_fp_rate(by_surface: &BTreeMap<String, MetricCounts>) -> f64 {
    REQUIRED_SURFACE_LABELS
        .iter()
        .map(|surface| {
            by_surface
                .get(*surface)
                .filter(|counts| counts.negatives > 0)
                .map_or(0.0, |counts| counts.fp_rate)
        })
        .fold(0.0, f64::max)
}

fn max_scenario_fp_rate(by_scenario: &BTreeMap<String, MetricCounts>) -> f64 {
    REQUIRED_SCENARIO_LABELS
        .iter()
        .map(|scenario| {
            by_scenario
                .get(*scenario)
                .filter(|counts| counts.negatives > 0)
                .map_or(0.0, |counts| counts.fp_rate)
        })
        .fold(0.0, f64::max)
}

fn text_variant_coverage(
    by_text_variant: &BTreeMap<String, MetricCounts>,
    configured_variants: &[TextVariant],
) -> usize {
    configured_variants
        .iter()
        .filter(|variant| {
            by_text_variant
                .get(variant.label())
                .is_some_and(|counts| counts.events > 0)
        })
        .count()
}

fn text_variant_positive_coverage(
    by_text_variant: &BTreeMap<String, MetricCounts>,
    configured_variants: &[TextVariant],
) -> usize {
    configured_variants
        .iter()
        .filter(|variant| {
            by_text_variant
                .get(variant.label())
                .is_some_and(|counts| counts.positives > 0)
        })
        .count()
}

fn min_text_variant_detect_rate(
    by_text_variant: &BTreeMap<String, MetricCounts>,
    configured_variants: &[TextVariant],
) -> f64 {
    configured_variants
        .iter()
        .map(|variant| {
            by_text_variant
                .get(variant.label())
                .filter(|counts| counts.positives > 0)
                .map_or(0.0, |counts| counts.detect_rate)
        })
        .fold(1.0, f64::min)
}

fn max_text_variant_fp_rate(
    by_text_variant: &BTreeMap<String, MetricCounts>,
    configured_variants: &[TextVariant],
) -> f64 {
    configured_variants
        .iter()
        .map(|variant| {
            by_text_variant
                .get(variant.label())
                .filter(|counts| counts.negatives > 0)
                .map_or(0.0, |counts| counts.fp_rate)
        })
        .fold(0.0, f64::max)
}

fn server_hint_positive_events(by_server_hint: &BTreeMap<String, MetricCounts>) -> usize {
    SERVER_HINTED_LABELS
        .iter()
        .filter_map(|label| by_server_hint.get(*label))
        .map(|counts| counts.positives)
        .sum()
}

fn server_hint_detect_rate(by_server_hint: &BTreeMap<String, MetricCounts>) -> f64 {
    let mut counts = MetricCounts::default();
    for label in SERVER_HINTED_LABELS {
        if let Some(row) = by_server_hint.get(*label) {
            counts.merge(row);
        }
    }
    if counts.positives == 0 {
        0.0
    } else {
        counts.detect_rate
    }
}

fn server_hint_fp_rate(by_server_hint: &BTreeMap<String, MetricCounts>) -> f64 {
    let mut counts = MetricCounts::default();
    for label in SERVER_HINTED_LABELS {
        if let Some(row) = by_server_hint.get(*label) {
            counts.merge(row);
        }
    }
    counts.fp_rate
}

fn evaluate_runtime_gate(report: &mut CommunitySimReport, args: &Args) {
    let Some(max_elapsed_ms) = args.max_elapsed_ms else {
        return;
    };

    if let Some(check) = report
        .gates
        .checks
        .iter_mut()
        .find(|check| check.name == "max_elapsed_ms")
    {
        check.actual = report.elapsed_ms as f64;
        check.threshold = max_elapsed_ms as f64;
        check.passed = report.elapsed_ms <= max_elapsed_ms;
    }
    report.gates.passed = report.gates.checks.iter().all(|check| check.passed);
}

fn apply_baseline_to_sim_report(
    report: &mut CommunitySimReport,
    args: &Args,
) -> Result<(), String> {
    let Some(comparison) =
        load_baseline_comparison(args, &report.total, &report.by_kind, &report.by_surface)?
    else {
        return Ok(());
    };
    append_baseline_gate_checks(&mut report.gates, &comparison);
    report.baseline = Some(comparison);
    Ok(())
}

fn apply_baseline_to_matrix_report(
    report: &mut CommunityMatrixReport,
    args: &Args,
) -> Result<(), String> {
    let Some(comparison) =
        load_baseline_comparison(args, &report.total, &report.by_kind, &report.by_surface)?
    else {
        return Ok(());
    };
    append_baseline_gate_checks(&mut report.gates, &comparison);
    report.baseline = Some(comparison);
    Ok(())
}

fn load_baseline_comparison(
    args: &Args,
    current: &MetricCounts,
    current_by_kind: &[MetricRow],
    current_by_surface: &[MetricRow],
) -> Result<Option<BaselineComparison>, String> {
    let Some(path) = &args.baseline_json else {
        return Ok(None);
    };

    let raw = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let value = serde_json::from_str::<serde_json::Value>(&raw)
        .map_err(|err| format!("{}: invalid JSON: {err}", path.display()))?;
    let baseline_detect_rate = json_path_f64(&value, &["total", "detect_rate"])
        .ok_or_else(|| format!("{}: missing total.detect_rate", path.display()))?;
    let baseline_fp_rate = json_path_f64(&value, &["total", "fp_rate"])
        .ok_or_else(|| format!("{}: missing total.fp_rate", path.display()))?;
    let detect_rate_drop = (baseline_detect_rate - current.detect_rate).max(0.0);
    let fp_rate_rise = (current.fp_rate - baseline_fp_rate).max(0.0);
    let worst_event_kind_detect_drop = worst_event_kind_detect_drop(&value, current_by_kind);
    let worst_surface_fp_rate_rise = worst_surface_fp_rate_rise(&value, current_by_surface);
    let event_kind_pass = worst_event_kind_detect_drop
        .as_ref()
        .is_none_or(|delta| delta.delta <= args.max_detect_rate_drop);
    let surface_pass = worst_surface_fp_rate_rise
        .as_ref()
        .is_none_or(|delta| delta.delta <= args.max_fp_rate_rise);

    Ok(Some(BaselineComparison {
        path: path.display().to_string(),
        schema_version: value
            .get("schema_version")
            .and_then(|schema| schema.as_str())
            .map(str::to_string),
        baseline_total_events: value
            .get("total_events")
            .and_then(|events| events.as_u64())
            .map(|events| events as usize),
        baseline_detect_rate,
        current_detect_rate: current.detect_rate,
        detect_rate_drop,
        max_detect_rate_drop: args.max_detect_rate_drop,
        baseline_fp_rate,
        current_fp_rate: current.fp_rate,
        fp_rate_rise,
        max_fp_rate_rise: args.max_fp_rate_rise,
        worst_event_kind_detect_drop,
        worst_surface_fp_rate_rise,
        passed: detect_rate_drop <= args.max_detect_rate_drop
            && fp_rate_rise <= args.max_fp_rate_rise
            && event_kind_pass
            && surface_pass,
    }))
}

fn append_baseline_gate_checks(gates: &mut GateReport, comparison: &BaselineComparison) {
    gates.checks.extend([
        GateCheck {
            name: "baseline_max_detect_rate_drop".to_string(),
            actual: comparison.detect_rate_drop,
            threshold: comparison.max_detect_rate_drop,
            comparison: "at_most".to_string(),
            passed: comparison.detect_rate_drop <= comparison.max_detect_rate_drop,
        },
        GateCheck {
            name: "baseline_max_safe_fp_rate_rise".to_string(),
            actual: comparison.fp_rate_rise,
            threshold: comparison.max_fp_rate_rise,
            comparison: "at_most".to_string(),
            passed: comparison.fp_rate_rise <= comparison.max_fp_rate_rise,
        },
    ]);
    if let Some(delta) = &comparison.worst_event_kind_detect_drop {
        gates.checks.push(GateCheck {
            name: "baseline_max_event_kind_detect_rate_drop".to_string(),
            actual: delta.delta,
            threshold: comparison.max_detect_rate_drop,
            comparison: "at_most".to_string(),
            passed: delta.delta <= comparison.max_detect_rate_drop,
        });
    }
    if let Some(delta) = &comparison.worst_surface_fp_rate_rise {
        gates.checks.push(GateCheck {
            name: "baseline_max_surface_safe_fp_rate_rise".to_string(),
            actual: delta.delta,
            threshold: comparison.max_fp_rate_rise,
            comparison: "at_most".to_string(),
            passed: delta.delta <= comparison.max_fp_rate_rise,
        });
    }
    gates.passed = gates.checks.iter().all(|check| check.passed);
}

fn json_path_f64(value: &serde_json::Value, path: &[&str]) -> Option<f64> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_f64()
}

fn worst_event_kind_detect_drop(
    baseline: &serde_json::Value,
    current_by_kind: &[MetricRow],
) -> Option<SliceBaselineDelta> {
    REQUIRED_POSITIVE_KIND_LABELS
        .iter()
        .filter_map(|kind| {
            let baseline_rate = json_metric_row_rate(baseline, "by_kind", kind, "detect_rate")?;
            let current_rate = current_metric_row_rate(current_by_kind, kind, |counts| {
                if counts.positives > 0 {
                    Some(counts.detect_rate)
                } else {
                    None
                }
            })
            .unwrap_or(0.0);
            Some(SliceBaselineDelta {
                name: (*kind).to_string(),
                baseline_rate,
                current_rate,
                delta: (baseline_rate - current_rate).max(0.0),
            })
        })
        .max_by(|a, b| {
            a.delta
                .total_cmp(&b.delta)
                .then_with(|| a.name.cmp(&b.name))
        })
}

fn worst_surface_fp_rate_rise(
    baseline: &serde_json::Value,
    current_by_surface: &[MetricRow],
) -> Option<SliceBaselineDelta> {
    REQUIRED_SURFACE_LABELS
        .iter()
        .filter_map(|surface| {
            let baseline_rate = json_metric_row_rate(baseline, "by_surface", surface, "fp_rate")?;
            let current_rate =
                current_metric_row_rate(current_by_surface, surface, |counts| Some(counts.fp_rate))
                    .unwrap_or(0.0);
            Some(SliceBaselineDelta {
                name: (*surface).to_string(),
                baseline_rate,
                current_rate,
                delta: (current_rate - baseline_rate).max(0.0),
            })
        })
        .max_by(|a, b| {
            a.delta
                .total_cmp(&b.delta)
                .then_with(|| a.name.cmp(&b.name))
        })
}

fn json_metric_row_rate(
    value: &serde_json::Value,
    row_key: &str,
    name: &str,
    rate_key: &str,
) -> Option<f64> {
    value
        .get(row_key)?
        .as_array()?
        .iter()
        .find(|row| row.get("name").and_then(|name| name.as_str()) == Some(name))?
        .get("counts")?
        .get(rate_key)?
        .as_f64()
}

fn current_metric_row_rate(
    rows: &[MetricRow],
    name: &str,
    rate: impl FnOnce(&MetricCounts) -> Option<f64>,
) -> Option<f64> {
    rows.iter()
        .find(|row| row.name == name)
        .and_then(|row| rate(&row.counts))
}

fn apply_history_to_sim_report(report: &mut CommunitySimReport, args: &Args) -> Result<(), String> {
    report.history = load_history_summary(args, &report.total)?;
    append_history_gate_checks(&mut report.gates, report.history.as_mut(), args);
    Ok(())
}

fn apply_history_to_matrix_report(
    report: &mut CommunityMatrixReport,
    args: &Args,
) -> Result<(), String> {
    report.history = load_history_summary(args, &report.total)?;
    append_history_gate_checks(&mut report.gates, report.history.as_mut(), args);
    Ok(())
}

fn load_history_summary(
    args: &Args,
    current: &MetricCounts,
) -> Result<Option<HistorySummary>, String> {
    let Some(path) = &args.history_ndjson else {
        return Ok(None);
    };

    if !path.exists() {
        return Ok(Some(empty_history_summary(
            path,
            args.history_window,
            current,
        )));
    }

    let raw = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let mut runs = Vec::new();
    for (line_idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = serde_json::from_str::<serde_json::Value>(line)
            .map_err(|err| format!("{}:{}: invalid JSON: {err}", path.display(), line_idx + 1))?;
        if let Some(run) = history_run_from_json(&value) {
            runs.push(run);
        }
    }

    let keep = args.history_window.min(runs.len());
    let start = runs.len().saturating_sub(keep);
    let recent_runs = runs[start..].to_vec();
    Ok(Some(history_summary_from_runs(
        path,
        args.history_window,
        current,
        recent_runs,
    )))
}

fn empty_history_summary(
    path: &Path,
    window_size: usize,
    current: &MetricCounts,
) -> HistorySummary {
    HistorySummary {
        path: path.display().to_string(),
        window_size,
        gate_enabled: false,
        gate_passed: None,
        max_detect_rate_drop: 0.0,
        max_fp_rate_rise: 0.0,
        loaded_runs: 0,
        avg_detect_rate: 0.0,
        avg_fp_rate: 0.0,
        min_detect_rate: 0.0,
        max_fp_rate: 0.0,
        current_detect_rate: current.detect_rate,
        current_fp_rate: current.fp_rate,
        current_vs_latest_detect_delta: None,
        current_vs_latest_fp_delta: None,
        current_vs_window_avg_detect_delta: None,
        current_vs_window_avg_fp_delta: None,
        recent_gate_failures: 0,
        recent_runs: Vec::new(),
    }
}

fn history_summary_from_runs(
    path: &Path,
    window_size: usize,
    current: &MetricCounts,
    recent_runs: Vec<HistoryRunSummary>,
) -> HistorySummary {
    if recent_runs.is_empty() {
        return empty_history_summary(path, window_size, current);
    }

    let loaded_runs = recent_runs.len();
    let avg_detect_rate =
        recent_runs.iter().map(|run| run.detect_rate).sum::<f64>() / loaded_runs as f64;
    let avg_fp_rate = recent_runs.iter().map(|run| run.fp_rate).sum::<f64>() / loaded_runs as f64;
    let min_detect_rate = recent_runs
        .iter()
        .map(|run| run.detect_rate)
        .fold(1.0, f64::min);
    let max_fp_rate = recent_runs
        .iter()
        .map(|run| run.fp_rate)
        .fold(0.0, f64::max);
    let latest = recent_runs.last();
    let recent_gate_failures = recent_runs
        .iter()
        .filter(|run| run.gates_passed == Some(false))
        .count();

    HistorySummary {
        path: path.display().to_string(),
        window_size,
        gate_enabled: false,
        gate_passed: None,
        max_detect_rate_drop: 0.0,
        max_fp_rate_rise: 0.0,
        loaded_runs,
        avg_detect_rate,
        avg_fp_rate,
        min_detect_rate,
        max_fp_rate,
        current_detect_rate: current.detect_rate,
        current_fp_rate: current.fp_rate,
        current_vs_latest_detect_delta: latest.map(|run| current.detect_rate - run.detect_rate),
        current_vs_latest_fp_delta: latest.map(|run| current.fp_rate - run.fp_rate),
        current_vs_window_avg_detect_delta: Some(current.detect_rate - avg_detect_rate),
        current_vs_window_avg_fp_delta: Some(current.fp_rate - avg_fp_rate),
        recent_gate_failures,
        recent_runs,
    }
}

fn history_run_from_json(value: &serde_json::Value) -> Option<HistoryRunSummary> {
    let total = value.get("total")?;
    Some(HistoryRunSummary {
        schema_version: value
            .get("schema_version")
            .and_then(|schema| schema.as_str())
            .map(str::to_string),
        generated_at_unix_ms: value
            .get("generated_at_unix_ms")
            .and_then(|generated| generated.as_u64())
            .map(u128::from),
        profile: value
            .get("profile")
            .and_then(|profile| profile.as_str())
            .map(str::to_string),
        total_events: value
            .get("total_events")
            .and_then(|events| events.as_u64())
            .unwrap_or(0) as usize,
        detect_rate: total.get("detect_rate")?.as_f64()?,
        fp_rate: total.get("fp_rate")?.as_f64()?,
        finding_count: value
            .get("findings")
            .and_then(|findings| findings.as_array())
            .map_or(0, Vec::len),
        gates_passed: value
            .get("gates")
            .and_then(|gates| gates.get("passed"))
            .and_then(|passed| passed.as_bool()),
    })
}

fn append_history_gate_checks(
    gates: &mut GateReport,
    history: Option<&mut HistorySummary>,
    args: &Args,
) {
    let Some(history) = history else {
        return;
    };
    if !args.history_gate {
        return;
    }

    history.gate_enabled = true;
    history.max_detect_rate_drop = args.max_detect_rate_drop;
    history.max_fp_rate_rise = args.max_fp_rate_rise;

    if history.loaded_runs == 0 {
        gates.checks.push(GateCheck {
            name: "history_has_prior_runs".to_string(),
            actual: 0.0,
            threshold: 1.0,
            comparison: "at_least".to_string(),
            passed: false,
        });
        history.gate_passed = Some(false);
        gates.passed = false;
        return;
    }

    let latest_detect_drop = detect_drop(history.current_vs_latest_detect_delta);
    let latest_fp_rise = fp_rise(history.current_vs_latest_fp_delta);
    let average_detect_drop = detect_drop(history.current_vs_window_avg_detect_delta);
    let average_fp_rise = fp_rise(history.current_vs_window_avg_fp_delta);

    gates.checks.extend([
        GateCheck {
            name: "history_latest_max_detect_rate_drop".to_string(),
            actual: latest_detect_drop,
            threshold: args.max_detect_rate_drop,
            comparison: "at_most".to_string(),
            passed: latest_detect_drop <= args.max_detect_rate_drop,
        },
        GateCheck {
            name: "history_latest_max_safe_fp_rate_rise".to_string(),
            actual: latest_fp_rise,
            threshold: args.max_fp_rate_rise,
            comparison: "at_most".to_string(),
            passed: latest_fp_rise <= args.max_fp_rate_rise,
        },
        GateCheck {
            name: "history_window_avg_max_detect_rate_drop".to_string(),
            actual: average_detect_drop,
            threshold: args.max_detect_rate_drop,
            comparison: "at_most".to_string(),
            passed: average_detect_drop <= args.max_detect_rate_drop,
        },
        GateCheck {
            name: "history_window_avg_max_safe_fp_rate_rise".to_string(),
            actual: average_fp_rise,
            threshold: args.max_fp_rate_rise,
            comparison: "at_most".to_string(),
            passed: average_fp_rise <= args.max_fp_rate_rise,
        },
    ]);

    history.gate_passed = Some(gates.checks.iter().all(|check| check.passed));
    gates.passed = gates.checks.iter().all(|check| check.passed);
}

fn detect_drop(delta: Option<f64>) -> f64 {
    match delta {
        Some(delta) if delta < 0.0 => -delta,
        _ => 0.0,
    }
}

fn fp_rise(delta: Option<f64>) -> f64 {
    match delta {
        Some(delta) if delta > 0.0 => delta,
        _ => 0.0,
    }
}

fn write_report_outputs(args: &Args, report: &CommunitySimReport) -> Result<(), String> {
    if let Some(path) = &args.json {
        write_json_report(path, report)?;
    }

    if let Some(path) = env_path("NDJSON") {
        ensure_parent_dir(&path)?;
        let json = serde_json::to_string(report).map_err(|err| err.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        writeln!(file, "{json}").map_err(|err| format!("{}: {err}", path.display()))?;
        println!("Appended NDJSON report: {}", path.display());
    }

    if env_bool("JSON_STDOUT").unwrap_or(false) {
        let json = serde_json::to_string_pretty(report).map_err(|err| err.to_string())?;
        println!("{json}");
    }

    Ok(())
}

fn write_matrix_report_outputs(args: &Args, report: &CommunityMatrixReport) -> Result<(), String> {
    if let Some(path) = &args.json {
        write_json_report(path, report)?;
    }

    if let Some(path) = env_path("NDJSON") {
        ensure_parent_dir(&path)?;
        let json = serde_json::to_string(report).map_err(|err| err.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        writeln!(file, "{json}").map_err(|err| format!("{}: {err}", path.display()))?;
        println!("Appended NDJSON matrix report: {}", path.display());
    }

    if env_bool("JSON_STDOUT").unwrap_or(false) {
        let json = serde_json::to_string_pretty(report).map_err(|err| err.to_string())?;
        println!("{json}");
    }

    Ok(())
}

fn write_json_report<T: Serialize>(path: &Path, report: &T) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let json = serde_json::to_string_pretty(report).map_err(|err| err.to_string())?;
    fs::write(path, json).map_err(|err| format!("{}: {err}", path.display()))?;
    println!("Wrote JSON report: {}", path.display());
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    Ok(())
}

fn env_path(key: &str) -> Option<PathBuf> {
    scoped_env(key)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn env_rate(key: &str) -> Option<f64> {
    scoped_env(key)
        .and_then(|raw| raw.parse::<f64>().ok())
        .map(|value| if value > 1.0 { value / 100.0 } else { value })
}

fn env_profile(key: &str) -> Result<Option<RunProfile>, String> {
    scoped_env(key)
        .map(|raw| RunProfile::parse(&raw))
        .transpose()
}

fn env_seed_list(key: &str) -> Result<Option<Vec<u64>>, String> {
    scoped_env(key).map(|raw| parse_seed_list(&raw)).transpose()
}

fn env_text_variant_list(key: &str) -> Result<Option<Vec<TextVariant>>, String> {
    scoped_env(key)
        .map(|raw| parse_text_variant_list(&raw))
        .transpose()
}

fn env_usize(key: &str) -> Option<usize> {
    scoped_env(key).and_then(|raw| raw.parse::<usize>().ok())
}

fn env_u64(key: &str) -> Option<u64> {
    scoped_env(key).and_then(|raw| raw.parse::<u64>().ok())
}

fn env_u128(key: &str) -> Option<u128> {
    scoped_env(key).and_then(|raw| raw.parse::<u128>().ok())
}

fn env_bool(key: &str) -> Option<bool> {
    scoped_env(key).and_then(|raw| match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    })
}

fn scoped_env(key: &str) -> Option<String> {
    [
        format!("{ENV_PREFIX}_{key}"),
        format!("{COMMON_PREFIX}_{key}"),
        format!("AURA_{key}"),
    ]
    .into_iter()
    .find_map(|name| env::var(name).ok())
}

fn generated_at_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn print_report(report: &CommunitySimReport) {
    println!("AURA community surface simulation");
    println!(
        "  profile={} seed={} children={} events_per_child={} variants={} total_events={} elapsed={}ms throughput={:.0}/s",
        profile_label(report.profile),
        report.seed,
        report.children,
        report.events_per_child,
        format_text_variants(&report.text_variants),
        report.total_events,
        report.elapsed_ms,
        report.events_per_second
    );
    println!(
        "  positives={}/{} detect_rate={:.1}% negatives={} fp={}/{} fp_rate={:.1}%",
        report.total.positives_detected,
        report.total.positives,
        report.total.detect_rate * 100.0,
        report.total.negatives,
        report.total.false_positives,
        report.total.negatives,
        report.total.fp_rate * 100.0
    );
    println!(
        "  gates={}",
        if report.gates.passed { "PASS" } else { "FAIL" }
    );
    for check in &report.gates.checks {
        let op = if check.comparison == "at_least" {
            ">="
        } else {
            "<="
        };
        println!(
            "    {} actual={} {} threshold={} {}",
            check.name,
            format_gate_value(check),
            op,
            format_gate_threshold(check),
            if check.passed { "ok" } else { "failed" }
        );
    }
    print_baseline_comparison(report.baseline.as_ref());
    print_history_summary(report.history.as_ref());

    print_metric_table("By surface", &report.by_surface);
    print_metric_table("By event kind", &report.by_kind);
    print_metric_table("By scenario", &report.by_scenario);
    print_metric_table("By text variant", &report.by_text_variant);
    print_metric_table("By server hint", &report.by_server_hint);
    print_metric_table("By expected threat", &report.by_expected_threat);

    println!();
    println!(
        "Top detected threats: {}",
        format_counts(&report.detected_threat_counts)
    );
    println!("Actions: {}", format_counts(&report.action_counts));

    println!();
    println!("Top senders");
    for sender in report.top_senders.iter().take(10) {
        println!(
            "  {:<24} events={:<4} threats={:<4} positives={}/{} fp={} max={:.2}",
            sender.sender_id,
            sender.events,
            sender.threat_events,
            sender.positives_detected,
            sender.positives,
            sender.false_positives,
            sender.max_score
        );
    }

    println!();
    if report.findings.is_empty() {
        println!("No misses, wrong-threat positives, or safe false positives.");
    } else {
        println!("First {} findings", report.findings.len().min(20));
        for finding in report.findings.iter().take(20) {
            println!(
                "  #{:<5} {:<14} {:<12} scenario={:<28} variant={:<14} hint={:<6} expected={:?} detected={:?} action={:?} score={:.2} expected_score={} text={}",
                finding.sequence,
                finding.kind,
                finding.surface.label(),
                finding.scenario.label(),
                finding.text_variant.label(),
                format_optional_hint(finding.server_sender_risk_hint),
                finding.expected_threat,
                finding.detected_threat,
                finding.action,
                finding.score,
                format_optional_score(finding.expected_score),
                compact_text(&finding.text)
            );
        }
    }
}

fn print_matrix_report(report: &CommunityMatrixReport) {
    println!("AURA community surface seed matrix");
    println!(
        "  profile={} seeds={} jobs={} children={} events_per_child={} variants={} total_events={} elapsed={}ms throughput={:.0}/s",
        profile_label(report.profile),
        report
            .seeds
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(","),
        report.jobs,
        report.children,
        report.events_per_child,
        format_text_variants(&report.text_variants),
        report.total_events,
        report.elapsed_ms,
        report.events_per_second
    );
    println!(
        "  aggregate positives={}/{} detect_rate={:.1}% negatives={} fp={}/{} fp_rate={:.1}%",
        report.total.positives_detected,
        report.total.positives,
        report.total.detect_rate * 100.0,
        report.total.negatives,
        report.total.false_positives,
        report.total.negatives,
        report.total.fp_rate * 100.0
    );
    println!(
        "  gates={}",
        if report.gates.passed { "PASS" } else { "FAIL" }
    );
    for check in &report.gates.checks {
        let op = if check.comparison == "at_least" {
            ">="
        } else {
            "<="
        };
        println!(
            "    {} actual={} {} threshold={} {}",
            check.name,
            format_gate_value(check),
            op,
            format_gate_threshold(check),
            if check.passed { "ok" } else { "failed" }
        );
    }
    print_baseline_comparison(report.baseline.as_ref());
    print_history_summary(report.history.as_ref());

    println!();
    println!("By seed");
    println!(
        "  {:>8} {:>7} {:>12} {:>8} {:>8} {:>8} {:>7}",
        "seed", "events", "pos_detect", "safe_fp", "wrong", "elapsed", "gates"
    );
    for row in &report.seed_reports {
        println!(
            "  {:>8} {:>7} {:>5}/{:<5} {:>7.1}% {:>8} {:>7}ms {:>7}",
            row.seed,
            row.total_events,
            row.positives_detected,
            row.positives,
            row.fp_rate * 100.0,
            row.wrong_threat_positives,
            row.elapsed_ms,
            if row.gates_passed { "PASS" } else { "FAIL" }
        );
    }

    if let Some(row) = &report.worst_detect_seed {
        println!(
            "  worst detect seed={} detect_rate={:.1}% findings={}",
            row.seed,
            row.detect_rate * 100.0,
            row.finding_count
        );
    }
    if let Some(row) = &report.worst_fp_seed {
        println!(
            "  worst fp seed={} fp_rate={:.1}% findings={}",
            row.seed,
            row.fp_rate * 100.0,
            row.finding_count
        );
    }

    print_metric_table("By surface", &report.by_surface);
    print_metric_table("By event kind", &report.by_kind);
    print_metric_table("By scenario", &report.by_scenario);
    print_metric_table("By text variant", &report.by_text_variant);
    print_metric_table("By server hint", &report.by_server_hint);
    print_metric_table("By expected threat", &report.by_expected_threat);

    println!();
    if report.findings.is_empty() {
        println!("No misses, wrong-threat positives, or safe false positives across seed matrix.");
    } else {
        println!("First {} matrix findings", report.findings.len().min(20));
        for matrix_finding in report.findings.iter().take(20) {
            let finding = &matrix_finding.finding;
            println!(
                "  seed={} #{:<5} {:<14} {:<12} scenario={:<28} variant={:<14} hint={:<6} expected={:?} detected={:?} action={:?} score={:.2} expected_score={} text={}",
                matrix_finding.seed,
                finding.sequence,
                finding.kind,
                finding.surface.label(),
                finding.scenario.label(),
                finding.text_variant.label(),
                format_optional_hint(finding.server_sender_risk_hint),
                finding.expected_threat,
                finding.detected_threat,
                finding.action,
                finding.score,
                format_optional_score(finding.expected_score),
                compact_text(&finding.text)
            );
        }
    }
}

fn profile_label(profile: Option<RunProfile>) -> &'static str {
    profile.map(RunProfile::label).unwrap_or("custom")
}

fn format_text_variants(variants: &[TextVariant]) -> String {
    variants
        .iter()
        .map(|variant| variant.label())
        .collect::<Vec<_>>()
        .join(",")
}

fn print_baseline_comparison(comparison: Option<&BaselineComparison>) {
    let Some(comparison) = comparison else {
        return;
    };

    println!(
        "  baseline={} detect_drop={:.1}%<= {:.1}% fp_rise={:.1}%<= {:.1}% {}",
        comparison.path,
        comparison.detect_rate_drop * 100.0,
        comparison.max_detect_rate_drop * 100.0,
        comparison.fp_rate_rise * 100.0,
        comparison.max_fp_rate_rise * 100.0,
        if comparison.passed { "ok" } else { "failed" }
    );
    if let Some(delta) = &comparison.worst_event_kind_detect_drop {
        println!(
            "  baseline_kind_worst={} detect_drop={:.1}%<= {:.1}% baseline={:.1}% current={:.1}%",
            delta.name,
            delta.delta * 100.0,
            comparison.max_detect_rate_drop * 100.0,
            delta.baseline_rate * 100.0,
            delta.current_rate * 100.0
        );
    }
    if let Some(delta) = &comparison.worst_surface_fp_rate_rise {
        println!(
            "  baseline_surface_worst={} fp_rise={:.1}%<= {:.1}% baseline={:.1}% current={:.1}%",
            delta.name,
            delta.delta * 100.0,
            comparison.max_fp_rate_rise * 100.0,
            delta.baseline_rate * 100.0,
            delta.current_rate * 100.0
        );
    }
}

fn print_history_summary(history: Option<&HistorySummary>) {
    let Some(history) = history else {
        return;
    };

    if history.loaded_runs == 0 {
        println!(
            "  history={} previous_runs=0 window={} gate={}",
            history.path,
            history.window_size,
            history_gate_label(history)
        );
        return;
    }

    println!(
        "  history={} previous_runs={} window={} avg_detect={:.1}% avg_fp={:.1}% latest_delta_detect={} latest_delta_fp={} gate_failures={} gate={}",
        history.path,
        history.loaded_runs,
        history.window_size,
        history.avg_detect_rate * 100.0,
        history.avg_fp_rate * 100.0,
        format_signed_rate(history.current_vs_latest_detect_delta),
        format_signed_rate(history.current_vs_latest_fp_delta),
        history.recent_gate_failures,
        history_gate_label(history)
    );
}

fn history_gate_label(history: &HistorySummary) -> &'static str {
    match (history.gate_enabled, history.gate_passed) {
        (false, _) => "off",
        (true, Some(true)) => "pass",
        (true, Some(false)) => "fail",
        (true, None) => "unknown",
    }
}

fn print_metric_table(title: &str, rows: &[MetricRow]) {
    println!();
    println!("{title}");
    println!(
        "  {:<30} {:>7} {:>12} {:>8} {:>8}",
        "slice", "events", "pos_detect", "safe_fp", "wrong"
    );
    for row in rows {
        println!(
            "  {:<30} {:>7} {:>5}/{:<5} {:>7.1}% {:>8}",
            row.name,
            row.counts.events,
            row.counts.positives_detected,
            row.counts.positives,
            row.counts.fp_rate * 100.0,
            row.counts.wrong_threat_positives
        );
    }
}

fn format_counts(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "-".to_string();
    }
    counts
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_optional_score(score: Option<f32>) -> String {
    score
        .map(|score| format!("{score:.2}"))
        .unwrap_or_else(|| "-".to_string())
}

fn format_optional_hint(score: Option<f32>) -> String {
    score
        .map(|score| format!("{score:.2}"))
        .unwrap_or_else(|| "-".to_string())
}

fn format_signed_rate(rate: Option<f64>) -> String {
    rate.map(|rate| format!("{:+.1}%", rate * 100.0))
        .unwrap_or_else(|| "-".to_string())
}

fn format_gate_value(check: &GateCheck) -> String {
    if check.name.contains("elapsed_ms") {
        format!("{:.0}ms", check.actual)
    } else if check.name == "history_has_prior_runs"
        || check.name == "text_variants_with_positive_events"
        || check.name == "server_hint_positive_events"
        || check.name.ends_with("_covered")
    {
        format!("{:.0}", check.actual)
    } else if check.name == "all_seed_gates_pass" {
        if check.actual >= 1.0 {
            "yes".to_string()
        } else {
            "no".to_string()
        }
    } else {
        format!("{:.1}%", check.actual * 100.0)
    }
}

fn format_gate_threshold(check: &GateCheck) -> String {
    if check.name.contains("elapsed_ms") {
        format!("{:.0}ms", check.threshold)
    } else if check.name == "history_has_prior_runs"
        || check.name == "text_variants_with_positive_events"
        || check.name == "server_hint_positive_events"
        || check.name.ends_with("_covered")
    {
        format!("{:.0}", check.threshold)
    } else if check.name == "all_seed_gates_pass" {
        "yes".to_string()
    } else {
        format!("{:.1}%", check.threshold * 100.0)
    }
}

fn compact_text(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let max_chars = 96;
    let mut out = collapsed.chars().take(max_chars).collect::<String>();
    if collapsed.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}
