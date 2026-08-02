use super::*;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct WorldFixture {
    label: String,
    owner: WorldOwner,
    #[serde(default)]
    config: WorldConfig,
    #[serde(default)]
    actors: Vec<WorldActor>,
    #[serde(default)]
    conversations: Vec<WorldConversation>,
    #[serde(default)]
    events: Vec<WorldEvent>,
    #[serde(default)]
    generated_batches: Vec<GeneratedBatch>,
}

#[derive(Debug, Deserialize)]
struct WorldOwner {
    id: String,
    #[serde(default)]
    age: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct WorldConfig {
    #[serde(default)]
    account_type: Option<String>,
    #[serde(default)]
    protection_level: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    account_holder_age: Option<u32>,
    #[serde(default)]
    ttl_days: Option<u32>,
    #[serde(default)]
    timezone_offset_minutes: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct WorldActor {
    id: String,
    #[serde(default)]
    trusted: bool,
    #[serde(default)]
    sender_relationship: Option<String>,
    #[serde(default)]
    relationship_trust_source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorldConversation {
    id: String,
    #[serde(default)]
    conversation_type: Option<String>,
    #[serde(default)]
    member_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct WorldEvent {
    at: String,
    sender_id: String,
    conversation_id: String,
    text: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    conversation_type: Option<String>,
    #[serde(default)]
    member_count: Option<u32>,
    #[serde(default)]
    sender_relationship: Option<String>,
    #[serde(default)]
    relationship_trust_source: Option<String>,
    #[serde(default)]
    expect_clean: bool,
    #[serde(default)]
    expect_threat: Option<String>,
    #[serde(default)]
    expect_min_action: Option<String>,
    #[serde(default)]
    expect_min_alert: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeneratedBatch {
    label: String,
    start_at: String,
    count: usize,
    interval_minutes: i64,
    #[serde(default = "default_day_repeats")]
    day_repeats: usize,
    #[serde(default = "default_day_stride_days")]
    day_stride_days: i64,
    sender_ids: Vec<String>,
    conversation_ids: Vec<String>,
    texts: Vec<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    conversation_type: Option<String>,
    #[serde(default)]
    member_count: Option<u32>,
    #[serde(default)]
    sender_relationship: Option<String>,
    #[serde(default)]
    relationship_trust_source: Option<String>,
    #[serde(default)]
    expect_clean: bool,
    #[serde(default)]
    expect_threat: Option<String>,
    #[serde(default)]
    expect_min_action: Option<String>,
    #[serde(default)]
    expect_min_alert: Option<String>,
}

fn default_day_repeats() -> usize {
    1
}

fn default_day_stride_days() -> i64 {
    1
}

#[derive(Debug, Clone)]
struct EventSeed {
    timestamp_ms: u64,
    sender_id: String,
    conversation_id: String,
    language: Option<String>,
    conversation_type: Option<String>,
    member_count: Option<u32>,
    sender_relationship: Option<String>,
    relationship_trust_source: Option<String>,
    expectation: Option<WorldExpectation>,
    text: String,
}

#[derive(Debug, Clone)]
struct ResolvedEvent {
    source_index: usize,
    timestamp_ms: u64,
    sender_id: String,
    conversation_id: String,
    language: String,
    conversation_type: proto::ConversationType,
    member_count: Option<u32>,
    sender_relationship: proto::SenderRelationship,
    relationship_trust_source: proto::RelationshipTrustSource,
    expectation: Option<WorldExpectation>,
    text: String,
}

#[derive(Debug, Clone)]
struct WorldExpectation {
    expect_clean: bool,
    expect_threat: Option<proto::ThreatType>,
    expect_min_action: Option<proto::Action>,
    expect_min_alert: Option<proto::AlertPriority>,
}

#[derive(Debug)]
struct ReplayReport {
    total_events: usize,
    labeled_positive_events: usize,
    labeled_clean_events: usize,
    true_positive_events: usize,
    false_positive_events: usize,
    restore_count: usize,
    findings: Vec<String>,
}

impl ReplayReport {
    fn positive_recall(&self) -> f64 {
        if self.labeled_positive_events == 0 {
            1.0
        } else {
            self.true_positive_events as f64 / self.labeled_positive_events as f64
        }
    }

    fn clean_false_positive_rate(&self) -> f64 {
        if self.labeled_clean_events == 0 {
            0.0
        } else {
            self.false_positive_events as f64 / self.labeled_clean_events as f64
        }
    }
}

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../aura-core/data")
        .join(relative)
}

fn load_world(relative: &str) -> WorldFixture {
    let path = fixture_path(relative);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read world fixture {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("parse world fixture {}: {error}", path.display()))
}

fn config_for_world(world: &WorldFixture) -> proto::AuraConfig {
    let account_type = match world.config.account_type.as_deref() {
        Some("adult") => proto::AccountType::Adult,
        Some("teen") => proto::AccountType::Teen,
        Some("child") | None => proto::AccountType::Child,
        Some(other) => panic!("unsupported fixture account_type: {other}"),
    };
    let mut config = proto_config(account_type, world.config.enabled.unwrap_or(true));
    config.protection_level = match world.config.protection_level.as_deref() {
        Some("off") => proto::ProtectionLevel::Off as i32,
        Some("low") => proto::ProtectionLevel::Low as i32,
        Some("medium") => proto::ProtectionLevel::Medium as i32,
        Some("high") | None => proto::ProtectionLevel::High as i32,
        Some(other) => panic!("unsupported fixture protection_level: {other}"),
    };
    config.language = world
        .config
        .language
        .clone()
        .unwrap_or_else(|| "uk".to_string());
    config.cultural_context = Some(proto::CulturalContext {
        kind: match config.language.as_str() {
            "uk" => proto::CulturalContextKind::Ukrainian as i32,
            "ru" => proto::CulturalContextKind::Russian as i32,
            "en" => proto::CulturalContextKind::English as i32,
            _ => proto::CulturalContextKind::Custom as i32,
        },
        custom_value: (!matches!(config.language.as_str(), "uk" | "ru" | "en"))
            .then(|| config.language.clone()),
    });
    config.account_holder_age = world.config.account_holder_age.or(world.owner.age);
    config.ttl_days = world.config.ttl_days.unwrap_or(30);
    config.timezone_offset_minutes = world.config.timezone_offset_minutes.unwrap_or(120);
    config
}

fn resolve_events(world: &WorldFixture) -> Vec<ResolvedEvent> {
    let actors: HashMap<_, _> = world
        .actors
        .iter()
        .map(|actor| (actor.id.as_str(), actor))
        .collect();
    let conversations: HashMap<_, _> = world
        .conversations
        .iter()
        .map(|conversation| (conversation.id.as_str(), conversation))
        .collect();

    let mut seeds = world
        .events
        .iter()
        .map(|event| EventSeed {
            timestamp_ms: parse_timestamp(&event.at),
            sender_id: event.sender_id.clone(),
            conversation_id: event.conversation_id.clone(),
            language: event.language.clone(),
            conversation_type: event.conversation_type.clone(),
            member_count: event.member_count,
            sender_relationship: event.sender_relationship.clone(),
            relationship_trust_source: event.relationship_trust_source.clone(),
            expectation: expectation(
                event.expect_clean,
                event.expect_threat.as_deref(),
                event.expect_min_action.as_deref(),
                event.expect_min_alert.as_deref(),
            ),
            text: event.text.clone(),
        })
        .collect::<Vec<_>>();
    for batch in &world.generated_batches {
        seeds.extend(expand_batch(batch));
    }

    let mut events = seeds
        .into_iter()
        .enumerate()
        .map(|(source_index, seed)| {
            let actor = actors.get(seed.sender_id.as_str()).copied();
            let conversation = conversations.get(seed.conversation_id.as_str()).copied();
            let mut trust_source =
                relationship_trust_source(seed.relationship_trust_source.as_deref().or_else(
                    || actor.and_then(|value| value.relationship_trust_source.as_deref()),
                ));
            if actor.is_some_and(|value| value.trusted)
                && trust_source == proto::RelationshipTrustSource::Unknown
            {
                trust_source = proto::RelationshipTrustSource::UserVerified;
            }
            ResolvedEvent {
                source_index,
                timestamp_ms: seed.timestamp_ms,
                sender_relationship: sender_relationship(
                    seed.sender_relationship
                        .as_deref()
                        .or_else(|| actor.and_then(|value| value.sender_relationship.as_deref())),
                ),
                relationship_trust_source: trust_source,
                conversation_type: conversation_type(
                    seed.conversation_type.as_deref().or_else(|| {
                        conversation.and_then(|value| value.conversation_type.as_deref())
                    }),
                ),
                member_count: seed
                    .member_count
                    .or_else(|| conversation.and_then(|value| value.member_count)),
                language: seed.language.unwrap_or_else(|| {
                    world
                        .config
                        .language
                        .clone()
                        .unwrap_or_else(|| "uk".to_string())
                }),
                sender_id: seed.sender_id,
                conversation_id: seed.conversation_id,
                expectation: seed.expectation,
                text: seed.text,
            }
        })
        .collect::<Vec<_>>();
    events.sort_by_key(|event| (event.timestamp_ms, event.source_index));
    events
}

fn expand_batch(batch: &GeneratedBatch) -> Vec<EventSeed> {
    assert!(batch.count > 0, "batch {} has zero count", batch.label);
    assert!(
        batch.interval_minutes > 0,
        "batch {} has non-positive interval",
        batch.label
    );
    assert!(
        batch.day_repeats > 0 && batch.day_stride_days > 0,
        "batch {} has invalid repeat dimensions",
        batch.label
    );
    assert!(
        !batch.sender_ids.is_empty()
            && !batch.conversation_ids.is_empty()
            && !batch.texts.is_empty(),
        "batch {} is missing generated dimensions",
        batch.label
    );

    let start = DateTime::parse_from_rfc3339(&batch.start_at)
        .unwrap_or_else(|error| panic!("batch {} timestamp: {error}", batch.label));
    let interval = Duration::minutes(batch.interval_minutes);
    let day_stride = Duration::days(batch.day_stride_days);
    let mut seeds = Vec::with_capacity(batch.count * batch.day_repeats);
    for day_index in 0..batch.day_repeats {
        let day_base = start + day_stride * day_index as i32;
        for event_index in 0..batch.count {
            let absolute_index = day_index * batch.count + event_index;
            let timestamp_ms = (day_base + interval * event_index as i32)
                .with_timezone(&Utc)
                .timestamp_millis();
            assert!(
                timestamp_ms >= 0,
                "batch {} produced negative time",
                batch.label
            );
            seeds.push(EventSeed {
                timestamp_ms: timestamp_ms as u64,
                sender_id: batch.sender_ids[absolute_index % batch.sender_ids.len()].clone(),
                conversation_id: batch.conversation_ids
                    [absolute_index % batch.conversation_ids.len()]
                .clone(),
                language: batch.language.clone(),
                conversation_type: batch.conversation_type.clone(),
                member_count: batch.member_count,
                sender_relationship: batch.sender_relationship.clone(),
                relationship_trust_source: batch.relationship_trust_source.clone(),
                expectation: expectation(
                    batch.expect_clean,
                    batch.expect_threat.as_deref(),
                    batch.expect_min_action.as_deref(),
                    batch.expect_min_alert.as_deref(),
                ),
                text: batch.texts[absolute_index % batch.texts.len()].clone(),
            });
        }
    }
    seeds
}

fn parse_timestamp(value: &str) -> u64 {
    let timestamp = DateTime::parse_from_rfc3339(value)
        .unwrap_or_else(|error| panic!("invalid fixture timestamp {value}: {error}"))
        .with_timezone(&Utc)
        .timestamp_millis();
    assert!(timestamp >= 0, "negative fixture timestamp: {value}");
    timestamp as u64
}

fn expectation(
    clean: bool,
    threat: Option<&str>,
    action: Option<&str>,
    alert: Option<&str>,
) -> Option<WorldExpectation> {
    let expect_threat = threat.map(threat_type);
    let expect_min_action = action.map(action_type);
    let expect_min_alert = alert.map(alert_priority);
    (clean || expect_threat.is_some() || expect_min_action.is_some() || expect_min_alert.is_some())
        .then_some(WorldExpectation {
            expect_clean: clean,
            expect_threat,
            expect_min_action,
            expect_min_alert,
        })
}

fn conversation_type(value: Option<&str>) -> proto::ConversationType {
    match value {
        Some("group") => proto::ConversationType::Group,
        Some("direct") | None => proto::ConversationType::Direct,
        Some(other) => panic!("unsupported fixture conversation_type: {other}"),
    }
}

fn sender_relationship(value: Option<&str>) -> proto::SenderRelationship {
    match value {
        Some("parent") => proto::SenderRelationship::Parent,
        Some("guardian") => proto::SenderRelationship::Guardian,
        Some("family") => proto::SenderRelationship::Family,
        Some("sibling") => proto::SenderRelationship::Sibling,
        Some("peer") => proto::SenderRelationship::Peer,
        Some("teacher") => proto::SenderRelationship::Teacher,
        Some("coach") => proto::SenderRelationship::Coach,
        Some("authority") => proto::SenderRelationship::Authority,
        Some("service") => proto::SenderRelationship::Service,
        Some("unknown_adult") => proto::SenderRelationship::UnknownAdult,
        Some("unknown_peer") => proto::SenderRelationship::UnknownPeer,
        Some("unknown") | None => proto::SenderRelationship::Unknown,
        Some(other) => panic!("unsupported fixture sender_relationship: {other}"),
    }
}

fn relationship_trust_source(value: Option<&str>) -> proto::RelationshipTrustSource {
    match value {
        Some("user_verified") => proto::RelationshipTrustSource::UserVerified,
        Some("guardian_verified") => proto::RelationshipTrustSource::GuardianVerified,
        Some("platform_verified") => proto::RelationshipTrustSource::PlatformVerified,
        Some("address_book") => proto::RelationshipTrustSource::AddressBook,
        Some("school_directory") => proto::RelationshipTrustSource::SchoolDirectory,
        Some("server_reputation") => proto::RelationshipTrustSource::ServerReputation,
        Some("local_heuristic") => proto::RelationshipTrustSource::LocalHeuristic,
        Some("self_declared") => proto::RelationshipTrustSource::SelfDeclared,
        Some("unknown") | None => proto::RelationshipTrustSource::Unknown,
        Some(other) => panic!("unsupported fixture relationship_trust_source: {other}"),
    }
}

fn threat_type(value: &str) -> proto::ThreatType {
    match value {
        "bullying" => proto::ThreatType::Bullying,
        "grooming" => proto::ThreatType::Grooming,
        "explicit" => proto::ThreatType::Explicit,
        "threat" => proto::ThreatType::Threat,
        "self_harm" => proto::ThreatType::SelfHarm,
        "spam" => proto::ThreatType::Spam,
        "scam" => proto::ThreatType::Scam,
        "phishing" => proto::ThreatType::Phishing,
        "manipulation" => proto::ThreatType::Manipulation,
        "nsfw" => proto::ThreatType::Nsfw,
        "hate_speech" => proto::ThreatType::HateSpeech,
        "doxxing" => proto::ThreatType::Doxxing,
        "pii_leakage" => proto::ThreatType::PiiLeakage,
        "propaganda" => proto::ThreatType::Propaganda,
        "opsec_violation" => proto::ThreatType::OpsecViolation,
        "psyops" => proto::ThreatType::Psyops,
        "military_social_eng" => proto::ThreatType::MilitarySocialEng,
        "coordinate_leak" => proto::ThreatType::CoordinateLeak,
        other => panic!("unsupported fixture threat_type: {other}"),
    }
}

fn action_type(value: &str) -> proto::Action {
    match value {
        "allow" => proto::Action::Allow,
        "mark" => proto::Action::Mark,
        "blur" => proto::Action::Blur,
        "warn" => proto::Action::Warn,
        "block" => proto::Action::Block,
        other => panic!("unsupported fixture action: {other}"),
    }
}

fn alert_priority(value: &str) -> proto::AlertPriority {
    match value {
        "none" => proto::AlertPriority::None,
        "low" => proto::AlertPriority::Low,
        "medium" => proto::AlertPriority::Medium,
        "high" => proto::AlertPriority::High,
        "urgent" => proto::AlertPriority::Urgent,
        other => panic!("unsupported fixture alert: {other}"),
    }
}

unsafe fn run_replay(relative: &str, restore_interval: Option<usize>) -> ReplayReport {
    if let Some(interval) = restore_interval {
        assert!(interval > 0, "restore interval must be positive");
    }
    let world = load_world(relative);
    let events = resolve_events(&world);
    let config = config_for_world(&world);
    let mut handle = init_canonical_handle(config.clone());
    let mut report = ReplayReport {
        total_events: events.len(),
        labeled_positive_events: 0,
        labeled_clean_events: 0,
        true_positive_events: 0,
        false_positive_events: 0,
        restore_count: 0,
        findings: Vec::new(),
    };

    for (sequence, event) in events.iter().enumerate() {
        let sender_id = if event.sender_id == world.owner.id {
            "account"
        } else {
            &event.sender_id
        };
        let mut message = proto_message(&event.text, sender_id, &event.conversation_id);
        message.language = Some(event.language.clone());
        message.conversation_type = event.conversation_type as i32;
        message.member_count = event.member_count;
        message.sender_relationship = event.sender_relationship as i32;
        message.relationship_trust_source = event.relationship_trust_source as i32;
        let response = analyze_local_decision(
            handle,
            message,
            &format!("world-{}", event.source_index),
            1,
            event.timestamp_ms,
        );
        let decision = response.decision.as_ref().unwrap_or_else(|| {
            panic!(
                "{}#{} did not return a first-attempt local decision: {:?}",
                world.label,
                sequence + 1,
                response
            )
        });
        evaluate_expectation(&world, event, decision, sequence + 1, &mut report);
        acknowledge_source_checkpoint(
            handle,
            &event.conversation_id,
            &format!("world-{}", event.source_index),
            1,
            event.timestamp_ms,
        );

        if restore_interval
            .is_some_and(|interval| (sequence + 1) % interval == 0 && sequence + 1 < events.len())
        {
            handle = restart_handle(&config, handle);
            report.restore_count += 1;
        }
    }
    aura_free(handle);
    report
}

unsafe fn restart_handle(config: &proto::AuraConfig, handle: *mut c_void) -> *mut c_void {
    let context = export_context(handle)
        .state
        .expect("FFI replay restore requires exported context state");
    let safety_cases = export_safety_case_state(handle);
    aura_free(handle);

    let restored = init_handle(config.clone());
    import_safety_case_state(restored, &safety_cases);
    import_context_state(restored, context);
    restored
}

fn evaluate_expectation(
    world: &WorldFixture,
    event: &ResolvedEvent,
    decision: &proto::LocalDecision,
    sequence: usize,
    report: &mut ReplayReport,
) {
    let product = decision
        .product_surface
        .as_ref()
        .expect("local decision must include the product surface");
    if let Some(expectation) = &event.expectation {
        if expectation.expect_clean {
            report.labeled_clean_events += 1;
            let threat = proto::ThreatType::try_from(product.threat_type)
                .unwrap_or(proto::ThreatType::Unspecified);
            let action =
                proto::Action::try_from(product.action).unwrap_or(proto::Action::Unspecified);
            if !matches!(
                threat,
                proto::ThreatType::None | proto::ThreatType::Unspecified
            ) || action != proto::Action::Allow
            {
                report.false_positive_events += 1;
                report.findings.push(format!(
                    "{}#{sequence}: expected clean allow, got threat={} action={}",
                    world.label, product.threat_type, product.action
                ));
            }
        }
        if let Some(expected) = expectation.expect_threat {
            report.labeled_positive_events += 1;
            if product.threat_type == expected as i32 {
                report.true_positive_events += 1;
            } else {
                report.findings.push(format!(
                    "{}#{sequence}: expected threat {expected:?}, got {}",
                    world.label, product.threat_type
                ));
            }
        }
        if let Some(expected) = expectation.expect_min_action {
            if product.action < expected as i32 {
                report.findings.push(format!(
                    "{}#{sequence}: expected action >= {expected:?}, got {}",
                    world.label, product.action
                ));
            }
        }
        if let Some(expected) = expectation.expect_min_alert {
            let actual = decision
                .recommended_action
                .as_ref()
                .map(|recommendation| recommendation.parent_alert)
                .unwrap_or(proto::AlertPriority::None as i32);
            if actual < expected as i32 {
                report.findings.push(format!(
                    "{}#{sequence}: expected alert >= {expected:?}, got {actual}",
                    world.label
                ));
            }
        }
    }
    if event.sender_id == world.owner.id
        && decision
            .reason_codes
            .iter()
            .any(|code| code.starts_with("conversation.contact."))
    {
        report.findings.push(format!(
            "{}#{sequence}: owner-authored message triggered contact-risk reason code",
            world.label
        ));
    }
    if event.sender_id == world.owner.id
        && decision
            .reason_codes
            .iter()
            .any(|code| code == "conversation.timing.late_night_minor_contact")
    {
        report.findings.push(format!(
            "{}#{sequence}: owner-authored message triggered late-night contact reason code",
            world.label
        ));
    }
}

fn assert_six_month_report(report: &ReplayReport) {
    assert!(report.total_events >= 400, "replay too small: {report:?}");
    assert!(
        report.positive_recall() >= 0.95,
        "recall below gate: {report:?}"
    );
    assert!(
        report.clean_false_positive_rate() <= 0.01,
        "clean false-positive rate above gate: {report:?}"
    );
    assert!(
        report.findings.is_empty(),
        "findings: {:#?}",
        report.findings
    );
}

fn assert_dense_report(report: &ReplayReport) {
    assert!(report.total_events >= 6_000, "replay too small: {report:?}");
    assert!(
        report.positive_recall() >= 0.95,
        "recall below gate: {report:?}"
    );
    assert!(
        report.clean_false_positive_rate() <= 0.01,
        "clean false-positive rate above gate: {report:?}"
    );
    assert!(
        report.findings.is_empty(),
        "findings: {:#?}",
        report.findings
    );
}

#[test]
#[ignore = "long fixture replay; run via ci/ffi_world_replay_gate.sh"]
fn ffi_replays_six_month_world_fixture() {
    unsafe { assert_six_month_report(&run_replay("world_sim_13yo_6mo.json", None)) }
}

#[test]
#[ignore = "long fixture replay; run via ci/ffi_world_replay_gate.sh"]
fn ffi_replays_dense_two_year_world_fixture() {
    unsafe {
        assert_dense_report(&run_replay(
            "world_lifecycle_suite/sofia_13_to_15_dense_2y.json",
            None,
        ))
    }
}

#[test]
#[ignore = "long client-boundary fixture replay; run via ci/client_boundary_replay_gate.sh"]
fn ffi_replays_six_month_world_across_periodic_state_restore() {
    unsafe {
        let report = run_replay("world_sim_13yo_6mo.json", Some(50));
        assert_six_month_report(&report);
        assert!(report.restore_count >= 8, "too few restores: {report:?}");
    }
}

#[test]
#[ignore = "long client-boundary fixture replay; run via ci/client_boundary_replay_gate.sh"]
fn ffi_replays_dense_two_year_world_across_periodic_state_restore() {
    unsafe {
        let report = run_replay(
            "world_lifecycle_suite/sofia_13_to_15_dense_2y.json",
            Some(500),
        );
        assert_dense_report(&report);
        assert!(report.restore_count >= 13, "too few restores: {report:?}");
    }
}
