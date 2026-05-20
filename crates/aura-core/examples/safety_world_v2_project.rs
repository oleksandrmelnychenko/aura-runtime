use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const DEFAULT_INPUT: &str = "crates/aura-core/data/safety_world_v2_schema.example.json";
const EXPECTED_SCHEMA_VERSION: &str = "safety_world.v2";

fn main() {
    let args = match Args::parse(env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("error: {err}");
            print_help();
            std::process::exit(2);
        }
    };

    if args.help {
        print_help();
        return;
    }

    let input = args.input.unwrap_or_else(|| PathBuf::from(DEFAULT_INPUT));
    let raw = fs::read_to_string(&input).unwrap_or_else(|err| {
        eprintln!("error: failed to read {}: {err}", input.display());
        std::process::exit(1);
    });
    let world: SafetyWorldV2 = serde_json::from_str(&raw).unwrap_or_else(|err| {
        eprintln!(
            "error: invalid Safety World v2 JSON in {}: {err}",
            input.display()
        );
        std::process::exit(1);
    });

    let projected = project_to_world_sim_v1(&world).unwrap_or_else(|err| {
        eprintln!("error: projection failed for {}: {err}", input.display());
        std::process::exit(1);
    });
    let json = serde_json::to_string_pretty(&projected).expect("projection serializes");

    if let Some(output) = args.output {
        fs::write(&output, format!("{json}\n")).unwrap_or_else(|err| {
            eprintln!("error: failed to write {}: {err}", output.display());
            std::process::exit(1);
        });
    } else {
        println!("{json}");
    }
}

#[derive(Debug, Default)]
struct Args {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    help: bool,
}

impl Args {
    fn parse<I>(mut args: I) -> Result<Self, String>
    where
        I: Iterator<Item = String>,
    {
        let mut parsed = Self::default();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input" => {
                    parsed.input = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| "--input requires a path".to_string())?,
                    ));
                }
                "--output" => {
                    parsed.output = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| "--output requires a path".to_string())?,
                    ));
                }
                "--help" | "-h" => parsed.help = true,
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, Deserialize)]
struct SafetyWorldV2 {
    schema_version: String,
    world: V2World,
    #[serde(default)]
    accounts: Vec<V2Account>,
    #[serde(default)]
    surfaces: Vec<V2Surface>,
    #[serde(default)]
    streams: Vec<V2Stream>,
    #[serde(default)]
    events: Vec<V2Event>,
}

#[derive(Debug, Deserialize)]
struct V2World {
    id: String,
    label: String,
    #[serde(default)]
    description: Option<String>,
    owner_account_id: String,
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    timezone_offset_minutes: Option<i32>,
    #[serde(default)]
    protection_profile: Option<String>,
    #[serde(default)]
    ttl_days: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct V2Account {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    account_type: Option<String>,
    #[serde(default)]
    age: Option<V2Age>,
    #[serde(default)]
    trust: Option<V2Trust>,
}

#[derive(Debug, Deserialize)]
struct V2Age {
    #[serde(default)]
    years: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct V2Trust {
    #[serde(default)]
    trusted: bool,
    #[serde(default)]
    relationship: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V2Surface {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    v1_conversation_type: Option<String>,
    #[serde(default)]
    member_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct V2Stream {
    id: String,
    #[serde(default)]
    replay: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V2Event {
    at: String,
    #[serde(rename = "type")]
    event_type: String,
    actor_account_id: String,
    surface_id: String,
    #[serde(default)]
    stream_refs: Vec<String>,
    #[serde(default)]
    content: Option<V2Content>,
    #[serde(default)]
    v1_projection: Option<V1Projection>,
    #[serde(default)]
    analyzer_expectation: Option<V2AnalyzerExpectation>,
}

#[derive(Debug, Deserialize)]
struct V2Content {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V1Projection {
    sender_id: String,
    conversation_id: String,
    conversation_type: String,
    #[serde(default)]
    member_count: Option<u32>,
    #[serde(default)]
    sender_relationship: Option<String>,
    #[serde(default)]
    relationship_trust_source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V2AnalyzerExpectation {
    #[serde(default)]
    expect_clean: bool,
    #[serde(default)]
    expect_threat: Option<String>,
    #[serde(default)]
    expect_min_action: Option<String>,
    #[serde(default)]
    expect_min_alert: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct WorldSimV1 {
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    owner: WorldSimOwner,
    config: WorldSimConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actors: Vec<WorldSimActor>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conversations: Vec<WorldSimConversation>,
    events: Vec<WorldSimEvent>,
}

#[derive(Debug, Serialize)]
struct WorldSimOwner {
    id: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    age: Option<u16>,
}

#[derive(Debug, Serialize)]
struct WorldSimConfig {
    account_type: String,
    protection_level: String,
    language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_holder_age: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone_offset_minutes: Option<i32>,
}

#[derive(Debug, Serialize)]
struct WorldSimActor {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    trusted: bool,
    #[serde(skip_serializing_if = "is_default_relationship")]
    sender_relationship: String,
    #[serde(skip_serializing_if = "is_default_trust_source")]
    relationship_trust_source: String,
}

#[derive(Debug, Serialize)]
struct WorldSimConversation {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    conversation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_count: Option<u32>,
}

#[derive(Debug, Serialize)]
struct WorldSimEvent {
    at: String,
    sender_id: String,
    conversation_id: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    conversation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_count: Option<u32>,
    #[serde(skip_serializing_if = "is_default_relationship")]
    sender_relationship: String,
    #[serde(skip_serializing_if = "is_default_trust_source")]
    relationship_trust_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    expect_clean: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect_threat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect_min_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect_min_alert: Option<String>,
}

fn project_to_world_sim_v1(world: &SafetyWorldV2) -> Result<WorldSimV1, String> {
    if world.schema_version != EXPECTED_SCHEMA_VERSION {
        return Err(format!(
            "expected schema_version `{EXPECTED_SCHEMA_VERSION}`, got `{}`",
            world.schema_version
        ));
    }

    let accounts = world
        .accounts
        .iter()
        .map(|account| (account.id.as_str(), account))
        .collect::<BTreeMap<_, _>>();
    let surfaces = world
        .surfaces
        .iter()
        .map(|surface| (surface.id.as_str(), surface))
        .collect::<BTreeMap<_, _>>();
    let replay_streams = world
        .streams
        .iter()
        .filter(|stream| stream.replay.as_deref() == Some("enabled"))
        .map(|stream| stream.id.as_str())
        .collect::<BTreeSet<_>>();

    let Some(owner_account) = accounts.get(world.world.owner_account_id.as_str()) else {
        return Err(format!(
            "owner_account_id `{}` does not resolve to an account",
            world.world.owner_account_id
        ));
    };

    let owner_age = owner_account.age.as_ref().and_then(|age| age.years);
    let owner = WorldSimOwner {
        id: owner_account.id.clone(),
        display_name: owner_account
            .display_name
            .clone()
            .unwrap_or_else(|| owner_account.id.clone()),
        age: owner_age,
    };

    let config = WorldSimConfig {
        account_type: normalize_account_type(owner_account.account_type.as_deref()),
        protection_level: normalize_protection_level(world.world.protection_profile.as_deref()),
        language: world
            .world
            .locale
            .clone()
            .unwrap_or_else(|| "und".to_string()),
        account_holder_age: owner_age,
        ttl_days: world.world.ttl_days,
        timezone_offset_minutes: world.world.timezone_offset_minutes,
    };

    let actors = world
        .accounts
        .iter()
        .map(|account| {
            let trust = account.trust.as_ref();
            WorldSimActor {
                id: account.id.clone(),
                display_name: account.display_name.clone(),
                trusted: trust.is_some_and(|trust| trust.trusted),
                sender_relationship: normalize_sender_relationship(
                    trust.and_then(|trust| trust.relationship.as_deref()),
                ),
                relationship_trust_source: normalize_trust_source(
                    trust.and_then(|trust| trust.source.as_deref()),
                ),
            }
        })
        .collect();

    let conversations = world
        .surfaces
        .iter()
        .map(|surface| {
            Ok(WorldSimConversation {
                id: surface.id.clone(),
                display_name: surface.display_name.clone(),
                conversation_type: normalize_conversation_type(
                    surface.v1_conversation_type.as_deref(),
                )?,
                member_count: surface.member_count,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let mut events = Vec::new();
    for event in &world.events {
        if event.event_type != "message_created" {
            continue;
        }
        if !event
            .stream_refs
            .iter()
            .any(|stream| replay_streams.contains(stream.as_str()))
        {
            continue;
        }

        let Some(projection) = event.v1_projection.as_ref() else {
            return Err(format!(
                "message event `{}` on `{}` is replay-enabled but missing v1_projection",
                event.actor_account_id, event.at
            ));
        };
        if !accounts.contains_key(event.actor_account_id.as_str()) {
            return Err(format!(
                "message event actor_account_id `{}` does not resolve",
                event.actor_account_id
            ));
        }
        if !surfaces.contains_key(event.surface_id.as_str()) {
            return Err(format!(
                "message event surface_id `{}` does not resolve",
                event.surface_id
            ));
        }

        let Some(content) = event.content.as_ref() else {
            return Err(format!(
                "message event `{}` on `{}` is missing content",
                event.actor_account_id, event.at
            ));
        };
        let Some(text) = content.text.as_ref().filter(|text| !text.is_empty()) else {
            return Err(format!(
                "message event `{}` on `{}` is replay-enabled but missing content.text",
                event.actor_account_id, event.at
            ));
        };

        let expectation = event.analyzer_expectation.as_ref();
        let expect_clean = expectation.is_some_and(|expectation| expectation.expect_clean);
        let expect_threat = expectation
            .and_then(|expectation| expectation.expect_threat.as_deref())
            .filter(|value| !value.is_empty())
            .map(normalize_threat_type)
            .transpose()?;
        let expect_min_action = expectation
            .and_then(|expectation| expectation.expect_min_action.as_deref())
            .filter(|value| !value.is_empty())
            .map(normalize_action)
            .transpose()?;
        let expect_min_alert = expectation
            .and_then(|expectation| expectation.expect_min_alert.as_deref())
            .filter(|value| !value.is_empty())
            .map(normalize_alert)
            .transpose()?;

        events.push(WorldSimEvent {
            at: event.at.clone(),
            sender_id: projection.sender_id.clone(),
            conversation_id: projection.conversation_id.clone(),
            text: text.clone(),
            language: content.language.clone(),
            conversation_type: normalize_conversation_type(Some(&projection.conversation_type))?,
            member_count: projection.member_count,
            sender_relationship: normalize_sender_relationship(
                projection.sender_relationship.as_deref(),
            ),
            relationship_trust_source: normalize_trust_source(
                projection.relationship_trust_source.as_deref(),
            ),
            note: expectation.and_then(|expectation| expectation.notes.clone()),
            expect_clean,
            expect_threat,
            expect_min_action,
            expect_min_alert,
        });
    }

    if events.is_empty() {
        return Err("projection produced zero replayable message events".to_string());
    }

    Ok(WorldSimV1 {
        label: world.world.label.clone(),
        description: world.world.description.clone().or_else(|| {
            Some(format!(
                "Projected from Safety World v2 fixture `{}`",
                world.world.id
            ))
        }),
        owner,
        config,
        actors,
        conversations,
        events,
    })
}

fn normalize_account_type(value: Option<&str>) -> String {
    match value {
        Some("child") => "child",
        Some("teen") => "teen",
        _ => "adult",
    }
    .to_string()
}

#[allow(clippy::manual_unwrap_or)]
fn normalize_protection_level(value: Option<&str>) -> String {
    match value {
        Some(level @ ("off" | "low" | "medium" | "high")) => level,
        _ => "high",
    }
    .to_string()
}

fn normalize_conversation_type(value: Option<&str>) -> Result<String, String> {
    match value {
        Some("direct") => Ok("direct".to_string()),
        Some("group") => Ok("group".to_string()),
        Some(other) => Err(format!(
            "unsupported v1 conversation_type `{other}`; expected `direct` or `group`"
        )),
        None => Ok("direct".to_string()),
    }
}

fn normalize_sender_relationship(value: Option<&str>) -> String {
    match value {
        Some(
            relationship @ ("parent" | "guardian" | "family" | "sibling" | "peer" | "teacher"
            | "coach" | "authority" | "service" | "unknown_adult" | "unknown_peer"),
        ) => relationship,
        Some("self") | Some("unknown") | None => "unknown",
        Some(_) => "unknown",
    }
    .to_string()
}

fn normalize_trust_source(value: Option<&str>) -> String {
    match value {
        Some(
            source @ ("user_verified" | "guardian_verified" | "platform_verified" | "address_book"
            | "school_directory" | "server_reputation" | "local_heuristic"
            | "self_declared"),
        ) => source,
        Some("unknown") | None => "unknown",
        Some(_) => "unknown",
    }
    .to_string()
}

fn normalize_threat_type(value: &str) -> Result<String, String> {
    let normalized = match value {
        "none"
        | "bullying"
        | "grooming"
        | "explicit"
        | "threat"
        | "self_harm"
        | "spam"
        | "scam"
        | "phishing"
        | "manipulation"
        | "nsfw"
        | "hate_speech"
        | "doxxing"
        | "pii_leakage"
        | "propaganda"
        | "opsec_violation"
        | "psyops"
        | "military_social_eng"
        | "coordinate_leak" => value,
        other => return Err(format!("unsupported expect_threat `{other}`")),
    };
    Ok(normalized.to_string())
}

fn normalize_action(value: &str) -> Result<String, String> {
    let normalized = match value {
        "allow" | "mark" | "blur" | "warn" | "block" => value,
        other => return Err(format!("unsupported expect_min_action `{other}`")),
    };
    Ok(normalized.to_string())
}

fn normalize_alert(value: &str) -> Result<String, String> {
    let normalized = match value {
        "none" | "low" | "medium" | "high" | "urgent" => value,
        other => return Err(format!("unsupported expect_min_alert `{other}`")),
    };
    Ok(normalized.to_string())
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_default_relationship(value: &str) -> bool {
    value == "unknown"
}

fn is_default_trust_source(value: &str) -> bool {
    value == "unknown"
}

fn print_help() {
    println!(
        "Usage: cargo run -p aura-core --example safety_world_v2_project -- [--input PATH] [--output PATH]\n\n\
         Projects a Safety World v2 fixture into the existing world_sim.v1 JSON format.\n\n\
         Options:\n\
           --input PATH   Safety World v2 JSON file to project\n\
           --output PATH  Write projected world_sim.v1 JSON to this path; stdout by default\n\
           --help         Show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_world() -> SafetyWorldV2 {
        serde_json::from_str(include_str!("../data/safety_world_v2_schema.example.json"))
            .expect("example Safety World v2 fixture should parse")
    }

    #[test]
    fn bundled_example_projects_to_world_sim_v1_shape() {
        let projected = project_to_world_sim_v1(&example_world()).expect("projection succeeds");

        assert_eq!(projected.label, "sofia_safety_world_v2_smoke");
        assert_eq!(projected.owner.id, "acct_sofia_13");
        assert_eq!(projected.config.account_type, "teen");
        assert_eq!(projected.config.protection_level, "high");
        assert_eq!(projected.actors.len(), 4);
        assert_eq!(projected.conversations.len(), 3);
        assert_eq!(projected.events.len(), 3);

        let clean_parent = &projected.events[0];
        assert!(clean_parent.expect_clean);
        assert_eq!(clean_parent.expect_threat, None);
        assert_eq!(clean_parent.sender_relationship, "parent");

        let grooming = &projected.events[1];
        assert_eq!(grooming.expect_threat.as_deref(), Some("grooming"));
        assert_eq!(grooming.expect_min_action.as_deref(), Some("warn"));
        assert_eq!(grooming.expect_min_alert.as_deref(), Some("high"));
        assert_eq!(grooming.sender_relationship, "unknown_adult");

        let phishing = &projected.events[2];
        assert_eq!(phishing.expect_threat.as_deref(), Some("phishing"));
        assert_eq!(phishing.sender_relationship, "service");
    }

    #[test]
    fn projection_normalizes_self_relationship_to_world_sim_unknown() {
        let projected = project_to_world_sim_v1(&example_world()).expect("projection succeeds");
        let owner_actor = projected
            .actors
            .iter()
            .find(|actor| actor.id == "acct_sofia_13")
            .expect("owner actor exists");

        assert_eq!(owner_actor.sender_relationship, "unknown");
        assert_eq!(owner_actor.relationship_trust_source, "user_verified");

        let json = serde_json::to_value(&projected).expect("projection serializes");
        let owner_json = json["actors"]
            .as_array()
            .expect("actors array")
            .iter()
            .find(|actor| actor["id"] == "acct_sofia_13")
            .expect("owner actor json exists");
        assert!(
            owner_json.get("sender_relationship").is_none(),
            "default unknown relationship should stay omitted in world_sim.v1 JSON"
        );
    }

    #[test]
    fn projection_skips_events_without_enabled_replay_stream() {
        let mut world = example_world();
        world.events[1].stream_refs = vec!["stream_platform_import".to_string()];

        let projected = project_to_world_sim_v1(&world).expect("projection succeeds");

        assert_eq!(projected.events.len(), 2);
        assert!(!projected
            .events
            .iter()
            .any(|event| event.expect_threat.as_deref() == Some("grooming")));
    }

    #[test]
    fn projection_rejects_unsupported_expectation_values() {
        let mut world = example_world();
        world.events[1]
            .analyzer_expectation
            .as_mut()
            .expect("grooming expectation exists")
            .expect_threat = Some("alien_abduction".to_string());

        let err = project_to_world_sim_v1(&world).expect_err("unsupported threat should fail");

        assert!(err.contains("unsupported expect_threat"));
    }

    #[test]
    fn projection_rejects_when_no_replayable_messages_remain() {
        let mut world = example_world();
        for stream in &mut world.streams {
            stream.replay = Some("platform_only".to_string());
        }

        let err = project_to_world_sim_v1(&world).expect_err("empty replay should fail");

        assert!(err.contains("zero replayable message events"));
    }
}
