use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_INPUT: &str = "crates/aura-core/data/safety_world_v2_schema.example.json";
const EXPECTED_SCHEMA_VERSION: &str = "safety_world.v2";
const PLATFORM_SEED_SCHEMA_VERSION: &str = "platform_seed.v1";

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

    let seed = export_platform_seed(&world).unwrap_or_else(|err| {
        eprintln!(
            "error: platform seed export failed for {}: {err}",
            input.display()
        );
        std::process::exit(1);
    });
    let json = serde_json::to_string_pretty(&seed).expect("platform seed serializes");

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
    guardian_links: Vec<V2GuardianLink>,
    #[serde(default)]
    follow_graph: Vec<V2FollowEdge>,
    #[serde(default)]
    surfaces: Vec<V2Surface>,
    #[serde(default)]
    objects: Vec<V2Object>,
    #[serde(default)]
    streams: Vec<V2Stream>,
    #[serde(default)]
    campaigns: Vec<V2Campaign>,
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
    created_for: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct V2Account {
    id: String,
    #[serde(default)]
    platform_account_ref: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    account_type: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    age: Option<V2Age>,
    #[serde(default)]
    declared_age: Option<u16>,
    #[serde(default)]
    age_band: Option<String>,
    #[serde(default)]
    risk_profile: Option<String>,
    #[serde(default)]
    guardian_visibility: Option<String>,
    #[serde(default)]
    trust: Option<V2Trust>,
}

#[derive(Debug, Deserialize)]
struct V2Age {
    #[serde(default)]
    years: Option<u16>,
    #[serde(default)]
    as_of: Option<String>,
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
struct V2GuardianLink {
    id: String,
    child_account_id: String,
    guardian_account_id: String,
    relationship: String,
    status: String,
    verified_by: String,
    visibility_scope: String,
    #[serde(default)]
    can_receive_alerts: bool,
}

#[derive(Debug, Deserialize)]
struct V2FollowEdge {
    id: String,
    from_account_id: String,
    to_account_id: String,
    edge_type: String,
    status: String,
    created_at: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct V2Surface {
    id: String,
    #[serde(default)]
    platform_surface_ref: Option<String>,
    kind: String,
    #[serde(default)]
    display_name: Option<String>,
    visibility: String,
    #[serde(default)]
    member_account_ids: Vec<String>,
    #[serde(default)]
    moderator_account_ids: Vec<String>,
    #[serde(default)]
    member_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct V2Object {
    id: String,
    #[serde(default)]
    platform_object_ref: Option<String>,
    kind: String,
    owner_account_id: String,
    surface_id: String,
    visibility: String,
    #[serde(default)]
    content_ref: Option<V2ContentRef>,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct V2ContentRef {
    mode: String,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V2Stream {
    id: String,
    kind: String,
    #[serde(default)]
    surface_ids: Vec<String>,
    start_at: String,
    end_at: String,
    #[serde(default)]
    replay: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V2Campaign {
    id: String,
    risk_intent: String,
    #[serde(default)]
    actor_account_ids: Vec<String>,
    #[serde(default)]
    target_account_ids: Vec<String>,
    #[serde(default)]
    surface_ids: Vec<String>,
    #[serde(default)]
    object_ids: Vec<String>,
    #[serde(default)]
    stream_ids: Vec<String>,
    start_at: String,
    #[serde(default)]
    end_at: Option<String>,
    description: String,
}

#[derive(Debug, Deserialize)]
struct V2Event {
    id: String,
    sequence: u64,
    at: String,
    #[serde(rename = "type")]
    event_type: String,
    actor_account_id: String,
    surface_id: String,
    visibility: String,
    #[serde(default)]
    stream_refs: Vec<String>,
    #[serde(default)]
    object_refs: Vec<String>,
    #[serde(default)]
    campaign_ids: Vec<String>,
    risk_intent: String,
    #[serde(default)]
    content: Option<V2Content>,
    #[serde(default)]
    platform_expectation: Option<V2PlatformExpectation>,
    #[serde(default)]
    analyzer_expectation: Option<V2AnalyzerExpectation>,
}

#[derive(Debug, Deserialize)]
struct V2Content {
    content_type: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct V2PlatformExpectation {
    visibility_expected: String,
    moderation_expected: String,
    #[serde(default)]
    guardian_visible_expected: bool,
    #[serde(default)]
    moderator_visible_expected: bool,
    notification_expected: String,
    #[serde(default)]
    audit_log_expected: bool,
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
    expected_reason_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PlatformSeed {
    schema_version: &'static str,
    source_schema_version: String,
    world: SeedWorld,
    accounts: Vec<SeedAccount>,
    guardian_links: Vec<SeedGuardianLink>,
    social_edges: Vec<SeedSocialEdge>,
    surfaces: Vec<SeedSurface>,
    objects: Vec<SeedObject>,
    streams: Vec<SeedStream>,
    campaigns: Vec<SeedCampaign>,
    events: Vec<SeedEvent>,
}

#[derive(Debug, Serialize)]
struct SeedWorld {
    id: String,
    label: String,
    description: Option<String>,
    owner_account_ref: String,
    locale: Option<String>,
    created_for: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SeedAccount {
    account_ref: String,
    source_account_id: String,
    display_name: Option<String>,
    account_type: Option<String>,
    role: Option<String>,
    age_years: Option<u16>,
    age_as_of: Option<String>,
    declared_age: Option<u16>,
    age_band: Option<String>,
    risk_profile: Option<String>,
    guardian_visibility: Option<String>,
    trusted: bool,
    relationship: Option<String>,
    trust_source: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeedGuardianLink {
    id: String,
    child_account_ref: String,
    guardian_account_ref: String,
    relationship: String,
    status: String,
    verified_by: String,
    visibility_scope: String,
    can_receive_alerts: bool,
}

#[derive(Debug, Serialize)]
struct SeedSocialEdge {
    id: String,
    from_account_ref: String,
    to_account_ref: String,
    edge_type: String,
    status: String,
    created_at: String,
    source: String,
}

#[derive(Debug, Serialize)]
struct SeedSurface {
    surface_ref: String,
    source_surface_id: String,
    kind: String,
    display_name: Option<String>,
    visibility: String,
    privacy_mode: String,
    member_account_refs: Vec<String>,
    moderator_account_refs: Vec<String>,
    member_count: Option<u32>,
}

#[derive(Debug, Serialize)]
struct SeedObject {
    object_ref: String,
    source_object_id: String,
    kind: String,
    owner_account_ref: String,
    surface_ref: String,
    visibility: String,
    privacy_mode: String,
    content: SeedContent,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct SeedStream {
    id: String,
    kind: String,
    surface_refs: Vec<String>,
    start_at: String,
    end_at: String,
    replay: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeedCampaign {
    id: String,
    risk_intent: String,
    actor_account_refs: Vec<String>,
    target_account_refs: Vec<String>,
    surface_refs: Vec<String>,
    object_refs: Vec<String>,
    stream_ids: Vec<String>,
    start_at: String,
    end_at: Option<String>,
    description: String,
}

#[derive(Debug, Serialize)]
struct SeedEvent {
    id: String,
    sequence: u64,
    at: String,
    operation: String,
    actor_account_ref: String,
    surface_ref: String,
    visibility: String,
    privacy_mode: String,
    stream_ids: Vec<String>,
    object_refs: Vec<String>,
    campaign_ids: Vec<String>,
    risk_intent: String,
    content: Option<SeedContent>,
    analyzer_expectation: Option<SeedAnalyzerExpectation>,
    platform_expectation: Option<V2PlatformExpectation>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum SeedContent {
    Plaintext {
        content_type: String,
        language: Option<String>,
        value: String,
    },
    OpaqueFixtureRef {
        content_type: String,
        language: Option<String>,
        fixture_ref: String,
        plaintext_sha256: String,
        plaintext_len: usize,
    },
    Redacted {
        content_type: Option<String>,
        language: Option<String>,
        fixture_ref: String,
        plaintext_sha256: Option<String>,
        plaintext_len: Option<usize>,
    },
}

#[derive(Debug, Serialize)]
struct SeedAnalyzerExpectation {
    expect_clean: bool,
    expect_threat: Option<String>,
    expect_min_action: Option<String>,
    expect_min_alert: Option<String>,
    expected_reason_codes: Vec<String>,
}

fn export_platform_seed(world: &SafetyWorldV2) -> Result<PlatformSeed, String> {
    if world.schema_version != EXPECTED_SCHEMA_VERSION {
        return Err(format!(
            "expected schema_version `{EXPECTED_SCHEMA_VERSION}`, got `{}`",
            world.schema_version
        ));
    }

    let account_refs = world
        .accounts
        .iter()
        .map(|account| (account.id.as_str(), account_ref(account)))
        .collect::<BTreeMap<_, _>>();
    let surface_refs = world
        .surfaces
        .iter()
        .map(|surface| (surface.id.as_str(), surface_ref(surface)))
        .collect::<BTreeMap<_, _>>();
    let object_refs = world
        .objects
        .iter()
        .map(|object| (object.id.as_str(), object_ref(object)))
        .collect::<BTreeMap<_, _>>();
    let platform_streams = world
        .streams
        .iter()
        .filter(|stream| stream.kind == "platform_import")
        .map(|stream| stream.id.as_str())
        .collect::<BTreeSet<_>>();

    let Some(owner_account_ref) = account_refs.get(world.world.owner_account_id.as_str()) else {
        return Err(format!(
            "owner_account_id `{}` does not resolve to an account",
            world.world.owner_account_id
        ));
    };

    let accounts = world
        .accounts
        .iter()
        .map(|account| {
            let trust = account.trust.as_ref();
            SeedAccount {
                account_ref: account_ref(account),
                source_account_id: account.id.clone(),
                display_name: account.display_name.clone(),
                account_type: account.account_type.clone(),
                role: account.role.clone(),
                age_years: account.age.as_ref().and_then(|age| age.years),
                age_as_of: account.age.as_ref().and_then(|age| age.as_of.clone()),
                declared_age: account.declared_age,
                age_band: account.age_band.clone(),
                risk_profile: account.risk_profile.clone(),
                guardian_visibility: account.guardian_visibility.clone(),
                trusted: trust.is_some_and(|trust| trust.trusted),
                relationship: trust.and_then(|trust| trust.relationship.clone()),
                trust_source: trust.and_then(|trust| trust.source.clone()),
            }
        })
        .collect();

    let guardian_links = world
        .guardian_links
        .iter()
        .map(|link| {
            Ok(SeedGuardianLink {
                id: link.id.clone(),
                child_account_ref: resolve_ref(
                    &account_refs,
                    &link.child_account_id,
                    "guardian link child_account_id",
                )?,
                guardian_account_ref: resolve_ref(
                    &account_refs,
                    &link.guardian_account_id,
                    "guardian link guardian_account_id",
                )?,
                relationship: link.relationship.clone(),
                status: link.status.clone(),
                verified_by: link.verified_by.clone(),
                visibility_scope: link.visibility_scope.clone(),
                can_receive_alerts: link.can_receive_alerts,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let social_edges = world
        .follow_graph
        .iter()
        .map(|edge| {
            Ok(SeedSocialEdge {
                id: edge.id.clone(),
                from_account_ref: resolve_ref(
                    &account_refs,
                    &edge.from_account_id,
                    "follow edge from_account_id",
                )?,
                to_account_ref: resolve_ref(
                    &account_refs,
                    &edge.to_account_id,
                    "follow edge to_account_id",
                )?,
                edge_type: edge.edge_type.clone(),
                status: edge.status.clone(),
                created_at: edge.created_at.clone(),
                source: edge.source.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let surfaces = world
        .surfaces
        .iter()
        .map(|surface| {
            Ok(SeedSurface {
                surface_ref: surface_ref(surface),
                source_surface_id: surface.id.clone(),
                kind: surface.kind.clone(),
                display_name: surface.display_name.clone(),
                visibility: surface.visibility.clone(),
                privacy_mode: privacy_mode(&surface.visibility).to_string(),
                member_account_refs: resolve_refs(
                    &account_refs,
                    &surface.member_account_ids,
                    "surface member_account_ids",
                )?,
                moderator_account_refs: resolve_refs(
                    &account_refs,
                    &surface.moderator_account_ids,
                    "surface moderator_account_ids",
                )?,
                member_count: surface.member_count,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let surface_visibility = world
        .surfaces
        .iter()
        .map(|surface| (surface.id.as_str(), surface.visibility.as_str()))
        .collect::<BTreeMap<_, _>>();

    let objects = world
        .objects
        .iter()
        .map(|object| {
            let visibility = object.visibility.as_str();
            Ok(SeedObject {
                object_ref: object_ref(object),
                source_object_id: object.id.clone(),
                kind: object.kind.clone(),
                owner_account_ref: resolve_ref(
                    &account_refs,
                    &object.owner_account_id,
                    "object owner_account_id",
                )?,
                surface_ref: resolve_ref(&surface_refs, &object.surface_id, "object surface_id")?,
                visibility: object.visibility.clone(),
                privacy_mode: privacy_mode(visibility).to_string(),
                content: seed_content_from_ref(&object.id, object.content_ref.as_ref(), visibility),
                created_at: object.created_at.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let streams = world
        .streams
        .iter()
        .map(|stream| {
            Ok(SeedStream {
                id: stream.id.clone(),
                kind: stream.kind.clone(),
                surface_refs: resolve_refs(
                    &surface_refs,
                    &stream.surface_ids,
                    "stream surface_ids",
                )?,
                start_at: stream.start_at.clone(),
                end_at: stream.end_at.clone(),
                replay: stream.replay.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let campaigns = world
        .campaigns
        .iter()
        .map(|campaign| {
            Ok(SeedCampaign {
                id: campaign.id.clone(),
                risk_intent: campaign.risk_intent.clone(),
                actor_account_refs: resolve_refs(
                    &account_refs,
                    &campaign.actor_account_ids,
                    "campaign actor_account_ids",
                )?,
                target_account_refs: resolve_refs(
                    &account_refs,
                    &campaign.target_account_ids,
                    "campaign target_account_ids",
                )?,
                surface_refs: resolve_refs(
                    &surface_refs,
                    &campaign.surface_ids,
                    "campaign surface_ids",
                )?,
                object_refs: resolve_refs(
                    &object_refs,
                    &campaign.object_ids,
                    "campaign object_ids",
                )?,
                stream_ids: campaign.stream_ids.clone(),
                start_at: campaign.start_at.clone(),
                end_at: campaign.end_at.clone(),
                description: campaign.description.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let events = world
        .events
        .iter()
        .filter(|event| {
            event
                .stream_refs
                .iter()
                .any(|stream_id| platform_streams.contains(stream_id.as_str()))
        })
        .map(|event| {
            let visibility = surface_visibility
                .get(event.surface_id.as_str())
                .copied()
                .unwrap_or(event.visibility.as_str());
            Ok(SeedEvent {
                id: event.id.clone(),
                sequence: event.sequence,
                at: event.at.clone(),
                operation: event.event_type.clone(),
                actor_account_ref: resolve_ref(
                    &account_refs,
                    &event.actor_account_id,
                    "event actor_account_id",
                )?,
                surface_ref: resolve_ref(&surface_refs, &event.surface_id, "event surface_id")?,
                visibility: event.visibility.clone(),
                privacy_mode: privacy_mode(visibility).to_string(),
                stream_ids: event.stream_refs.clone(),
                object_refs: resolve_refs(&object_refs, &event.object_refs, "event object_refs")?,
                campaign_ids: event.campaign_ids.clone(),
                risk_intent: event.risk_intent.clone(),
                content: event
                    .content
                    .as_ref()
                    .map(|content| seed_content_from_event(&event.id, content, visibility)),
                analyzer_expectation: event.analyzer_expectation.as_ref().map(|expectation| {
                    SeedAnalyzerExpectation {
                        expect_clean: expectation.expect_clean,
                        expect_threat: expectation.expect_threat.clone(),
                        expect_min_action: expectation.expect_min_action.clone(),
                        expect_min_alert: expectation.expect_min_alert.clone(),
                        expected_reason_codes: expectation.expected_reason_codes.clone(),
                    }
                }),
                platform_expectation: event.platform_expectation.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(PlatformSeed {
        schema_version: PLATFORM_SEED_SCHEMA_VERSION,
        source_schema_version: world.schema_version.clone(),
        world: SeedWorld {
            id: world.world.id.clone(),
            label: world.world.label.clone(),
            description: world.world.description.clone(),
            owner_account_ref: owner_account_ref.clone(),
            locale: world.world.locale.clone(),
            created_for: world.world.created_for.clone(),
        },
        accounts,
        guardian_links,
        social_edges,
        surfaces,
        objects,
        streams,
        campaigns,
        events,
    })
}

fn account_ref(account: &V2Account) -> String {
    account
        .platform_account_ref
        .clone()
        .unwrap_or_else(|| format!("platform:user:{}", account.id))
}

fn surface_ref(surface: &V2Surface) -> String {
    surface
        .platform_surface_ref
        .clone()
        .unwrap_or_else(|| format!("platform:surface:{}", surface.id))
}

fn object_ref(object: &V2Object) -> String {
    object
        .platform_object_ref
        .clone()
        .unwrap_or_else(|| format!("platform:object:{}", object.id))
}

fn resolve_ref(
    refs: &BTreeMap<&str, String>,
    source_id: &str,
    context: &str,
) -> Result<String, String> {
    refs.get(source_id)
        .cloned()
        .ok_or_else(|| format!("{context} `{source_id}` does not resolve"))
}

fn resolve_refs(
    refs: &BTreeMap<&str, String>,
    source_ids: &[String],
    context: &str,
) -> Result<Vec<String>, String> {
    source_ids
        .iter()
        .map(|source_id| resolve_ref(refs, source_id, context))
        .collect()
}

fn seed_content_from_ref(
    fixture_ref: &str,
    content_ref: Option<&V2ContentRef>,
    visibility: &str,
) -> SeedContent {
    let Some(content_ref) = content_ref else {
        return SeedContent::Redacted {
            content_type: None,
            language: None,
            fixture_ref: fixture_ref.to_string(),
            plaintext_sha256: None,
            plaintext_len: None,
        };
    };

    let value = content_ref.value.as_deref().unwrap_or_default();
    if is_server_visible(visibility) && content_ref.mode == "plaintext" {
        SeedContent::Plaintext {
            content_type: "text".to_string(),
            language: None,
            value: value.to_string(),
        }
    } else {
        SeedContent::Redacted {
            content_type: Some("text".to_string()),
            language: None,
            fixture_ref: fixture_ref.to_string(),
            plaintext_sha256: (!value.is_empty()).then(|| sha256_hex(value)),
            plaintext_len: (!value.is_empty()).then_some(value.len()),
        }
    }
}

fn seed_content_from_event(
    fixture_ref: &str,
    content: &V2Content,
    visibility: &str,
) -> SeedContent {
    let text = content.text.as_deref().unwrap_or_default();
    if is_server_visible(visibility) {
        SeedContent::Plaintext {
            content_type: content.content_type.clone(),
            language: content.language.clone(),
            value: text.to_string(),
        }
    } else {
        SeedContent::OpaqueFixtureRef {
            content_type: content.content_type.clone(),
            language: content.language.clone(),
            fixture_ref: fixture_ref.to_string(),
            plaintext_sha256: sha256_hex(text),
            plaintext_len: text.len(),
        }
    }
}

fn privacy_mode(visibility: &str) -> &'static str {
    if is_server_visible(visibility) {
        "server_visible"
    } else {
        "metadata_only"
    }
}

fn is_server_visible(visibility: &str) -> bool {
    matches!(visibility, "public" | "moderators_only")
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn print_help() {
    println!(
        "Usage: cargo run -p aura-core --example safety_world_v2_platform_seed -- [--input PATH] [--output PATH]\n\n\
         Exports a Safety World v2 fixture into a privacy-preserving platform_seed.v1 contract.\n\n\
         Options:\n\
           --input PATH   Safety World v2 JSON file to export\n\
           --output PATH  Write platform_seed.v1 JSON to this path; stdout by default\n\
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
    fn bundled_example_exports_platform_seed_shape() {
        let seed = export_platform_seed(&example_world()).expect("platform seed exports");

        assert_eq!(seed.schema_version, "platform_seed.v1");
        assert_eq!(seed.world.owner_account_ref, "platform:user:sofia");
        assert_eq!(seed.accounts.len(), 4);
        assert_eq!(seed.guardian_links.len(), 1);
        assert_eq!(seed.social_edges.len(), 2);
        assert_eq!(seed.surfaces.len(), 3);
        assert_eq!(seed.objects.len(), 2);
        assert_eq!(seed.campaigns.len(), 2);
        assert_eq!(seed.events.len(), 3);
    }

    #[test]
    fn private_event_content_is_opaque_not_plaintext() {
        let seed = export_platform_seed(&example_world()).expect("platform seed exports");
        let json = serde_json::to_string(&seed).expect("seed serializes");

        assert!(!json.contains("Don't tell your parents"));

        let private_event = seed
            .events
            .iter()
            .find(|event| event.id == "evt_grooming_secret_001")
            .expect("private event exists");
        assert_eq!(private_event.privacy_mode, "metadata_only");
        match private_event
            .content
            .as_ref()
            .expect("private content exists")
        {
            SeedContent::OpaqueFixtureRef {
                fixture_ref,
                plaintext_len,
                ..
            } => {
                assert_eq!(fixture_ref, "evt_grooming_secret_001");
                assert!(*plaintext_len > 0);
            }
            other => panic!("expected opaque private content, got {other:?}"),
        }
    }

    #[test]
    fn public_event_content_remains_plaintext_for_server_side_moderation() {
        let seed = export_platform_seed(&example_world()).expect("platform seed exports");

        let public_event = seed
            .events
            .iter()
            .find(|event| event.id == "evt_public_phishing_001")
            .expect("public event exists");
        assert_eq!(public_event.privacy_mode, "server_visible");
        match public_event
            .content
            .as_ref()
            .expect("public content exists")
        {
            SeedContent::Plaintext { value, .. } => {
                assert!(value.contains("free skins"));
            }
            other => panic!("expected plaintext public content, got {other:?}"),
        }
    }

    #[test]
    fn exporter_keeps_only_platform_import_events() {
        let mut world = example_world();
        world.events[2].stream_refs = vec!["stream_analyzer_replay".to_string()];

        let seed = export_platform_seed(&world).expect("platform seed exports");

        assert_eq!(seed.events.len(), 2);
        assert!(!seed
            .events
            .iter()
            .any(|event| event.id == "evt_public_phishing_001"));
    }

    #[test]
    fn exporter_rejects_unresolved_event_actor() {
        let mut world = example_world();
        world.events[0].actor_account_id = "missing_account".to_string();

        let err = export_platform_seed(&world).expect_err("missing actor should fail");

        assert!(err.contains("event actor_account_id"));
    }
}
