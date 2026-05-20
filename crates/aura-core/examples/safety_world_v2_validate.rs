use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

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
    let value: Value = serde_json::from_str(&raw).unwrap_or_else(|err| {
        eprintln!("error: invalid JSON in {}: {err}", input.display());
        std::process::exit(1);
    });

    let report = validate_safety_world_v2(&value);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report serializes")
        );
    } else {
        print_report(&input, &report);
    }

    if !report.errors.is_empty() {
        std::process::exit(1);
    }
}

#[derive(Debug, Default)]
struct Args {
    input: Option<PathBuf>,
    json: bool,
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
                    let value = args
                        .next()
                        .ok_or_else(|| "--input requires a path".to_string())?;
                    parsed.input = Some(PathBuf::from(value));
                }
                "--json" => parsed.json = true,
                "--help" | "-h" => parsed.help = true,
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, serde::Serialize)]
struct ValidationReport {
    schema: String,
    ok: bool,
    counts: BTreeMap<String, usize>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

fn validate_safety_world_v2(value: &Value) -> ValidationReport {
    let mut validator = Validator::default();
    validator.validate(value);
    let ok = validator.errors.is_empty();
    ValidationReport {
        schema: EXPECTED_SCHEMA_VERSION.to_string(),
        ok,
        counts: validator.counts,
        errors: validator.errors,
        warnings: validator.warnings,
    }
}

#[derive(Debug, Default)]
struct Validator {
    accounts: BTreeSet<String>,
    protected_accounts: BTreeSet<String>,
    surfaces: BTreeSet<String>,
    objects: BTreeSet<String>,
    streams: BTreeSet<String>,
    campaigns: BTreeSet<String>,
    risky_campaigns: BTreeSet<String>,
    risky_campaign_events: BTreeSet<String>,
    active_guardian_children: BTreeSet<String>,
    counts: BTreeMap<String, usize>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl Validator {
    fn validate(&mut self, value: &Value) {
        let Some(root) = value.as_object() else {
            self.error("$", "top-level value must be a JSON object");
            return;
        };

        self.expect_string_eq(
            root.get("schema_version"),
            "$.schema_version",
            EXPECTED_SCHEMA_VERSION,
        );
        for field in ["world", "run_sizes", "accounts", "surfaces", "events"] {
            if !root.contains_key(field) {
                self.error("$", format!("missing required top-level field `{field}`"));
            }
        }

        self.collect_ids(root);
        self.validate_world(root);
        self.validate_accounts(root);
        self.validate_guardian_links(root);
        self.validate_follow_graph(root);
        self.validate_surfaces(root);
        self.validate_objects(root);
        self.validate_streams(root);
        self.validate_campaigns(root);
        self.validate_run_sizes(root);
        self.validate_events(root);
        self.validate_cross_collection_rules();
    }

    fn collect_ids(&mut self, root: &serde_json::Map<String, Value>) {
        self.accounts = collect_required_ids(root.get("accounts"), "$.accounts", &mut self.errors);
        self.surfaces = collect_required_ids(root.get("surfaces"), "$.surfaces", &mut self.errors);
        self.objects = collect_required_ids(root.get("objects"), "$.objects", &mut self.errors);
        self.streams = collect_required_ids(root.get("streams"), "$.streams", &mut self.errors);
        self.campaigns =
            collect_required_ids(root.get("campaigns"), "$.campaigns", &mut self.errors);

        self.counts
            .insert("accounts".to_string(), self.accounts.len());
        self.counts
            .insert("surfaces".to_string(), self.surfaces.len());
        self.counts
            .insert("objects".to_string(), self.objects.len());
        self.counts
            .insert("streams".to_string(), self.streams.len());
        self.counts
            .insert("campaigns".to_string(), self.campaigns.len());
        self.counts.insert(
            "guardian_links".to_string(),
            array_len(root.get("guardian_links")),
        );
        self.counts.insert(
            "follow_graph".to_string(),
            array_len(root.get("follow_graph")),
        );
        self.counts
            .insert("events".to_string(), array_len(root.get("events")));
    }

    fn validate_world(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(world) = object_at(root.get("world")) else {
            self.error("$.world", "must be an object");
            return;
        };
        for field in [
            "id",
            "label",
            "description",
            "source_family",
            "owner_account_id",
            "locale",
            "protection_profile",
        ] {
            self.require_nonempty_string(world.get(field), &format!("$.world.{field}"));
        }

        if let Some(owner) = string_at(world.get("owner_account_id")) {
            self.require_ref(&self.accounts.clone(), owner, "$.world.owner_account_id");
        }

        if world
            .get("created_for")
            .and_then(Value::as_array)
            .is_none_or(|items| items.is_empty())
        {
            self.error("$.world.created_for", "must be a non-empty array");
        }

        if world
            .get("ttl_days")
            .and_then(Value::as_u64)
            .is_none_or(|days| days == 0)
        {
            self.error("$.world.ttl_days", "must be a positive integer");
        }
    }

    fn validate_accounts(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(accounts) = array_at(root.get("accounts")) else {
            self.error("$.accounts", "must be an array");
            return;
        };

        for (index, account) in accounts.iter().enumerate() {
            let path = format!("$.accounts[{index}]");
            let Some(account) = account.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };

            for field in ["id", "display_name", "account_type", "role"] {
                self.require_nonempty_string(account.get(field), &format!("{path}.{field}"));
            }

            let account_id = string_at(account.get("id")).unwrap_or_default();
            let account_type = string_at(account.get("account_type")).unwrap_or_default();
            let role = string_at(account.get("role")).unwrap_or_default();

            if role == "protected_user" {
                self.protected_accounts.insert(account_id.to_string());
                if !matches!(account_type, "child" | "teen") {
                    self.warn(
                        &path,
                        "protected_user should normally have account_type child or teen",
                    );
                }
            }

            if matches!(account_type, "child" | "teen") || role == "protected_user" {
                let age_years = account
                    .get("age")
                    .and_then(Value::as_object)
                    .and_then(|age| age.get("years"))
                    .and_then(Value::as_u64);
                if age_years.is_none() {
                    self.error(format!("{path}.age.years"), "child/teen account needs age");
                }
            }

            let Some(trust) = object_at(account.get("trust")) else {
                self.error(format!("{path}.trust"), "must be an object");
                continue;
            };
            if trust.get("trusted").and_then(Value::as_bool).is_none() {
                self.error(format!("{path}.trust.trusted"), "must be a boolean");
            }
            self.require_nonempty_string(
                trust.get("relationship"),
                &format!("{path}.trust.relationship"),
            );
            self.require_nonempty_string(trust.get("source"), &format!("{path}.trust.source"));
        }
    }

    fn validate_guardian_links(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(links) = optional_array(root.get("guardian_links"), "$.guardian_links", self)
        else {
            return;
        };

        for (index, link) in links.iter().enumerate() {
            let path = format!("$.guardian_links[{index}]");
            let Some(link) = link.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };
            self.require_nonempty_string(link.get("id"), &format!("{path}.id"));
            let child = string_at(link.get("child_account_id"));
            let guardian = string_at(link.get("guardian_account_id"));
            if let Some(child) = child {
                self.require_ref(
                    &self.accounts.clone(),
                    child,
                    &format!("{path}.child_account_id"),
                );
            }
            if let Some(guardian) = guardian {
                self.require_ref(
                    &self.accounts.clone(),
                    guardian,
                    &format!("{path}.guardian_account_id"),
                );
            }
            if child.is_none() {
                self.error(
                    format!("{path}.child_account_id"),
                    "must be a non-empty string",
                );
            }
            if guardian.is_none() {
                self.error(
                    format!("{path}.guardian_account_id"),
                    "must be a non-empty string",
                );
            }
            if string_at(link.get("status")) == Some("active") {
                if let Some(child) = child {
                    self.active_guardian_children.insert(child.to_string());
                }
                if link.get("can_receive_alerts").and_then(Value::as_bool) != Some(true) {
                    self.warn(&path, "active guardian link cannot receive alerts");
                }
            }
        }
    }

    fn validate_follow_graph(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(edges) = optional_array(root.get("follow_graph"), "$.follow_graph", self) else {
            return;
        };

        for (index, edge) in edges.iter().enumerate() {
            let path = format!("$.follow_graph[{index}]");
            let Some(edge) = edge.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };
            for field in ["id", "edge_type", "status", "created_at", "source"] {
                self.require_nonempty_string(edge.get(field), &format!("{path}.{field}"));
            }
            for field in ["from_account_id", "to_account_id"] {
                match string_at(edge.get(field)) {
                    Some(value) => {
                        self.require_ref(&self.accounts.clone(), value, &format!("{path}.{field}"))
                    }
                    None => self.error(format!("{path}.{field}"), "must be a non-empty string"),
                }
            }
        }
    }

    fn validate_surfaces(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(surfaces) = array_at(root.get("surfaces")) else {
            self.error("$.surfaces", "must be an array");
            return;
        };

        for (index, surface) in surfaces.iter().enumerate() {
            let path = format!("$.surfaces[{index}]");
            let Some(surface) = surface.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };
            for field in [
                "id",
                "kind",
                "display_name",
                "visibility",
                "v1_conversation_type",
            ] {
                self.require_nonempty_string(surface.get(field), &format!("{path}.{field}"));
            }
            match string_at(surface.get("v1_conversation_type")) {
                Some("direct" | "group") => {}
                Some(other) => self.error(
                    format!("{path}.v1_conversation_type"),
                    format!("must be `direct` or `group`, got `{other}`"),
                ),
                None => {}
            }
            if let Some(members) = surface.get("member_account_ids").and_then(Value::as_array) {
                for (member_index, member) in members.iter().enumerate() {
                    match string_at(Some(member)) {
                        Some(value) => self.require_ref(
                            &self.accounts.clone(),
                            value,
                            &format!("{path}.member_account_ids[{member_index}]"),
                        ),
                        None => self.error(
                            format!("{path}.member_account_ids[{member_index}]"),
                            "must be a non-empty string",
                        ),
                    }
                }
            } else {
                self.error(format!("{path}.member_account_ids"), "must be an array");
            }
        }
    }

    fn validate_objects(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(objects) = optional_array(root.get("objects"), "$.objects", self) else {
            return;
        };

        for (index, object) in objects.iter().enumerate() {
            let path = format!("$.objects[{index}]");
            let Some(object) = object.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };
            for field in ["id", "kind", "visibility", "created_at"] {
                self.require_nonempty_string(object.get(field), &format!("{path}.{field}"));
            }
            for (field, refs) in [
                ("owner_account_id", self.accounts.clone()),
                ("surface_id", self.surfaces.clone()),
            ] {
                match string_at(object.get(field)) {
                    Some(value) => self.require_ref(&refs, value, &format!("{path}.{field}")),
                    None => self.error(format!("{path}.{field}"), "must be a non-empty string"),
                }
            }
        }
    }

    fn validate_streams(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(streams) = optional_array(root.get("streams"), "$.streams", self) else {
            return;
        };

        for (index, stream) in streams.iter().enumerate() {
            let path = format!("$.streams[{index}]");
            let Some(stream) = stream.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };
            for field in ["id", "kind", "start_at", "end_at", "ordering", "replay"] {
                self.require_nonempty_string(stream.get(field), &format!("{path}.{field}"));
            }
            self.require_refs_array(
                stream.get("surface_ids"),
                &self.surfaces.clone(),
                &format!("{path}.surface_ids"),
            );
        }
    }

    fn validate_campaigns(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(campaigns) = optional_array(root.get("campaigns"), "$.campaigns", self) else {
            return;
        };

        for (index, campaign) in campaigns.iter().enumerate() {
            let path = format!("$.campaigns[{index}]");
            let Some(campaign) = campaign.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };
            for field in ["id", "risk_intent", "start_at", "description"] {
                self.require_nonempty_string(campaign.get(field), &format!("{path}.{field}"));
            }
            let campaign_id = string_at(campaign.get("id")).unwrap_or_default();
            if string_at(campaign.get("risk_intent")).is_some_and(|intent| intent != "none") {
                self.risky_campaigns.insert(campaign_id.to_string());
            }
            self.require_refs_array(
                campaign.get("actor_account_ids"),
                &self.accounts.clone(),
                &format!("{path}.actor_account_ids"),
            );
            self.require_refs_array(
                campaign.get("target_account_ids"),
                &self.accounts.clone(),
                &format!("{path}.target_account_ids"),
            );
            self.require_refs_array(
                campaign.get("surface_ids"),
                &self.surfaces.clone(),
                &format!("{path}.surface_ids"),
            );
            self.require_refs_array(
                campaign.get("object_ids"),
                &self.objects.clone(),
                &format!("{path}.object_ids"),
            );
            self.require_refs_array(
                campaign.get("stream_ids"),
                &self.streams.clone(),
                &format!("{path}.stream_ids"),
            );
        }
    }

    fn validate_run_sizes(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(run_sizes) = object_at(root.get("run_sizes")) else {
            self.error("$.run_sizes", "must be an object");
            return;
        };

        for name in ["smoke", "ci", "nightly"] {
            let path = format!("$.run_sizes.{name}");
            let Some(size) = object_at(run_sizes.get(name)) else {
                self.error(&path, "must be present and must be an object");
                continue;
            };
            if size.get("event_limit").and_then(Value::as_u64).is_none()
                && size
                    .get("repeat_multiplier")
                    .and_then(Value::as_u64)
                    .is_none()
            {
                self.error(
                    &path,
                    "must define at least one of event_limit or repeat_multiplier",
                );
            }
            self.require_refs_array(
                size.get("streams"),
                &self.streams.clone(),
                &format!("{path}.streams"),
            );
            if size
                .get("min_labeled_recall")
                .and_then(Value::as_f64)
                .is_none_or(|rate| !(0.0..=1.0).contains(&rate))
            {
                self.error(
                    format!("{path}.min_labeled_recall"),
                    "must be a number in 0.0..=1.0",
                );
            }
            if size
                .get("max_clean_fp_rate")
                .and_then(Value::as_f64)
                .is_none_or(|rate| !(0.0..=1.0).contains(&rate))
            {
                self.error(
                    format!("{path}.max_clean_fp_rate"),
                    "must be a number in 0.0..=1.0",
                );
            }
        }
    }

    fn validate_events(&mut self, root: &serde_json::Map<String, Value>) {
        let Some(events) = array_at(root.get("events")) else {
            self.error("$.events", "must be an array");
            return;
        };

        let mut event_ids = BTreeSet::new();
        let mut sequences = BTreeSet::new();
        for (index, event) in events.iter().enumerate() {
            let path = format!("$.events[{index}]");
            let Some(event) = event.as_object() else {
                self.error(&path, "must be an object");
                continue;
            };
            for field in ["id", "at", "type", "visibility", "risk_intent"] {
                self.require_nonempty_string(event.get(field), &format!("{path}.{field}"));
            }
            if let Some(id) = string_at(event.get("id")) {
                if !event_ids.insert(id.to_string()) {
                    self.error(format!("{path}.id"), format!("duplicate event id `{id}`"));
                }
            }
            if let Some(sequence) = event.get("sequence").and_then(Value::as_u64) {
                if sequence == 0 {
                    self.error(format!("{path}.sequence"), "must be positive");
                } else if !sequences.insert(sequence) {
                    self.error(
                        format!("{path}.sequence"),
                        format!("duplicate sequence `{sequence}`"),
                    );
                }
            } else {
                self.error(format!("{path}.sequence"), "must be a positive integer");
            }

            for (field, refs) in [
                ("actor_account_id", self.accounts.clone()),
                ("surface_id", self.surfaces.clone()),
            ] {
                match string_at(event.get(field)) {
                    Some(value) => self.require_ref(&refs, value, &format!("{path}.{field}")),
                    None => self.error(format!("{path}.{field}"), "must be a non-empty string"),
                }
            }

            self.require_refs_array(
                event.get("stream_refs"),
                &self.streams.clone(),
                &format!("{path}.stream_refs"),
            );
            self.require_refs_array(
                event.get("object_refs"),
                &self.objects.clone(),
                &format!("{path}.object_refs"),
            );
            self.require_refs_array(
                event.get("campaign_ids"),
                &self.campaigns.clone(),
                &format!("{path}.campaign_ids"),
            );

            if string_at(event.get("type")) == Some("message_created") {
                self.validate_message_event(event, &path);
            }
            self.validate_event_expectations(event, &path);
        }
    }

    fn validate_message_event(&mut self, event: &serde_json::Map<String, Value>, path: &str) {
        let Some(content) = object_at(event.get("content")) else {
            self.error(
                format!("{path}.content"),
                "message_created requires content",
            );
            return;
        };
        self.require_nonempty_string(
            content.get("content_type"),
            &format!("{path}.content.content_type"),
        );
        self.require_nonempty_string(content.get("language"), &format!("{path}.content.language"));

        let Some(v1_projection) = object_at(event.get("v1_projection")) else {
            self.error(
                format!("{path}.v1_projection"),
                "message_created requires v1_projection",
            );
            return;
        };
        for field in [
            "sender_id",
            "conversation_id",
            "conversation_type",
            "sender_relationship",
            "relationship_trust_source",
        ] {
            self.require_nonempty_string(
                v1_projection.get(field),
                &format!("{path}.v1_projection.{field}"),
            );
        }
        match string_at(v1_projection.get("conversation_type")) {
            Some("direct" | "group") => {}
            Some(other) => self.error(
                format!("{path}.v1_projection.conversation_type"),
                format!("must be `direct` or `group`, got `{other}`"),
            ),
            None => {}
        }
    }

    fn validate_event_expectations(&mut self, event: &serde_json::Map<String, Value>, path: &str) {
        let Some(analyzer) = object_at(event.get("analyzer_expectation")) else {
            self.error(format!("{path}.analyzer_expectation"), "must be an object");
            return;
        };
        if analyzer
            .get("expect_clean")
            .and_then(Value::as_bool)
            .is_none()
        {
            self.error(
                format!("{path}.analyzer_expectation.expect_clean"),
                "must be a boolean",
            );
        }
        if analyzer.get("expect_clean").and_then(Value::as_bool) == Some(false) {
            self.require_nonempty_string(
                analyzer.get("expect_threat"),
                &format!("{path}.analyzer_expectation.expect_threat"),
            );
            if let Some(campaign_ids) = event.get("campaign_ids").and_then(Value::as_array) {
                for campaign_id in campaign_ids.iter().filter_map(|id| string_at(Some(id))) {
                    self.risky_campaign_events.insert(campaign_id.to_string());
                }
            }
        }

        let Some(platform) = object_at(event.get("platform_expectation")) else {
            self.error(format!("{path}.platform_expectation"), "must be an object");
            return;
        };
        for field in [
            "visibility_expected",
            "moderation_expected",
            "notification_expected",
        ] {
            self.require_nonempty_string(
                platform.get(field),
                &format!("{path}.platform_expectation.{field}"),
            );
        }
        for field in [
            "guardian_visible_expected",
            "moderator_visible_expected",
            "audit_log_expected",
        ] {
            if platform.get(field).and_then(Value::as_bool).is_none() {
                self.error(
                    format!("{path}.platform_expectation.{field}"),
                    "must be a boolean",
                );
            }
        }
    }

    fn validate_cross_collection_rules(&mut self) {
        for protected in self.protected_accounts.clone() {
            if !self.active_guardian_children.contains(&protected) {
                self.warn(
                    "$.guardian_links",
                    format!("protected account `{protected}` has no active guardian link"),
                );
            }
        }

        for campaign in self.risky_campaigns.clone() {
            if !self.risky_campaign_events.contains(&campaign) {
                self.error(
                    "$.campaigns",
                    format!("risky campaign `{campaign}` has no positive analyzer event"),
                );
            }
        }
    }

    fn expect_string_eq(&mut self, value: Option<&Value>, path: &str, expected: &str) {
        match string_at(value) {
            Some(actual) if actual == expected => {}
            Some(actual) => self.error(path, format!("expected `{expected}`, got `{actual}`")),
            None => self.error(path, format!("expected string `{expected}`")),
        }
    }

    fn require_nonempty_string(&mut self, value: Option<&Value>, path: &str) {
        if string_at(value).is_none() {
            self.error(path, "must be a non-empty string");
        }
    }

    fn require_refs_array(&mut self, value: Option<&Value>, refs: &BTreeSet<String>, path: &str) {
        let Some(values) = value.and_then(Value::as_array) else {
            self.error(path, "must be an array");
            return;
        };
        for (index, value) in values.iter().enumerate() {
            match string_at(Some(value)) {
                Some(reference) => {
                    self.require_ref(refs, reference, &format!("{path}[{index}]"));
                }
                None => self.error(format!("{path}[{index}]"), "must be a non-empty string"),
            }
        }
    }

    fn require_ref(&mut self, refs: &BTreeSet<String>, reference: &str, path: &str) {
        if !refs.contains(reference) {
            self.error(path, format!("unknown reference `{reference}`"));
        }
    }

    fn error(&mut self, path: impl AsRef<str>, message: impl AsRef<str>) {
        self.errors
            .push(format!("{}: {}", path.as_ref(), message.as_ref()));
    }

    fn warn(&mut self, path: impl AsRef<str>, message: impl AsRef<str>) {
        self.warnings
            .push(format!("{}: {}", path.as_ref(), message.as_ref()));
    }
}

fn collect_required_ids(
    value: Option<&Value>,
    path: &str,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let Some(items) = value.and_then(Value::as_array) else {
        errors.push(format!("{path}: must be an array"));
        return ids;
    };
    for (index, item) in items.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(object) = item.as_object() else {
            errors.push(format!("{item_path}: must be an object"));
            continue;
        };
        let Some(id) = string_at(object.get("id")) else {
            errors.push(format!("{item_path}.id: must be a non-empty string"));
            continue;
        };
        if !ids.insert(id.to_string()) {
            errors.push(format!("{item_path}.id: duplicate id `{id}`"));
        }
    }
    ids
}

fn optional_array<'a>(
    value: Option<&'a Value>,
    path: &str,
    validator: &mut Validator,
) -> Option<&'a Vec<Value>> {
    match value {
        Some(value) => match value.as_array() {
            Some(items) => Some(items),
            None => {
                validator.error(path, "must be an array");
                None
            }
        },
        None => Some(empty_array()),
    }
}

fn empty_array() -> &'static Vec<Value> {
    use std::sync::OnceLock;
    static EMPTY: OnceLock<Vec<Value>> = OnceLock::new();
    EMPTY.get_or_init(Vec::new)
}

fn array_at(value: Option<&Value>) -> Option<&Vec<Value>> {
    value.and_then(Value::as_array)
}

fn object_at(value: Option<&Value>) -> Option<&serde_json::Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn string_at(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, Vec::len)
}

fn print_report(input: &Path, report: &ValidationReport) {
    if report.ok {
        println!("Safety World v2 validation passed: {}", input.display());
    } else {
        println!("Safety World v2 validation failed: {}", input.display());
    }

    if !report.counts.is_empty() {
        println!("Counts:");
        for (name, count) in &report.counts {
            println!("  {name}: {count}");
        }
    }

    if !report.warnings.is_empty() {
        println!("Warnings:");
        for warning in &report.warnings {
            println!("  - {warning}");
        }
    }

    if !report.errors.is_empty() {
        println!("Errors:");
        for error in &report.errors {
            println!("  - {error}");
        }
    }
}

fn print_help() {
    println!(
        "Usage: cargo run -p aura-core --example safety_world_v2_validate -- [--input PATH] [--json]\n\n\
         Validates Safety World v2 schema/reference integrity.\n\n\
         Options:\n\
           --input PATH  Safety World v2 JSON file to validate\n\
           --json        Print a machine-readable validation report\n\
           --help        Show this help"
    );
}
