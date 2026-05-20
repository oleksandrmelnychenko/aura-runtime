# Safety World v2

Safety World v2 is the proposed single source of truth for long-running safety
worlds. It extends the existing `world_sim` fixtures without changing Rust
execution yet, and is intended to support two consumers:

- analyzer replay in `aura-core`, by losslessly projecting v2 messages into the
  current `world_sim.v1` event shape
- future `aura-platform` seed/load import, by carrying accounts, graph,
  visibility, object references, stream references, campaigns, and moderation
  expectations in one artifact

Status: design artifact only. Existing fixtures under
`crates/aura-core/data/world_sim*.json` and
`crates/aura-core/data/world_lifecycle_suite/*.json` remain authoritative for
runtime until a parser/importer is implemented.

## Goals

- Keep replay deterministic and reviewable.
- Preserve current analyzer expectations: `expect_clean`, `expect_threat`,
  `expect_min_action`, and `expect_min_alert`.
- Add platform-native context that v1 cannot express: account records, age
  snapshots, guardian links, follow graph, surfaces, content visibility,
  object refs, stream refs, and campaign ids.
- Make platform visibility and moderation expectations explicit instead of
  inferring them from text fixtures.
- Define run sizes for smoke, CI, and nightly without duplicating worlds.

## Non-Goals

- No Rust parser, importer, generator, or analyzer behavior change in this
  phase.
- No production policy change. v2 records expected behavior; it does not define
  enforcement logic.
- No plaintext requirement for future platform replay. v2 can carry plaintext
  seed content for local eval, but platform imports should support redacted or
  synthetic content references.

## Top-Level Shape

```json
{
  "schema_version": "safety_world.v2",
  "world": {},
  "run_sizes": {},
  "accounts": [],
  "guardian_links": [],
  "follow_graph": [],
  "surfaces": [],
  "objects": [],
  "streams": [],
  "campaigns": [],
  "events": []
}
```

Required top-level fields are `schema_version`, `world`, `accounts`,
`surfaces`, `events`, and `run_sizes`. Other collections may be empty arrays.

## World Metadata

`world` identifies the fixture and default replay settings.

- `id`: stable machine id, for example `safety_world_v2_sofia_dense`.
- `label`: human-readable label matching current world naming style.
- `description`: one-paragraph scenario summary.
- `source_family`: `world_sim`, `world_lifecycle_suite`, `platform_seed`, or
  another reviewable source family.
- `owner_account_id`: protected account for default replay.
- `locale`: BCP-47 or existing short code, for example `uk` or `en`.
- `timezone_offset_minutes`: default offset for generated local timestamps.
- `protection_profile`: current protection level vocabulary, for example
  `high`.
- `ttl_days`: replay memory horizon.
- `created_for`: list such as `["analyzer_replay", "aura_platform_seed_load"]`.

## Accounts

`accounts` replaces v1 `owner` plus `actors` while preserving the fields needed
to project back to v1.

Required fields:

- `id`
- `display_name`
- `account_type`: `child`, `teen`, `adult`, `service`, `bot`, `organization`,
  or `unknown`
- `age.years`: integer or `null` when unknown
- `age.as_of`: date or timestamp for age snapshots
- `role`: `protected_user`, `guardian`, `peer`, `trusted_adult`,
  `unknown_adult`, `service`, `moderator`, or `other`
- `trust.trusted`: boolean
- `trust.relationship`: maps to current `sender_relationship`
- `trust.source`: maps to current `relationship_trust_source`

Recommended fields:

- `platform_account_ref`: import id for `aura-platform`
- `declared_age`, when different from verified age
- `age_band`: `under_13`, `13_15`, `16_17`, `adult`, or `unknown`
- `risk_profile`: `baseline`, `watch`, `elevated`, `restricted`, or `unknown`
- `guardian_visibility`: `none`, `summary`, `full`, or `emergency_only`

## Guardian Links

`guardian_links` explicitly models protected-user supervision instead of
encoding it as a trusted actor.

- `id`
- `child_account_id`
- `guardian_account_id`
- `relationship`: `parent`, `guardian`, `relative`, `school_staff`, or
  `authorized_adult`
- `status`: `active`, `pending`, `revoked`, or `expired`
- `verified_by`: `guardian_verified`, `school_directory`, `platform_verified`,
  `manual_review`, or `unknown`
- `visibility_scope`: `all_surfaces`, `managed_surfaces`,
  `emergency_only`, or `none`
- `can_receive_alerts`: boolean

## Follow Graph

`follow_graph` captures social reach and asymmetric relationships.

- `id`
- `from_account_id`
- `to_account_id`
- `edge_type`: `follows`, `friend`, `blocked`, `muted`, `subscriber`,
  `member`, or `invited`
- `status`: `active`, `pending`, `removed`, or `blocked`
- `created_at`
- `source`: `user_action`, `imported_contacts`, `school_directory`,
  `platform_recommendation`, or `synthetic_seed`

## Surfaces

`surfaces` generalizes v1 `conversations` and platform destinations.

- `id`
- `kind`: `direct_message`, `group_chat`, `public_comments`, `livestream_chat`,
  `story_reply`, `forum_thread`, `game_chat`, `feed_post`, or `system_notice`
- `display_name`
- `visibility`: `private`, `guardian_visible`, `members`, `followers`,
  `public`, or `moderators_only`
- `member_account_ids`: accounts with normal access
- `moderator_account_ids`: platform or community moderators
- `member_count`: integer when known
- `platform_surface_ref`: import id for platform seed/load
- `v1_conversation_type`: `direct` or `group` for analyzer projection

## Objects

`objects` are durable content records that messages or platform events refer to.
They let one world represent comments on posts, profile updates, shared media,
and takedowns without making every object a conversation.

- `id`
- `kind`: `message`, `post`, `comment`, `profile`, `image`, `video`, `link`,
  `invite`, `report`, or `moderation_case`
- `owner_account_id`
- `surface_id`
- `visibility`: same vocabulary as surfaces
- `platform_object_ref`
- `content_ref`: optional plaintext, redacted text, or fixture-local reference
- `created_at`

## Streams

`streams` group ordered events for replay, import, and performance scaling.

- `id`
- `kind`: `analyzer_replay`, `platform_import`, `shadow_bundle`,
  `moderation_queue`, or `notification_feed`
- `surface_ids`
- `start_at`
- `end_at`
- `ordering`: `timestamp_then_sequence`
- `replay`: `enabled`, `platform_only`, or `disabled`

## Campaigns

`campaigns` groups related risky behavior across accounts, surfaces, objects,
and streams.

- `id`
- `risk_intent`: `none`, `grooming`, `bullying`, `self_harm`, `phishing`,
  `scam`, `pii_leakage`, `doxxing`, `manipulation`, `threat`, `propaganda`,
  `spam`, or `mixed`
- `actor_account_ids`
- `target_account_ids`
- `surface_ids`
- `object_ids`
- `stream_ids`
- `start_at`
- `end_at`
- `description`

Use `risk_intent` for fixture author intent. Analyzer output remains an
expectation on individual events.

## Events

Events are the ordered replay unit. Analyzer-compatible message events should
carry enough data to project into the current v1 `events` entry.

Required fields:

- `id`
- `sequence`
- `at`
- `type`: `message_created`, `object_created`, `visibility_changed`,
  `follow_edge_changed`, `report_created`, `moderation_action`, or
  `guardian_notification`
- `actor_account_id`
- `surface_id`
- `visibility`
- `stream_refs`: array of stream ids
- `object_refs`: array of object ids
- `campaign_ids`: array of campaign ids
- `risk_intent`
- `analyzer_expectation`
- `platform_expectation`

Message event fields:

- `content.text`: plaintext seed text for local eval, if permitted
- `content.language`
- `content.content_type`: `text`, `image`, `video`, `link`, `mixed`, or
  `redacted`
- `v1_projection.sender_id`
- `v1_projection.conversation_id`
- `v1_projection.conversation_type`
- `v1_projection.member_count`
- `v1_projection.sender_relationship`
- `v1_projection.relationship_trust_source`

`analyzer_expectation` fields:

- `expect_clean`
- `expect_threat`
- `expect_min_action`
- `expect_min_alert`
- `expected_reason_codes`
- `max_false_positive`
- `notes`

`platform_expectation` fields:

- `visibility_expected`: expected post-event visibility
- `moderation_expected`: `none`, `allow`, `label`, `warn`, `limit`,
  `hide`, `remove`, `escalate`, or `guardian_alert`
- `guardian_visible_expected`: boolean
- `moderator_visible_expected`: boolean
- `notification_expected`: `none`, `guardian_summary`, `guardian_urgent`,
  `moderator_queue`, or `user_warning`
- `audit_log_expected`: boolean

## Run Sizes

`run_sizes` defines scale without copying the same world.

- `smoke`: fast local parse/replay. Recommended max: 25 events.
- `ci`: deterministic gate. Recommended max: 2,000 events or one dense world
  shard.
- `nightly`: lifecycle and scale stress. Recommended max: 100,000+ generated
  events.

Each run size should include:

- `event_limit` or `repeat_multiplier`
- `streams`
- `require_clean`
- `min_labeled_recall`
- `max_clean_fp_rate`
- `intended_command`, when a current or future command exists

## v1 Projection Rules

Until Rust supports v2 directly, a v2-to-v1 adapter should:

- select `message_created` events where the referenced stream has
  `replay: "enabled"`
- project `world.owner_account_id` to v1 `owner.id`
- project `accounts` to v1 `actors`
- project `surfaces` with `v1_conversation_type` to v1 `conversations`
- project event `content.text`, `content.language`, `actor_account_id`,
  `surface_id`, and `v1_projection` to v1 event fields
- map `analyzer_expectation` to existing `expect_*` fields
- ignore platform-only fields for analyzer replay, but preserve them for
  evidence manifests and future platform import

## Validation Expectations

Before a v2 artifact is promoted, validation should check:

- every account, surface, object, stream, and campaign reference resolves
- protected accounts have age snapshots
- child or teen protected accounts with guardian expectations have active
  guardian links
- every analyzer-replayed message has a v1 projection
- every risky campaign has at least one positive analyzer expectation or an
  explicit negative-control note
- platform expectations are present for public or guardian-visible surfaces
- smoke, CI, and nightly run sizes are defined

Current validation command:

```bash
cargo run -p aura-core --example safety_world_v2_validate -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json
```

Current v2-to-v1 projection command:

```bash
cargo run -p aura-core --example safety_world_v2_project -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json \
  --output /tmp/safety_world_v2_projected_world_sim.json
```

Projected worlds can then run through the existing analyzer gate:

```bash
cargo run -p aura-core --example world_sim -- \
  --input /tmp/safety_world_v2_projected_world_sim.json \
  --summary-only \
  --require-clean
```

Current privacy-preserving platform seed export command:

```bash
cargo run -p aura-core --example safety_world_v2_platform_seed -- \
  --input crates/aura-core/data/safety_world_v2_schema.example.json \
  --output /tmp/safety_world_v2_platform_seed.json
```

Private and guardian-visible messages are exported as metadata-only opaque
fixture references with hashes, not plaintext. Public or moderator-visible
surfaces may carry plaintext for server-side search and moderation tests.

See `crates/aura-core/data/safety_world_v2_schema.example.json` for a compact
example instance.
