# Product Integration Contract

This document is the stable product-facing contract for messenger clients that
integrate AURA Core through protobuf and FFI.

Status: synchronized with runtime payload behavior on August 1, 2026.

The rule is strict:

- Apple clients consume `LocalDecision.product_surface` first
- Rust clients consume the product projection built from `AnalysisResult`
- clients may use `reason_codes` and `inference` for richer internal routing
- clients should not rebuild child/guardian/review policy from raw scores

## Wire Surface

The canonical Apple request is `LocalDecisionAnalyzeRequest`:

- `message`: the bounded message input
- `identity`: stable account, subject, conversation, event, revision, and
  timestamp identity

The response is `LocalDecisionAnalyzeResponse`. It carries the canonical source
disposition and, only for a successful first processing attempt, one
`LocalDecision` containing:

- `product_surface`
- `recommended_action`
- `reason_codes`
- `inference`
- `runtime_backend`
- `degraded`
- `temporal_context`

It deliberately excludes raw message text, explanations, individual detection
signals, contact identifiers, and arbitrary JSON. Duplicate and stale
responses never contain `decision`.

## Temporal Decision Context

Every successful first-attempt `LocalDecision` carries
`LocalDecisionTemporalContext` schema `1`. This is the content-free bridge from
the canonical source event to the longitudinal Safety Case and the product
surface. It contains:

- the host-owned event time and the runtime's frozen observation time;
- their exact difference as observation delay, never analyzer latency;
- whether this source contributed a retained case observation;
- the case generation/revision and status before/after the reduction;
- the retained observation count, peak risk index in basis points, and the
  first/last source-event times represented by the case.

For an ignored result, the timing fields remain present while every case field
is absent, unspecified, or zero. For a reduced result, the temporal case
generation, revision, and final status must equal the canonical response
receipt. Clients must reject a mismatch rather than reconstruct it from scores.

The temporal context contains no message text, free-form explanation, sender
or conversation identifier, reason code, or server-readable semantic result.
It is persisted only inside the same encrypted local decision ledger as the
rest of `LocalDecision`.

Rust-internal integrations may additionally inspect `AnalysisResult`, including
`signals[].threat_subtype` and `kids_memory`; these fields do not cross the
Apple ABI.

## Exactly-Once Client Rule

The local decision and canonical Safety Case API share one native source
ledger. For each stable source identity and revision:

1. call `analyzeLocalDecision` once;
2. atomically persist its response, exported context, and encrypted
   account-scoped Safety Case state before applying any UI or guardian effect;
3. on duplicate or stale disposition, do not reconstruct policy and do not
   reapply effects; resolve the already persisted response by source identity;
4. if host persistence fails, apply nothing, destroy the uncommitted runtime,
   restore the last durable native state in a fresh runtime, reapply the signed
   execution policy, and retry the same identity.

The full ownership and retry table is in
[ADR 0001](./adr/0001-canonical-local-decision-api.md).

## Threat Subtype Guidance

`threat_subtype` is a Rust-internal fine-grained signal hint for analyst
context and governed evaluation segmentation. It is additive context and does
not replace primary policy fields like `product_surface`,
`recommended_action`, or `threat_type`.

Current important military/propaganda examples include:

- propaganda narrative/source examples: `war_denial`, `dehumanization`,
  `state_media`
- coordinate examples: `ukraine_dd`, `mgrs`, `milgrid`, `google_maps`, `w3w`,
  `pluscode`
- military social engineering examples: `phishing_diia`, `phishing_tck`,
  `phishing_delta`, `phishing_command`, `phishing_account`,
  `military_phishing`
- psyops examples: `surrender`, `surrender_volga`, `command_distrust`,
  `family_targeting`, `regional_division`, `fake_ceasefire`, `demoralization`
- heuristic URL examples: `doppelganger`, `homoglyph`, `heuristic`

Rust integration rule:

- treat unknown/new subtype values as non-breaking additive values and fall back
  to threat-type-level handling.

## KIDS Memory Explainability Guidance

`AnalysisResult.kids_memory` is a Rust-internal additive helper for strict KIDS
integrations. Apple clients consume the already reduced product surface and do
not receive this structure.

Fields:

- `reason_codes`: normalized `kids.memory.*` reasons (without `domain.` prefix)
- `mandatory_guardian_escalation`: whether any reason belongs to the mandatory
  guardian-escalation set

Rust integration rule:

- do not recompute this from raw reason codes when the field is present
- treat missing `kids_memory` as "no KIDS memory reasons observed"
- treat unknown/new `kids.memory.*` strings as non-breaking additive values

For Swift/iOS, the repository ships generated `SwiftProtobuf` models for the
Apple boundary from
[messenger.proto](../proto/aura/messenger/v1/messenger.proto).

The typed entry point is
`AuraAgentRuntime.analyzeLocalDecision(_:)`. SwiftProtobuf is pinned exactly in
`Package.swift` and `Package.resolved`; updating either the schema or generator
requires regenerating and reviewing the checked-in Swift source.

## Product Surface Model

`product_surface` is a stable projection from the Rust domain model into three
product-visible surfaces:

- `child`
- `guardian`
- `review`

It also carries:

- `rollout_mode`
- `uncertainty_disposition`
- copied `threat_type`
- copied `action`
- copied `score`

## Rollout Modes

### `shadow`

- child delivery is mirrored, not applied
- guardian delivery is mirrored, not applied
- review delivery is active
- intended for validation and replay capture

### `staging_pilot`

- child delivery is still conservative
- high-confidence guardian pathways may be applied by product policy
- review delivery remains active
- intended for controlled pilot slices

### `guardian_enabled`

- child surface may be applied live
- guardian alerts may be applied live
- review surface remains active for auditability

## Child Surface

`ProductChildSurface` answers one question:

What may the child-facing client do with this decision?

Fields:

- `delivery_mode`
- `visible`
- `intervention`
- `ui_actions`
- `reason_codes`

Client guidance:

- respect `delivery_mode` before rendering any intervention
- use `intervention` as the primary UI shape
- use `ui_actions` for detailed UI affordances
- use `reason_codes` only for internal copy/routing, not raw end-user display

## Guardian Surface

`ProductGuardianSurface` answers:

Should the guardian-facing product be notified, and at what level?

Fields:

- `delivery_mode`
- `notify`
- `priority`
- `follow_ups`
- `reason_codes`

Client guidance:

- `notify=false` means do not generate a guardian event
- `priority` drives channel urgency and batching policy
- `follow_ups` drive guardian CTA choices, not detection logic

## Review Surface

`ProductReviewSurface` answers:

Should this decision enter human review or moderation tooling?

Fields:

- `delivery_mode`
- `open_review`
- `urgency`
- `reason_codes`
- `latent_states`

Client guidance:

- review tools should key off `open_review` and `urgency`
- `latent_states` are intended for reviewer context, not end-user copy

## Uncertainty Handling

`uncertainty_disposition` defines how clients should behave when confidence is
not strong enough for fully automatic enforcement.

Values:

- `normal`
- `mirror_only`
- `require_review`
- `guardian_priority`

Product rule:

- when `mirror_only`, do not enforce a child-visible intervention live
- when `require_review`, prefer review routing over automatic escalation
- when `guardian_priority`, preserve guardian escalation while keeping the child
  surface conservative

## Do Not Recompute Policy Client-Side

Clients must not:

- convert `score` directly into UI actions
- reinterpret latent states into new alerts
- rebuild guardian urgency from raw `reason_codes`
- guess shadow/staging/live behavior from `Action` alone

That logic already exists in:

- [product.rs](../crates/aura-core/src/product.rs)
- [action.rs](../crates/aura-core/src/action.rs)

## Recommended Client Mapping

Use this priority order:

1. `product_surface`
2. `recommended_action`
3. `inference`
4. `reason_codes`
5. copied `threat_type` / `score` within `product_surface`

This keeps product behavior aligned with the runtime and reduces client drift.
