# Product Integration Contract

This document is the stable product-facing contract for messenger clients that
integrate AURA Core through protobuf and FFI.

Status: synchronized with runtime payload behavior on March 23, 2026.

The rule is strict:

- clients should consume `AnalysisResult.product_surface` first
- clients may use `threat_type`, `reason_codes`, and `inference` for richer UI
- clients should not rebuild child/guardian/review policy from raw scores

## Wire Surface

The canonical integration payload is:

- `AnalysisResult`
- `AnalysisResult.product_surface`
- `AnalysisResult.recommended_action`
- `AnalysisResult.inference`
- `AnalysisResult.reason_codes`
- `AnalysisResult.signals[].threat_subtype`

## Threat Subtype Guidance

`threat_subtype` is a fine-grained signal hint for UI routing, analyst context,
and telemetry segmentation. It is additive context and does not replace primary
policy fields like `product_surface`, `recommended_action`, or `threat_type`.

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

Client rule:

- treat unknown/new subtype values as non-breaking additive values and fall back
  to threat-type-level handling.

For Swift/iOS, the intended path is generated `SwiftProtobuf` models from:

- [messenger.proto](/c:/Users/123/ecliptix-aura/proto/aura/messenger/v1/messenger.proto)
- [pilot.proto](/c:/Users/123/ecliptix-aura/proto/aura/messenger/v1/pilot.proto)

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

- [product.rs](/c:/Users/123/ecliptix-aura/crates/aura-core/src/product.rs)
- [action.rs](/c:/Users/123/ecliptix-aura/crates/aura-core/src/action.rs)

## Recommended Client Mapping

Use this priority order:

1. `product_surface`
2. `recommended_action`
3. `inference`
4. `reason_codes`
5. raw `threat_type` / `score`

This keeps product behavior aligned with the runtime and reduces client drift.
