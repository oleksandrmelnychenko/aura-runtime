//! Agent-side policy layer for AURA.
//!
//! This crate re-exports the policy-related modules from `aura-core` and
//! provides a dedicated home for agent-specific policy logic that does not
//! belong in the shared contracts or the relay.
//!
//! Modules re-exported here will gradually migrate from `aura-core` as
//! the split progresses.

// ── Re-exports from aura-core (transitional) ────────────────────────

pub use aura_core::action;
pub use aura_core::pilot;
pub use aura_core::pilot_gate;
pub use aura_core::product;

// Convenience re-exports of the most commonly used items.
pub use aura_core::action::{
    augment_recommendation_for_inference, augment_recommendation_for_reason_codes, decide_action,
    decide_action_v2, escalate_by_contact_history, propaganda_action_for_subtype,
    should_soften_policy_for_context, should_soften_policy_for_context_summary,
    soften_recommendation_for_context, soften_recommendation_for_context_summary,
};

pub use aura_core::product::{
    build_product_decision_surface, ProductChildIntervention, ProductChildSurface,
    ProductDecisionSurface, ProductDeliveryMode, ProductGuardianSurface, ProductReviewSurface,
    ProductReviewUrgency, ProductRolloutMode, ProductUncertaintyDisposition,
    PRODUCT_DECISION_SURFACE_SCHEMA_VERSION,
};

pub use aura_core::pilot::{
    build_shadow_mode_event, ShadowModeBundle, ShadowModeContactSummary, ShadowModeDecision,
    ShadowModeEvent, ShadowModeEventInput, ShadowModeExpectation, ShadowModeFinding,
    ShadowModeMirror, ShadowModePrivacy, ShadowModeSummary, SHADOW_MODE_BUNDLE_SCHEMA_VERSION,
    SHADOW_MODE_WIRE_PACKAGE,
};

pub use aura_core::pilot_gate::*;
