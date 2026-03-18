use serde::{Deserialize, Serialize};

use crate::{
    Action, AlertPriority, AnalysisResult, FollowUpAction, LatentStateKind, ThreatType, UiAction,
    UncertaintyLevel,
};

pub const PRODUCT_DECISION_SURFACE_SCHEMA_VERSION: &str = "aura.product_decision_surface.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductRolloutMode {
    Shadow,
    StagingPilot,
    GuardianEnabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductDeliveryMode {
    Suppress,
    MirrorOnly,
    Apply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductChildIntervention {
    None,
    Mark,
    Blur,
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductReviewUrgency {
    None,
    Standard,
    High,
    Urgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductUncertaintyDisposition {
    Normal,
    MirrorOnly,
    RequireReview,
    GuardianPriority,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductChildSurface {
    pub delivery_mode: ProductDeliveryMode,
    pub visible: bool,
    pub intervention: ProductChildIntervention,
    pub ui_actions: Vec<UiAction>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductGuardianSurface {
    pub delivery_mode: ProductDeliveryMode,
    pub notify: bool,
    pub priority: AlertPriority,
    pub follow_ups: Vec<FollowUpAction>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductReviewSurface {
    pub delivery_mode: ProductDeliveryMode,
    pub open_review: bool,
    pub urgency: ProductReviewUrgency,
    pub reason_codes: Vec<String>,
    pub latent_states: Vec<LatentStateKind>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductDecisionSurface {
    pub schema_version: String,
    pub rollout_mode: ProductRolloutMode,
    pub threat_type: ThreatType,
    pub action: Action,
    pub score: f32,
    pub child: ProductChildSurface,
    pub guardian: ProductGuardianSurface,
    pub review: ProductReviewSurface,
    pub uncertainty_disposition: ProductUncertaintyDisposition,
}

pub fn build_product_decision_surface(
    result: &AnalysisResult,
    rollout_mode: ProductRolloutMode,
) -> ProductDecisionSurface {
    let recommendation = result.recommended_action.as_ref();
    let parent_alert = recommendation
        .map(|recommendation| recommendation.parent_alert)
        .unwrap_or(AlertPriority::None);
    let follow_ups = recommendation
        .map(|recommendation| recommendation.follow_ups.clone())
        .unwrap_or_default();
    let child_ui_actions = recommendation
        .map(|recommendation| {
            recommendation
                .ui_actions
                .iter()
                .copied()
                .filter(is_child_facing_ui_action)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let reason_codes = if result.reason_codes.is_empty() {
        recommendation
            .map(|recommendation| recommendation.reason_codes.clone())
            .unwrap_or_default()
    } else {
        result.reason_codes.clone()
    };

    let child_visible = result.action != Action::Allow || !child_ui_actions.is_empty();
    let guardian_notify = parent_alert != AlertPriority::None;
    let review_latent_states = latent_state_kinds(result);
    let review_open = result.is_threat()
        || result.action >= Action::Warn
        || guardian_notify
        || child_ui_actions.contains(&UiAction::SuggestReport)
        || !review_latent_states.is_empty();

    let mut child_delivery = child_delivery_mode(rollout_mode, child_visible);
    let mut guardian_delivery = guardian_delivery_mode(rollout_mode, guardian_notify, parent_alert);
    let review_delivery = review_delivery_mode(review_open);

    let uncertainty_disposition = match result.inference.uncertainty {
        UncertaintyLevel::High => {
            if guardian_notify && parent_alert >= AlertPriority::High {
                soften_delivery(&mut child_delivery, child_visible);
                ProductUncertaintyDisposition::GuardianPriority
            } else if review_open {
                soften_delivery(&mut child_delivery, child_visible);
                if parent_alert < AlertPriority::High {
                    soften_delivery(&mut guardian_delivery, guardian_notify);
                }
                ProductUncertaintyDisposition::RequireReview
            } else if child_visible || guardian_notify {
                soften_delivery(&mut child_delivery, child_visible);
                soften_delivery(&mut guardian_delivery, guardian_notify);
                ProductUncertaintyDisposition::MirrorOnly
            } else {
                ProductUncertaintyDisposition::Normal
            }
        }
        UncertaintyLevel::Low | UncertaintyLevel::Medium => ProductUncertaintyDisposition::Normal,
    };

    ProductDecisionSurface {
        schema_version: PRODUCT_DECISION_SURFACE_SCHEMA_VERSION.to_string(),
        rollout_mode,
        threat_type: result.threat_type,
        action: result.action,
        score: result.score,
        child: ProductChildSurface {
            delivery_mode: child_delivery,
            visible: child_visible,
            intervention: child_intervention(result.action),
            ui_actions: child_ui_actions,
            reason_codes: reason_codes.clone(),
        },
        guardian: ProductGuardianSurface {
            delivery_mode: guardian_delivery,
            notify: guardian_notify,
            priority: parent_alert,
            follow_ups,
            reason_codes: reason_codes.clone(),
        },
        review: ProductReviewSurface {
            delivery_mode: review_delivery,
            open_review: review_open,
            urgency: review_urgency(result, parent_alert, review_open),
            reason_codes: reason_codes.clone(),
            latent_states: review_latent_states,
        },
        uncertainty_disposition,
    }
}

fn is_child_facing_ui_action(action: &UiAction) -> bool {
    match action {
        UiAction::WarnBeforeSend
        | UiAction::WarnBeforeDisplay
        | UiAction::BlurUntilTap
        | UiAction::ConfirmBeforeOpenLink
        | UiAction::SuggestBlockContact
        | UiAction::SuggestReport
        | UiAction::RestrictUnknownContact
        | UiAction::SlowDownConversation
        | UiAction::ShowCrisisSupport => true,
        UiAction::EscalateToGuardian => false,
    }
}

fn child_intervention(action: Action) -> ProductChildIntervention {
    match action {
        Action::Allow => ProductChildIntervention::None,
        Action::Mark => ProductChildIntervention::Mark,
        Action::Blur => ProductChildIntervention::Blur,
        Action::Warn => ProductChildIntervention::Warn,
        Action::Block => ProductChildIntervention::Block,
    }
}

fn child_delivery_mode(
    rollout_mode: ProductRolloutMode,
    child_visible: bool,
) -> ProductDeliveryMode {
    if !child_visible {
        return ProductDeliveryMode::Suppress;
    }
    match rollout_mode {
        ProductRolloutMode::Shadow | ProductRolloutMode::StagingPilot => {
            ProductDeliveryMode::MirrorOnly
        }
        ProductRolloutMode::GuardianEnabled => ProductDeliveryMode::Apply,
    }
}

fn guardian_delivery_mode(
    rollout_mode: ProductRolloutMode,
    guardian_notify: bool,
    parent_alert: AlertPriority,
) -> ProductDeliveryMode {
    if !guardian_notify {
        return ProductDeliveryMode::Suppress;
    }
    match rollout_mode {
        ProductRolloutMode::Shadow => ProductDeliveryMode::MirrorOnly,
        ProductRolloutMode::StagingPilot if parent_alert >= AlertPriority::High => {
            ProductDeliveryMode::Apply
        }
        ProductRolloutMode::StagingPilot => ProductDeliveryMode::MirrorOnly,
        ProductRolloutMode::GuardianEnabled => ProductDeliveryMode::Apply,
    }
}

fn review_delivery_mode(review_open: bool) -> ProductDeliveryMode {
    if review_open {
        ProductDeliveryMode::Apply
    } else {
        ProductDeliveryMode::Suppress
    }
}

fn soften_delivery(delivery_mode: &mut ProductDeliveryMode, active: bool) {
    if active && *delivery_mode == ProductDeliveryMode::Apply {
        *delivery_mode = ProductDeliveryMode::MirrorOnly;
    }
}

fn review_urgency(
    result: &AnalysisResult,
    parent_alert: AlertPriority,
    review_open: bool,
) -> ProductReviewUrgency {
    if !review_open {
        return ProductReviewUrgency::None;
    }
    if parent_alert == AlertPriority::Urgent {
        return ProductReviewUrgency::Urgent;
    }
    if parent_alert >= AlertPriority::High || result.action == Action::Block {
        return ProductReviewUrgency::High;
    }
    ProductReviewUrgency::Standard
}

fn latent_state_kinds(result: &AnalysisResult) -> Vec<LatentStateKind> {
    let mut kinds = Vec::new();
    for state in &result.inference.latent_states {
        if !kinds.contains(&state.kind) {
            kinds.push(state.kind);
        }
    }
    kinds
}

#[cfg(test)]
mod tests {
    use crate::{
        ActionRecommendation, BehavioralTrend, CircleTier, Confidence, ContactSnapshot,
        DetectionSignal, InferenceSummary, LatentStateEvidence, RiskBreakdown, RiskHorizon,
        UiAction,
    };

    use super::*;

    fn sample_result() -> AnalysisResult {
        AnalysisResult {
            threat_type: ThreatType::Grooming,
            confidence: Confidence::High,
            action: Action::Warn,
            score: 0.91,
            explanation: "detected grooming pattern".to_string(),
            detected_threats: vec![(ThreatType::Grooming, 0.91)],
            signals: vec![DetectionSignal::pattern(
                ThreatType::Grooming,
                0.91,
                Confidence::High,
                "conversation.grooming.stage_sequence",
                "stage sequence",
            )],
            recommended_action: Some(ActionRecommendation {
                parent_alert: AlertPriority::High,
                follow_ups: vec![FollowUpAction::MonitorConversation],
                crisis_resources: false,
                ui_actions: vec![
                    UiAction::SuggestBlockContact,
                    UiAction::SuggestReport,
                    UiAction::EscalateToGuardian,
                ],
                reason_codes: vec!["conversation.grooming.stage_sequence".to_string()],
            }),
            risk_breakdown: RiskBreakdown {
                content: 0.2,
                conversation: 0.8,
                link: 0.0,
                abuse: 0.2,
            },
            contact_snapshot: Some(ContactSnapshot {
                sender_id: "stranger_1".into(),
                rating: 12.0,
                trust_level: 0.2,
                circle_tier: CircleTier::New,
                trend: BehavioralTrend::RapidWorsening,
                is_trusted: false,
                is_new_contact: true,
                first_seen_ms: 1_000,
                last_seen_ms: 2_000,
                conversation_count: 1,
            }),
            reason_codes: vec!["conversation.grooming.stage_sequence".to_string()],
            inference: InferenceSummary {
                uncertainty: UncertaintyLevel::Medium,
                risk_horizon: RiskHorizon::ShortTerm,
                escalation_likelihood_24h: 0.78,
                protective_factor_strength: 0.05,
                latent_states: vec![LatentStateEvidence {
                    kind: LatentStateKind::DependencyBuilding,
                    score: 0.84,
                    reason_codes: vec!["conversation.grooming.stage_sequence".to_string()],
                }],
            },
            analysis_time_us: 42,
        }
    }

    #[test]
    fn guardian_enabled_surface_applies_live_actions() {
        let surface =
            build_product_decision_surface(&sample_result(), ProductRolloutMode::GuardianEnabled);
        assert_eq!(surface.rollout_mode, ProductRolloutMode::GuardianEnabled);
        assert_eq!(surface.child.delivery_mode, ProductDeliveryMode::Apply);
        assert_eq!(surface.guardian.delivery_mode, ProductDeliveryMode::Apply);
        assert_eq!(surface.review.delivery_mode, ProductDeliveryMode::Apply);
        assert!(!surface
            .child
            .ui_actions
            .contains(&UiAction::EscalateToGuardian));
    }

    #[test]
    fn shadow_surface_mirrors_child_and_guardian() {
        let surface = build_product_decision_surface(&sample_result(), ProductRolloutMode::Shadow);
        assert_eq!(surface.child.delivery_mode, ProductDeliveryMode::MirrorOnly);
        assert_eq!(
            surface.guardian.delivery_mode,
            ProductDeliveryMode::MirrorOnly
        );
        assert_eq!(surface.review.delivery_mode, ProductDeliveryMode::Apply);
    }

    #[test]
    fn high_uncertainty_softens_child_surface() {
        let mut result = sample_result();
        result.inference.uncertainty = UncertaintyLevel::High;
        result.recommended_action.as_mut().unwrap().parent_alert = AlertPriority::Medium;
        let surface = build_product_decision_surface(&result, ProductRolloutMode::GuardianEnabled);
        assert_eq!(
            surface.uncertainty_disposition,
            ProductUncertaintyDisposition::RequireReview
        );
        assert_eq!(surface.child.delivery_mode, ProductDeliveryMode::MirrorOnly);
        assert_eq!(surface.review.delivery_mode, ProductDeliveryMode::Apply);
    }
}
