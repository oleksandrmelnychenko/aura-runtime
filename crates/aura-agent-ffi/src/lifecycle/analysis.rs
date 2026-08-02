use super::*;

pub(super) fn decode_config_request(
    config_ptr: *const u8,
    config_len: usize,
) -> Result<DecodedConfig, String> {
    let config_proto: proto::AuraConfig = unsafe {
        decode_proto_bounded(config_ptr, config_len, "config", MAX_CONFIG_REQUEST_BYTES)?
    };
    decoded_config_from_proto(config_proto)
}

pub(super) fn canonical_safety_identity_from_proto(
    identity: proto::CanonicalSafetyEventIdentity,
    input: &MessageInput,
) -> Result<SafetyCaseIngestIdentity, String> {
    let canonical = canonical_safety_identity_without_message_from_proto(identity)?;
    if canonical.source_event().conversation_key().as_str() != input.conversation_id.0.as_str() {
        return Err(
            "canonical conversation key does not match message conversation id".to_string(),
        );
    }
    Ok(canonical)
}

pub(super) fn canonical_safety_identity_without_message_from_proto(
    identity: proto::CanonicalSafetyEventIdentity,
) -> Result<SafetyCaseIngestIdentity, String> {
    let account_key =
        SafetyAccountKey::new(identity.account_key).map_err(|error| error.to_string())?;
    let subject_key =
        SafetyCaseSubjectKey::new(identity.subject_key).map_err(|error| error.to_string())?;
    let conversation_key =
        ConversationEventKey::new(identity.conversation_key).map_err(|error| error.to_string())?;
    let event_id = SourceEventId::new(identity.event_id).map_err(|error| error.to_string())?;
    if identity.occurred_at_ms == 0 || identity.observed_at_ms == 0 {
        return Err("canonical source timestamps must be nonzero".to_string());
    }
    if identity.observed_at_ms < identity.occurred_at_ms {
        return Err("canonical observation timestamp predates source event".to_string());
    }
    Ok(SafetyCaseIngestIdentity::new(
        account_key,
        subject_key,
        conversation_key,
        event_id,
        identity.revision,
        identity.occurred_at_ms,
        identity.observed_at_ms,
    ))
}

pub(super) unsafe fn decode_safety_account_key(
    ptr: *const u8,
    len: usize,
) -> Result<SafetyAccountKey, String> {
    if ptr.is_null() {
        return Err("null safety account key pointer".to_string());
    }
    if len == 0 || len > 256 {
        return Err("safety account key must contain 1..=256 bytes".to_string());
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let value = std::str::from_utf8(bytes)
        .map_err(|_| "safety account key is not valid UTF-8".to_string())?;
    SafetyAccountKey::new(value.to_string()).map_err(|error| error.to_string())
}

pub(super) fn canonical_safety_response_to_proto(
    outcome: CanonicalSafetyAnalysisOutcome,
    runtime: &AgentRuntime,
) -> Result<proto::CanonicalSafetyAnalyzeResponse, String> {
    let mut response = proto::CanonicalSafetyAnalyzeResponse {
        disposition: proto::CanonicalSafetyDisposition::Unspecified as i32,
        ignored_reason: None,
        case_id: None,
        case_revision: None,
        case_status: proto::SafetyCaseLifecycleStatus::Unspecified as i32,
        latest_revision: None,
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        case_generation: None,
    };

    match outcome {
        CanonicalSafetyAnalysisOutcome::Processed { safety_case } => match safety_case {
            Ok(SafetyCaseIngestOutcome::Ignored(reason)) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedIgnored as i32;
                response.ignored_reason = Some(safety_case_ignored_reason(reason).to_string());
            }
            Ok(SafetyCaseIngestOutcome::Reduced(decision)) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedReduced as i32;
                response.case_id = Some(decision.case_id().to_string());
                response.case_revision = Some(decision.case_revision());
                response.case_status = proto_safety_case_status(decision.status()) as i32;
                response.case_generation = Some(
                    runtime
                        .safety_cases()
                        .case_generation_by_id(decision.case_id())
                        .ok_or_else(|| {
                            "canonical safety decision is missing its case generation".to_string()
                        })?
                        .value(),
                );
            }
            Ok(_) => {
                return Err(
                    "canonical safety runtime returned an inconsistent processed outcome"
                        .to_string(),
                );
            }
            Err(
                SafetyCaseRuntimeError::AccountStateByteBudgetExceeded { .. }
                | SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded { .. },
            ) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedRejected as i32;
                response.ignored_reason = Some("persistence_byte_budget_exceeded".to_string());
            }
            Err(SafetyCaseRuntimeError::CanonicalResponseByteBudgetExceeded { .. }) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedRejected as i32;
                response.ignored_reason = Some("response_byte_budget_exceeded".to_string());
            }
            Err(_) => {
                response.disposition = proto::CanonicalSafetyDisposition::ProcessedRejected as i32;
                response.ignored_reason = Some("projection_rejected".to_string());
            }
        },
        CanonicalSafetyAnalysisOutcome::DuplicateIgnored { receipt } => match receipt {
            SafetyCaseSourceReceipt::Ignored(reason) => {
                response.disposition = proto::CanonicalSafetyDisposition::DuplicateIgnored as i32;
                response.ignored_reason = Some(safety_case_ignored_reason(reason).to_string());
            }
            SafetyCaseSourceReceipt::Applied {
                case_id,
                case_revision,
                status,
            } => {
                response.disposition = proto::CanonicalSafetyDisposition::DuplicateApplied as i32;
                response.case_id = Some(case_id.to_string());
                response.case_revision = Some(case_revision);
                response.case_status = proto_safety_case_status(status) as i32;
                response.case_generation = Some(
                    runtime
                        .safety_cases()
                        .case_generation_by_id(&case_id)
                        .ok_or_else(|| {
                            "canonical safety receipt is missing its case generation".to_string()
                        })?
                        .value(),
                );
            }
            SafetyCaseSourceReceipt::Rejected => {
                response.disposition = proto::CanonicalSafetyDisposition::DuplicateRejected as i32;
            }
            _ => return Err("unsupported canonical safety receipt".to_string()),
        },
        CanonicalSafetyAnalysisOutcome::StaleIgnored { latest_revision } => {
            response.disposition = proto::CanonicalSafetyDisposition::StaleIgnored as i32;
            response.latest_revision = Some(latest_revision);
        }
    }

    Ok(response)
}

pub(super) fn local_decision_response_to_proto(
    outcome: CanonicalLocalDecisionAnalysisOutcome,
    runtime: &AgentRuntime,
) -> Result<proto::LocalDecisionAnalyzeResponse, String> {
    let decision = match &outcome {
        CanonicalLocalDecisionAnalysisOutcome::Processed {
            local_result: Some(result),
            safety_case: Ok(_),
        } => Some(local_decision_to_proto(result, runtime)),
        CanonicalLocalDecisionAnalysisOutcome::Processed { .. }
        | CanonicalLocalDecisionAnalysisOutcome::DuplicateIgnored { .. }
        | CanonicalLocalDecisionAnalysisOutcome::StaleIgnored { .. } => None,
    };
    let canonical_outcome = match outcome {
        CanonicalLocalDecisionAnalysisOutcome::Processed { safety_case, .. } => {
            CanonicalSafetyAnalysisOutcome::Processed { safety_case }
        }
        CanonicalLocalDecisionAnalysisOutcome::DuplicateIgnored { receipt } => {
            CanonicalSafetyAnalysisOutcome::DuplicateIgnored { receipt }
        }
        CanonicalLocalDecisionAnalysisOutcome::StaleIgnored { latest_revision } => {
            CanonicalSafetyAnalysisOutcome::StaleIgnored { latest_revision }
        }
    };
    let receipt = canonical_safety_response_to_proto(canonical_outcome, runtime)?;
    Ok(proto::LocalDecisionAnalyzeResponse {
        disposition: receipt.disposition,
        decision,
        ignored_reason: receipt.ignored_reason,
        case_id: receipt.case_id,
        case_revision: receipt.case_revision,
        case_status: receipt.case_status,
        latest_revision: receipt.latest_revision,
        runtime_state_schema_version: receipt.runtime_state_schema_version,
        case_generation: receipt.case_generation,
    })
}

pub(super) fn local_decision_to_proto(
    result: &aura_agent_core::AnalysisResult,
    runtime: &AgentRuntime,
) -> proto::LocalDecision {
    let capabilities = runtime.runtime_capabilities();
    let degraded = capabilities.backend == RuntimeBackend::RulesFallback;
    proto::LocalDecision {
        product_surface: Some(product_decision_surface_to_proto(
            &build_product_decision_surface(result, runtime.product_rollout_mode()),
        )),
        recommended_action: result
            .recommended_action
            .as_ref()
            .map(action_recommendation_to_proto),
        reason_codes: result.reason_codes.clone(),
        inference: Some(inference_summary_to_proto(&result.inference)),
        runtime_backend: proto_runtime_backend(capabilities.backend) as i32,
        degraded,
    }
}

fn product_decision_surface_to_proto(
    surface: &aura_agent_core::ProductDecisionSurface,
) -> proto::ProductDecisionSurface {
    proto::ProductDecisionSurface {
        schema_version: surface.schema_version.clone(),
        rollout_mode: proto_product_rollout_mode(surface.rollout_mode) as i32,
        threat_type: proto_threat_type(surface.threat_type) as i32,
        action: proto_action(surface.action) as i32,
        score: surface.score,
        child: Some(product_child_surface_to_proto(&surface.child)),
        guardian: Some(product_guardian_surface_to_proto(&surface.guardian)),
        review: Some(product_review_surface_to_proto(&surface.review)),
        uncertainty_disposition: proto_product_uncertainty_disposition(
            surface.uncertainty_disposition,
        ) as i32,
    }
}

fn product_child_surface_to_proto(
    surface: &aura_agent_core::ProductChildSurface,
) -> proto::ProductChildSurface {
    proto::ProductChildSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        visible: surface.visible,
        intervention: proto_product_child_intervention(surface.intervention) as i32,
        ui_actions: surface
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        reason_codes: surface.reason_codes.clone(),
    }
}

fn product_guardian_surface_to_proto(
    surface: &aura_agent_core::ProductGuardianSurface,
) -> proto::ProductGuardianSurface {
    proto::ProductGuardianSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        notify: surface.notify,
        priority: proto_alert_priority(surface.priority) as i32,
        follow_ups: surface
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        reason_codes: surface.reason_codes.clone(),
    }
}

fn product_review_surface_to_proto(
    surface: &aura_agent_core::ProductReviewSurface,
) -> proto::ProductReviewSurface {
    proto::ProductReviewSurface {
        delivery_mode: proto_product_delivery_mode(surface.delivery_mode) as i32,
        open_review: surface.open_review,
        urgency: proto_product_review_urgency(surface.urgency) as i32,
        reason_codes: surface.reason_codes.clone(),
        latent_states: surface
            .latent_states
            .iter()
            .map(|kind| proto_latent_state_kind(*kind) as i32)
            .collect(),
    }
}

fn action_recommendation_to_proto(
    recommendation: &aura_agent_core::ActionRecommendation,
) -> proto::ActionRecommendation {
    proto::ActionRecommendation {
        parent_alert: proto_alert_priority(recommendation.parent_alert) as i32,
        follow_ups: recommendation
            .follow_ups
            .iter()
            .map(|action| proto_follow_up_action(*action) as i32)
            .collect(),
        crisis_resources: recommendation.crisis_resources,
        ui_actions: recommendation
            .ui_actions
            .iter()
            .map(|action| proto_ui_action(*action) as i32)
            .collect(),
        reason_codes: recommendation.reason_codes.clone(),
    }
}

fn inference_summary_to_proto(
    summary: &aura_agent_core::InferenceSummary,
) -> proto::InferenceSummary {
    proto::InferenceSummary {
        uncertainty: proto_uncertainty_level(summary.uncertainty) as i32,
        risk_horizon: proto_risk_horizon(summary.risk_horizon) as i32,
        escalation_likelihood_24h: summary.escalation_likelihood_24h,
        protective_factor_strength: summary.protective_factor_strength,
        latent_states: summary
            .latent_states
            .iter()
            .map(latent_state_evidence_to_proto)
            .collect(),
    }
}

fn latent_state_evidence_to_proto(
    evidence: &aura_agent_core::LatentStateEvidence,
) -> proto::LatentStateEvidence {
    proto::LatentStateEvidence {
        kind: proto_latent_state_kind(evidence.kind) as i32,
        score: evidence.score,
        reason_codes: evidence.reason_codes.clone(),
    }
}

fn proto_runtime_backend(value: RuntimeBackend) -> proto::RuntimeBackend {
    match value {
        RuntimeBackend::RulesFallback => proto::RuntimeBackend::RulesFallback,
        RuntimeBackend::Onnx => proto::RuntimeBackend::Onnx,
    }
}

fn proto_threat_type(value: aura_agent_core::ThreatType) -> proto::ThreatType {
    match value {
        aura_agent_core::ThreatType::None => proto::ThreatType::None,
        aura_agent_core::ThreatType::Bullying => proto::ThreatType::Bullying,
        aura_agent_core::ThreatType::Grooming => proto::ThreatType::Grooming,
        aura_agent_core::ThreatType::Explicit => proto::ThreatType::Explicit,
        aura_agent_core::ThreatType::Threat => proto::ThreatType::Threat,
        aura_agent_core::ThreatType::SelfHarm => proto::ThreatType::SelfHarm,
        aura_agent_core::ThreatType::Spam => proto::ThreatType::Spam,
        aura_agent_core::ThreatType::Scam => proto::ThreatType::Scam,
        aura_agent_core::ThreatType::Phishing => proto::ThreatType::Phishing,
        aura_agent_core::ThreatType::Manipulation => proto::ThreatType::Manipulation,
        aura_agent_core::ThreatType::Nsfw => proto::ThreatType::Nsfw,
        aura_agent_core::ThreatType::HateSpeech => proto::ThreatType::HateSpeech,
        aura_agent_core::ThreatType::Doxxing => proto::ThreatType::Doxxing,
        aura_agent_core::ThreatType::PiiLeakage => proto::ThreatType::PiiLeakage,
        aura_agent_core::ThreatType::Propaganda => proto::ThreatType::Propaganda,
        aura_agent_core::ThreatType::OpsecViolation => proto::ThreatType::OpsecViolation,
        aura_agent_core::ThreatType::Psyops => proto::ThreatType::Psyops,
        aura_agent_core::ThreatType::MilitarySocialEng => proto::ThreatType::MilitarySocialEng,
        aura_agent_core::ThreatType::CoordinateLeak => proto::ThreatType::CoordinateLeak,
    }
}

fn proto_action(value: aura_agent_core::Action) -> proto::Action {
    match value {
        aura_agent_core::Action::Allow => proto::Action::Allow,
        aura_agent_core::Action::Mark => proto::Action::Mark,
        aura_agent_core::Action::Blur => proto::Action::Blur,
        aura_agent_core::Action::Warn => proto::Action::Warn,
        aura_agent_core::Action::Block => proto::Action::Block,
    }
}

fn proto_alert_priority(value: aura_agent_core::AlertPriority) -> proto::AlertPriority {
    match value {
        aura_agent_core::AlertPriority::None => proto::AlertPriority::None,
        aura_agent_core::AlertPriority::Low => proto::AlertPriority::Low,
        aura_agent_core::AlertPriority::Medium => proto::AlertPriority::Medium,
        aura_agent_core::AlertPriority::High => proto::AlertPriority::High,
        aura_agent_core::AlertPriority::Urgent => proto::AlertPriority::Urgent,
    }
}

fn proto_follow_up_action(value: aura_agent_core::FollowUpAction) -> proto::FollowUpAction {
    match value {
        aura_agent_core::FollowUpAction::MonitorConversation => {
            proto::FollowUpAction::MonitorConversation
        }
        aura_agent_core::FollowUpAction::BlockSuggested => proto::FollowUpAction::BlockSuggested,
        aura_agent_core::FollowUpAction::ReviewContactProfile => {
            proto::FollowUpAction::ReviewContactProfile
        }
        aura_agent_core::FollowUpAction::ReportToAuthorities => {
            proto::FollowUpAction::ReportToAuthorities
        }
    }
}

fn proto_product_rollout_mode(
    value: aura_agent_core::ProductRolloutMode,
) -> proto::ProductRolloutMode {
    match value {
        aura_agent_core::ProductRolloutMode::Shadow => proto::ProductRolloutMode::Shadow,
        aura_agent_core::ProductRolloutMode::StagingPilot => {
            proto::ProductRolloutMode::StagingPilot
        }
        aura_agent_core::ProductRolloutMode::GuardianEnabled => {
            proto::ProductRolloutMode::GuardianEnabled
        }
    }
}

fn proto_product_delivery_mode(
    value: aura_agent_core::ProductDeliveryMode,
) -> proto::ProductDeliveryMode {
    match value {
        aura_agent_core::ProductDeliveryMode::Suppress => proto::ProductDeliveryMode::Suppress,
        aura_agent_core::ProductDeliveryMode::MirrorOnly => proto::ProductDeliveryMode::MirrorOnly,
        aura_agent_core::ProductDeliveryMode::Apply => proto::ProductDeliveryMode::Apply,
    }
}

fn proto_product_child_intervention(
    value: aura_agent_core::ProductChildIntervention,
) -> proto::ProductChildIntervention {
    match value {
        aura_agent_core::ProductChildIntervention::None => proto::ProductChildIntervention::None,
        aura_agent_core::ProductChildIntervention::Mark => proto::ProductChildIntervention::Mark,
        aura_agent_core::ProductChildIntervention::Blur => proto::ProductChildIntervention::Blur,
        aura_agent_core::ProductChildIntervention::Warn => proto::ProductChildIntervention::Warn,
        aura_agent_core::ProductChildIntervention::Block => proto::ProductChildIntervention::Block,
    }
}

fn proto_product_review_urgency(
    value: aura_agent_core::ProductReviewUrgency,
) -> proto::ProductReviewUrgency {
    match value {
        aura_agent_core::ProductReviewUrgency::None => proto::ProductReviewUrgency::None,
        aura_agent_core::ProductReviewUrgency::Standard => proto::ProductReviewUrgency::Standard,
        aura_agent_core::ProductReviewUrgency::High => proto::ProductReviewUrgency::High,
        aura_agent_core::ProductReviewUrgency::Urgent => proto::ProductReviewUrgency::Urgent,
    }
}

fn proto_product_uncertainty_disposition(
    value: aura_agent_core::ProductUncertaintyDisposition,
) -> proto::ProductUncertaintyDisposition {
    match value {
        aura_agent_core::ProductUncertaintyDisposition::Normal => {
            proto::ProductUncertaintyDisposition::Normal
        }
        aura_agent_core::ProductUncertaintyDisposition::MirrorOnly => {
            proto::ProductUncertaintyDisposition::MirrorOnly
        }
        aura_agent_core::ProductUncertaintyDisposition::RequireReview => {
            proto::ProductUncertaintyDisposition::RequireReview
        }
        aura_agent_core::ProductUncertaintyDisposition::GuardianPriority => {
            proto::ProductUncertaintyDisposition::GuardianPriority
        }
    }
}

fn proto_ui_action(value: aura_agent_core::UiAction) -> proto::UiAction {
    match value {
        aura_agent_core::UiAction::WarnBeforeSend => proto::UiAction::WarnBeforeSend,
        aura_agent_core::UiAction::WarnBeforeDisplay => proto::UiAction::WarnBeforeDisplay,
        aura_agent_core::UiAction::BlurUntilTap => proto::UiAction::BlurUntilTap,
        aura_agent_core::UiAction::ConfirmBeforeOpenLink => proto::UiAction::ConfirmBeforeOpenLink,
        aura_agent_core::UiAction::SuggestBlockContact => proto::UiAction::SuggestBlockContact,
        aura_agent_core::UiAction::SuggestReport => proto::UiAction::SuggestReport,
        aura_agent_core::UiAction::RestrictUnknownContact => {
            proto::UiAction::RestrictUnknownContact
        }
        aura_agent_core::UiAction::SlowDownConversation => proto::UiAction::SlowDownConversation,
        aura_agent_core::UiAction::ShowCrisisSupport => proto::UiAction::ShowCrisisSupport,
        aura_agent_core::UiAction::EscalateToGuardian => proto::UiAction::EscalateToGuardian,
    }
}

fn proto_uncertainty_level(value: aura_agent_core::UncertaintyLevel) -> proto::UncertaintyLevel {
    match value {
        aura_agent_core::UncertaintyLevel::Low => proto::UncertaintyLevel::Low,
        aura_agent_core::UncertaintyLevel::Medium => proto::UncertaintyLevel::Medium,
        aura_agent_core::UncertaintyLevel::High => proto::UncertaintyLevel::High,
    }
}

fn proto_risk_horizon(value: aura_agent_core::RiskHorizon) -> proto::RiskHorizon {
    match value {
        aura_agent_core::RiskHorizon::Unknown => proto::RiskHorizon::Unknown,
        aura_agent_core::RiskHorizon::Immediate => proto::RiskHorizon::Immediate,
        aura_agent_core::RiskHorizon::ShortTerm => proto::RiskHorizon::ShortTerm,
        aura_agent_core::RiskHorizon::Sustained => proto::RiskHorizon::Sustained,
    }
}

fn proto_latent_state_kind(value: aura_agent_core::LatentStateKind) -> proto::LatentStateKind {
    match value {
        aura_agent_core::LatentStateKind::DependencyBuilding => {
            proto::LatentStateKind::DependencyBuilding
        }
        aura_agent_core::LatentStateKind::IsolationPressure => {
            proto::LatentStateKind::IsolationPressure
        }
        aura_agent_core::LatentStateKind::CoerciveControl => {
            proto::LatentStateKind::CoerciveControl
        }
        aura_agent_core::LatentStateKind::Humiliation => proto::LatentStateKind::Humiliation,
        aura_agent_core::LatentStateKind::CrisisVulnerability => {
            proto::LatentStateKind::CrisisVulnerability
        }
        aura_agent_core::LatentStateKind::ProtectiveSupport => {
            proto::LatentStateKind::ProtectiveSupport
        }
        aura_agent_core::LatentStateKind::GroupEscalation => {
            proto::LatentStateKind::GroupEscalation
        }
    }
}

pub(super) fn canonical_persistence_state_lengths(
    runtime: &AgentRuntime,
    account_key: &SafetyAccountKey,
) -> Result<(usize, usize, usize), SafetyCaseRuntimeError> {
    let case_state_len =
        serde_json::to_vec(&runtime.safety_cases().export_account_state(account_key))
            .map_err(|error| SafetyCaseRuntimeError::StateSerialization(error.to_string()))?
            .len();
    let context_state = tracker_state_to_proto(
        &runtime.export_context_state(),
        &runtime.export_kids_memory_state(),
    );
    let context_state_len = proto::ExportContextResponse {
        state: Some(context_state),
    }
    .encoded_len();
    let combined = case_state_len.checked_add(context_state_len).ok_or(
        SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded {
            maximum: MAX_CANONICAL_COMBINED_STATE_BYTES,
            current: usize::MAX,
            required_reserve: 0,
        },
    )?;
    Ok((case_state_len, context_state_len, combined))
}

pub(super) fn ensure_canonical_persistence_within_budget(
    runtime: &AgentRuntime,
    account_key: &SafetyAccountKey,
) -> Result<(), SafetyCaseRuntimeError> {
    let (case_state_len, context_state_len, combined) =
        canonical_persistence_state_lengths(runtime, account_key)?;
    if case_state_len > SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES {
        return Err(SafetyCaseRuntimeError::AccountStateByteBudgetExceeded {
            maximum: SAFETY_CASE_ACCOUNT_STATE_MAX_BYTES,
            current: case_state_len,
            required_reserve: 0,
        });
    }
    if context_state_len > MAX_CANONICAL_CONTEXT_STATE_BYTES {
        return Err(
            SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded {
                maximum: MAX_CANONICAL_CONTEXT_STATE_BYTES,
                current: context_state_len,
                required_reserve: 0,
            },
        );
    }
    if combined > MAX_CANONICAL_COMBINED_STATE_BYTES {
        return Err(
            SafetyCaseRuntimeError::CombinedPersistenceByteBudgetExceeded {
                maximum: MAX_CANONICAL_COMBINED_STATE_BYTES,
                current: combined,
                required_reserve: 0,
            },
        );
    }
    Ok(())
}

pub(super) fn safety_case_ignored_reason(reason: SafetyCaseIgnoredReason) -> &'static str {
    match reason {
        SafetyCaseIgnoredReason::NoThreat => "no_threat",
        SafetyCaseIgnoredReason::NonActionable => "non_actionable",
        SafetyCaseIgnoredReason::ZeroRisk => "zero_risk",
        _ => "unknown",
    }
}

pub(super) fn proto_safety_case_status(
    status: SafetyCaseStatus,
) -> proto::SafetyCaseLifecycleStatus {
    match status {
        SafetyCaseStatus::Observing => proto::SafetyCaseLifecycleStatus::Observing,
        SafetyCaseStatus::Open => proto::SafetyCaseLifecycleStatus::Open,
        SafetyCaseStatus::Escalated => proto::SafetyCaseLifecycleStatus::Escalated,
        SafetyCaseStatus::Urgent => proto::SafetyCaseLifecycleStatus::Urgent,
        SafetyCaseStatus::Resolved => proto::SafetyCaseLifecycleStatus::Resolved,
        SafetyCaseStatus::Dismissed => proto::SafetyCaseLifecycleStatus::Dismissed,
        _ => proto::SafetyCaseLifecycleStatus::Unspecified,
    }
}

pub(super) fn proto_guardian_report_trigger(
    trigger: GuardianReportTrigger,
) -> proto::GuardianReportTrigger {
    match trigger {
        GuardianReportTrigger::CaseOpened => proto::GuardianReportTrigger::CaseOpened,
        GuardianReportTrigger::CaseEscalated => proto::GuardianReportTrigger::CaseEscalated,
        GuardianReportTrigger::UrgentReview => proto::GuardianReportTrigger::UrgentReview,
        GuardianReportTrigger::CaseResolved => proto::GuardianReportTrigger::CaseResolved,
        _ => proto::GuardianReportTrigger::Unspecified,
    }
}

pub(super) fn proto_safety_case_severity(
    severity: SafetyCaseSeverity,
) -> proto::SafetyCaseSeverity {
    match severity {
        SafetyCaseSeverity::Informational => proto::SafetyCaseSeverity::Informational,
        SafetyCaseSeverity::Elevated => proto::SafetyCaseSeverity::Elevated,
        SafetyCaseSeverity::High => proto::SafetyCaseSeverity::High,
        SafetyCaseSeverity::Critical => proto::SafetyCaseSeverity::Critical,
        _ => proto::SafetyCaseSeverity::Unspecified,
    }
}

pub(super) fn proto_confidence(confidence: Confidence) -> proto::Confidence {
    match confidence {
        Confidence::Low => proto::Confidence::Low,
        Confidence::Medium => proto::Confidence::Medium,
        Confidence::High => proto::Confidence::High,
    }
}

pub(super) fn guardian_report_risk_family(
    threat_type: ThreatType,
) -> proto::GuardianReportRiskFamily {
    match threat_type {
        ThreatType::Bullying => proto::GuardianReportRiskFamily::Bullying,
        ThreatType::Grooming => proto::GuardianReportRiskFamily::Grooming,
        ThreatType::Explicit => proto::GuardianReportRiskFamily::Explicit,
        ThreatType::Threat => proto::GuardianReportRiskFamily::Threat,
        ThreatType::SelfHarm => proto::GuardianReportRiskFamily::SelfHarm,
        ThreatType::Spam => proto::GuardianReportRiskFamily::Spam,
        ThreatType::Scam => proto::GuardianReportRiskFamily::Scam,
        ThreatType::Phishing => proto::GuardianReportRiskFamily::Phishing,
        ThreatType::Manipulation => proto::GuardianReportRiskFamily::Manipulation,
        ThreatType::Nsfw => proto::GuardianReportRiskFamily::Nsfw,
        ThreatType::HateSpeech => proto::GuardianReportRiskFamily::HateSpeech,
        ThreatType::Doxxing => proto::GuardianReportRiskFamily::Doxxing,
        ThreatType::PiiLeakage => proto::GuardianReportRiskFamily::PiiLeakage,
        ThreatType::Propaganda => proto::GuardianReportRiskFamily::Propaganda,
        ThreatType::OpsecViolation => proto::GuardianReportRiskFamily::OpsecViolation,
        ThreatType::Psyops => proto::GuardianReportRiskFamily::Psyops,
        ThreatType::MilitarySocialEng => proto::GuardianReportRiskFamily::MilitarySocialEng,
        ThreatType::CoordinateLeak => proto::GuardianReportRiskFamily::CoordinateLeak,
        ThreatType::None => proto::GuardianReportRiskFamily::Unspecified,
    }
}

pub(super) fn guardian_report_delivery_class(
    delivery_class: GuardianDeliveryClass,
) -> proto::GuardianReportDeliveryClass {
    match delivery_class {
        GuardianDeliveryClass::NeedsAttention => proto::GuardianReportDeliveryClass::NeedsAttention,
        GuardianDeliveryClass::Urgent => proto::GuardianReportDeliveryClass::Urgent,
    }
}

pub(super) fn guardian_report_to_proto(
    report: &GuardianReport,
    generation: SafetyCaseGeneration,
) -> proto::GuardianReport {
    let binding = report.execution_binding();
    proto::GuardianReport {
        schema_version: 2,
        case_id: report.key().case_id().to_string(),
        case_generation: generation.value(),
        transition_revision: report.key().transition_revision(),
        trigger: proto_guardian_report_trigger(report.trigger()) as i32,
        queued_at_ms: report.queued_at_ms(),
        risk_family: guardian_report_risk_family(report.threat_type()) as i32,
        case_status: proto_safety_case_status(report.case_status()) as i32,
        severity: proto_safety_case_severity(report.severity()) as i32,
        confidence_band: proto_confidence(report.confidence()) as i32,
        first_observed_at_ms: report.first_observed_at_ms(),
        last_observed_at_ms: report.last_observed_at_ms(),
        observation_volume_band: match report.observation_volume_band() {
            GuardianReportObservationVolumeBand::Isolated => {
                proto::GuardianReportObservationVolumeBand::Isolated as i32
            }
            GuardianReportObservationVolumeBand::Repeated => {
                proto::GuardianReportObservationVolumeBand::Repeated as i32
            }
            GuardianReportObservationVolumeBand::Sustained => {
                proto::GuardianReportObservationVolumeBand::Sustained as i32
            }
        },
        report_reason_codes: report
            .reason_codes()
            .iter()
            .map(ToString::to_string)
            .collect(),
        evidence_commitments: report
            .evidence_commitments()
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect(),
        execution_policy_authority_lineage_id: binding.authority_lineage_id.clone(),
        execution_policy_epoch: binding.policy_epoch,
        execution_policy_version: binding.policy_version.clone(),
        execution_policy_assertion_digest: binding.policy_assertion_digest.to_vec(),
        execution_rule_id: binding.rule_id.clone(),
        execution_rule_digest: binding.rule_digest.to_vec(),
        delivery_class: guardian_report_delivery_class(binding.delivery_class) as i32,
        runtime_capabilities_digest: binding.runtime_capabilities_digest.to_vec(),
        model_manifest_digest: binding.model_manifest_digest.to_vec(),
        policy_evaluated_at_ms: binding.policy_evaluated_at_ms,
    }
}

pub(super) fn guardian_report_snapshot_to_proto(
    case: &SafetyCase,
    generation: SafetyCaseGeneration,
) -> proto::GuardianReportSnapshotResponse {
    let mut response = proto::GuardianReportSnapshotResponse {
        disposition: proto::GuardianReportDisposition::NotRequired as i32,
        case_id: case.case_id().to_string(),
        case_generation: generation.value(),
        current_case_revision: case.revision(),
        current_case_status: proto_safety_case_status(case.status()) as i32,
        report: None,
        deferred_trigger: None,
        deferred_eligible_at_ms: None,
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        prepared_at_ms: None,
        canonical_report_bytes: Vec::new(),
        semantic_digest: Vec::new(),
        report_id: String::new(),
    };
    if let Some(report) = case.pending_guardian_report() {
        response.disposition = proto::GuardianReportDisposition::Pending as i32;
        let wire = guardian_report_to_proto(report, generation);
        let canonical_report_bytes = guardian_report_canonical_bytes(&wire);
        let semantic_digest: [u8; 32] = Sha256::digest(&canonical_report_bytes).into();
        response.report_id = format!(
            "aura.guardian.report.v2:{}",
            lowercase_hex(&semantic_digest)
        );
        response.canonical_report_bytes = canonical_report_bytes;
        response.semantic_digest = semantic_digest.to_vec();
        response.report = Some(wire);
        response.prepared_at_ms = case
            .guardian_report_preparation()
            .map(|receipt| receipt.prepared_at_ms());
    } else if let Some(deferred) = case.deferred_guardian_report() {
        response.disposition = proto::GuardianReportDisposition::Deferred as i32;
        response.deferred_trigger = Some(proto_guardian_report_trigger(deferred.trigger()) as i32);
        response.deferred_eligible_at_ms = Some(deferred.eligible_at_ms());
    }
    response
}

pub(super) fn guardian_report_canonical_bytes(report: &proto::GuardianReport) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1024);
    append_length_prefixed(b"aura.guardian.report.semantic.v2", &mut bytes);
    bytes.extend_from_slice(&2u16.to_be_bytes());
    append_length_prefixed(report.case_id.as_bytes(), &mut bytes);
    bytes.extend_from_slice(&report.case_generation.to_be_bytes());
    bytes.extend_from_slice(&report.transition_revision.to_be_bytes());
    bytes.push(u8::try_from(report.trigger).expect("native trigger fits u8"));
    bytes.extend_from_slice(&report.queued_at_ms.to_be_bytes());
    let risk_family = guardian_report_risk_family_name(report.risk_family);
    append_length_prefixed(risk_family.as_bytes(), &mut bytes);
    bytes.push(u8::try_from(report.case_status).expect("native case status fits u8"));
    let severity = guardian_report_severity_name(report.severity);
    append_length_prefixed(severity.as_bytes(), &mut bytes);
    bytes.push(u8::try_from(report.confidence_band).expect("native confidence fits u8"));
    bytes.extend_from_slice(&report.first_observed_at_ms.to_be_bytes());
    bytes.extend_from_slice(&report.last_observed_at_ms.to_be_bytes());
    bytes.push(
        u8::try_from(report.observation_volume_band)
            .expect("native observation volume band fits u8"),
    );
    bytes.extend_from_slice(
        &u16::try_from(report.report_reason_codes.len())
            .expect("native reason-code count fits u16")
            .to_be_bytes(),
    );
    for reason in &report.report_reason_codes {
        append_length_prefixed(reason.as_bytes(), &mut bytes);
    }
    bytes.extend_from_slice(
        &u16::try_from(report.evidence_commitments.len())
            .expect("native evidence count fits u16")
            .to_be_bytes(),
    );
    for commitment in &report.evidence_commitments {
        append_length_prefixed(commitment, &mut bytes);
    }
    append_length_prefixed(
        report.execution_policy_authority_lineage_id.as_bytes(),
        &mut bytes,
    );
    bytes.extend_from_slice(&report.execution_policy_epoch.to_be_bytes());
    append_length_prefixed(report.execution_policy_version.as_bytes(), &mut bytes);
    append_length_prefixed(&report.execution_policy_assertion_digest, &mut bytes);
    append_length_prefixed(report.execution_rule_id.as_bytes(), &mut bytes);
    append_length_prefixed(&report.execution_rule_digest, &mut bytes);
    bytes.push(u8::try_from(report.delivery_class).expect("native delivery class fits u8"));
    append_length_prefixed(&report.runtime_capabilities_digest, &mut bytes);
    append_length_prefixed(&report.model_manifest_digest, &mut bytes);
    bytes.extend_from_slice(&report.policy_evaluated_at_ms.to_be_bytes());
    bytes
}

pub(super) fn guardian_report_risk_family_name(value: i32) -> &'static str {
    match proto::GuardianReportRiskFamily::try_from(value)
        .unwrap_or(proto::GuardianReportRiskFamily::Unspecified)
    {
        proto::GuardianReportRiskFamily::Bullying => "bullying",
        proto::GuardianReportRiskFamily::Grooming => "grooming",
        proto::GuardianReportRiskFamily::Explicit => "explicit",
        proto::GuardianReportRiskFamily::Threat => "threat",
        proto::GuardianReportRiskFamily::SelfHarm => "self_harm",
        proto::GuardianReportRiskFamily::Spam => "spam",
        proto::GuardianReportRiskFamily::Scam => "scam",
        proto::GuardianReportRiskFamily::Phishing => "phishing",
        proto::GuardianReportRiskFamily::Manipulation => "manipulation",
        proto::GuardianReportRiskFamily::Nsfw => "nsfw",
        proto::GuardianReportRiskFamily::HateSpeech => "hate_speech",
        proto::GuardianReportRiskFamily::Doxxing => "doxxing",
        proto::GuardianReportRiskFamily::PiiLeakage => "pii_leakage",
        proto::GuardianReportRiskFamily::Propaganda => "propaganda",
        proto::GuardianReportRiskFamily::OpsecViolation => "opsec_violation",
        proto::GuardianReportRiskFamily::Psyops => "psyops",
        proto::GuardianReportRiskFamily::MilitarySocialEng => "military_social_eng",
        proto::GuardianReportRiskFamily::CoordinateLeak => "coordinate_leak",
        proto::GuardianReportRiskFamily::Unspecified => "",
    }
}

pub(super) fn guardian_report_severity_name(value: i32) -> &'static str {
    match proto::SafetyCaseSeverity::try_from(value)
        .unwrap_or(proto::SafetyCaseSeverity::Unspecified)
    {
        proto::SafetyCaseSeverity::Informational => "informational",
        proto::SafetyCaseSeverity::Elevated => "elevated",
        proto::SafetyCaseSeverity::High => "high",
        proto::SafetyCaseSeverity::Critical => "critical",
        proto::SafetyCaseSeverity::Unspecified => "",
    }
}

pub(super) fn append_length_prefixed(value: &[u8], output: &mut Vec<u8>) {
    let length = u32::try_from(value.len()).expect("bounded native value fits u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

pub(super) fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn safety_case_lifecycle_command_from_proto(
    request: proto::SafetyCaseLifecycleCommandRequest,
) -> Result<(SafetyAccountKey, SafetyCaseId, SafetyCaseCommand), String> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    if request.at_ms == 0 {
        return Err("safety case lifecycle timestamp must be non-zero".to_string());
    }
    let reason_code =
        SafetyReasonCode::new(request.reason_code).map_err(|error| error.to_string())?;
    let command_type = proto::SafetyCaseLifecycleCommandType::try_from(request.command_type)
        .map_err(|_| "unsupported safety case lifecycle command type".to_string())?;
    let command = match command_type {
        proto::SafetyCaseLifecycleCommandType::Resolve => SafetyCaseCommand::Resolve {
            at_ms: request.at_ms,
            reason_code,
        },
        proto::SafetyCaseLifecycleCommandType::Dismiss => SafetyCaseCommand::Dismiss {
            at_ms: request.at_ms,
            reason_code,
        },
        proto::SafetyCaseLifecycleCommandType::Unspecified => {
            return Err("safety case lifecycle command type is unspecified".to_string());
        }
    };
    Ok((account_key, case_id, command))
}

pub(super) fn safety_case_lifecycle_response_to_proto(
    decision: &SafetyCaseDecision,
    case_generation: SafetyCaseGeneration,
) -> proto::SafetyCaseLifecycleCommandResponse {
    proto::SafetyCaseLifecycleCommandResponse {
        case_id: decision.case_id().to_string(),
        case_revision: decision.case_revision(),
        case_status: proto_safety_case_status(decision.status()) as i32,
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
        case_generation: Some(case_generation.value()),
    }
}

pub(super) fn safety_case_successor_activation_from_proto(
    request: proto::SafetyCaseSuccessorActivationRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        u64,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let predecessor_case_id =
        SafetyCaseId::new(request.predecessor_case_id).map_err(|error| error.to_string())?;
    let expected_generation = request
        .expected_case_generation
        .ok_or_else(|| "expected safety case generation is missing".to_string())?;
    if request.expected_case_revision == 0 {
        return Err("expected safety case revision must be non-zero".to_string());
    }
    if request.activated_at_ms == 0 {
        return Err("safety case successor activation timestamp must be non-zero".to_string());
    }
    Ok((
        account_key,
        predecessor_case_id,
        SafetyCaseGeneration::new(expected_generation),
        request.expected_case_revision,
        request.activated_at_ms,
    ))
}

pub(super) fn safety_case_successor_activation_to_proto(
    outcome: &SafetyCaseSuccessorActivationOutcome,
) -> proto::SafetyCaseSuccessorActivationResponse {
    let disposition = match outcome.disposition() {
        SafetyCaseSuccessorActivationDisposition::Activated => {
            proto::SafetyCaseSuccessorActivationDisposition::Activated
        }
        SafetyCaseSuccessorActivationDisposition::AlreadyActivated => {
            proto::SafetyCaseSuccessorActivationDisposition::AlreadyActivated
        }
    };
    proto::SafetyCaseSuccessorActivationResponse {
        disposition: disposition as i32,
        predecessor_case_id: outcome.predecessor_case_id().to_string(),
        predecessor_case_generation: outcome.predecessor_generation().value(),
        successor_case_id: outcome.successor_case_id().to_string(),
        successor_case_generation: outcome.successor_generation().value(),
        activated_at_ms: outcome.activated_at_ms(),
        runtime_state_schema_version: SAFETY_CASE_RUNTIME_STATE_SCHEMA_VERSION.to_string(),
    }
}

pub(super) fn guardian_report_snapshot_request_from_proto(
    request: proto::GuardianReportSnapshotRequest,
) -> Result<(SafetyAccountKey, SafetyCaseId, SafetyCaseGeneration, u64), String> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report case generation is missing".to_string())?;
    if request.expected_case_revision == 0 {
        return Err("expected guardian report case revision must be non-zero".to_string());
    }
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        request.expected_case_revision,
    ))
}

pub(super) fn guardian_report_preparation_request_from_proto(
    request: proto::GuardianReportPreparationRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        GuardianReportKey,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report preparation generation is missing".to_string())?;
    if request.report_transition_revision == 0 {
        return Err("guardian report preparation revision must be non-zero".to_string());
    }
    if request.prepared_at_ms == 0 {
        return Err("guardian report preparation timestamp must be non-zero".to_string());
    }
    let report_key = GuardianReportKey::new(case_id.clone(), request.report_transition_revision);
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        report_key,
        request.prepared_at_ms,
    ))
}

pub(super) fn guardian_report_flush_request_from_proto(
    request: proto::GuardianReportFlushRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        u64,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report flush generation is missing".to_string())?;
    if request.expected_case_revision == 0 {
        return Err("expected guardian report flush revision must be non-zero".to_string());
    }
    if request.evaluated_at_ms == 0 {
        return Err("guardian report flush timestamp must be non-zero".to_string());
    }
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        request.expected_case_revision,
        request.evaluated_at_ms,
    ))
}

pub(super) fn guardian_report_acknowledgement_request_from_proto(
    request: proto::GuardianReportAcknowledgementRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        GuardianReportKey,
        u64,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request.expected_case_generation.ok_or_else(|| {
        "expected guardian report acknowledgement generation is missing".to_string()
    })?;
    if request.report_transition_revision == 0 {
        return Err("guardian report transition revision must be non-zero".to_string());
    }
    if request.delivered_at_ms == 0 {
        return Err("guardian report delivery timestamp must be non-zero".to_string());
    }
    let report_key = GuardianReportKey::new(case_id.clone(), request.report_transition_revision);
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        report_key,
        request.delivered_at_ms,
    ))
}

pub(super) fn guardian_report_suppression_request_from_proto(
    request: proto::GuardianReportSuppressionRequest,
) -> Result<
    (
        SafetyAccountKey,
        SafetyCaseId,
        SafetyCaseGeneration,
        GuardianReportKey,
        u64,
        SafetyReasonCode,
    ),
    String,
> {
    let account_key =
        SafetyAccountKey::new(request.account_key).map_err(|error| error.to_string())?;
    let case_id = SafetyCaseId::new(request.case_id).map_err(|error| error.to_string())?;
    let generation = request
        .expected_case_generation
        .ok_or_else(|| "expected guardian report suppression generation is missing".to_string())?;
    if request.report_transition_revision == 0 {
        return Err("guardian report suppression revision must be non-zero".to_string());
    }
    if request.suppressed_at_ms == 0 {
        return Err("guardian report suppression timestamp must be non-zero".to_string());
    }
    let report_key = GuardianReportKey::new(case_id.clone(), request.report_transition_revision);
    let reason_code =
        SafetyReasonCode::new(request.reason_code).map_err(|error| error.to_string())?;
    Ok((
        account_key,
        case_id,
        SafetyCaseGeneration::new(generation),
        report_key,
        request.suppressed_at_ms,
        reason_code,
    ))
}

#[cfg(test)]
mod local_decision_mapping_tests {
    use super::*;

    #[test]
    fn every_product_ui_action_has_an_exact_wire_value() {
        let mappings = [
            (
                aura_agent_core::UiAction::WarnBeforeSend,
                proto::UiAction::WarnBeforeSend,
            ),
            (
                aura_agent_core::UiAction::WarnBeforeDisplay,
                proto::UiAction::WarnBeforeDisplay,
            ),
            (
                aura_agent_core::UiAction::BlurUntilTap,
                proto::UiAction::BlurUntilTap,
            ),
            (
                aura_agent_core::UiAction::ConfirmBeforeOpenLink,
                proto::UiAction::ConfirmBeforeOpenLink,
            ),
            (
                aura_agent_core::UiAction::SuggestBlockContact,
                proto::UiAction::SuggestBlockContact,
            ),
            (
                aura_agent_core::UiAction::SuggestReport,
                proto::UiAction::SuggestReport,
            ),
            (
                aura_agent_core::UiAction::RestrictUnknownContact,
                proto::UiAction::RestrictUnknownContact,
            ),
            (
                aura_agent_core::UiAction::SlowDownConversation,
                proto::UiAction::SlowDownConversation,
            ),
            (
                aura_agent_core::UiAction::ShowCrisisSupport,
                proto::UiAction::ShowCrisisSupport,
            ),
            (
                aura_agent_core::UiAction::EscalateToGuardian,
                proto::UiAction::EscalateToGuardian,
            ),
        ];

        for (core, wire) in mappings {
            assert_eq!(proto_ui_action(core), wire);
        }
    }

    #[test]
    fn every_product_policy_enum_has_an_exact_wire_value() {
        for (core, wire) in [
            (
                aura_agent_core::ProductDeliveryMode::Suppress,
                proto::ProductDeliveryMode::Suppress,
            ),
            (
                aura_agent_core::ProductDeliveryMode::MirrorOnly,
                proto::ProductDeliveryMode::MirrorOnly,
            ),
            (
                aura_agent_core::ProductDeliveryMode::Apply,
                proto::ProductDeliveryMode::Apply,
            ),
        ] {
            assert_eq!(proto_product_delivery_mode(core), wire);
        }
        for (core, wire) in [
            (
                aura_agent_core::ProductChildIntervention::None,
                proto::ProductChildIntervention::None,
            ),
            (
                aura_agent_core::ProductChildIntervention::Mark,
                proto::ProductChildIntervention::Mark,
            ),
            (
                aura_agent_core::ProductChildIntervention::Blur,
                proto::ProductChildIntervention::Blur,
            ),
            (
                aura_agent_core::ProductChildIntervention::Warn,
                proto::ProductChildIntervention::Warn,
            ),
            (
                aura_agent_core::ProductChildIntervention::Block,
                proto::ProductChildIntervention::Block,
            ),
        ] {
            assert_eq!(proto_product_child_intervention(core), wire);
        }
        for (core, wire) in [
            (
                aura_agent_core::FollowUpAction::MonitorConversation,
                proto::FollowUpAction::MonitorConversation,
            ),
            (
                aura_agent_core::FollowUpAction::BlockSuggested,
                proto::FollowUpAction::BlockSuggested,
            ),
            (
                aura_agent_core::FollowUpAction::ReviewContactProfile,
                proto::FollowUpAction::ReviewContactProfile,
            ),
            (
                aura_agent_core::FollowUpAction::ReportToAuthorities,
                proto::FollowUpAction::ReportToAuthorities,
            ),
        ] {
            assert_eq!(proto_follow_up_action(core), wire);
        }
    }
}
