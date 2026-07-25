use super::*;

pub(super) fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn downweight_secondary_timing_grooming(signals: &mut [DetectionSignal]) {
    let mut has_stronger_non_grooming = false;
    for signal in signals.iter() {
        if signal.threat_type != ThreatType::Grooming
            && signal.threat_type != ThreatType::None
            && signal.score >= 0.55
        {
            has_stronger_non_grooming = true;
            break;
        }
    }
    if !has_stronger_non_grooming {
        return;
    }

    for signal in signals {
        if signal.threat_type == ThreatType::Grooming
            && (signal.reason_code.starts_with("conversation.timing.")
                || signal.reason_code.starts_with("conversation.contact.")
                || signal.reason_code == "conversation.grooming.stage_sequence")
        {
            signal.score = signal.score.min(0.20);
            signal.confidence = score_to_confidence(signal.score);
        }
    }
}

pub(super) fn prioritize_direct_threat_signals(signals: &mut [DetectionSignal]) {
    let mut has_strong_direct_threat = false;
    for signal in signals.iter() {
        if matches!(signal.threat_type, ThreatType::Threat | ThreatType::Doxxing)
            && signal.score >= 0.75
            && (signal.reason_code.starts_with("pattern.threat_")
                || signal.reason_code.starts_with("pattern.doxxing"))
        {
            has_strong_direct_threat = true;
            break;
        }
    }
    if !has_strong_direct_threat {
        return;
    }

    for signal in signals {
        if signal.threat_type == ThreatType::Explicit
            && signal.reason_code.starts_with("pattern.profanity_")
        {
            signal.score = signal.score.min(0.25);
            signal.confidence = score_to_confidence(signal.score);
        }

        if signal.threat_type == ThreatType::Grooming
            && (signal.layer == DetectionLayer::ContextAnalysis
                || signal.reason_code.starts_with("contact.")
                || signal.reason_code.starts_with("conversation.grooming")
                || signal.reason_code.starts_with("conversation.timing")
                || signal.reason_code.starts_with("pattern.grooming_meeting_")
                || signal.reason_code.starts_with("pattern.grooming_location_"))
        {
            signal.score = signal.score.min(0.20);
            signal.confidence = score_to_confidence(signal.score);
        }
    }
}

pub(super) fn anchor_context_signals_to_current_message(signals: &mut [DetectionSignal]) {
    let mut has_pattern_or_ml = false;
    for signal in signals.iter() {
        match signal.layer {
            DetectionLayer::PatternMatching | DetectionLayer::MlClassification => {
                has_pattern_or_ml = true;
                break;
            }
            DetectionLayer::ContextAnalysis => {}
        }
    }
    if has_pattern_or_ml {
        return;
    }

    let mut max_context_score: f32 = 0.0;
    let mut context_count: u32 = 0;
    for signal in signals.iter() {
        match signal.layer {
            DetectionLayer::ContextAnalysis => {
                max_context_score = max_context_score.max(signal.score);
                context_count += 1;
            }
            DetectionLayer::PatternMatching | DetectionLayer::MlClassification => {}
        }
    }

    let damping = if max_context_score >= 0.6 || context_count >= 3 {
        0.75
    } else if max_context_score >= 0.4 || context_count >= 2 {
        0.55
    } else {
        0.3
    };

    for signal in signals {
        match signal.layer {
            DetectionLayer::ContextAnalysis => {
                let raw_score = signal.score;
                signal.score *= damping;
                // Floor protection prevents damping from burying
                // genuine safety-critical context signals. However, it
                // must only apply when the raw (pre-damping) score was
                // already meaningful — otherwise a noise-level signal
                // (e.g. raw=0.10) would be artificially boosted to the
                // floor value, creating a false escalation.
                const MIN_RAW_FOR_FLOOR: f32 = 0.35;
                match signal.threat_type {
                    ThreatType::SelfHarm => {
                        if raw_score >= MIN_RAW_FOR_FLOOR {
                            signal.score = signal.score.max(0.55);
                        }
                    }
                    ThreatType::Grooming | ThreatType::Manipulation => {
                        if raw_score >= MIN_RAW_FOR_FLOOR {
                            signal.score = signal.score.max(0.45);
                        }
                    }
                    ThreatType::None
                    | ThreatType::Bullying
                    | ThreatType::Explicit
                    | ThreatType::Threat
                    | ThreatType::Spam
                    | ThreatType::Scam
                    | ThreatType::Phishing
                    | ThreatType::Nsfw
                    | ThreatType::HateSpeech
                    | ThreatType::Doxxing
                    | ThreatType::PiiLeakage
                    | ThreatType::Propaganda
                    | ThreatType::OpsecViolation
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak => {}
                }
                signal.confidence = score_to_confidence(signal.score);
            }
            DetectionLayer::PatternMatching | DetectionLayer::MlClassification => {}
        }
    }
}

pub(super) fn prioritize_suicide_coercion_as_manipulation(signals: &mut [DetectionSignal]) {
    let mut has_strong_suicide_coercion = false;
    for signal in signals.iter() {
        if signal.threat_type == ThreatType::Manipulation
            && signal.score >= 0.75
            && (signal.reason_code.contains("coercion_suicide")
                || signal.reason_code.contains("suicide_coercion"))
        {
            has_strong_suicide_coercion = true;
            break;
        }
    }
    if !has_strong_suicide_coercion {
        return;
    }

    for signal in signals {
        if signal.threat_type == ThreatType::SelfHarm {
            signal.score = signal.score.min(0.35);
            signal.confidence = score_to_confidence(signal.score);
        }
    }
}

pub(super) fn compute_risk_breakdown(signals: &[DetectionSignal]) -> RiskBreakdown {
    let mut breakdown = RiskBreakdown::default();
    for signal in signals {
        match signal.family {
            SignalFamily::Content => breakdown.content = breakdown.content.max(signal.score),
            SignalFamily::Conversation => {
                breakdown.conversation = breakdown.conversation.max(signal.score)
            }
            SignalFamily::Link => breakdown.link = breakdown.link.max(signal.score),
            SignalFamily::Abuse => breakdown.abuse = breakdown.abuse.max(signal.score),
        }
    }
    breakdown
}

pub(super) fn collect_reason_codes(signals: &[DetectionSignal]) -> Vec<String> {
    let mut sorted: Vec<&DetectionSignal> = signals.iter().collect();
    sorted.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));

    let mut seen = HashSet::new();
    let mut codes = Vec::new();
    for signal in sorted {
        if signal.reason_code.is_empty() || !seen.insert(signal.reason_code.clone()) {
            continue;
        }
        codes.push(signal.reason_code.clone());
        if codes.len() >= 8 {
            break;
        }
    }
    codes
}

pub(super) fn build_inference_summary(
    signals: &[DetectionSignal],
    risk_breakdown: &RiskBreakdown,
    primary_threat: ThreatType,
    primary_score: f32,
    conversation_type: ConversationType,
    contact_snapshot: Option<&ContactSnapshot>,
    context_summary: &AnalysisContextSummary,
) -> InferenceSummary {
    let latent_states = collect_latent_states(
        signals,
        conversation_type,
        contact_snapshot,
        primary_threat,
        context_summary,
    );
    let mut protective_factor_strength = 0.0;
    for state in &latent_states {
        if state.kind == LatentStateKind::ProtectiveSupport {
            protective_factor_strength = state.score;
            break;
        }
    }

    InferenceSummary {
        uncertainty: estimate_uncertainty(signals, primary_threat, primary_score),
        risk_horizon: infer_risk_horizon(
            signals,
            primary_threat,
            primary_score,
            contact_snapshot,
            context_summary,
        ),
        escalation_likelihood_24h: estimate_escalation_likelihood(
            signals,
            risk_breakdown,
            primary_threat,
            contact_snapshot,
            protective_factor_strength,
            &latent_states,
            context_summary,
        ),
        protective_factor_strength,
        latent_states,
    }
}

pub(super) fn collect_latent_states(
    signals: &[DetectionSignal],
    conversation_type: ConversationType,
    contact_snapshot: Option<&ContactSnapshot>,
    primary_threat: ThreatType,
    context_summary: &AnalysisContextSummary,
) -> Vec<LatentStateEvidence> {
    let mut states = Vec::new();
    let suppress_harmful_states =
        crate::action::should_soften_policy_for_context_summary(primary_threat, context_summary);

    if !suppress_harmful_states {
        push_latent_state(
            &mut states,
            LatentStateKind::DependencyBuilding,
            match_signal_family(
                signals,
                &[
                    "grooming",
                    "love_bomb",
                    "flattery",
                    "gift",
                    "financial",
                    "fake_vulnerability",
                    "false_consensus",
                    "identity_erosion",
                ],
                &[ThreatType::Grooming],
            ),
            0.30,
        );
        push_latent_state(
            &mut states,
            LatentStateKind::IsolationPressure,
            match_signal_family(
                signals,
                &[
                    "secrecy",
                    "platform_switch",
                    "network_poisoning",
                    "exclusion",
                    "isolation",
                ],
                &[
                    ThreatType::Grooming,
                    ThreatType::Manipulation,
                    ThreatType::Bullying,
                ],
            ),
            0.30,
        );
        push_latent_state(
            &mut states,
            LatentStateKind::CoerciveControl,
            match_signal_family(
                signals,
                &[
                    "coercion",
                    "blackmail",
                    "debt",
                    "reputation",
                    "screenshot",
                    "emotional_blackmail",
                    "darvo",
                    "control",
                ],
                &[ThreatType::Manipulation, ThreatType::Threat],
            ),
            0.35,
        );
        push_latent_state(
            &mut states,
            LatentStateKind::Humiliation,
            match_signal_family(
                signals,
                &[
                    "bullying",
                    "mockery",
                    "denigration",
                    "rumor",
                    "hate",
                    "doxx",
                    "exclusion",
                ],
                &[
                    ThreatType::Bullying,
                    ThreatType::HateSpeech,
                    ThreatType::Doxxing,
                ],
            ),
            0.35,
        );
        push_latent_state(
            &mut states,
            LatentStateKind::CrisisVulnerability,
            match_signal_family(
                signals,
                &[
                    "selfharm",
                    "hopeless",
                    "farewell",
                    "ideation",
                    "acute_crisis",
                    "chronic_pattern",
                ],
                &[ThreatType::SelfHarm],
            ),
            0.40,
        );
    }

    let mut protective = match_signal_family(
        signals,
        &["protective_factor", "defense_of_victim", "support_network"],
        &[],
    );
    protective.score = protective.score.abs();
    apply_contextual_protective_floor(&mut protective, context_summary);
    if let Some(snapshot) = contact_snapshot {
        if snapshot.trend == BehavioralTrend::Improving {
            protective.score = protective.score.max(0.25);
            protective
                .reason_codes
                .push("contact.trend.improving".to_string());
        }
        if snapshot.is_trusted && snapshot.trust_level >= 0.8 {
            protective.score = protective.score.max(0.20);
            protective
                .reason_codes
                .push("contact.trusted.high_trust".to_string());
        }
    }
    push_latent_state(
        &mut states,
        LatentStateKind::ProtectiveSupport,
        protective,
        0.15,
    );

    if !suppress_harmful_states {
        let mut group_escalation = match_signal_family(
            signals,
            &["raid", "pile_on", "message_bombing", "bystander", "group"],
            &[ThreatType::Bullying, ThreatType::Spam, ThreatType::Scam],
        );
        if conversation_type != ConversationType::Direct {
            let mut max_abuse_score = 0.0_f32;
            for signal in signals {
                if signal.family == SignalFamily::Abuse {
                    max_abuse_score = f32::max(max_abuse_score, signal.score);
                }
            }
            group_escalation.score = group_escalation.score.max(max_abuse_score);
        }
        push_latent_state(
            &mut states,
            LatentStateKind::GroupEscalation,
            group_escalation,
            0.35,
        );
    }

    states.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
    states.truncate(5);
    states
}

#[derive(Default)]
pub(super) struct MatchedSignals {
    pub(super) score: f32,
    pub(super) reason_codes: Vec<String>,
}

pub(super) fn match_signal_family(
    signals: &[DetectionSignal],
    reason_needles: &[&str],
    threat_types: &[ThreatType],
) -> MatchedSignals {
    let mut matched = MatchedSignals::default();
    let mut seen = HashSet::new();

    for signal in signals {
        let mut reason_match = false;
        for needle in reason_needles {
            if signal.reason_code.contains(needle) {
                reason_match = true;
                break;
            }
        }
        let threat_match = threat_types.contains(&signal.threat_type);
        if !reason_match && !threat_match {
            continue;
        }

        matched.score = matched.score.max(signal.score);
        if !signal.reason_code.is_empty() && seen.insert(signal.reason_code.clone()) {
            matched.reason_codes.push(signal.reason_code.clone());
        }
    }

    matched
}

pub(super) fn apply_contextual_protective_floor(
    matched: &mut MatchedSignals,
    context_summary: &AnalysisContextSummary,
) {
    let has_support = context_summary.speech_act == ContextSpeechAct::Support;
    let has_counter = context_summary.speech_act == ContextSpeechAct::Counter;
    let has_report = context_summary.speech_act == ContextSpeechAct::Report;
    let has_quote = context_summary.speech_act == ContextSpeechAct::Quote;
    let has_oppose = context_summary.stance == ContextStance::Oppose;
    let has_trusted = context_summary.relationship.is_trusted;

    if has_support {
        matched.score = matched.score.max(0.60);
        push_unique_reason_code(&mut matched.reason_codes, "context.speech_act.support");
    }

    if has_counter {
        matched.score = matched.score.max(if has_oppose { 0.45 } else { 0.35 });
        push_unique_reason_code(&mut matched.reason_codes, "context.speech_act.counter");
    }

    if has_oppose {
        matched.score = matched.score.max(0.35);
        push_unique_reason_code(&mut matched.reason_codes, "context.stance.oppose");
    }

    if has_trusted && (has_support || has_counter || has_report || has_quote) {
        matched.score = matched.score.max(0.25);
        push_unique_reason_code(&mut matched.reason_codes, "context.relationship.trusted");
    }
}

pub(super) fn push_unique_reason_code(reason_codes: &mut Vec<String>, reason_code: &str) {
    if !reason_codes.iter().any(|existing| existing == reason_code) {
        reason_codes.push(reason_code.to_string());
    }
}

pub(super) fn push_latent_state(
    states: &mut Vec<LatentStateEvidence>,
    kind: LatentStateKind,
    matched: MatchedSignals,
    min_score: f32,
) {
    if matched.score < min_score {
        return;
    }

    states.push(LatentStateEvidence {
        kind,
        score: matched.score.clamp(0.0, 1.0),
        reason_codes: matched.reason_codes,
    });
}

pub(super) fn estimate_uncertainty(
    signals: &[DetectionSignal],
    primary_threat: ThreatType,
    primary_score: f32,
) -> UncertaintyLevel {
    let mut threat_scores: HashMap<ThreatType, f32> = HashMap::with_capacity(8);
    for signal in signals {
        threat_scores
            .entry(signal.threat_type)
            .and_modify(|score| *score = score.max(signal.score))
            .or_insert(signal.score);
    }

    let mut ordered_scores = Vec::with_capacity(threat_scores.len());
    for (threat, score) in threat_scores.into_iter() {
        if threat != ThreatType::None {
            ordered_scores.push(score);
        }
    }
    ordered_scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(Ordering::Equal));

    let top_gap = match ordered_scores.as_slice() {
        [top, second, ..] => top - second,
        [_top] => 1.0,
        [] => 0.0,
    };
    let mut primary_support = 0;
    for signal in signals {
        if signal.threat_type == primary_threat && signal.score >= (primary_score - 0.15) {
            primary_support += 1;
        }
    }

    if primary_support >= 2 && primary_score >= 0.75 && top_gap >= 0.25 {
        UncertaintyLevel::Low
    } else if primary_support <= 1 || top_gap < 0.15 {
        UncertaintyLevel::High
    } else {
        UncertaintyLevel::Medium
    }
}

pub(super) fn infer_risk_horizon(
    signals: &[DetectionSignal],
    primary_threat: ThreatType,
    primary_score: f32,
    contact_snapshot: Option<&ContactSnapshot>,
    context_summary: &AnalysisContextSummary,
) -> RiskHorizon {
    if crate::action::should_soften_policy_for_context_summary(primary_threat, context_summary) {
        return RiskHorizon::Unknown;
    }

    let mut has_immediate_reason = false;
    for signal in signals {
        if signal.reason_code.contains("farewell_after_ideation")
            || signal.reason_code.contains("acute_crisis")
            || signal.reason_code.contains("blocked_domain")
        {
            has_immediate_reason = true;
            break;
        }
    }
    if has_immediate_reason
        || matches!(
            primary_threat,
            ThreatType::Threat | ThreatType::Explicit | ThreatType::Phishing
        ) && primary_score >= 0.8
        || (primary_threat == ThreatType::SelfHarm && primary_score >= 0.8)
    {
        return RiskHorizon::Immediate;
    }

    if matches!(
        primary_threat,
        ThreatType::Grooming | ThreatType::Manipulation | ThreatType::SelfHarm
    ) && primary_score >= 0.55
    {
        return RiskHorizon::ShortTerm;
    }

    if matches!(primary_threat, ThreatType::Bullying)
        || contact_snapshot.is_some_and(|snapshot| match snapshot.trend {
            BehavioralTrend::GradualWorsening
            | BehavioralTrend::RapidWorsening
            | BehavioralTrend::RoleReversal => true,
            BehavioralTrend::Stable | BehavioralTrend::Improving => false,
        })
    {
        return RiskHorizon::Sustained;
    }

    RiskHorizon::Unknown
}

pub(super) fn estimate_escalation_likelihood(
    signals: &[DetectionSignal],
    risk_breakdown: &RiskBreakdown,
    primary_threat: ThreatType,
    contact_snapshot: Option<&ContactSnapshot>,
    protective_factor_strength: f32,
    latent_states: &[LatentStateEvidence],
    context_summary: &AnalysisContextSummary,
) -> f32 {
    let context_softened =
        crate::action::should_soften_policy_for_context_summary(primary_threat, context_summary);
    let mut estimate = risk_breakdown
        .conversation
        .max(risk_breakdown.abuse)
        .max(risk_breakdown.link)
        .max(risk_breakdown.content * 0.85);

    if !context_softened && matches!(primary_threat, ThreatType::SelfHarm) {
        let mut max_selfharm_score = 0.0_f32;
        for signal in signals {
            if signal.threat_type == ThreatType::SelfHarm {
                max_selfharm_score = f32::max(max_selfharm_score, signal.score);
            }
        }
        estimate = estimate.max(max_selfharm_score);
    }

    let coercive_control = latent_score(latent_states, LatentStateKind::CoerciveControl);
    let dependency = latent_score(latent_states, LatentStateKind::DependencyBuilding);
    let isolation = latent_score(latent_states, LatentStateKind::IsolationPressure);
    let crisis = latent_score(latent_states, LatentStateKind::CrisisVulnerability);

    if !context_softened {
        if coercive_control >= 0.6 {
            estimate += 0.10;
        }
        if dependency >= 0.45 && isolation >= 0.45 {
            estimate += 0.10;
        }
        if crisis >= 0.7 {
            estimate += 0.15;
        }

        if let Some(snapshot) = contact_snapshot {
            if snapshot.is_new_contact && matches!(primary_threat, ThreatType::Grooming) {
                estimate += 0.10;
            }
            estimate += match snapshot.trend {
                BehavioralTrend::RapidWorsening | BehavioralTrend::RoleReversal => 0.15,
                BehavioralTrend::GradualWorsening => 0.08,
                BehavioralTrend::Improving => -0.05,
                BehavioralTrend::Stable => 0.0,
            };
        }
    } else {
        estimate = (estimate * 0.30).min(0.30);
    }

    let protective_weight = if context_softened { 0.50 } else { 0.35 };
    (estimate - protective_factor_strength * protective_weight).clamp(0.0, 1.0)
}

pub(super) fn latent_score(latent_states: &[LatentStateEvidence], kind: LatentStateKind) -> f32 {
    let mut result = 0.0;
    for state in latent_states {
        if state.kind == kind {
            result = state.score;
            break;
        }
    }
    result
}

pub(super) fn infer_suspicious_url_subtype(explanation: &str) -> &'static str {
    let explanation = explanation.to_lowercase();
    if explanation.contains("doppelganger campaign") {
        return "doppelganger";
    }
    if explanation.contains("homoglyph attack") {
        return "homoglyph";
    }
    "heuristic"
}
