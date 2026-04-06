use std::time::Instant;

use super::*;

impl Analyzer {
    pub(super) fn analyze_staged(&mut self, input: &MessageInput) -> AnalysisResult {
        let start = Instant::now();
        let protection = self.config.effective_protection_level();

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
        }

        // Rate-limit: skip expensive pipeline for senders that exceed
        // 60 messages/minute. The message is still counted (total_messages
        // increments) but pattern/ML/context analysis is skipped.
        // Uses wall-clock millis since MessageInput has no timestamp field.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if !self.rate_limiter.check(&input.sender_id, now_ms) {
            return AnalysisResult::rate_limited(start.elapsed().as_micros() as u64);
        }

        let mut raw_observations = Vec::with_capacity(12);

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let pattern_result = self.collect_pattern_layer(input, text, None);
            raw_observations.extend(pattern_result.observations);
        }

        // Run ML first so we can pass safety hints to the domain module.
        let ml_safety_hint = if let Some(ref raw_text) = input.text {
            let ml_signals = self.run_ml_layer(truncate_text(raw_text));
            let hint = Self::extract_ml_safety_hint(&ml_signals);
            raw_observations.extend(build_signal_observations(ml_signals, None));
            hint
        } else {
            None
        };

        let domain_mode = self.config.effective_domain_mode();
        let domain_output = self.domain_runtime.analyze_for_mode_with_hints(
            domain_mode,
            protection,
            input,
            ml_safety_hint,
            input.server_sender_risk_hint,
        );
        let domain_signals = build_domain_detection_signals(domain_output.as_ref());
        raw_observations.extend(build_domain_observations(domain_signals, None));
        let contact_snapshot = self
            .context_tracker
            .contact_profiler()
            .snapshot(&input.sender_id);
        let interpretation = self.context_interpreter.interpret_observations(
            input,
            input.text.as_deref().map(truncate_text),
            None,
            None,
            raw_observations,
            contact_snapshot.as_ref(),
        );
        let interpretation_context = interpretation.analysis_context_summary();
        let interpretation_reason_codes = interpretation.diagnostic_reason_codes();
        let signals = interpretation.adjusted_signals;

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        let mut result = self.combine_signals(
            signals,
            protection,
            input.conversation_type,
            analysis_time_us,
        );
        result.context_markers = interpretation_reason_codes.clone();
        result.context_summary = interpretation_context;
        result.action = merge_domain_output_effects(
            &mut result.reason_codes,
            result.action,
            domain_output.as_ref(),
        );
        append_reason_codes(&mut result.reason_codes, &interpretation_reason_codes);
        if let Some(recommendation) = result.recommended_action.as_mut() {
            recommendation.reason_codes = result.reason_codes.clone();
            crate::action::soften_recommendation_for_context_summary(
                recommendation,
                result.threat_type,
                &result.context_summary,
            );
        }
        result
    }

    pub(super) fn analyze_with_context_staged(
        &mut self,
        input: &MessageInput,
        timestamp_ms: u64,
    ) -> AnalysisResult {
        let start = Instant::now();
        let protection = self.config.effective_protection_level();

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
        }

        let mut raw_observations = Vec::with_capacity(12);
        let content_hash = input.text.as_ref().map(|text| content_fingerprint_u64(text));

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let pattern_result = self.collect_pattern_layer(input, text, content_hash);
            raw_observations.extend(pattern_result.observations);
        }

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let enrichment = self
                .signal_enricher
                .enrich_observations_with_hash(text, content_hash);
            raw_observations.extend(enrichment.observations);

            if let Some(age) = enrichment.extracted_age {
                self.context_tracker
                    .contact_profiler_mut()
                    .set_inferred_age(&input.sender_id, age);
            }
        }

        // Run ML first so we can extract safety hints for the domain module.
        let ml_safety_hint = if let Some(ref raw_text) = input.text {
            let ml_signals = self.run_ml_layer(truncate_text(raw_text));

            let hint = Self::extract_ml_safety_hint(&ml_signals);

            raw_observations.extend(build_signal_observations(ml_signals, content_hash));
            hint
        } else {
            None
        };

        // Run domain module with ML safety hints.
        let domain_mode = self.config.effective_domain_mode();
        let domain_output = self.domain_runtime.analyze_for_mode_with_hints(
            domain_mode,
            protection,
            input,
            ml_safety_hint,
            input.server_sender_risk_hint,
        );
        let domain_signals = build_domain_detection_signals(domain_output.as_ref());
        raw_observations.extend(build_domain_observations(domain_signals, content_hash));

        if let Some(ref raw_text) = input.text {
            self.apply_contextual_false_positive_filters(
                input,
                truncate_text(raw_text),
                timestamp_ms,
                &mut raw_observations,
            );
        }
        let contact_snapshot = self
            .context_tracker
            .contact_profiler()
            .snapshot(&input.sender_id);
        let interpretation_reason_codes;
        let interpretation = {
            let timeline = self.context_tracker.timeline(&input.conversation_id);
            let interpretation = self.context_interpreter.interpret_observations(
                input,
                input.text.as_deref().map(truncate_text),
                Some(timestamp_ms),
                timeline,
                raw_observations,
                contact_snapshot.as_ref(),
            );
            interpretation_reason_codes = interpretation.diagnostic_reason_codes();
            interpretation
        };
        let interpretation_context = interpretation.analysis_context_summary();
        let mut signals = interpretation.adjusted_signals;
        let mut context_events = interpretation.confirmed_events;

        if context_events.is_empty() {
            context_events.push(ContextEvent {
                event_id: 0,
                timestamp_ms,
                sender_id: input.sender_id.clone(),
                conversation_id: input.conversation_id.clone(),
                kind: EventKind::NormalConversation,
                confidence: 1.0,
                subtype: None,
                content_hash,
                context: Default::default(),
            });
        }

        self.context_tracker
            .set_conversation_type(&input.conversation_id, input.conversation_type);

        let context_signals = self.context_tracker.record_events(context_events);

        let sender_is_defender = match self.context_tracker.timeline(&input.conversation_id) {
            Some(t) => {
                let mut found = false;
                for e in t.all_events() {
                    if e.sender_id == input.sender_id && e.kind == EventKind::DefenseOfVictim {
                        found = true;
                        break;
                    }
                }
                found
            }
            None => false,
        };

        for signal in context_signals {
            let is_pile_on_signal = signal.layer == DetectionLayer::ContextAnalysis
                && signal.threat_type == ThreatType::Bullying
                && (signal.explanation.contains("Group bullying")
                    || signal.explanation.contains("Isolation"));

            if is_pile_on_signal && sender_is_defender {
                continue;
            }
            signals.push(signal);
        }

        let is_child = self.config.account_type == AccountType::Child;
        if let Some(timeline) = self.context_tracker.timeline(&input.conversation_id) {
            let tz_offset = self.context_tracker.config().timezone_offset_minutes;
            let timing_signals = self.timing_analyzer.analyze_with_tz(
                timeline,
                &input.sender_id,
                timestamp_ms,
                is_child,
                tz_offset,
            );
            signals.extend(timing_signals);
        }

        if let Some(ref raw_text) = input.text {
            self.apply_post_context_signal_filters(
                input,
                truncate_text(raw_text),
                timestamp_ms,
                &mut signals,
            );
        }

        let mut escalation_match_found = false;
        for s in &signals {
            if is_escalation_bonus_threat(s.threat_type) {
                escalation_match_found = true;
                break;
            }
        }
        if escalation_match_found {
            self.escalation_tracker
                .record(&input.conversation_id, &input.sender_id, timestamp_ms);
        }

        let escalation_factor = self
            .escalation_tracker
            .check_bonus(&input.conversation_id, timestamp_ms);
        if escalation_factor > 0.0 {
            for s in &mut signals {
                if is_escalation_bonus_threat(s.threat_type) {
                    s.score = (s.score * (1.0 + escalation_factor)).min(1.0);
                }
            }
        }

        apply_contact_risk_boost(
            &mut signals,
            self.context_tracker.contact_profiler(),
            &input.sender_id,
        );
        apply_context_signal_filters(&interpretation_context, &mut signals);
        apply_contextual_corroboration_boost(&interpretation_context, &mut signals);

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        let mut result = self.combine_signals(
            signals,
            protection,
            input.conversation_type,
            analysis_time_us,
        );
        result.context_markers = interpretation_reason_codes.clone();
        result.context_summary = interpretation_context;
        result.contact_snapshot = self
            .context_tracker
            .contact_profiler()
            .snapshot(&input.sender_id);
        result.inference = build_inference_summary(
            &result.signals,
            &result.risk_breakdown,
            result.threat_type,
            result.score,
            input.conversation_type,
            result.contact_snapshot.as_ref(),
            &result.context_summary,
        );
        if let Some(recommendation) = result.recommended_action.as_mut() {
            augment_recommendation_for_inference(
                recommendation,
                result.threat_type,
                &result.inference,
            );
        }
        result.action = merge_domain_output_effects(
            &mut result.reason_codes,
            result.action,
            domain_output.as_ref(),
        );
        append_reason_codes(&mut result.reason_codes, &interpretation_reason_codes);
        if let Some(recommendation) = result.recommended_action.as_mut() {
            recommendation.reason_codes = result.reason_codes.clone();
        }

        if let Some(ref snapshot) = result.contact_snapshot {
            if result.threat_type != ThreatType::None {
                if let Some(recommendation) = result.recommended_action.as_mut() {
                    crate::action::escalate_by_contact_history(
                        &mut result.action,
                        recommendation,
                        result.threat_type,
                        snapshot,
                    );
                }
            }
        }

        if let Some(recommendation) = result.recommended_action.as_mut() {
            crate::action::soften_recommendation_for_context_summary(
                recommendation,
                result.threat_type,
                &result.context_summary,
            );
        }

        result
    }
}

fn append_reason_codes(reason_codes: &mut Vec<String>, extras: &[String]) {
    for extra in extras {
        if reason_codes.iter().any(|existing| existing == extra) {
            continue;
        }
        reason_codes.push(extra.clone());
        if reason_codes.len() >= 12 {
            break;
        }
    }
}

fn apply_context_signal_filters(
    context_summary: &AnalysisContextSummary,
    signals: &mut Vec<DetectionSignal>,
) {
    let has_support = context_summary.speech_act == ContextSpeechAct::Support;
    let has_third_party = context_summary.directionality == ContextDirectionality::ThirdParty;
    let has_neutral_or_oppose = matches!(
        context_summary.stance,
        ContextStance::Neutral | ContextStance::Oppose
    );

    if has_support && has_third_party && has_neutral_or_oppose {
        signals.retain(|signal| {
            !(signal.threat_type == ThreatType::Grooming
                && signal.reason_code == "conversation.timing.late_night_minor_contact")
        });
    }
}

fn apply_contextual_corroboration_boost(
    context_summary: &AnalysisContextSummary,
    signals: &mut [DetectionSignal],
) {
    let risky_direct_context = context_summary.directionality
        == ContextDirectionality::DirectedAtUser
        && context_summary.relationship.is_new_contact
        && context_summary.reciprocity == ContextReciprocity::OneSided;
    if !risky_direct_context {
        return;
    }

    let mut has_flattery_pattern = false;
    let mut has_grooming_ml = false;
    for signal in signals.iter() {
        if signal.threat_type != ThreatType::Grooming {
            continue;
        }
        match signal.layer {
            DetectionLayer::PatternMatching => {
                if signal.reason_code.starts_with("pattern.grooming_flattery_") {
                    has_flattery_pattern = true;
                }
            }
            DetectionLayer::MlClassification => {
                if signal.reason_code == "ml.safety.grooming" {
                    has_grooming_ml = true;
                }
            }
            DetectionLayer::ContextAnalysis => {}
        }
    }

    if !(has_flattery_pattern && has_grooming_ml) {
        return;
    }

    for signal in signals.iter_mut() {
        if signal.threat_type != ThreatType::Grooming {
            continue;
        }
        let corroborated = match signal.layer {
            DetectionLayer::PatternMatching => {
                signal.reason_code.starts_with("pattern.grooming_flattery_")
            }
            DetectionLayer::MlClassification => signal.reason_code == "ml.safety.grooming",
            DetectionLayer::ContextAnalysis => false,
        };
        if corroborated {
            signal.score = (signal.score + 0.12).min(0.98);
            signal.confidence = score_to_confidence(signal.score);
        }
    }
}

fn build_signal_observations(
    signals: Vec<DetectionSignal>,
    content_hash: Option<u64>,
) -> Vec<RawObservation> {
    let mut domain_signals = Vec::new();
    let mut observations = Vec::with_capacity(signals.len());

    for signal in signals {
        if signal.reason_code.starts_with("domain.") {
            domain_signals.push(signal);
            continue;
        }

        let event_kind = if signal.layer == DetectionLayer::MlClassification {
            map_ml_signal_to_event_kind(signal.threat_type)
        } else {
            None
        };

        let observation = match event_kind {
            Some(kind) => {
                let score = signal.score;
                RawObservation::signal_with_event(signal, kind, score, None, content_hash)
            }
            None => RawObservation::signal(signal),
        };
        observations.push(observation);
    }

    observations.extend(build_domain_observations(domain_signals, content_hash));
    observations
}

/// Boosts signal scores for contacts with accumulated threat history.
///
/// A contact with prior grooming/bullying/manipulation events gets a score boost
/// on matching signals, making it easier to cross action thresholds. This ensures
/// the app receives progressively stronger signals from repeat offenders.
fn apply_contact_risk_boost(
    signals: &mut [DetectionSignal],
    profiler: &crate::context::contact::ContactProfiler,
    sender_id: &str,
) {
    let profile = match profiler.profile(sender_id) {
        Some(p) => p,
        None => return,
    };

    if profile.is_trusted {
        return;
    }

    for signal in signals.iter_mut() {
        let prior_count = match signal.threat_type {
            ThreatType::Grooming => profile.grooming_event_count,
            ThreatType::Bullying => profile.bullying_event_count,
            ThreatType::Manipulation => profile.manipulation_event_count,
            _ => 0,
        };

        if prior_count < 2 {
            continue;
        }

        // Boost: 3% per prior event, max 20%
        let boost = (prior_count.min(7) as f32 * 0.03).min(0.20);
        signal.score = (signal.score * (1.0 + boost)).min(0.98);
    }
}

fn is_escalation_bonus_threat(threat_type: ThreatType) -> bool {
    threat_type == ThreatType::Bullying
        || threat_type == ThreatType::Threat
        || threat_type == ThreatType::Explicit
        || threat_type == ThreatType::Grooming
        || threat_type == ThreatType::Manipulation
        || threat_type == ThreatType::SelfHarm
        || threat_type == ThreatType::Doxxing
        || threat_type == ThreatType::HateSpeech
        || threat_type == ThreatType::Propaganda
        || threat_type == ThreatType::Psyops
        || threat_type == ThreatType::MilitarySocialEng
}
