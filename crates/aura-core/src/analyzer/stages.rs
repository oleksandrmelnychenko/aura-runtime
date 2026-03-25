use std::time::Instant;

use super::*;

impl Analyzer {
    pub(super) fn analyze_staged(&mut self, input: &MessageInput) -> AnalysisResult {
        let start = Instant::now();
        let protection = self.config.effective_protection_level();
        let domain_mode = self.config.effective_domain_mode();
        let domain_output = self.domain_runtime.analyze_for_mode(domain_mode, input);
        let domain_signals = build_domain_detection_signals(domain_output.as_ref());

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
        }

        let mut signals = Vec::with_capacity(8);

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let pattern_result = self.collect_pattern_layer(input, text, None, None);
            signals.extend(pattern_result.signals);
        }

        if let Some(ref raw_text) = input.text {
            let ml_signals = self.run_ml_layer(truncate_text(raw_text));
            signals.extend(ml_signals);
        }
        signals.extend(domain_signals);

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        let mut result = self.combine_signals(
            signals,
            protection,
            input.conversation_type,
            analysis_time_us,
        );
        result.action = merge_domain_output_effects(
            &mut result.reason_codes,
            result.action,
            domain_output.as_ref(),
        );
        if let Some(recommendation) = result.recommended_action.as_mut() {
            recommendation.reason_codes = result.reason_codes.clone();
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
        let domain_mode = self.config.effective_domain_mode();
        let domain_output = self.domain_runtime.analyze_for_mode(domain_mode, input);
        let domain_signals = build_domain_detection_signals(domain_output.as_ref());

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
        }

        let mut signals = Vec::with_capacity(8);

        let mut context_events = Vec::with_capacity(4);
        let content_hash = match input.text.as_ref() {
            Some(text) => Some(content_fingerprint_u64(text)),
            None => None,
        };

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let pattern_result =
                self.collect_pattern_layer(input, text, Some(timestamp_ms), content_hash);
            signals.extend(pattern_result.signals);
            context_events.extend(pattern_result.context_events);
        }

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let enrichment = self.signal_enricher.enrich_full_with_hash(
                text,
                &input.sender_id,
                &input.conversation_id,
                timestamp_ms,
                content_hash,
            );
            context_events.extend(enrichment.events);

            if let Some(age) = enrichment.extracted_age {
                self.context_tracker
                    .contact_profiler_mut()
                    .set_inferred_age(&input.sender_id, age);
            }
        }

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
            });
        }

        if let Some(ref raw_text) = input.text {
            let ml_signals = self.run_ml_layer(truncate_text(raw_text));

            for signal in &ml_signals {
                if let Some(kind) = map_ml_signal_to_event_kind(signal.threat_type) {
                    context_events.push(ContextEvent {
                        event_id: 0,
                        timestamp_ms,
                        sender_id: input.sender_id.clone(),
                        conversation_id: input.conversation_id.clone(),
                        kind,
                        confidence: signal.score,
                        subtype: None,
                        content_hash,
                    });
                }
            }

            signals.extend(ml_signals);
        }

        context_events.extend(build_domain_context_events(
            &domain_signals,
            timestamp_ms,
            &input.sender_id,
            &input.conversation_id,
            content_hash,
        ));
        signals.extend(domain_signals);

        if let Some(ref raw_text) = input.text {
            self.apply_contextual_false_positive_filters(
                input,
                truncate_text(raw_text),
                timestamp_ms,
                &mut signals,
                &mut context_events,
            );
        }

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
            let is_escalation_threat = s.threat_type == ThreatType::Bullying
                || s.threat_type == ThreatType::Threat
                || s.threat_type == ThreatType::Explicit;
            if is_escalation_threat {
                escalation_match_found = true;
                break;
            }
        }
        if escalation_match_found {
            self.escalation_tracker
                .record(&input.conversation_id, &input.sender_id, timestamp_ms);
        }

        let bonus = self
            .escalation_tracker
            .check_bonus(&input.conversation_id, timestamp_ms);
        if bonus > 0.0 {
            for s in &mut signals {
                let is_escalation_threat = s.threat_type == ThreatType::Bullying
                    || s.threat_type == ThreatType::Threat
                    || s.threat_type == ThreatType::Explicit;
                if is_escalation_threat {
                    s.score = (s.score + bonus).min(1.0);
                }
            }
        }

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        let mut result = self.combine_signals(
            signals,
            protection,
            input.conversation_type,
            analysis_time_us,
        );
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
        if let Some(recommendation) = result.recommended_action.as_mut() {
            recommendation.reason_codes = result.reason_codes.clone();
        }
        result
    }
}
