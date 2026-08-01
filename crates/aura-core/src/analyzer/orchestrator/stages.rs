use std::time::Instant;

use super::*;

impl Analyzer {
    pub(super) fn analyze_staged(&mut self, input: &MessageInput) -> AnalysisResult {
        let start = Instant::now();
        let protection = self.config.effective_protection_level();

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
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
        );
        raw_observations.extend(build_domain_observations(domain_output.as_ref(), None));
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
        let mut signals = interpretation.adjusted_signals;
        let relationship_metadata_context = self.context_interpreter.apply_relationship_metadata(
            input,
            self.config.account_type,
            &mut signals,
        );

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        let mut result = self.combine_signals(
            signals,
            protection,
            input.conversation_type,
            analysis_time_us,
        );
        result.context_markers = interpretation_reason_codes.clone();
        append_context_markers(
            &mut result.context_markers,
            &relationship_metadata_context.context_markers,
        );
        result.context_summary = interpretation_context;
        result.action = merge_domain_output_effects(
            &mut result.reason_codes,
            result.action,
            domain_output.as_ref(),
        );
        append_reason_codes(&mut result.reason_codes, &interpretation_reason_codes);
        append_reason_codes(
            &mut result.reason_codes,
            &relationship_metadata_context.reason_codes,
        );
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
        let content_hash = input
            .text
            .as_ref()
            .map(|text| content_fingerprint_u64(text));

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
            if self.config.effective_domain_mode() == DomainMode::Military {
                if let Some(observation) = military_coordinate_crumb_observation(text, content_hash)
                {
                    raw_observations.push(observation);
                }
            }
            raw_observations.extend(doxxing_crumb_observations(text, content_hash));

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
        );
        raw_observations.extend(build_domain_observations(
            domain_output.as_ref(),
            content_hash,
        ));

        raw_observations.push(RawObservation::event(
            EventKind::NormalConversation,
            1.0,
            None,
            content_hash,
        ));
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
        let context_signal_adjustments = interpretation.signal_adjustments;
        let mut signals = interpretation.adjusted_signals;
        let context_events = interpretation.confirmed_events;

        self.context_tracker
            .set_conversation_type(&input.conversation_id, input.conversation_type);

        signals.extend(self.context_tracker.record_events(context_events));

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
            let contact_snapshot = self
                .context_tracker
                .contact_profiler()
                .snapshot(&input.sender_id);
            let timeline = self.context_tracker.timeline(&input.conversation_id);
            self.context_interpreter.apply_downstream_signal_semantics(
                input,
                truncate_text(raw_text),
                timestamp_ms,
                timeline,
                contact_snapshot.as_ref(),
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
        context_signal_adjustments.apply_calibration(&mut signals);
        let relationship_metadata_context = self.context_interpreter.apply_relationship_metadata(
            input,
            self.config.account_type,
            &mut signals,
        );

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        let mut result = self.combine_signals(
            signals,
            protection,
            input.conversation_type,
            analysis_time_us,
        );
        result.context_markers = interpretation_reason_codes.clone();
        append_context_markers(
            &mut result.context_markers,
            &relationship_metadata_context.context_markers,
        );
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
        append_reason_codes(
            &mut result.reason_codes,
            &relationship_metadata_context.reason_codes,
        );
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

mod observations;

use observations::*;
