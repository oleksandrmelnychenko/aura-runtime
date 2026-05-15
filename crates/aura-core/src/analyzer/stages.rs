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
        let mut signals = interpretation.adjusted_signals;
        let relationship_metadata_context =
            apply_relationship_metadata_context(input, self.config.account_type, &mut signals);

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
        let relationship_metadata_context =
            apply_relationship_metadata_context(input, self.config.account_type, &mut signals);

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

fn military_coordinate_crumb_observation(
    text: &str,
    content_hash: Option<u64>,
) -> Option<RawObservation> {
    let normalized = normalize_location_crumb_text(text);
    if normalized.is_empty() || looks_like_coordinate_warning_fragment(&normalized) {
        return None;
    }

    let has_area = contains_any(
        &normalized,
        &[
            "місто ",
            "місот ",
            "село ",
            "селище ",
            "район ",
            "західній частині",
            "східній частині",
        ],
    ) || contains_token(
        &normalized,
        &["місто", "міст", "місо", "місот", "село", "селище"],
    );
    let has_relative = contains_any(
        &normalized,
        &[
            "околиц",
            "південн",
            "північн",
            "західн",
            "східн",
            "за струм",
            "поряд струм",
            "на іншому березі",
            "далі за",
        ],
    );
    let has_site = contains_any(
        &normalized,
        &[
            "завод",
            "заво ",
            "цемент",
            "цех",
            "лісосмуг",
            "силос",
            "шосе",
            "антенн",
            "веж",
            "горбі",
        ],
    );
    let has_current_position = has_site
        && contains_any(
            &normalized,
            &[
                "наш цех",
                "наш це",
                "аш цех",
                "наша позиц",
                "наш пункт",
                "там ми",
                "ми тут",
                "видно нас",
            ],
        );

    let (subtype, confidence) = if has_current_position {
        ("coordinate_crumb.current_position", 0.55)
    } else if has_site {
        ("coordinate_crumb.site", 0.45)
    } else if has_relative {
        ("coordinate_crumb.relative", 0.40)
    } else if has_area {
        ("coordinate_crumb.area", 0.35)
    } else {
        return None;
    };

    Some(RawObservation::event(
        EventKind::CoordinateMention,
        confidence,
        Some(subtype.to_string()),
        content_hash,
    ))
}

fn doxxing_crumb_observations(text: &str, content_hash: Option<u64>) -> Vec<RawObservation> {
    let normalized = normalize_doxxing_crumb_text(text);
    if normalized.is_empty() || looks_like_benign_doxxing_fragment(&normalized) {
        return Vec::new();
    }

    let mut crumbs = Vec::with_capacity(4);
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_distribution_intent(&normalized),
        "doxxing_crumb.intent",
        0.48,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_name_fragment(&normalized),
        "doxxing_crumb.name",
        0.34,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_address_fragment(&normalized),
        "doxxing_crumb.address",
        0.42,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_city_fragment(&normalized),
        "doxxing_crumb.city",
        0.34,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_school_fragment(&normalized),
        "doxxing_crumb.school",
        0.40,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_phone_fragment(&normalized),
        "doxxing_crumb.phone",
        0.42,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_family_fragment(&normalized),
        "doxxing_crumb.family",
        0.38,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_work_fragment(&normalized),
        "doxxing_crumb.work",
        0.36,
        content_hash,
    );

    crumbs
}

fn push_doxxing_crumb_if(
    crumbs: &mut Vec<RawObservation>,
    condition: bool,
    subtype: &str,
    confidence: f32,
    content_hash: Option<u64>,
) {
    if condition {
        crumbs.push(RawObservation::event(
            EventKind::DoxxingAttempt,
            confidence,
            Some(subtype.to_string()),
            content_hash,
        ));
    }
}

fn normalize_doxxing_crumb_text(text: &str) -> String {
    let normalized = TextNormalizer::new().normalize(text);
    normalize_location_crumb_text(&normalized)
}

fn looks_like_benign_doxxing_fragment(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "my address",
            "my place",
            "my bakery",
            "business contact",
            "for the conference",
            "open house",
            "listing agent",
            "all welcome",
            "courier",
            "pickup address",
            "for the package",
            "thanks for sending",
            "patient",
            "consent",
            "on file",
            "public library",
            "safest place",
            "reporting it",
            "won t repeat",
            "news article",
            "this piece",
            "interviews with victims",
            "doxxing campaigns",
            "address leaks",
            "не повторюйте",
            "закидайте скаргами",
        ],
    )
}

fn doxxing_has_distribution_intent(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "find everything",
            "knock yourself out",
            "knock yourselves out",
            "go for it",
            "go forth",
            "pass it around",
            "pass it along",
            "repost the address",
            "drop the bundle",
            "drop the dox",
            "post the full dox",
            "full dox",
            "dox in the group",
            "bundle in the discord",
            "burner accounts",
            "send pizzas",
            "fake deliveries",
            "call the school",
            "scaring her",
            "info is out forever",
        ],
    )
}

fn doxxing_has_name_fragment(normalized: &str) -> bool {
    normalized.starts_with("name ")
        || contains_any(
            normalized,
            &[
                " first name ",
                " last name ",
                " real name ",
                "full name",
                "is her handle",
            ],
        )
}

fn doxxing_has_address_fragment(normalized: &str) -> bool {
    let has_street_type = contains_token(
        normalized,
        &[
            "st", "street", "ave", "avenue", "rd", "road", "drive", "dr", "ln", "lane", "court",
            "ct", "blvd", "way",
        ],
    );
    let has_digit = normalized.chars().any(|ch| ch.is_ascii_digit());

    (has_digit && has_street_type)
        || (has_street_type
            && contains_any(
                normalized,
                &[
                    "lives at",
                    "live at",
                    "lives on",
                    "live on",
                    "they live",
                    "address",
                    "county records",
                ],
            ))
}

fn doxxing_has_city_fragment(normalized: &str) -> bool {
    (normalized.starts_with("city ") || contains_any(normalized, &[" city ", " zip "]))
        && (has_zip_token(normalized)
            || contains_token(
                normalized,
                &[
                    "il", "ca", "pa", "or", "az", "ny", "wa", "tx", "fl", "oh", "mi", "ma",
                ],
            ))
}

fn doxxing_has_school_fragment(normalized: &str) -> bool {
    let has_school_identifier = contains_any(
        normalized,
        &[
            " school",
            " high",
            " hs",
            " elementary",
            " locker",
            " junior",
            " sophomore",
            " freshman",
            " senior",
            " grade",
            " class",
            " period",
            " bus ",
        ],
    );
    let has_sensitive_context = normalized.starts_with("school ")
        || contains_any(
            normalized,
            &[
                " goes to ",
                " attends ",
                " junior at ",
                " locker",
                " class ",
                " period",
                " call the school",
                " her ",
                " his ",
                " she ",
                " he ",
                " they ",
                " target",
                "@",
            ],
        );

    has_school_identifier && has_sensitive_context
}

fn doxxing_has_phone_fragment(normalized: &str) -> bool {
    let digit_count = normalized.chars().filter(|ch| ch.is_ascii_digit()).count();
    if !(10..=12).contains(&digit_count) {
        return false;
    }

    contains_any(
        normalized,
        &[
            " phone",
            " cell",
            " number",
            " called",
            " call em",
            " call them",
            "verified i called",
        ],
    ) || normalized
        .split_whitespace()
        .all(|token| token.chars().all(|ch| ch.is_ascii_digit()))
}

fn doxxing_has_family_fragment(normalized: &str) -> bool {
    contains_token(
        normalized,
        &[
            "mom", "mother", "dad", "father", "parents", "brother", "sister", "son", "daughter",
            "aunt", "uncle", "grandma", "grandpa",
        ],
    )
}

fn doxxing_has_work_fragment(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            " works at",
            " work at",
            " works as",
            " work as",
            " works night",
            " it guy",
            " credit union",
            " pharmacy",
            " nurse",
            " consultant",
        ],
    )
}

fn has_zip_token(normalized: &str) -> bool {
    normalized
        .split_whitespace()
        .any(|token| token.len() == 5 && token.chars().all(|ch| ch.is_ascii_digit()))
}

fn normalize_location_crumb_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(
            ch,
            '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{FEFF}'
                | '\u{00AD}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{034F}'
        ) {
            continue;
        }
        for lower in ch.to_lowercase() {
            if lower.is_alphanumeric() {
                out.push(lower);
            } else {
                out.push(' ');
            }
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn contains_token(text: &str, tokens: &[&str]) -> bool {
    text.split_whitespace()
        .any(|word| tokens.iter().any(|token| word == *token))
}

fn looks_like_coordinate_warning_fragment(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "не публіку",
            "не публику",
            "не пиш",
            "не скидай",
            "нагадую",
            "інструкція",
            "стирались",
            "видаліть",
            "видаляй",
        ],
    )
}

fn append_reason_codes(reason_codes: &mut Vec<String>, extras: &[String]) {
    for priority in 0..=2 {
        for extra in extras {
            if context_reason_priority(extra) != Some(priority) {
                continue;
            }
            if !push_reason_code(reason_codes, extra) {
                return;
            }
        }
    }

    for extra in extras {
        if context_reason_priority(extra).is_some() {
            continue;
        }
        if !push_reason_code(reason_codes, extra) {
            return;
        }
    }
}

fn append_context_markers(context_markers: &mut Vec<String>, extras: &[String]) {
    for extra in extras {
        if !context_markers.iter().any(|existing| existing == extra) {
            context_markers.push(extra.clone());
        }
    }
}

fn push_reason_code(reason_codes: &mut Vec<String>, extra: &str) -> bool {
    if reason_codes.iter().any(|existing| existing == extra) {
        return true;
    }
    reason_codes.push(extra.to_string());
    reason_codes.len() < 12
}

fn context_reason_priority(code: &str) -> Option<u8> {
    if code.starts_with("context.trajectory.") {
        return Some(0);
    }
    if code == "context.filter.applied"
        || matches!(
            code,
            "context.speech_act.quote"
                | "context.speech_act.report"
                | "context.speech_act.counter"
                | "context.speech_act.support"
                | "context.direction.directed_at_user"
                | "context.direction.self_referential"
                | "context.direction.third_party"
        )
    {
        return Some(1);
    }
    if code.starts_with("context.relationship.") || matches!(code, "context.reciprocity.one_sided")
    {
        return Some(2);
    }
    None
}

#[derive(Default)]
struct RelationshipMetadataContext {
    context_markers: Vec<String>,
    reason_codes: Vec<String>,
}

fn apply_relationship_metadata_context(
    input: &MessageInput,
    account_type: AccountType,
    signals: &mut [DetectionSignal],
) -> RelationshipMetadataContext {
    if input.sender_relationship == SenderRelationship::Unknown {
        return RelationshipMetadataContext::default();
    }

    let mut context = RelationshipMetadataContext::default();
    context.context_markers.push(format!(
        "context.relationship.sender.{}",
        sender_relationship_marker(input.sender_relationship)
    ));
    context.context_markers.push(format!(
        "context.relationship.source.{}",
        relationship_trust_source_marker(input.relationship_trust_source)
    ));

    let minor_account = matches!(account_type, AccountType::Child | AccountType::Teen);
    let has_relevant_signal = signals.iter().any(relationship_sensitive_signal);
    let mut score_boost = 0.0_f32;

    if minor_account && input.sender_relationship == SenderRelationship::UnknownAdult {
        context
            .context_markers
            .push("context.relationship.unknown_adult_minor".to_string());
        if has_relevant_signal {
            context
                .reason_codes
                .push("context.relationship.unknown_adult_minor".to_string());
            score_boost += 0.08;
        }
    }

    if input.relationship_trust_source == RelationshipTrustSource::SelfDeclared {
        context
            .context_markers
            .push("context.relationship.self_declared_untrusted".to_string());
        if privileged_relationship_claim(input.sender_relationship) {
            context
                .context_markers
                .push("context.relationship.self_declared_privileged_claim".to_string());
            if minor_account && has_relevant_signal {
                context
                    .reason_codes
                    .push("context.relationship.self_declared_privileged_claim".to_string());
                score_boost += 0.05;
            }
        }
    }

    if verified_relationship_source(input.relationship_trust_source)
        && trusted_family_or_guardian_relationship(input.sender_relationship)
    {
        context
            .context_markers
            .push("context.relationship.verified_family_context".to_string());
    }

    if score_boost > 0.0 {
        for signal in signals
            .iter_mut()
            .filter(|signal| relationship_sensitive_signal(signal))
        {
            signal.score = (signal.score + score_boost).min(1.0);
        }
    }

    context
}

fn relationship_sensitive_signal(signal: &DetectionSignal) -> bool {
    signal.score > 0.0
        && matches!(
            signal.threat_type,
            ThreatType::Grooming
                | ThreatType::Manipulation
                | ThreatType::Explicit
                | ThreatType::Threat
                | ThreatType::Doxxing
                | ThreatType::PiiLeakage
        )
}

fn privileged_relationship_claim(relationship: SenderRelationship) -> bool {
    matches!(
        relationship,
        SenderRelationship::Parent
            | SenderRelationship::Guardian
            | SenderRelationship::Teacher
            | SenderRelationship::Coach
            | SenderRelationship::Authority
    )
}

fn trusted_family_or_guardian_relationship(relationship: SenderRelationship) -> bool {
    matches!(
        relationship,
        SenderRelationship::Parent
            | SenderRelationship::Guardian
            | SenderRelationship::Family
            | SenderRelationship::Sibling
    )
}

fn verified_relationship_source(source: RelationshipTrustSource) -> bool {
    matches!(
        source,
        RelationshipTrustSource::UserVerified
            | RelationshipTrustSource::GuardianVerified
            | RelationshipTrustSource::PlatformVerified
            | RelationshipTrustSource::AddressBook
            | RelationshipTrustSource::SchoolDirectory
    )
}

fn sender_relationship_marker(relationship: SenderRelationship) -> &'static str {
    match relationship {
        SenderRelationship::Unknown => "unknown",
        SenderRelationship::Parent => "parent",
        SenderRelationship::Guardian => "guardian",
        SenderRelationship::Family => "family",
        SenderRelationship::Sibling => "sibling",
        SenderRelationship::Peer => "peer",
        SenderRelationship::Teacher => "teacher",
        SenderRelationship::Coach => "coach",
        SenderRelationship::Authority => "authority",
        SenderRelationship::Service => "service",
        SenderRelationship::UnknownAdult => "unknown_adult",
        SenderRelationship::UnknownPeer => "unknown_peer",
    }
}

fn relationship_trust_source_marker(source: RelationshipTrustSource) -> &'static str {
    match source {
        RelationshipTrustSource::Unknown => "unknown",
        RelationshipTrustSource::UserVerified => "user_verified",
        RelationshipTrustSource::GuardianVerified => "guardian_verified",
        RelationshipTrustSource::PlatformVerified => "platform_verified",
        RelationshipTrustSource::AddressBook => "address_book",
        RelationshipTrustSource::SchoolDirectory => "school_directory",
        RelationshipTrustSource::ServerReputation => "server_reputation",
        RelationshipTrustSource::LocalHeuristic => "local_heuristic",
        RelationshipTrustSource::SelfDeclared => "self_declared",
    }
}

fn apply_context_signal_filters(
    context_summary: &AnalysisContextSummary,
    signals: &mut Vec<DetectionSignal>,
) {
    let has_support = context_summary.speech_act == ContextSpeechAct::Support;
    let has_neutral_or_oppose = matches!(
        context_summary.stance,
        ContextStance::Neutral | ContextStance::Oppose
    );

    if has_support && has_neutral_or_oppose {
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
