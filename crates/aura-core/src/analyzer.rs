use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use aura_ml::{MlConfig, MlPipeline, SafetyLabel, IntentLabel, ToxicityLabel};
use aura_patterns::{PatternDatabase, PatternMatcher, UrlChecker};
use tracing::debug;

use crate::action::{
    augment_recommendation_for_inference, augment_recommendation_for_reason_codes, decide_action_v2,
};
use crate::config::AuraConfig;
use crate::context::enricher::{EnricherConfig, SignalEnricher};
use crate::context::events::{ContextEvent, EventKind};
use crate::context::timing::TimingAnalyzer;
use crate::context::tracker::{ConversationTracker, TrackerConfig, TrackerWireState};
use crate::ids::{ConversationId, SenderId};
use crate::types::*;

struct EscalationTracker {
    recent_events: HashMap<ConversationId, Vec<(u64, SenderId)>>,
}

impl EscalationTracker {
    fn new() -> Self {
        Self {
            recent_events: HashMap::with_capacity(16),
        }
    }

    fn record(&mut self, conversation_id: &str, sender_id: &str, timestamp_ms: u64) {
        let entries = self
            .recent_events
            .entry(ConversationId::from(conversation_id))
            .or_default();
        entries.push((timestamp_ms, SenderId::from(sender_id)));
    }

    fn check_bonus(&self, conversation_id: &str, now_ms: u64) -> f32 {
        let one_hour = 3600 * 1000;
        let cutoff = now_ms.saturating_sub(one_hour);

        if let Some(entries) = self.recent_events.get(conversation_id) {
            let mut recent = Vec::with_capacity(entries.len());
            for entry in entries.iter() {
                if entry.0 >= cutoff {
                    recent.push(entry);
                }
            }
            if recent.len() >= 5 {
                let mut senders = Vec::with_capacity(recent.len());
                for (_, s) in &recent {
                    senders.push(&**s);
                }
                senders.sort();
                senders.dedup();
                if senders.len() >= 2 {
                    return 0.15;
                }
            }
        }
        0.0
    }

    fn cleanup(&mut self, now_ms: u64) {
        let one_hour = 3600 * 1000;
        let cutoff = now_ms.saturating_sub(one_hour);
        self.recent_events.retain(|_, entries| {
            entries.retain(|(ts, _)| *ts >= cutoff);
            !entries.is_empty()
        });
    }
}

const MAX_TEXT_LENGTH: usize = 10_000;

fn truncate_text(text: &str) -> &str {
    if text.len() <= MAX_TEXT_LENGTH {
        return text;
    }
    let mut end = MAX_TEXT_LENGTH;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Performs message analysis combining pattern matching, ML inference, and context tracking.
pub struct Analyzer {
    config: AuraConfig,
    pattern_db: PatternDatabase,
    pattern_matchers: HashMap<String, PatternMatcher>,
    url_checker: UrlChecker,
    context_tracker: ConversationTracker,
    signal_enricher: SignalEnricher,
    timing_analyzer: TimingAnalyzer,
    ml_pipeline: MlPipeline,
    escalation_tracker: EscalationTracker,
}

impl Analyzer {
    /// Creates a new analyzer with the given configuration and pattern database.
    pub fn new(config: AuraConfig, pattern_db: &PatternDatabase) -> Self {
        let default_pattern_language = config.language.clone();
        let pattern_matcher = PatternMatcher::from_database(pattern_db, &default_pattern_language);
        let url_checker = UrlChecker::from_database(pattern_db);
        let context_tracker = ConversationTracker::new(Self::tracker_config(&config));
        let signal_enricher = Self::signal_enricher(&config);
        let timing_analyzer = TimingAnalyzer::new();
        let ml_pipeline = MlPipeline::new(Self::ml_config(&config));

        debug!(
            language = %config.language,
            protection = ?config.effective_protection_level(),
            rules = pattern_matcher.rule_count(),
            blocked_urls = url_checker.blocked_count(),
            ml_active = ml_pipeline.is_active(),
            "AURA analyzer initialized"
        );

        Self {
            config,
            pattern_db: pattern_db.clone(),
            pattern_matchers: HashMap::from([(default_pattern_language, pattern_matcher)]),
            url_checker,
            context_tracker,
            signal_enricher,
            timing_analyzer,
            ml_pipeline,
            escalation_tracker: EscalationTracker::new(),
        }
    }

    fn tracker_config(config: &AuraConfig) -> TrackerConfig {
        TrackerConfig {
            analysis_window_ms: config.ttl_days as u64 * 24 * 60 * 60 * 1000,
            is_child_account: config.account_type == AccountType::Child,
            is_teen_account: config.account_type == AccountType::Teen,
            account_holder_age: config.account_holder_age,
            auto_cleanup_interval: 100,
            timezone_offset_minutes: config.timezone_offset_minutes,
            ..Default::default()
        }
    }

    fn signal_enricher(config: &AuraConfig) -> SignalEnricher {
        SignalEnricher::new(EnricherConfig {
            mode: match config.account_type {
                AccountType::Child | AccountType::Teen => AnalysisMode::Strict,
                AccountType::Adult => AnalysisMode::Standard,
            },
            ..Default::default()
        })
    }

    fn ml_config(config: &AuraConfig) -> MlConfig {
        match config.models_path {
            Some(ref base_path) => {
                let base = std::path::Path::new(base_path);
                let probe = |name: &str| -> Option<String> {
                    let p = base.join(name);
                    p.exists().then(|| p.to_string_lossy().into_owned())
                };
                MlConfig {
                    toxicity_model_path: probe("toxicity.onnx"),
                    sentiment_model_path: probe("sentiment.onnx"),
                    safety_model_path: probe("safety.onnx"),
                    intent_model_path: probe("intent.onnx"),
                    vocab_path: probe("vocab.txt"),
                    use_fallback: true,
                    language: config.language.clone(),
                    ..Default::default()
                }
            }
            None => MlConfig {
                use_fallback: true,
                language: config.language.clone(),
                ..Default::default()
            },
        }
    }

    /// Analyzes a single message for threats without updating conversation context.
    pub fn analyze(&mut self, input: &MessageInput) -> AnalysisResult {
        let start = Instant::now();
        let protection = self.config.effective_protection_level();

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
        }

        let mut signals = Vec::with_capacity(8);

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let matches = {
                let matcher = self.pattern_matcher_for(input.language.as_deref());
                matcher.scan(text)
            };
            for m in matches {
                let threat_type = parse_threat_type(&m.threat_type);

                if !self.is_detection_enabled(threat_type) {
                    continue;
                }

                signals.push(DetectionSignal::pattern(
                    threat_type,
                    m.score,
                    score_to_confidence(m.score),
                    format!("pattern.{}", m.rule_id),
                    m.explanation,
                ));
            }

            let blocked_urls = self.url_checker.find_blocked_urls(text);
            for url in blocked_urls {
                signals.push(DetectionSignal::pattern(
                    ThreatType::Phishing,
                    0.95,
                    Confidence::High,
                    "link.blocked_domain",
                    format!("Blocked URL detected: {url}"),
                ));
            }

            for finding in self.url_checker.find_suspicious_urls(text) {
                signals.push(DetectionSignal::pattern(
                    ThreatType::Phishing,
                    finding.score,
                    score_to_confidence(finding.score),
                    "link.suspicious_url_heuristic",
                    finding.explanation,
                ));
            }
        }

        if let Some(ref raw_text) = input.text {
            let ml_signals = self.run_ml_layer(truncate_text(raw_text));
            signals.extend(ml_signals);
        }

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        self.combine_signals(
            signals,
            protection,
            input.conversation_type,
            analysis_time_us,
        )
    }

    /// Analyzes a message and updates conversation context with detected events at the given timestamp.
    pub fn analyze_with_context(
        &mut self,
        input: &MessageInput,
        timestamp_ms: u64,
    ) -> AnalysisResult {
        let start = Instant::now();
        let protection = self.config.effective_protection_level();

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
        }

        let mut signals = Vec::with_capacity(8);

        let mut context_events = Vec::with_capacity(4);

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let matches = {
                let matcher = self.pattern_matcher_for(input.language.as_deref());
                matcher.scan(text)
            };
            for m in matches {
                let threat_type = parse_threat_type(&m.threat_type);
                if !self.is_detection_enabled(threat_type) {
                    continue;
                }

                signals.push(DetectionSignal::pattern(
                    threat_type,
                    m.score,
                    score_to_confidence(m.score),
                    format!("pattern.{}", m.rule_id),
                    m.explanation,
                ));

                if let Some(event_kind) = match_to_event_kind(&m.rule_id, threat_type) {
                    context_events.push(ContextEvent {
                        event_id: 0,
                        timestamp_ms,
                        sender_id: input.sender_id.clone(),
                        conversation_id: input.conversation_id.clone(),
                        kind: event_kind,
                        confidence: m.score,
                        subtype: None,
                    });
                }
            }

            let blocked_urls = self.url_checker.find_blocked_urls(text);
            for url in blocked_urls {
                signals.push(DetectionSignal::pattern(
                    ThreatType::Phishing,
                    0.95,
                    Confidence::High,
                    "link.blocked_domain",
                    format!("Blocked URL detected: {url}"),
                ));
            }

            for finding in self.url_checker.find_suspicious_urls(text) {
                signals.push(DetectionSignal::pattern(
                    ThreatType::Phishing,
                    finding.score,
                    score_to_confidence(finding.score),
                    "link.suspicious_url_heuristic",
                    finding.explanation,
                ));
            }
        }

        if let Some(ref raw_text) = input.text {
            let text = truncate_text(raw_text);
            let enrichment = self.signal_enricher.enrich_full(
                text,
                &input.sender_id,
                &input.conversation_id,
                timestamp_ms,
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
            });
        }

        if let Some(ref raw_text) = input.text {
            let ml_signals = self.run_ml_layer(truncate_text(raw_text));

            for signal in &ml_signals {
                if let Some(kind) = ml_signal_to_event_kind(signal) {
                    context_events.push(ContextEvent {
                        event_id: 0,
                        timestamp_ms,
                        sender_id: input.sender_id.clone(),
                        conversation_id: input.conversation_id.clone(),
                        kind,
                        confidence: signal.score,
                        subtype: None,
                    });
                }
            }

            signals.extend(ml_signals);
        }

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
            });
        }

        self.context_tracker
            .set_conversation_type(&input.conversation_id, input.conversation_type);

        let context_signals = self.context_tracker.record_events(context_events);

        let sender_is_defender =
            match self.context_tracker.timeline(&input.conversation_id) {
                Some(t) => {
                    let mut found = false;
                    for e in t.all_events() {
                        if e.sender_id == input.sender_id
                            && e.kind == EventKind::DefenseOfVictim
                        {
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

        if let Some(ref raw_text) = input.text {
            self.apply_post_context_signal_filters(
                input,
                truncate_text(raw_text),
                timestamp_ms,
                &mut signals,
            );
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

        for s in &signals {
            if match s.threat_type {
                ThreatType::Bullying | ThreatType::Threat | ThreatType::Explicit => true,
                ThreatType::None
                | ThreatType::Grooming
                | ThreatType::SelfHarm
                | ThreatType::Spam
                | ThreatType::Scam
                | ThreatType::Phishing
                | ThreatType::Manipulation
                | ThreatType::Nsfw
                | ThreatType::HateSpeech
                | ThreatType::Doxxing
                | ThreatType::PiiLeakage
                | ThreatType::Propaganda
                | ThreatType::OpsecViolation
                | ThreatType::Psyops
                | ThreatType::MilitarySocialEng
                | ThreatType::CoordinateLeak => false,
            } {
                self.escalation_tracker.record(
                    &input.conversation_id,
                    &input.sender_id,
                    timestamp_ms,
                );
                break;
            }
        }

        let bonus = self
            .escalation_tracker
            .check_bonus(&input.conversation_id, timestamp_ms);
        if bonus > 0.0 {
            for s in &mut signals {
                if match s.threat_type {
                    ThreatType::Bullying | ThreatType::Threat | ThreatType::Explicit => true,
                    ThreatType::None
                    | ThreatType::Grooming
                    | ThreatType::SelfHarm
                    | ThreatType::Spam
                    | ThreatType::Scam
                    | ThreatType::Phishing
                    | ThreatType::Manipulation
                    | ThreatType::Nsfw
                    | ThreatType::HateSpeech
                    | ThreatType::Doxxing
                    | ThreatType::PiiLeakage
                    | ThreatType::Propaganda
                    | ThreatType::OpsecViolation
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak => false,
                } {
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
        result
    }

    fn combine_signals(
        &self,
        mut signals: Vec<DetectionSignal>,
        protection: ProtectionLevel,
        conversation_type: ConversationType,
        analysis_time_us: u64,
    ) -> AnalysisResult {
        downweight_secondary_timing_grooming(&mut signals);
        prioritize_direct_threat_signals(&mut signals);
        prioritize_suicide_coercion_as_manipulation(&mut signals);
        anchor_context_signals_to_current_message(&mut signals);

        let noise_factor = match conversation_type {
            ConversationType::Direct => 1.0,
            ConversationType::GroupChat => 0.85,
            ConversationType::Group => 0.80,
        };
        if noise_factor < 1.0 {
            for s in &mut signals {
                if s.layer != DetectionLayer::ContextAnalysis {
                    s.score *= noise_factor;
                    s.confidence = score_to_confidence(s.score);
                }
            }
        }
        if signals.is_empty() {
            return AnalysisResult::clean(analysis_time_us);
        }

        let mut max_signal = &signals[0];
        for s in &signals {
            if s.score
                .partial_cmp(&max_signal.score)
                .unwrap_or(Ordering::Equal)
                == Ordering::Greater
            {
                max_signal = s;
            }
        }
        let max_score = max_signal.score;

        let mut anchored_priority = None;
        let mut any_priority = None;
        for s in &signals {
            if s.score >= max_score - 0.3 && s.threat_type != ThreatType::None {
                let is_anchored = match s.layer {
                    DetectionLayer::PatternMatching | DetectionLayer::MlClassification => true,
                    DetectionLayer::ContextAnalysis => false,
                };
                if is_anchored {
                    match anchored_priority {
                        None => anchored_priority = Some(s),
                        Some(current) => {
                            if threat_priority(s.threat_type)
                                < threat_priority(current.threat_type)
                            {
                                anchored_priority = Some(s);
                            }
                        }
                    }
                }
                match any_priority {
                    None => any_priority = Some(s),
                    Some(current) => {
                        if threat_priority(s.threat_type) < threat_priority(current.threat_type) {
                            any_priority = Some(s);
                        }
                    }
                }
            }
        }
        let priority_signal = match (anchored_priority, any_priority) {
            (Some(anchored), Some(any)) => {
                let anchored_p = threat_priority(anchored.threat_type);
                let any_p = threat_priority(any.threat_type);
                if any_p + 4 <= anchored_p {
                    any
                } else {
                    anchored
                }
            }
            (Some(anchored), None) => anchored,
            (None, Some(any)) => any,
            (None, None) => max_signal,
        };

        let mut score = priority_signal.score;
        for signal in &signals {
            if signal.threat_type == priority_signal.threat_type {
                score = f32::max(score, signal.score);
            }
        }
        let primary = priority_signal;

        let (action_v2, mut recommendation) =
            decide_action_v2(primary.threat_type, score, protection);
        let action = action_v2;

        let mut threat_map: std::collections::HashMap<ThreatType, f32> =
            std::collections::HashMap::with_capacity(8);
        for s in &signals {
            if s.threat_type != ThreatType::None {
                let entry = threat_map.entry(s.threat_type).or_insert(0.0);
                if s.score > *entry {
                    *entry = s.score;
                }
            }
        }
        let mut detected_threats = Vec::with_capacity(threat_map.len());
        for entry in threat_map.into_iter() {
            detected_threats.push(entry);
        }
        detected_threats.sort_by_key(|(tt, _)| threat_priority(*tt));

        let risk_breakdown = compute_risk_breakdown(&signals);
        let reason_codes = collect_reason_codes(&signals);
        recommendation.reason_codes = reason_codes.clone();
        augment_recommendation_for_reason_codes(
            &mut recommendation,
            primary.threat_type,
            &reason_codes,
        );
        let inference = build_inference_summary(
            &signals,
            &risk_breakdown,
            primary.threat_type,
            score,
            conversation_type,
            None,
        );
        augment_recommendation_for_inference(&mut recommendation, primary.threat_type, &inference);

        AnalysisResult {
            threat_type: primary.threat_type,
            confidence: primary.confidence,
            action,
            score,
            explanation: primary.explanation.clone(),
            detected_threats,
            signals,
            recommended_action: Some(recommendation),
            risk_breakdown,
            contact_snapshot: None,
            reason_codes,
            inference,
            analysis_time_us,
        }
    }

    fn is_detection_enabled(&self, threat_type: ThreatType) -> bool {
        match threat_type {
            ThreatType::Grooming => self.config.grooming_detection_enabled(),
            ThreatType::SelfHarm => self.config.self_harm_detection_enabled(),
            ThreatType::Bullying => self.config.bullying_detection_enabled(),

            ThreatType::Threat
            | ThreatType::Phishing
            | ThreatType::Explicit
            | ThreatType::Spam
            | ThreatType::Nsfw => self.config.enabled,

            ThreatType::Scam | ThreatType::Manipulation => self.config.enabled,

            ThreatType::HateSpeech | ThreatType::Doxxing | ThreatType::PiiLeakage => {
                self.config.enabled
            }
            ThreatType::Propaganda => self.config.propaganda_detection_enabled(),
            ThreatType::OpsecViolation | ThreatType::CoordinateLeak => {
                self.config.opsec_detection_enabled()
            }
            ThreatType::Psyops | ThreatType::MilitarySocialEng => {
                self.config.psyops_detection_enabled()
            }
            ThreatType::None => false,
        }
    }

    /// Returns a reference to the internal conversation tracker.
    pub fn context_tracker(&self) -> &ConversationTracker {
        &self.context_tracker
    }

    /// Returns the effective protection level currently applied by the analyzer.
    pub fn protection_level(&self) -> ProtectionLevel {
        self.config.effective_protection_level()
    }

    /// Exports the conversation tracker state for persistence or transfer.
    pub fn export_context_state(&self) -> TrackerWireState {
        self.context_tracker.export_wire_state()
    }

    /// Imports a previously exported tracker state, merging it with existing data.
    pub fn import_context_state(
        &mut self,
        state: TrackerWireState,
    ) -> Result<(), crate::error::AuraError> {
        self.context_tracker.import_wire_state(state)
    }

    /// Removes expired events and escalation entries older than the analysis window.
    pub fn cleanup_context(&mut self, now_ms: u64) {
        self.context_tracker.cleanup(now_ms);
        self.escalation_tracker.cleanup(now_ms);
    }

    /// Marks a contact as trusted, reducing future risk scores for that sender.
    pub fn mark_contact_trusted(&mut self, sender_id: &str) {
        self.context_tracker.mark_contact_trusted(sender_id);
    }

    /// Replaces the analyzer configuration and rebuilds pattern matchers and ML pipeline.
    pub fn update_config(&mut self, config: AuraConfig, pattern_db: &PatternDatabase) {
        let tracker_config = Self::tracker_config(&config);
        let signal_enricher = Self::signal_enricher(&config);
        let ml_pipeline = MlPipeline::new(Self::ml_config(&config));
        self.pattern_db = pattern_db.clone();
        self.pattern_matchers = HashMap::from([(
            config.language.clone(),
            PatternMatcher::from_database(pattern_db, &config.language),
        )]);
        self.url_checker = UrlChecker::from_database(pattern_db);
        self.context_tracker.update_config(tracker_config);
        self.signal_enricher = signal_enricher;
        self.ml_pipeline = ml_pipeline;
        self.config = config;
    }

    /// Reloads pattern matchers and URL checker from an updated pattern database.
    pub fn reload_patterns(&mut self, pattern_db: &PatternDatabase) {
        self.pattern_db = pattern_db.clone();
        self.pattern_matchers = HashMap::from([(
            self.config.language.clone(),
            PatternMatcher::from_database(pattern_db, &self.config.language),
        )]);
        self.url_checker = UrlChecker::from_database(pattern_db);
    }

    fn pattern_matcher_for(&mut self, message_language: Option<&str>) -> &PatternMatcher {
        let language = self.pattern_language(message_language);
        self.pattern_matchers
            .entry(language.clone())
            .or_insert_with(|| PatternMatcher::from_database(&self.pattern_db, &language))
    }

    fn pattern_language(&self, message_language: Option<&str>) -> String {
        let Some(language) = message_language else {
            return self.config.language.clone();
        };

        let mut found = false;
        for rule in &self.pattern_db.rules {
            for candidate in &rule.languages {
                if candidate == language {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        if found {
            language.to_string()
        } else {
            self.config.language.clone()
        }
    }

    fn run_ml_layer(&mut self, text: &str) -> Vec<DetectionSignal> {
        let ml_result = self.ml_pipeline.analyze_text(text);
        let mut signals = Vec::with_capacity(4);
        let threshold = self.ml_pipeline.toxicity_threshold();

        if let Some(ref tox) = ml_result.toxicity {
            if tox.toxicity >= threshold {
                let (threat_type, explanation) = match tox.primary_label {
                    Some(ToxicityLabel::Threat) => (
                        ThreatType::Threat,
                        format!("ML: threat detected (score: {:.2})", tox.threat),
                    ),
                    Some(ToxicityLabel::SexualExplicit) => (
                        ThreatType::Explicit,
                        format!(
                            "ML: sexual content detected (score: {:.2})",
                            tox.sexual_explicit
                        ),
                    ),
                    Some(ToxicityLabel::SevereToxicity) => (
                        ThreatType::Bullying,
                        format!(
                            "ML: severe toxicity detected (score: {:.2})",
                            tox.severe_toxicity
                        ),
                    ),
                    Some(ToxicityLabel::Insult) => (
                        ThreatType::Bullying,
                        format!("ML: insult detected (score: {:.2})", tox.insult),
                    ),
                    Some(ToxicityLabel::IdentityAttack) => (
                        ThreatType::Bullying,
                        format!(
                            "ML: identity attack detected (score: {:.2})",
                            tox.identity_attack
                        ),
                    ),
                    None => (
                        ThreatType::Bullying,
                        format!("ML: toxic content detected (score: {:.2})", tox.toxicity),
                    ),
                };

                if self.is_detection_enabled(threat_type) {
                    let reason_code = match threat_type {
                        ThreatType::Threat => "ml.threat",
                        ThreatType::Explicit => "ml.sexual_explicit",
                        ThreatType::Bullying => "ml.toxicity",
                        ThreatType::None
                        | ThreatType::Grooming
                        | ThreatType::SelfHarm
                        | ThreatType::Spam
                        | ThreatType::Scam
                        | ThreatType::Phishing
                        | ThreatType::Manipulation
                        | ThreatType::Nsfw
                        | ThreatType::HateSpeech
                        | ThreatType::Doxxing
                        | ThreatType::PiiLeakage
                        | ThreatType::Propaganda
                        | ThreatType::OpsecViolation
                        | ThreatType::Psyops
                        | ThreatType::MilitarySocialEng
                        | ThreatType::CoordinateLeak => "ml.generic",
                    };
                    signals.push(DetectionSignal::ml(
                        threat_type,
                        tox.toxicity,
                        score_to_confidence(tox.toxicity),
                        reason_code,
                        explanation,
                    ));
                }
            }
        }

        if let Some(ref safety) = ml_result.safety {
            let safety_threshold = 0.5;
            let (threat_type, score, reason_code, explanation) = match safety.primary_label {
                Some(SafetyLabel::Grooming) if safety.grooming >= safety_threshold => (
                    ThreatType::Grooming,
                    safety.grooming,
                    "ml.safety.grooming",
                    format!("ML safety: grooming detected (score: {:.2})", safety.grooming),
                ),
                Some(SafetyLabel::Bullying) if safety.bullying >= safety_threshold => (
                    ThreatType::Bullying,
                    safety.bullying,
                    "ml.safety.bullying",
                    format!("ML safety: bullying detected (score: {:.2})", safety.bullying),
                ),
                Some(SafetyLabel::SelfHarm) if safety.self_harm >= safety_threshold => (
                    ThreatType::SelfHarm,
                    safety.self_harm,
                    "ml.safety.selfharm",
                    format!("ML safety: self-harm detected (score: {:.2})", safety.self_harm),
                ),
                Some(SafetyLabel::Manipulation) if safety.manipulation >= safety_threshold => (
                    ThreatType::Manipulation,
                    safety.manipulation,
                    "ml.safety.manipulation",
                    format!("ML safety: manipulation detected (score: {:.2})", safety.manipulation),
                ),
                _ => (ThreatType::None, 0.0, "", String::new()),
            };

            if threat_type != ThreatType::None && self.is_detection_enabled(threat_type) {
                signals.push(DetectionSignal::ml(
                    threat_type,
                    score,
                    score_to_confidence(score),
                    reason_code,
                    explanation,
                ));
            }
        }

        if let Some(ref intent) = ml_result.intent {
            let intent_threshold = 0.5;
            match intent.primary_intent {
                Some(IntentLabel::RequestMeeting) if intent.request_meeting >= intent_threshold => {
                    if self.is_detection_enabled(ThreatType::Grooming) {
                        signals.push(DetectionSignal::ml(
                            ThreatType::Grooming,
                            intent.request_meeting,
                            score_to_confidence(intent.request_meeting),
                            "ml.intent.meeting",
                            format!("ML intent: meeting request detected (score: {:.2})", intent.request_meeting),
                        ));
                    }
                }
                Some(IntentLabel::RequestSecret) if intent.request_secret >= intent_threshold => {
                    if self.is_detection_enabled(ThreatType::Grooming) {
                        signals.push(DetectionSignal::ml(
                            ThreatType::Grooming,
                            intent.request_secret,
                            score_to_confidence(intent.request_secret),
                            "ml.intent.secret",
                            format!("ML intent: secrecy request detected (score: {:.2})", intent.request_secret),
                        ));
                    }
                }
                Some(IntentLabel::RequestMedia) if intent.request_media >= intent_threshold => {
                    if self.is_detection_enabled(ThreatType::Grooming) {
                        signals.push(DetectionSignal::ml(
                            ThreatType::Grooming,
                            intent.request_media,
                            score_to_confidence(intent.request_media),
                            "ml.intent.media",
                            format!("ML intent: media request detected (score: {:.2})", intent.request_media),
                        ));
                    }
                }
                _ => {}
            }
        }

        signals
    }

    fn apply_contextual_false_positive_filters(
        &self,
        input: &MessageInput,
        text: &str,
        timestamp_ms: u64,
        signals: &mut Vec<DetectionSignal>,
        context_events: &mut Vec<ContextEvent>,
    ) {
        signals.retain(|signal| signal.reason_code != "pattern.profanity_uk_euphemisms");

        let mut has_substance_pressure_context = false;
        for signal in signals.iter() {
            if signal.reason_code.starts_with("pattern.substance_")
                || signal.reason_code == "pattern.manipulation_pressure_uk"
                || signal.reason_code == "pattern.manipulation_pressure_en"
                || signal.reason_code == "pattern.false_consensus_uk"
                || signal.reason_code == "pattern.false_consensus_en"
            {
                has_substance_pressure_context = true;
                break;
            }
        }
        if has_substance_pressure_context {
            signals.retain(|signal| {
                !(signal.threat_type == ThreatType::Explicit
                    && signal.reason_code.starts_with("pattern.profanity_uk_"))
            });
        }

        if is_self_referential_distress_profanity_message(text) {
            signals.retain(|signal| {
                !(match signal.threat_type {
                    ThreatType::Explicit | ThreatType::Bullying => true,
                    ThreatType::None
                    | ThreatType::Grooming
                    | ThreatType::Threat
                    | ThreatType::SelfHarm
                    | ThreatType::Spam
                    | ThreatType::Scam
                    | ThreatType::Phishing
                    | ThreatType::Manipulation
                    | ThreatType::Nsfw
                    | ThreatType::HateSpeech
                    | ThreatType::Doxxing
                    | ThreatType::PiiLeakage
                    | ThreatType::Propaganda
                    | ThreatType::OpsecViolation
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak => false,
                } && signal.reason_code.starts_with("pattern.profanity_uk_"))
            });
            context_events.retain(|event| !match event.kind {
                EventKind::Insult | EventKind::Denigration | EventKind::Mockery => true,
                EventKind::Flattery
                | EventKind::GiftOffer
                | EventKind::SecrecyRequest
                | EventKind::PlatformSwitch
                | EventKind::PersonalInfoRequest
                | EventKind::PhotoRequest
                | EventKind::VideoCallRequest
                | EventKind::FinancialGrooming
                | EventKind::MeetingRequest
                | EventKind::SexualContent
                | EventKind::AgeInappropriate
                | EventKind::HarmEncouragement
                | EventKind::PhysicalThreat
                | EventKind::RumorSpreading
                | EventKind::Exclusion
                | EventKind::GuiltTripping
                | EventKind::Gaslighting
                | EventKind::EmotionalBlackmail
                | EventKind::PeerPressure
                | EventKind::LoveBombing
                | EventKind::Darvo
                | EventKind::Devaluation
                | EventKind::SuicidalIdeation
                | EventKind::Hopelessness
                | EventKind::FarewellMessage
                | EventKind::DoxxingAttempt
                | EventKind::ScreenshotThreat
                | EventKind::HateSpeech
                | EventKind::LocationRequest
                | EventKind::MoneyOffer
                | EventKind::PiiSelfDisclosure
                | EventKind::CasualMeetingRequest
                | EventKind::DareChallenge
                | EventKind::SuicideCoercion
                | EventKind::FalseConsensus
                | EventKind::DebtCreation
                | EventKind::ReputationThreat
                | EventKind::IdentityErosion
                | EventKind::NetworkPoisoning
                | EventKind::FakeVulnerability
                | EventKind::NormalConversation
                | EventKind::TrustedContact
                | EventKind::DefenseOfVictim
                | EventKind::PropagandaNarrative
                | EventKind::SuspiciousSource
                | EventKind::PositionLeak
                | EventKind::UnitInfoLeak
                | EventKind::EquipmentLeak
                | EventKind::CoordinateMention
                | EventKind::PsyopsPattern
                | EventKind::IntelGathering
                | EventKind::MilitaryPhishing
                | EventKind::MilitaryDisinfo => false,
            });
        }

        let has_friendly_context = self.has_recent_playful_reciprocity(
            &input.conversation_id,
            &input.sender_id,
            timestamp_ms,
        ) || self
            .context_tracker
            .contact_profiler()
            .snapshot(&input.sender_id)
            .is_some_and(|snapshot| {
                !snapshot.is_new_contact
                    && snapshot.conversation_count > 0
                    && (snapshot.is_trusted
                        || snapshot.trust_level >= 0.60
                        || snapshot.circle_tier != CircleTier::New)
            });
        let mut has_high_risk_grooming = false;
        for signal in signals.iter() {
            if is_high_risk_grooming_signal(signal) {
                has_high_risk_grooming = true;
                break;
            }
        }
        let plain_peer_compliment = input.conversation_type == ConversationType::Direct
            && (has_friendly_context || is_casual_appearance_compliment_message(text))
            && is_plain_peer_compliment_message(text)
            && !has_high_risk_grooming;
        if plain_peer_compliment {
            signals.retain(|signal| {
                !(signal.threat_type == ThreatType::Grooming && signal.score <= 0.30)
            });
            context_events.retain(|event| !match event.kind {
                EventKind::Flattery | EventKind::LoveBombing => true,
                EventKind::GiftOffer
                | EventKind::SecrecyRequest
                | EventKind::PlatformSwitch
                | EventKind::PersonalInfoRequest
                | EventKind::PhotoRequest
                | EventKind::VideoCallRequest
                | EventKind::FinancialGrooming
                | EventKind::MeetingRequest
                | EventKind::SexualContent
                | EventKind::AgeInappropriate
                | EventKind::Insult
                | EventKind::Denigration
                | EventKind::HarmEncouragement
                | EventKind::PhysicalThreat
                | EventKind::RumorSpreading
                | EventKind::Exclusion
                | EventKind::Mockery
                | EventKind::GuiltTripping
                | EventKind::Gaslighting
                | EventKind::EmotionalBlackmail
                | EventKind::PeerPressure
                | EventKind::Darvo
                | EventKind::Devaluation
                | EventKind::SuicidalIdeation
                | EventKind::Hopelessness
                | EventKind::FarewellMessage
                | EventKind::DoxxingAttempt
                | EventKind::ScreenshotThreat
                | EventKind::HateSpeech
                | EventKind::LocationRequest
                | EventKind::MoneyOffer
                | EventKind::PiiSelfDisclosure
                | EventKind::CasualMeetingRequest
                | EventKind::DareChallenge
                | EventKind::SuicideCoercion
                | EventKind::FalseConsensus
                | EventKind::DebtCreation
                | EventKind::ReputationThreat
                | EventKind::IdentityErosion
                | EventKind::NetworkPoisoning
                | EventKind::FakeVulnerability
                | EventKind::NormalConversation
                | EventKind::TrustedContact
                | EventKind::DefenseOfVictim
                | EventKind::PropagandaNarrative
                | EventKind::SuspiciousSource
                | EventKind::PositionLeak
                | EventKind::UnitInfoLeak
                | EventKind::EquipmentLeak
                | EventKind::CoordinateMention
                | EventKind::PsyopsPattern
                | EventKind::IntelGathering
                | EventKind::MilitaryPhishing
                | EventKind::MilitaryDisinfo => false,
            });
        }

        let mut has_high_risk_grooming_2 = false;
        for signal in signals.iter() {
            if is_high_risk_grooming_signal(signal) {
                has_high_risk_grooming_2 = true;
                break;
            }
        }
        let non_romantic_group_praise = input.conversation_type != ConversationType::Direct
            && is_non_romantic_group_praise_message(text)
            && !has_high_risk_grooming_2;
        if non_romantic_group_praise {
            signals.retain(|signal| {
                !(signal.threat_type == ThreatType::Grooming && signal.score <= 0.35)
            });
            context_events.retain(|event| !match event.kind {
                EventKind::Flattery | EventKind::LoveBombing => true,
                EventKind::GiftOffer
                | EventKind::SecrecyRequest
                | EventKind::PlatformSwitch
                | EventKind::PersonalInfoRequest
                | EventKind::PhotoRequest
                | EventKind::VideoCallRequest
                | EventKind::FinancialGrooming
                | EventKind::MeetingRequest
                | EventKind::SexualContent
                | EventKind::AgeInappropriate
                | EventKind::Insult
                | EventKind::Denigration
                | EventKind::HarmEncouragement
                | EventKind::PhysicalThreat
                | EventKind::RumorSpreading
                | EventKind::Exclusion
                | EventKind::Mockery
                | EventKind::GuiltTripping
                | EventKind::Gaslighting
                | EventKind::EmotionalBlackmail
                | EventKind::PeerPressure
                | EventKind::Darvo
                | EventKind::Devaluation
                | EventKind::SuicidalIdeation
                | EventKind::Hopelessness
                | EventKind::FarewellMessage
                | EventKind::DoxxingAttempt
                | EventKind::ScreenshotThreat
                | EventKind::HateSpeech
                | EventKind::LocationRequest
                | EventKind::MoneyOffer
                | EventKind::PiiSelfDisclosure
                | EventKind::CasualMeetingRequest
                | EventKind::DareChallenge
                | EventKind::SuicideCoercion
                | EventKind::FalseConsensus
                | EventKind::DebtCreation
                | EventKind::ReputationThreat
                | EventKind::IdentityErosion
                | EventKind::NetworkPoisoning
                | EventKind::FakeVulnerability
                | EventKind::NormalConversation
                | EventKind::TrustedContact
                | EventKind::DefenseOfVictim
                | EventKind::PropagandaNarrative
                | EventKind::SuspiciousSource
                | EventKind::PositionLeak
                | EventKind::UnitInfoLeak
                | EventKind::EquipmentLeak
                | EventKind::CoordinateMention
                | EventKind::PsyopsPattern
                | EventKind::IntelGathering
                | EventKind::MilitaryPhishing
                | EventKind::MilitaryDisinfo => false,
            });
        }

        let mut has_high_threat_or_hate = false;
        for signal in signals.iter() {
            if (match signal.threat_type {
                ThreatType::Threat | ThreatType::HateSpeech => true,
                ThreatType::None
                | ThreatType::Bullying
                | ThreatType::Grooming
                | ThreatType::Explicit
                | ThreatType::SelfHarm
                | ThreatType::Spam
                | ThreatType::Scam
                | ThreatType::Phishing
                | ThreatType::Manipulation
                | ThreatType::Nsfw
                | ThreatType::Doxxing
                | ThreatType::PiiLeakage
                | ThreatType::Propaganda
                | ThreatType::OpsecViolation
                | ThreatType::Psyops
                | ThreatType::MilitarySocialEng
                | ThreatType::CoordinateLeak => false,
            }) && signal.score >= 0.75
            {
                has_high_threat_or_hate = true;
                break;
            }
        }
        let gaming_banter = input.conversation_type != ConversationType::Direct
            && (is_competitive_gaming_banter_message(text)
                || is_lightweight_competitive_banter_message(text))
            && !has_high_threat_or_hate;
        if gaming_banter {
            signals.retain(|signal| {
                !(match signal.threat_type {
                    ThreatType::Bullying | ThreatType::Explicit | ThreatType::Threat => true,
                    ThreatType::None
                    | ThreatType::Grooming
                    | ThreatType::SelfHarm
                    | ThreatType::Spam
                    | ThreatType::Scam
                    | ThreatType::Phishing
                    | ThreatType::Manipulation
                    | ThreatType::Nsfw
                    | ThreatType::HateSpeech
                    | ThreatType::Doxxing
                    | ThreatType::PiiLeakage
                    | ThreatType::Propaganda
                    | ThreatType::OpsecViolation
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak => false,
                } && signal.score <= 0.60)
            });
            context_events.retain(|event| !match event.kind {
                EventKind::Insult | EventKind::Denigration | EventKind::Mockery => true,
                EventKind::Flattery
                | EventKind::GiftOffer
                | EventKind::SecrecyRequest
                | EventKind::PlatformSwitch
                | EventKind::PersonalInfoRequest
                | EventKind::PhotoRequest
                | EventKind::VideoCallRequest
                | EventKind::FinancialGrooming
                | EventKind::MeetingRequest
                | EventKind::SexualContent
                | EventKind::AgeInappropriate
                | EventKind::HarmEncouragement
                | EventKind::PhysicalThreat
                | EventKind::RumorSpreading
                | EventKind::Exclusion
                | EventKind::GuiltTripping
                | EventKind::Gaslighting
                | EventKind::EmotionalBlackmail
                | EventKind::PeerPressure
                | EventKind::LoveBombing
                | EventKind::Darvo
                | EventKind::Devaluation
                | EventKind::SuicidalIdeation
                | EventKind::Hopelessness
                | EventKind::FarewellMessage
                | EventKind::DoxxingAttempt
                | EventKind::ScreenshotThreat
                | EventKind::HateSpeech
                | EventKind::LocationRequest
                | EventKind::MoneyOffer
                | EventKind::PiiSelfDisclosure
                | EventKind::CasualMeetingRequest
                | EventKind::DareChallenge
                | EventKind::SuicideCoercion
                | EventKind::FalseConsensus
                | EventKind::DebtCreation
                | EventKind::ReputationThreat
                | EventKind::IdentityErosion
                | EventKind::NetworkPoisoning
                | EventKind::FakeVulnerability
                | EventKind::NormalConversation
                | EventKind::TrustedContact
                | EventKind::DefenseOfVictim
                | EventKind::PropagandaNarrative
                | EventKind::SuspiciousSource
                | EventKind::PositionLeak
                | EventKind::UnitInfoLeak
                | EventKind::EquipmentLeak
                | EventKind::CoordinateMention
                | EventKind::PsyopsPattern
                | EventKind::IntelGathering
                | EventKind::MilitaryPhishing
                | EventKind::MilitaryDisinfo => false,
            });
        }

        let casual_media_share = is_casual_media_share_message(text);
        if casual_media_share {
            signals.retain(|signal| {
                !(signal.threat_type == ThreatType::Grooming
                    && signal.score <= 0.50
                    && !is_high_risk_grooming_signal(signal))
            });
            context_events.retain(|event| !match event.kind {
                EventKind::PhotoRequest
                | EventKind::SecrecyRequest
                | EventKind::CasualMeetingRequest
                | EventKind::Flattery
                | EventKind::LoveBombing => true,
                EventKind::GiftOffer
                | EventKind::PlatformSwitch
                | EventKind::PersonalInfoRequest
                | EventKind::VideoCallRequest
                | EventKind::FinancialGrooming
                | EventKind::MeetingRequest
                | EventKind::SexualContent
                | EventKind::AgeInappropriate
                | EventKind::Insult
                | EventKind::Denigration
                | EventKind::HarmEncouragement
                | EventKind::PhysicalThreat
                | EventKind::RumorSpreading
                | EventKind::Exclusion
                | EventKind::Mockery
                | EventKind::GuiltTripping
                | EventKind::Gaslighting
                | EventKind::EmotionalBlackmail
                | EventKind::PeerPressure
                | EventKind::Darvo
                | EventKind::Devaluation
                | EventKind::SuicidalIdeation
                | EventKind::Hopelessness
                | EventKind::FarewellMessage
                | EventKind::DoxxingAttempt
                | EventKind::ScreenshotThreat
                | EventKind::HateSpeech
                | EventKind::LocationRequest
                | EventKind::MoneyOffer
                | EventKind::PiiSelfDisclosure
                | EventKind::DareChallenge
                | EventKind::SuicideCoercion
                | EventKind::FalseConsensus
                | EventKind::DebtCreation
                | EventKind::ReputationThreat
                | EventKind::IdentityErosion
                | EventKind::NetworkPoisoning
                | EventKind::FakeVulnerability
                | EventKind::NormalConversation
                | EventKind::TrustedContact
                | EventKind::DefenseOfVictim
                | EventKind::PropagandaNarrative
                | EventKind::SuspiciousSource
                | EventKind::PositionLeak
                | EventKind::UnitInfoLeak
                | EventKind::EquipmentLeak
                | EventKind::CoordinateMention
                | EventKind::PsyopsPattern
                | EventKind::IntelGathering
                | EventKind::MilitaryPhishing
                | EventKind::MilitaryDisinfo => false,
            });
        }

        if self.is_playful_banter_message(input, text, timestamp_ms) {
            signals.retain(|signal| !match signal.threat_type {
                ThreatType::Threat
                | ThreatType::Bullying
                | ThreatType::Explicit
                | ThreatType::SelfHarm => true,
                ThreatType::None
                | ThreatType::Grooming
                | ThreatType::Spam
                | ThreatType::Scam
                | ThreatType::Phishing
                | ThreatType::Manipulation
                | ThreatType::Nsfw
                | ThreatType::HateSpeech
                | ThreatType::Doxxing
                | ThreatType::PiiLeakage
                | ThreatType::Propaganda
                | ThreatType::OpsecViolation
                | ThreatType::Psyops
                | ThreatType::MilitarySocialEng
                | ThreatType::CoordinateLeak => false,
            });
            context_events.retain(|event| !match event.kind {
                EventKind::Insult
                | EventKind::Denigration
                | EventKind::Mockery
                | EventKind::PhysicalThreat
                | EventKind::SexualContent
                | EventKind::Hopelessness
                | EventKind::SuicidalIdeation => true,
                EventKind::Flattery
                | EventKind::GiftOffer
                | EventKind::SecrecyRequest
                | EventKind::PlatformSwitch
                | EventKind::PersonalInfoRequest
                | EventKind::PhotoRequest
                | EventKind::VideoCallRequest
                | EventKind::FinancialGrooming
                | EventKind::MeetingRequest
                | EventKind::AgeInappropriate
                | EventKind::HarmEncouragement
                | EventKind::RumorSpreading
                | EventKind::Exclusion
                | EventKind::GuiltTripping
                | EventKind::Gaslighting
                | EventKind::EmotionalBlackmail
                | EventKind::PeerPressure
                | EventKind::LoveBombing
                | EventKind::Darvo
                | EventKind::Devaluation
                | EventKind::FarewellMessage
                | EventKind::DoxxingAttempt
                | EventKind::ScreenshotThreat
                | EventKind::HateSpeech
                | EventKind::LocationRequest
                | EventKind::MoneyOffer
                | EventKind::PiiSelfDisclosure
                | EventKind::CasualMeetingRequest
                | EventKind::DareChallenge
                | EventKind::SuicideCoercion
                | EventKind::FalseConsensus
                | EventKind::DebtCreation
                | EventKind::ReputationThreat
                | EventKind::IdentityErosion
                | EventKind::NetworkPoisoning
                | EventKind::FakeVulnerability
                | EventKind::NormalConversation
                | EventKind::TrustedContact
                | EventKind::DefenseOfVictim
                | EventKind::PropagandaNarrative
                | EventKind::SuspiciousSource
                | EventKind::PositionLeak
                | EventKind::UnitInfoLeak
                | EventKind::EquipmentLeak
                | EventKind::CoordinateMention
                | EventKind::PsyopsPattern
                | EventKind::IntelGathering
                | EventKind::MilitaryPhishing
                | EventKind::MilitaryDisinfo => false,
            });
        }
    }

    fn apply_post_context_signal_filters(
        &self,
        input: &MessageInput,
        text: &str,
        timestamp_ms: u64,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let friendly_context = self.has_recent_playful_reciprocity(
            &input.conversation_id,
            &input.sender_id,
            timestamp_ms,
        ) || self
            .context_tracker
            .contact_profiler()
            .snapshot(&input.sender_id)
            .is_some_and(|snapshot| {
                !snapshot.is_new_contact
                    && snapshot.conversation_count > 0
                    && (snapshot.is_trusted
                        || snapshot.trust_level >= 0.60
                        || snapshot.circle_tier != CircleTier::New)
            });

        let safe_media_context = is_casual_media_share_message(text)
            || is_non_romantic_group_praise_message(text)
            || (friendly_context && is_lightweight_media_banter_message(text));
        if safe_media_context {
            signals.retain(|signal| {
                !(signal.threat_type == ThreatType::Grooming
                    && signal.score <= 0.50
                    && !is_high_risk_grooming_signal(signal))
            });
        }

        let safe_gaming_banter = input.conversation_type != ConversationType::Direct
            && is_lightweight_competitive_banter_message(text);
        if safe_gaming_banter {
            signals.retain(|signal| {
                let dominated = match signal.threat_type {
                    ThreatType::Bullying | ThreatType::Explicit | ThreatType::Threat => {
                        signal.score <= 0.75
                    }
                    ThreatType::Grooming => {
                        signal.score <= 0.35
                            && signal.reason_code == "conversation.contact.new_risky_contact"
                    }
                    ThreatType::None
                    | ThreatType::SelfHarm
                    | ThreatType::Spam
                    | ThreatType::Scam
                    | ThreatType::Phishing
                    | ThreatType::Manipulation
                    | ThreatType::Nsfw
                    | ThreatType::HateSpeech
                    | ThreatType::Doxxing
                    | ThreatType::PiiLeakage
                    | ThreatType::Propaganda
                    | ThreatType::OpsecViolation
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak => false,
                };
                !dominated
            });
        }

        if friendly_context && self.is_playful_banter_message(input, text, timestamp_ms) {
            signals.retain(|signal| {
                !(match signal.threat_type {
                    ThreatType::Bullying | ThreatType::Explicit | ThreatType::Threat => true,
                    ThreatType::None
                    | ThreatType::Grooming
                    | ThreatType::SelfHarm
                    | ThreatType::Spam
                    | ThreatType::Scam
                    | ThreatType::Phishing
                    | ThreatType::Manipulation
                    | ThreatType::Nsfw
                    | ThreatType::HateSpeech
                    | ThreatType::Doxxing
                    | ThreatType::PiiLeakage
                    | ThreatType::Propaganda
                    | ThreatType::OpsecViolation
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak => false,
                } && signal.score <= 0.60)
            });
        }
    }

    fn is_playful_banter_message(
        &self,
        input: &MessageInput,
        text: &str,
        timestamp_ms: u64,
    ) -> bool {
        let lower = text.to_lowercase();
        let joke_disclaimer = contains_any(
            &lower,
            &["жартую", "jk", "just kidding", "just kiddin", "kidding"],
        );
        let playful_marker = contains_any(
            &lower,
            &[
                "ахаха",
                "хаха",
                "😂",
                "🤣",
                "😜",
                "😈",
                "💀",
                "рофл",
                "лол",
                "мем",
                "bro",
                "бро",
            ],
        );
        let mild_teasing_marker = contains_any(
            &lower,
            &[
                "дурень",
                "дурна",
                "дебіли",
                "дебіли",
                "кринж",
                "заткнись",
                "ненавіджу вас",
                "сук!",
                "сук ",
            ],
        );
        let silly_object = contains_any(
            &lower,
            &[
                "бутерброд",
                "бутік",
                "обід",
                "снідан",
                "піц",
                "pizza",
                "sandwich",
                "lunch",
                "мем",
            ],
        );
        let media_marker = contains_any(
            &lower,
            &[
                "тікток",
                "tiktok",
                "мем",
                "відео",
                "video",
                "пост",
                "інста",
                "instagram",
                "селфі",
                "selfie",
                "скетч",
                "зошит",
            ],
        );
        let gaming_marker = contains_any(
            &lower,
            &[
                "катк",
                "лобі",
                "клатч",
                "кіл",
                "кіли",
                "сервер",
                "хіліл",
                "rank",
                "рейд",
                "матч",
                "game",
                "гру",
                "катку",
            ],
        );
        let crush_marker = contains_any(
            &lower,
            &[
                "подобається",
                "краш",
                "подобаєшся",
                "ти думаєш",
                "😳",
                "🥺",
                "😍",
                "💕",
            ],
        );
        let exam_marker = contains_any(
            &lower,
            &["контрольн", "матеш", "урок", "екзам", "школи", "дз"],
        );
        let goodnight_marker = contains_any(
            &lower,
            &[
                "на добраніч",
                "добраніч",
                "goodnight",
                "gn",
                "не проспи",
                "соня",
            ],
        );
        let reciprocal_play = self.has_recent_playful_reciprocity(
            &input.conversation_id,
            &input.sender_id,
            timestamp_ms,
        );

        let self_nullified_teasing = joke_disclaimer && (playful_marker || reciprocal_play);
        let playful_hyperbole = lower.contains("я тебе вб'ю за")
            || lower.contains("kill you for")
            || lower.contains("помру від сміх")
            || lower.contains("здохну від")
            || lower.contains("dying from laughing")
            || lower.contains("dead from laughing")
            || (lower.contains("монстр") && (playful_marker || reciprocal_play))
            || ((lower.contains("вбивця") || lower.contains("знищ") || lower.contains("тікайте"))
                && silly_object
                && playful_marker);
        let casual_death_hyperbole = contains_any(
            &lower,
            &[
                "я здохла",
                "я здох",
                "я мертва",
                "я мертвий",
                "я помру",
                "ми всі здохнемо",
                "не здохніть",
                "ледь жива",
                "ледь живий",
                "i'm dead",
                "im dead",
                "literally died",
                "i died",
            ],
        ) && (playful_marker
            || reciprocal_play
            || media_marker
            || gaming_marker
            || crush_marker
            || exam_marker);
        let conditional_mock_threat = reciprocal_play
            && (lower.contains("я тебе вб'ю якщо") || lower.contains("kill you if you"))
            && !contains_any(
                &lower,
                &[
                    "знаю де ти живеш",
                    "i know where you live",
                    "школ",
                    "поб'ю",
                    "beat you",
                    "заріжу",
                    "збро",
                    "knife",
                ],
            );
        let joking_mild_teasing = mild_teasing_marker
            && (playful_marker || joke_disclaimer || reciprocal_play)
            && !contains_any(
                &lower,
                &[
                    "(ні)",
                    "не жарт",
                    "не шучу",
                    "всі знають",
                    "найтуп",
                    "ніхто",
                ],
            );
        let friendly_goodnight_teasing = goodnight_marker
            && reciprocal_play
            && (playful_marker || mild_teasing_marker || lower.contains("не проспи"));

        self_nullified_teasing
            || playful_hyperbole
            || casual_death_hyperbole
            || conditional_mock_threat
            || joking_mild_teasing
            || friendly_goodnight_teasing
    }

    fn has_recent_playful_reciprocity(
        &self,
        conversation_id: &str,
        sender_id: &str,
        now_ms: u64,
    ) -> bool {
        let Some(timeline) = self.context_tracker.timeline(conversation_id) else {
            return false;
        };
        let since = now_ms.saturating_sub(15 * 60 * 1000);
        let recent = timeline.events_since(since);

        let mut sender_has_prior = false;
        for event in &recent {
            if event.sender_id == sender_id {
                sender_has_prior = true;
                break;
            }
        }
        let mut other_sender_replied = false;
        for event in &recent {
            if event.sender_id != sender_id && event.kind == EventKind::NormalConversation {
                other_sender_replied = true;
                break;
            }
        }

        sender_has_prior && other_sender_replied
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    let mut found = false;
    for needle in needles {
        if text.contains(needle) {
            found = true;
            break;
        }
    }
    found
}

fn count_contains(text: &str, needles: &[&str]) -> usize {
    let mut count = 0;
    for needle in needles {
        if text.contains(needle) {
            count += 1;
        }
    }
    count
}

fn is_plain_peer_compliment_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let compliment_markers = [
        "beautiful",
        "pretty",
        "gorgeous",
        "cute",
        "amazing",
        "perfect",
        "incredible",
        "special",
        "wonderful",
        "lovely",
        "adorable",
        "sweet",
        "таланов",
        "гарн",
        "крас",
        "подобає",
        "зачіск",
        "найкращ",
        "чудов",
        "мила",
        "крутан",
        "талант",
        "ідеаль",
        "неймовірн",
        "особлив",
        "чарівн",
    ];
    let grooming_anchors = [
        "for your age",
        "для свого віку",
        "special connection",
        "особливий зв'язок",
        "не кажи",
        "secret",
        "секрет",
        "зустрінем",
        "meet",
        "photo",
        "фото",
        "selfie",
        "camera",
        "камера",
        "parents",
        "батьк",
        "where do you live",
        "де ти живеш",
        "gift",
        "подар",
        "money",
        "грош",
    ];

    let compliment_count = count_contains(&lower, &compliment_markers);
    compliment_count > 0 && compliment_count <= 2 && !contains_any(&lower, &grooming_anchors)
}

fn is_casual_appearance_compliment_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let simple_markers = [
        "гарна сьогодні",
        "гарно сьогодні",
        "красива сьогодні",
        "pretty today",
        "look nice today",
        "look good today",
        "класна зачіска",
        "класний лук",
        "nice haircut",
        "nice outfit",
    ];
    contains_any(&lower, &simple_markers)
}

fn is_non_romantic_group_praise_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let praise_markers = [
        "ти бог",
        "you are god",
        "ти топ",
        "рятівниц",
        "шедевр",
        "легенда",
        "неймовірна",
        "неймовірний",
        "найкраща",
        "найкращий",
    ];
    let context_markers = [
        "катк",
        "лобі",
        "клатч",
        "кіл",
        "сервер",
        "дз",
        "зошит",
        "проект",
        "скетч",
        "портрет",
        "селфі",
        "групове",
        "фотограф",
    ];
    contains_any(&lower, &praise_markers)
        && contains_any(&lower, &context_markers)
        && !contains_any(
            &lower,
            &[
                "секрет",
                "батьк",
                "мама",
                "купальник",
                "гола",
                "тіло",
                "адрес",
            ],
        )
}

fn is_casual_media_share_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let char_len = lower.chars().count();
    let media_markers = [
        "тікток",
        "tiktok",
        "мем",
        "відео",
        "video",
        "пост",
        "запостив",
        "інста",
        "instagram",
        "селфі",
        "selfie",
        "скетч",
        "зошит",
        "проект",
        "фотку зошита",
        "групове селфі",
        "фотограф",
    ];
    let share_markers = ["скинь", "покажи", "дивись", "кидаю", "покажи", "сфотк"];
    let curiosity_markers = [
        "який",
        "шо там",
        "що там",
        "ні шо там",
        "нi шо там",
        "не покажу нікому",
        "не скажу нікому",
        "тільки не показуй нікому",
        "клянусь",
    ];
    let risky_markers = [
        "купальник",
        "ліфчик",
        "гола",
        "голий",
        "тіло",
        "огол",
        "камера",
        "адрес",
        "локац",
        "де ти живеш",
        "батьк",
        "мама",
        "зустрінем",
    ];

    (contains_any(&lower, &media_markers)
        || (contains_any(&lower, &share_markers)
            && (contains_any(
                &lower,
                &["мем", "відео", "тікток", "зошит", "селфі", "пост"],
            ) || char_len <= 40))
        || (contains_any(&lower, &curiosity_markers)
            && (contains_any(&lower, &media_markers)
                || contains_any(
                    &lower,
                    &["😂", "🤣", "💀", "😭", "кринж", "тіпа", "ахаха", "хахах"],
                )
                || char_len <= 14)))
        && !contains_any(&lower, &risky_markers)
}

fn is_lightweight_media_banter_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_any(
        &lower,
        &[
            "помирала від",
            "помираю від цього",
            "я мертва",
            "який скинь",
            "ні шо там",
            "що там",
            "покажи я помру",
            "покажи я здохну",
            "не скажу нікому",
            "не покажу нікому",
            "це реально він",
            "групове селфі",
        ],
    ) && contains_any(
        &lower,
        &["😂", "🤣", "💀", "😭", "тікток", "мем", "відео", "селфі"],
    )
}

fn is_high_risk_grooming_signal(signal: &DetectionSignal) -> bool {
    signal.threat_type == ThreatType::Grooming
        && (signal.score > 0.55
            || contains_any(
                &signal.reason_code,
                &[
                    "secrecy",
                    "gift",
                    "money",
                    "photo",
                    "meeting",
                    "platform",
                    "sexual",
                    "location",
                    "personal_info",
                    "identity_erosion",
                ],
            ))
}

fn is_lightweight_competitive_banter_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_any(
        &lower,
        &[
            "ти шо робиш там",
            "ти шо робиш",
            "мене вбили через",
            "ти бог",
            "ти топ",
            "ми мусор",
            "минулі 10 каток",
            "ще катку",
            "ненавіджу (жарт)",
            "ненавіджу жарт",
        ],
    ) || (contains_any(&lower, &["😂", "🤣", "💀", "😤"])
        && contains_any(&lower, &["катк", "лобі", "клатч", "кіл", "хіліл"]))
}

fn downweight_secondary_timing_grooming(signals: &mut [DetectionSignal]) {
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

fn is_self_referential_distress_profanity_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_any(
        &lower,
        &[
            "мені мама дала",
            "мене мама",
            "мені пздц",
            "мені пізда",
            "мені п*зда",
            "мені хана",
            "ми в сраці",
            "я в сраці",
            "я в жопі",
        ],
    ) && !contains_any(
        &lower,
        &[
            "тобі",
            "тобе",
            "ти ",
            "тебе",
            "він ",
            "вона ",
            "вони ",
            "з тобою",
        ],
    )
}

fn is_competitive_gaming_banter_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    let gaming_markers = [
        "катк",
        "лобі",
        "клатч",
        "кіл",
        "кіли",
        "хіліл",
        "сервер",
        "game",
        "гру",
        "катку",
        "матч",
    ];
    let banter_markers = [
        "лол",
        "ахах",
        "😂",
        "🤣",
        "💀",
        "😤",
        "го",
        "рілі",
        "бог",
        "топ",
        "мусор",
    ];
    let severe_abuse = [
        "потвора",
        "шмара",
        "урод",
        "здохни",
        "нехай здохне",
        "нікому не потрібна",
        "всі тебе ненавидять",
    ];

    contains_any(&lower, &gaming_markers)
        && (contains_any(&lower, &banter_markers)
            || lower.contains("ти шо робиш")
            || lower.contains("ще катку"))
        && !contains_any(&lower, &severe_abuse)
}

fn prioritize_direct_threat_signals(signals: &mut [DetectionSignal]) {
    let mut has_strong_direct_threat = false;
    for signal in signals.iter() {
        if (match signal.threat_type {
            ThreatType::Threat | ThreatType::Doxxing => true,
            ThreatType::None
            | ThreatType::Bullying
            | ThreatType::Grooming
            | ThreatType::Explicit
            | ThreatType::SelfHarm
            | ThreatType::Spam
            | ThreatType::Scam
            | ThreatType::Phishing
            | ThreatType::Manipulation
            | ThreatType::Nsfw
            | ThreatType::HateSpeech
            | ThreatType::PiiLeakage
            | ThreatType::Propaganda
            | ThreatType::OpsecViolation
            | ThreatType::Psyops
            | ThreatType::MilitarySocialEng
            | ThreatType::CoordinateLeak => false,
        }) && signal.score >= 0.75
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

fn anchor_context_signals_to_current_message(signals: &mut [DetectionSignal]) {
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
                signal.score *= damping;
                signal.confidence = score_to_confidence(signal.score);
            }
            DetectionLayer::PatternMatching | DetectionLayer::MlClassification => {}
        }
    }
}

fn prioritize_suicide_coercion_as_manipulation(signals: &mut [DetectionSignal]) {
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

fn compute_risk_breakdown(signals: &[DetectionSignal]) -> RiskBreakdown {
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

fn collect_reason_codes(signals: &[DetectionSignal]) -> Vec<String> {
    let mut sorted = signals.to_vec();
    sorted.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));

    let mut seen = HashSet::new();
    let mut codes = Vec::new();
    for signal in sorted {
        if signal.reason_code.is_empty() || !seen.insert(signal.reason_code.clone()) {
            continue;
        }
        codes.push(signal.reason_code);
        if codes.len() >= 8 {
            break;
        }
    }
    codes
}

fn build_inference_summary(
    signals: &[DetectionSignal],
    risk_breakdown: &RiskBreakdown,
    primary_threat: ThreatType,
    primary_score: f32,
    conversation_type: ConversationType,
    contact_snapshot: Option<&ContactSnapshot>,
) -> InferenceSummary {
    let latent_states = collect_latent_states(signals, conversation_type, contact_snapshot);
    let mut protective_factor_strength = 0.0;
    for state in &latent_states {
        if state.kind == LatentStateKind::ProtectiveSupport {
            protective_factor_strength = state.score;
            break;
        }
    }

    InferenceSummary {
        uncertainty: estimate_uncertainty(signals, primary_threat, primary_score),
        risk_horizon: infer_risk_horizon(signals, primary_threat, primary_score, contact_snapshot),
        escalation_likelihood_24h: estimate_escalation_likelihood(
            signals,
            risk_breakdown,
            primary_threat,
            contact_snapshot,
            protective_factor_strength,
            &latent_states,
        ),
        protective_factor_strength,
        latent_states,
    }
}

fn collect_latent_states(
    signals: &[DetectionSignal],
    conversation_type: ConversationType,
    contact_snapshot: Option<&ContactSnapshot>,
) -> Vec<LatentStateEvidence> {
    let mut states = Vec::new();

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

    let mut protective = match_signal_family(
        signals,
        &["protective_factor", "defense_of_victim", "support_network"],
        &[],
    );
    protective.score = protective.score.abs();
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

    states.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
    states.truncate(5);
    states
}

#[derive(Default)]
struct MatchedSignals {
    score: f32,
    reason_codes: Vec<String>,
}

fn match_signal_family(
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

fn push_latent_state(
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

fn estimate_uncertainty(
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

fn infer_risk_horizon(
    signals: &[DetectionSignal],
    primary_threat: ThreatType,
    primary_score: f32,
    contact_snapshot: Option<&ContactSnapshot>,
) -> RiskHorizon {
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
        || (match primary_threat {
            ThreatType::Threat | ThreatType::Explicit | ThreatType::Phishing => true,
            ThreatType::None
            | ThreatType::Bullying
            | ThreatType::Grooming
            | ThreatType::SelfHarm
            | ThreatType::Spam
            | ThreatType::Scam
            | ThreatType::Manipulation
            | ThreatType::Nsfw
            | ThreatType::HateSpeech
            | ThreatType::Doxxing
            | ThreatType::PiiLeakage
            | ThreatType::Propaganda
            | ThreatType::OpsecViolation
            | ThreatType::Psyops
            | ThreatType::MilitarySocialEng
            | ThreatType::CoordinateLeak => false,
        }) && primary_score >= 0.8
    {
        return RiskHorizon::Immediate;
    }

    if (match primary_threat {
        ThreatType::Grooming | ThreatType::Manipulation | ThreatType::SelfHarm => true,
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
        | ThreatType::CoordinateLeak => false,
    }) && primary_score >= 0.55
    {
        return RiskHorizon::ShortTerm;
    }

    if (match primary_threat {
        ThreatType::Bullying => true,
        ThreatType::None
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage
        | ThreatType::Propaganda
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => false,
    }) || contact_snapshot.is_some_and(|snapshot| match snapshot.trend {
        BehavioralTrend::GradualWorsening
        | BehavioralTrend::RapidWorsening
        | BehavioralTrend::RoleReversal => true,
        BehavioralTrend::Stable | BehavioralTrend::Improving => false,
    }) {
        return RiskHorizon::Sustained;
    }

    RiskHorizon::Unknown
}

fn estimate_escalation_likelihood(
    signals: &[DetectionSignal],
    risk_breakdown: &RiskBreakdown,
    primary_threat: ThreatType,
    contact_snapshot: Option<&ContactSnapshot>,
    protective_factor_strength: f32,
    latent_states: &[LatentStateEvidence],
) -> f32 {
    let mut estimate = risk_breakdown
        .conversation
        .max(risk_breakdown.abuse)
        .max(risk_breakdown.link)
        .max(risk_breakdown.content * 0.85);

    if match primary_threat {
        ThreatType::SelfHarm => true,
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage
        | ThreatType::Propaganda
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => false,
    } {
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
        if snapshot.is_new_contact
            && (match primary_threat {
                ThreatType::Grooming => true,
                ThreatType::None
                | ThreatType::Bullying
                | ThreatType::Explicit
                | ThreatType::Threat
                | ThreatType::SelfHarm
                | ThreatType::Spam
                | ThreatType::Scam
                | ThreatType::Phishing
                | ThreatType::Manipulation
                | ThreatType::Nsfw
                | ThreatType::HateSpeech
                | ThreatType::Doxxing
                | ThreatType::PiiLeakage
                | ThreatType::Propaganda
                | ThreatType::OpsecViolation
                | ThreatType::Psyops
                | ThreatType::MilitarySocialEng
                | ThreatType::CoordinateLeak => false,
            })
        {
            estimate += 0.10;
        }
        estimate += match snapshot.trend {
            BehavioralTrend::RapidWorsening | BehavioralTrend::RoleReversal => 0.15,
            BehavioralTrend::GradualWorsening => 0.08,
            BehavioralTrend::Improving => -0.05,
            BehavioralTrend::Stable => 0.0,
        };
    }

    (estimate - protective_factor_strength * 0.35).clamp(0.0, 1.0)
}

fn latent_score(latent_states: &[LatentStateEvidence], kind: LatentStateKind) -> f32 {
    let mut result = 0.0;
    for state in latent_states {
        if state.kind == kind {
            result = state.score;
            break;
        }
    }
    result
}

fn match_to_event_kind(rule_id: &str, threat_type: ThreatType) -> Option<EventKind> {
    if rule_id.starts_with("grooming_secrecy") {
        return Some(EventKind::SecrecyRequest);
    }
    if rule_id.starts_with("grooming_gifts") {
        return Some(EventKind::GiftOffer);
    }
    if rule_id.starts_with("grooming_meeting") {
        return Some(EventKind::MeetingRequest);
    }
    if rule_id.starts_with("grooming_age_probing") {
        return Some(EventKind::PersonalInfoRequest);
    }
    if rule_id.starts_with("grooming_flattery") {
        return Some(EventKind::Flattery);
    }
    if rule_id.starts_with("grooming_photo") {
        return Some(EventKind::PhotoRequest);
    }
    if rule_id.starts_with("grooming_platform_switch") {
        return Some(EventKind::PlatformSwitch);
    }
    if rule_id.starts_with("grooming_sexual") {
        return Some(EventKind::SexualContent);
    }
    if rule_id.starts_with("grooming_emotional_dependency") {
        return Some(EventKind::EmotionalBlackmail);
    }

    if rule_id.contains("encourage_harm") {
        return Some(EventKind::HarmEncouragement);
    }
    if rule_id.contains("bodyshame") || rule_id.contains("dehumanize") || rule_id.contains("ugly") {
        return Some(EventKind::Denigration);
    }
    if rule_id.contains("exclusion")
        || rule_id.contains("you_dont_belong")
        || rule_id.contains("isolate_suggest")
    {
        return Some(EventKind::Exclusion);
    }
    if rule_id.contains("coordinate") {
        return Some(EventKind::Exclusion);
    }
    if rule_id.contains("passive_agg") {
        return Some(EventKind::Mockery);
    }
    if rule_id.contains("bullying") && rule_id.contains("003") {
        return Some(EventKind::Exclusion);
    }
    if rule_id.contains("bullying") && rule_id.contains("002") {
        return Some(EventKind::Denigration);
    }
    if rule_id.contains("bullying") {
        return Some(EventKind::Insult);
    }

    if rule_id.starts_with("manipulation_gaslighting") {
        return Some(EventKind::Gaslighting);
    }
    if rule_id.starts_with("manipulation_guilt") {
        return Some(EventKind::GuiltTripping);
    }
    if rule_id.starts_with("manipulation_pressure") {
        return Some(EventKind::PeerPressure);
    }
    if rule_id.starts_with("manipulation_isolation") {
        return Some(EventKind::Exclusion);
    }
    if rule_id.starts_with("manipulation_blackmail") || rule_id.starts_with("sextortion") {
        return Some(EventKind::EmotionalBlackmail);
    }
    if rule_id.starts_with("manipulation_darvo") {
        return Some(EventKind::Darvo);
    }
    if rule_id.starts_with("manipulation_intermittent") {
        return Some(EventKind::Devaluation);
    }
    if rule_id.starts_with("substance_") {
        return Some(EventKind::PeerPressure);
    }
    if rule_id.starts_with("grooming_video_call") {
        return Some(EventKind::VideoCallRequest);
    }
    if rule_id.starts_with("grooming_body_comment") {
        return Some(EventKind::SexualContent);
    }

    if rule_id.starts_with("selfharm") && rule_id.contains("002") {
        return Some(EventKind::SuicidalIdeation);
    }
    if rule_id.starts_with("selfharm") {
        return Some(EventKind::Hopelessness);
    }

    if rule_id.starts_with("doxxing") {
        return Some(EventKind::DoxxingAttempt);
    }

    if rule_id.starts_with("screenshot_threat") {
        return Some(EventKind::ScreenshotThreat);
    }

    if rule_id.starts_with("hate_") {
        return Some(EventKind::HateSpeech);
    }

    if rule_id.starts_with("grooming_location") {
        return Some(EventKind::LocationRequest);
    }

    if rule_id.starts_with("grooming_money") {
        return Some(EventKind::MoneyOffer);
    }

    if rule_id.starts_with("pii_") {
        return Some(EventKind::PiiSelfDisclosure);
    }
    if rule_id.starts_with("meeting_casual") {
        return Some(EventKind::CasualMeetingRequest);
    }
    if rule_id.starts_with("dare_") || rule_id.starts_with("dangerous_") {
        return Some(EventKind::DareChallenge);
    }

    if rule_id.starts_with("coercion_suicide") {
        return Some(EventKind::SuicideCoercion);
    }
    if rule_id.starts_with("false_consensus") {
        return Some(EventKind::FalseConsensus);
    }
    if rule_id.starts_with("debt_creation") {
        return Some(EventKind::DebtCreation);
    }
    if rule_id.starts_with("reputation_threat") {
        return Some(EventKind::ReputationThreat);
    }
    if rule_id.starts_with("identity_erosion") {
        return Some(EventKind::IdentityErosion);
    }
    if rule_id.starts_with("network_poisoning") {
        return Some(EventKind::NetworkPoisoning);
    }
    if rule_id.starts_with("fake_vulnerability") {
        return Some(EventKind::FakeVulnerability);
    }
    if rule_id.starts_with("platform_switch_teen") {
        return Some(EventKind::PlatformSwitch);
    }
    if rule_id.starts_with("gaming_bribery") {
        return Some(EventKind::GiftOffer);
    }
    if rule_id.starts_with("emotional_withdrawal") {
        return Some(EventKind::Devaluation);
    }

    match threat_type {
        ThreatType::Grooming => Some(EventKind::SecrecyRequest),
        ThreatType::Bullying => Some(EventKind::Insult),
        ThreatType::Threat => Some(EventKind::PhysicalThreat),
        ThreatType::SelfHarm => Some(EventKind::SuicidalIdeation),
        ThreatType::Manipulation => Some(EventKind::GuiltTripping),
        ThreatType::Doxxing => Some(EventKind::DoxxingAttempt),
        ThreatType::HateSpeech => Some(EventKind::HateSpeech),
        ThreatType::PiiLeakage => Some(EventKind::PiiSelfDisclosure),
        ThreatType::Propaganda => Some(EventKind::PropagandaNarrative),
        ThreatType::OpsecViolation => Some(EventKind::PositionLeak),
        ThreatType::Psyops => Some(EventKind::PsyopsPattern),
        ThreatType::MilitarySocialEng => Some(EventKind::IntelGathering),
        ThreatType::CoordinateLeak => Some(EventKind::CoordinateMention),
        ThreatType::Phishing
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Explicit
        | ThreatType::Nsfw
        | ThreatType::None => None,
    }
}

fn ml_signal_to_event_kind(signal: &DetectionSignal) -> Option<EventKind> {
    match signal.threat_type {
        ThreatType::Bullying => Some(EventKind::Insult),
        ThreatType::Threat => Some(EventKind::PhysicalThreat),
        ThreatType::Explicit => Some(EventKind::SexualContent),
        ThreatType::None
        | ThreatType::Grooming
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage
        | ThreatType::Propaganda
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => None,
    }
}

fn parse_threat_type(s: &str) -> ThreatType {
    match s {
        "bullying" => ThreatType::Bullying,
        "grooming" => ThreatType::Grooming,
        "explicit" => ThreatType::Explicit,
        "threat" => ThreatType::Threat,
        "self_harm" => ThreatType::SelfHarm,
        "spam" => ThreatType::Spam,
        "scam" => ThreatType::Scam,
        "phishing" => ThreatType::Phishing,
        "manipulation" => ThreatType::Manipulation,
        "nsfw" => ThreatType::Nsfw,
        "hate_speech" => ThreatType::HateSpeech,
        "doxxing" => ThreatType::Doxxing,
        "pii_leakage" => ThreatType::PiiLeakage,
        "propaganda" => ThreatType::Propaganda,
        "opsec_violation" => ThreatType::OpsecViolation,
        "psyops" => ThreatType::Psyops,
        "military_social_eng" => ThreatType::MilitarySocialEng,
        "coordinate_leak" => ThreatType::CoordinateLeak,
        _ => ThreatType::None,
    }
}

fn threat_priority(tt: ThreatType) -> u8 {
    match tt {
        ThreatType::SelfHarm => 0,
        ThreatType::Grooming => 1,
        ThreatType::Explicit => 2,
        ThreatType::Threat => 3,
        ThreatType::Doxxing => 4,
        ThreatType::PiiLeakage => 5,
        ThreatType::Manipulation => 6,
        ThreatType::HateSpeech => 7,
        ThreatType::Bullying => 8,
        ThreatType::Nsfw => 9,
        ThreatType::Phishing => 10,
        ThreatType::Scam => 11,
        ThreatType::Spam => 12,
        ThreatType::OpsecViolation | ThreatType::CoordinateLeak => 2,
        ThreatType::Psyops => 5,
        ThreatType::MilitarySocialEng => 6,
        ThreatType::Propaganda => 7,
        ThreatType::None => 13,
    }
}

fn score_to_confidence(score: f32) -> Confidence {
    if score >= 0.8 {
        Confidence::High
    } else if score >= 0.5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> PatternDatabase {
        let json = r#"{
            "version": "test",
            "updated_at": "2026-01-01",
            "rules": [
                {
                    "id": "threat_001",
                    "threat_type": "threat",
                    "kind": { "type": "keyword", "words": ["kill you", "i will hurt you"] },
                    "score": 0.9,
                    "languages": [],
                    "explanation": "Direct threat detected"
                },
                {
                    "id": "grooming_001",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["don't tell your parents", "our little secret"] },
                    "score": 0.7,
                    "languages": [],
                    "explanation": "Secrecy request (potential grooming)"
                },
                {
                    "id": "selfharm_001",
                    "threat_type": "self_harm",
                    "kind": { "type": "keyword", "words": ["no reason to live", "want to end it all"] },
                    "score": 0.75,
                    "languages": [],
                    "explanation": "Self-harm language detected"
                },
                {
                    "id": "bullying_001",
                    "threat_type": "bullying",
                    "kind": { "type": "keyword", "words": ["nobody likes you", "you're worthless", "everyone hates you", "you're disgusting"] },
                    "score": 0.8,
                    "languages": [],
                    "explanation": "Bullying language detected"
                },
                {
                    "id": "url_block",
                    "threat_type": "phishing",
                    "kind": { "type": "url_domain", "domains": ["evil-site.com"] },
                    "score": 0.95,
                    "languages": [],
                    "explanation": "Blocked URL"
                },
                {
                    "id": "substance_slang_en",
                    "threat_type": "scam",
                    "kind": { "type": "keyword", "words": ["got gas", "dm for prices", "delivery available", "percs", "xans"] },
                    "score": 0.6,
                    "languages": [],
                    "explanation": "Drug slang detected"
                },
                {
                    "id": "sextortion_countdown_en",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["you have 24 hours", "time is running out to pay", "last warning before i share"] },
                    "score": 0.9,
                    "languages": [],
                    "explanation": "Sextortion countdown detected"
                },
                {
                    "id": "grooming_video_call_en",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["let's video call just us", "turn on your camera for me", "go on cam for me"] },
                    "score": 0.65,
                    "languages": [],
                    "explanation": "Video call pressure detected"
                },
                {
                    "id": "grooming_body_comment_en",
                    "threat_type": "grooming",
                    "kind": { "type": "keyword", "words": ["you must have a nice body", "what do you wear to bed", "do you sleep naked"] },
                    "score": 0.85,
                    "languages": [],
                    "explanation": "Body-focused comments detected"
                },
                {
                    "id": "manipulation_darvo_en",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["you're the one who started this", "i'm the victim here", "stop playing victim"] },
                    "score": 0.65,
                    "languages": [],
                    "explanation": "DARVO pattern detected"
                },
                {
                    "id": "substance_pressure_uk",
                    "threat_type": "manipulation",
                    "kind": { "type": "keyword", "words": ["просто спробуй раз", "всі пробують це", "перший раз безкоштовно для тебе"] },
                    "score": 0.55,
                    "languages": [],
                    "explanation": "Drug pressure detected"
                }
            ]
        }"#;
        PatternDatabase::from_json(json).unwrap()
    }

    fn default_input(text: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: "user_123".into(),
            conversation_id: "conv_456".into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
        }
    }

    fn child_input(text: &str, sender: &str, conversation: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: sender.into(),
            conversation_id: conversation.into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
        }
    }

    fn child_config() -> AuraConfig {
        AuraConfig {
            account_type: AccountType::Child,
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        }
    }

    #[test]
    fn clean_message_passes() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input("Hey, how are you?"));
        assert!(!result.is_threat());
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn threat_is_detected_and_warned() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input("I will kill you"));
        assert!(result.is_threat());
        assert_eq!(result.threat_type, ThreatType::Threat);
        assert!(result.score >= 0.9);
        assert!(result.action >= Action::Warn);
    }

    #[test]
    fn grooming_detected_for_all_users() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let result = analyzer.analyze(&default_input("Don't tell your parents about us"));
        assert!(result.is_threat());
        assert_eq!(result.threat_type, ThreatType::Grooming);
    }

    #[test]
    fn self_harm_never_blocked_only_warned() {
        let db = test_db();
        let config = AuraConfig {
            protection_level: ProtectionLevel::High,
            account_type: AccountType::Child,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze(&default_input("I feel like there's no reason to live"));
        assert_eq!(result.threat_type, ThreatType::SelfHarm);
        assert_eq!(result.action, Action::Warn);
        assert!(result.needs_crisis_resources());
    }

    #[test]
    fn blocked_url_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input("Check this out: https://evil-site.com/free"));
        assert!(result.is_threat());
        assert_eq!(result.threat_type, ThreatType::Phishing);
    }

    #[test]
    fn disabled_aura_allows_everything() {
        let db = test_db();
        let config = AuraConfig {
            enabled: false,
            account_type: AccountType::Adult,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze(&default_input("I will kill you"));
        assert!(!result.is_threat());
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn update_config_refreshes_runtime_components() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);

        let adult_events = analyzer.signal_enricher.enrich_full(
            "you are beautiful and amazing",
            "new_contact",
            "conv_1",
            1_000,
        );
        assert!(!adult_events
            .events
            .iter()
            .any(|event| event.kind == crate::context::events::EventKind::LoveBombing));

        let updated_config = AuraConfig {
            account_type: AccountType::Child,
            protection_level: ProtectionLevel::High,
            language: "en".to_string(),
            account_holder_age: Some(12),
            ttl_days: 7,
            timezone_offset_minutes: 180,
            ..AuraConfig::default()
        };
        analyzer.update_config(updated_config, &db);

        let child_events = analyzer.signal_enricher.enrich_full(
            "you are beautiful and amazing",
            "new_contact",
            "conv_1",
            2_000,
        );
        assert!(child_events
            .events
            .iter()
            .any(|event| event.kind == crate::context::events::EventKind::LoveBombing));
        assert!(analyzer.context_tracker.config().is_child_account);
        assert!(!analyzer.context_tracker.config().is_teen_account);
        assert_eq!(
            analyzer.context_tracker.config().account_holder_age,
            Some(12)
        );
        assert_eq!(
            analyzer.context_tracker.config().timezone_offset_minutes,
            180
        );
        assert_eq!(
            analyzer.context_tracker.config().analysis_window_ms,
            7 * 24 * 60 * 60 * 1000
        );
    }

    #[test]
    fn teen_cannot_disable_aura() {
        let db = test_db();
        let config = AuraConfig {
            enabled: true,
            protection_level: ProtectionLevel::Off,
            account_type: AccountType::Teen,
            ..AuraConfig::default()
        };
        assert_eq!(config.effective_protection_level(), ProtectionLevel::Low);
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze(&default_input("I will kill you"));
        assert!(result.is_threat());
    }

    #[test]
    fn analysis_is_fast() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            analyzer.analyze(&default_input("This is a normal message with no threats"));
        }
        let elapsed = start.elapsed();
        let per_message_us = elapsed.as_micros() / 1000;

        assert!(
            per_message_us < 1000,
            "Pattern matching took {per_message_us}us per message, expected <1000us"
        );
    }

    #[test]
    fn context_grooming_sequence_detected_for_child() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let sender = "stranger_42";
        let conv = "conv_child_1";

        let r1 = analyzer.analyze_with_context(
            &child_input("Hey, you seem really cool!", sender, conv),
            1000,
        );

        assert_eq!(r1.action, Action::Allow);

        let r2 = analyzer.analyze_with_context(
            &child_input("Don't tell your parents about this", sender, conv),
            2000,
        );

        assert!(r2.is_threat());

        let r3 = analyzer.analyze_with_context(
            &child_input(
                "Don't tell your parents, our little secret ok?",
                sender,
                conv,
            ),
            3000,
        );
        assert!(r3.is_threat());

        assert!(r3.score >= 0.7);
    }

    #[test]
    fn context_accumulates_across_messages() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let sender = "user_a";
        let conv = "conv_1";

        for i in 0..5 {
            analyzer.analyze_with_context(&child_input("Normal message", sender, conv), i * 1000);
        }

        let timeline = analyzer.context_tracker().timeline(conv);
        assert!(timeline.is_some());
        assert_eq!(timeline.unwrap().len(), 5);
    }

    #[test]
    fn context_export_import_preserves_state() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);

        analyzer.analyze_with_context(
            &child_input("Don't tell your parents", "stranger", "conv_1"),
            1000,
        );
        analyzer.analyze_with_context(&child_input("Hello there", "friend", "conv_2"), 2000);

        let state = analyzer.export_context_state();

        let mut analyzer2 = Analyzer::new(child_config(), &db);
        analyzer2.import_context_state(state).unwrap();

        assert!(analyzer2.context_tracker().timeline("conv_1").is_some());
        assert!(analyzer2.context_tracker().timeline("conv_2").is_some());
    }

    #[test]
    fn scenario_classic_grooming_over_hours() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let predator = "nice_guy_99";
        let conv = "dm_child_1";
        let hour = 3600 * 1000u64;

        let r = analyzer.analyze_with_context(
            &child_input(
                "Hey! I saw your profile, you seem really cool",
                predator,
                conv,
            ),
            0,
        );
        assert_eq!(r.action, Action::Allow);

        let _ = analyzer.analyze_with_context(
            &child_input(
                "You're so beautiful and amazing, truly special",
                predator,
                conv,
            ),
            hour / 2,
        );

        let _ = analyzer.analyze_with_context(
            &child_input(
                "You seem so mature for your age. Where do you live?",
                predator,
                conv,
            ),
            hour,
        );

        let r = analyzer.analyze_with_context(
            &child_input(
                "Don't tell your parents about me ok? They wouldn't understand",
                predator,
                conv,
            ),
            2 * hour,
        );
        assert!(r.is_threat(), "Should detect grooming secrecy request");

        let r = analyzer.analyze_with_context(
            &child_input(
                "Our little secret, ok? Let's meet, just us two",
                predator,
                conv,
            ),
            3 * hour,
        );
        assert!(r.is_threat());

        assert!(
            r.score >= 0.7,
            "Score should be high after multi-stage grooming, got {}",
            r.score
        );
    }

    #[test]
    fn scenario_group_bullying_pile_on() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "class_group_chat";
        let minute = 60 * 1000u64;

        analyzer.analyze_with_context(&child_input("nobody likes you", "bully_1", conv), 0);

        analyzer.analyze_with_context(&child_input("you're worthless", "bully_2", conv), minute);

        analyzer.analyze_with_context(
            &child_input("everyone hates you", "bully_3", conv),
            2 * minute,
        );

        let r = analyzer.analyze_with_context(
            &child_input("you're disgusting", "bully_4", conv),
            3 * minute,
        );

        assert!(r.is_threat());

        assert!(
            r.score >= 0.7,
            "Pile-on should have high score, got {}",
            r.score
        );
    }

    #[test]
    fn pile_on_context_is_not_dropped_for_new_sender_without_direct_bullying_signal() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "class_group_chat_context_only";
        let minute = 60 * 1000u64;

        analyzer.analyze_with_context(&child_input("nobody likes you", "bully_1", conv), 0);
        analyzer.analyze_with_context(&child_input("you're worthless", "bully_2", conv), minute);

        let result = analyzer.analyze_with_context(
            &child_input("they're all against you", "bully_3", conv),
            2 * minute,
        );

        assert!(
            result.signals.iter().any(|signal| {
                signal.layer == DetectionLayer::ContextAnalysis
                    && signal.threat_type == ThreatType::Bullying
                    && (signal.explanation.contains("Group bullying")
                        || signal.explanation.contains("Isolation"))
            }),
            "Expected context bullying signal for new pile-on sender, got: {:?}",
            result.signals
        );
    }

    #[test]
    fn scenario_self_harm_escalation() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let child = "sad_child";
        let conv = "journal";
        let day = 24 * 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input("I had a bad day, nobody talked to me", child, conv),
            0,
        );

        analyzer.analyze_with_context(
            &child_input("I feel like nobody cares about me at all", child, conv),
            3 * day,
        );

        let r = analyzer.analyze_with_context(
            &child_input("There's no reason to live anymore", child, conv),
            5 * day,
        );
        assert!(r.is_threat());
        assert_eq!(r.threat_type, ThreatType::SelfHarm);
        assert_eq!(r.action, Action::Warn);

        assert!(r.needs_crisis_resources());
    }

    #[test]
    fn primary_threat_score_is_not_inflated_by_lower_priority_signal() {
        let db = test_db();
        let analyzer = Analyzer::new(child_config(), &db);
        let signals = vec![
            DetectionSignal::pattern(
                ThreatType::Spam,
                0.95,
                Confidence::High,
                "abuse.spam",
                "spam burst",
            ),
            DetectionSignal::context(
                ThreatType::SelfHarm,
                0.72,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.self_harm.crisis",
                "acute self-harm disclosure",
            ),
        ];

        let result =
            analyzer.combine_signals(signals, ProtectionLevel::High, ConversationType::Direct, 42);

        assert_eq!(result.threat_type, ThreatType::SelfHarm);
        assert!(
            (result.score - 0.72).abs() < f32::EPSILON,
            "Primary threat score should stay on the selected threat, got {}",
            result.score
        );
    }

    #[test]
    fn scenario_farewell_detection() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);

        let _r = analyzer.analyze_with_context(
            &child_input(
                "Goodbye everyone. I'm sorry for everything. Thank you for everything.",
                "child",
                "conv_1",
            ),
            1000,
        );

        let timeline = analyzer.context_tracker().timeline("conv_1").unwrap();
        let has_farewell = timeline
            .all_events()
            .iter()
            .any(|e| e.kind == EventKind::FarewellMessage);
        assert!(has_farewell, "Should detect farewell pattern via enricher");
    }

    #[test]
    fn scenario_love_bombing_enricher() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);

        analyzer.analyze_with_context(
            &child_input(
                "You're so beautiful and amazing and perfect, the most incredible person!",
                "stranger",
                "conv_1",
            ),
            1000,
        );

        let timeline = analyzer.context_tracker().timeline("conv_1").unwrap();
        let has_bombing = timeline
            .all_events()
            .iter()
            .any(|e| e.kind == EventKind::LoveBombing || e.kind == EventKind::Flattery);
        assert!(has_bombing, "Should detect love bombing via enricher");
    }

    #[test]
    fn scenario_probing_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);

        analyzer.analyze_with_context(
            &child_input(
                "Where do you live? What school do you go to? Are you home alone?",
                "stranger",
                "conv_1",
            ),
            1000,
        );

        let timeline = analyzer.context_tracker().timeline("conv_1").unwrap();
        let has_probing = timeline
            .all_events()
            .iter()
            .any(|e| e.kind == EventKind::PersonalInfoRequest);
        assert!(
            has_probing,
            "Should detect personal info probing via enricher"
        );
    }

    #[test]
    fn drug_slang_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input(
            "hey i got gas, dm for prices, delivery available",
        ));
        assert!(
            result.score > 0.0,
            "Drug slang should be detected: {result:?}"
        );
    }

    #[test]
    fn sextortion_countdown_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input("you have 24 hours or i'll share everything"));
        assert!(
            result.score > 0.0,
            "Sextortion countdown should be detected: {result:?}"
        );
    }

    #[test]
    fn grooming_video_call_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let result = analyzer.analyze(&default_input(
            "let's video call just us, turn on your camera for me",
        ));
        assert!(
            result.score > 0.0,
            "Grooming video call should be detected: {result:?}"
        );
    }

    #[test]
    fn grooming_body_comments_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let result = analyzer.analyze(&default_input(
            "you must have a nice body, what do you wear to bed",
        ));
        assert!(
            result.score > 0.0,
            "Grooming body comments should be detected: {result:?}"
        );
    }

    #[test]
    fn darvo_manipulation_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input(
            "you're the one who started this, i'm the victim here",
        ));
        assert!(
            result.score > 0.0,
            "DARVO manipulation should be detected: {result:?}"
        );
    }

    #[test]
    fn drug_pressure_detected_uk() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input(
            "просто спробуй раз, всі пробують це, перший раз безкоштовно для тебе",
        ));
        assert!(
            result.score > 0.0,
            "Drug pressure UK should be detected: {result:?}"
        );
    }

    #[test]
    fn sextortion_photo_blackmail_sequence_detected() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "dm_sextort";

        let texts = [
            "у мене є твої голі фотки",
            "якщо не скинеш ще — покажу всім",
            "скинь нові фото або розповім батькам",
        ];

        let mut last_result = None;
        for (idx, text) in texts.iter().enumerate() {
            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: "sextort".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            };
            last_result = Some(analyzer.analyze_with_context(&input, (idx as u64 + 1) * 1_000));
        }

        let result = last_result.expect("sextortion result");
        assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
        assert!(result.score >= 0.70, "{result:?}");
    }

    #[test]
    fn substance_offer_and_pressure_detected_as_manipulation() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "dm_drugs";

        let first = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("хочеш спробувати тр@вку? перший раз на халяву".to_string()),
                image_data: None,
                sender_id: "dealer".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1_000,
        );
        assert_eq!(first.threat_type, ThreatType::Manipulation, "{first:?}");

        let second = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("не сси, всі так роблять в нашому віці".to_string()),
                image_data: None,
                sender_id: "dealer".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            2_000,
        );
        assert_eq!(second.threat_type, ThreatType::Manipulation, "{second:?}");
        assert!(second.score >= 0.50, "{second:?}");
    }

    #[test]
    fn integration_grooming_sequence_produces_recommendation() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_groom";
        let hour = 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input(
                "You're so beautiful and amazing and special!",
                "stranger",
                conv,
            ),
            0,
        );

        let r = analyzer.analyze_with_context(
            &child_input("Don't tell your parents about me ok?", "stranger", conv),
            hour,
        );

        assert!(r.is_threat(), "Should detect grooming");
        assert!(
            r.recommended_action.is_some(),
            "Should include recommended_action"
        );
        let rec = r.recommended_action.unwrap();
        assert!(
            rec.parent_alert >= AlertPriority::High,
            "Grooming should alert parent"
        );
    }

    #[test]
    fn integration_selfharm_never_blocked_always_crisis() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_sh";

        let r = analyzer.analyze_with_context(
            &child_input(
                "I don't want to live anymore. I want to end it all.",
                "child",
                conv,
            ),
            1000,
        );
        assert_ne!(r.action, Action::Block, "Self-harm must NEVER be blocked");
        assert!(
            r.needs_crisis_resources(),
            "Self-harm must show crisis resources"
        );
        assert!(r.recommended_action.is_some());
        let rec = r.recommended_action.unwrap();
        assert!(rec.crisis_resources, "Crisis resources must be enabled");
    }

    #[test]
    fn integration_bullying_pile_on_escalates() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_bully";
        let min = 60 * 1000u64;
        let base = 10 * 3600 * 1000u64;

        let bullies = ["b1", "b2", "b3", "b4"];
        let insults = [
            "Nobody likes you, just leave",
            "You're worthless and pathetic",
            "Everyone hates you, go away",
            "You're disgusting, nobody wants you",
        ];

        let mut last_result = None;
        for (i, (bully, insult)) in bullies.iter().zip(insults.iter()).enumerate() {
            let r = analyzer
                .analyze_with_context(&child_input(insult, bully, conv), base + (i as u64) * min);
            last_result = Some(r);
        }

        let r = last_result.unwrap();
        assert!(r.is_threat(), "Pile-on bullying should be detected");
        assert!(
            r.score >= 0.5,
            "Pile-on should produce significant score: {}",
            r.score
        );
    }

    #[test]
    fn integration_manipulation_multi_tactic() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            protection_level: ProtectionLevel::High,
            language: "en".to_string(),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "int_manip";
        let day = 24 * 3600 * 1000u64;
        let manip = "manipulator";

        analyzer.analyze_with_context(
            &child_input(
                "That never happened, you're imagining things. You're being dramatic.",
                manip,
                conv,
            ),
            0,
        );

        analyzer.analyze_with_context(
            &child_input(
                "It's all in your head, you're making things up. Nobody will believe you.",
                manip,
                conv,
            ),
            day,
        );

        let r = analyzer.analyze_with_context(
            &child_input(
                "After everything I've done for you, you're so ungrateful. This is your fault.",
                manip,
                conv,
            ),
            2 * day,
        );

        assert!(
            r.is_threat(),
            "Multi-tactic manipulation should be detected"
        );
        assert!(r.recommended_action.is_some());
    }

    #[test]
    fn integration_explicit_content_always_alerts_parent() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);

        let r = analyzer.analyze(&child_input(
            "send me nudes right now, take off your clothes",
            "creep",
            "conv_x",
        ));
        if r.is_threat() {
            if let Some(rec) = &r.recommended_action {
                assert!(
                    rec.parent_alert >= AlertPriority::Medium,
                    "Explicit content should alert parent: {:?}",
                    rec.parent_alert
                );
            }
        }
    }

    #[test]
    fn integration_context_preserves_across_export_import() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_persist";

        analyzer.analyze_with_context(
            &child_input("You're so beautiful and amazing!", "stranger", conv),
            1000,
        );

        let state = analyzer.export_context_state();
        assert!(
            state
                .timelines
                .iter()
                .any(|timeline| timeline.conversation_id == conv),
            "State should contain conversation"
        );

        let mut analyzer2 = Analyzer::new(child_config(), &db);
        analyzer2
            .import_context_state(state)
            .expect("import should work");

        let r = analyzer2.analyze_with_context(
            &child_input("Don't tell your parents about me", "stranger", conv),
            2000,
        );
        assert!(
            r.is_threat(),
            "Context should persist: grooming detected after import"
        );
    }

    #[test]
    fn integration_clean_conversation_no_false_positives() {
        let db = test_db();

        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let conv = "int_clean";
        let min = 60 * 1000u64;

        let messages = [
            ("friend_1", "Hey did you finish the homework?"),
            ("child", "Yeah it was hard! Want to play Minecraft?"),
            ("friend_1", "Sure! My mom said I can play until 7"),
            ("child", "Let's build a castle together!"),
            ("friend_1", "Cool see you in the game!"),
        ];

        for (i, (sender, text)) in messages.iter().enumerate() {
            let r = analyzer.analyze_with_context(&child_input(text, sender, conv), i as u64 * min);
            assert!(
                !r.is_threat(),
                "Normal message should not be a threat: '{text}' got {:?} ({:?})",
                r.action,
                r.threat_type
            );
        }
    }

    #[test]
    fn integration_sextortion_countdown_high_severity() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_sextort";
        let day = 24 * 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input("You're so beautiful, send me a photo", "predator", conv),
            0,
        );

        let r = analyzer.analyze_with_context(
            &child_input(
                "You have 24 hours or everyone sees your photos",
                "predator",
                conv,
            ),
            day,
        );

        assert!(r.is_threat(), "Sextortion should be detected");
        assert!(
            r.score >= 0.5,
            "Sextortion should have high score: {}",
            r.score
        );
    }

    #[test]
    fn integration_raid_detection_multiple_senders() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_raid";
        let min = 60 * 1000u64;
        let base = 14 * 3600 * 1000u64;

        for i in 1..=5 {
            let sender = format!("raider_{i}");
            let text = format!("You're worthless and pathetic, nobody likes you (attack #{i})");
            analyzer.analyze_with_context(&child_input(&text, &sender, conv), base + i * min);
        }

        let profiler = analyzer.context_tracker().contact_profiler();
        let contacts = profiler.contacts_by_risk();
        let hostile_count = contacts.iter().filter(|c| c.risk_score() > 0.0).count();
        assert!(
            hostile_count >= 3,
            "Raid should produce multiple hostile contacts: got {hostile_count}"
        );
    }

    #[test]
    fn integration_bullying_to_selfharm_pathway() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_b2sh";
        let hour = 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input("Nobody likes you, you're worthless", "bully_1", conv),
            0,
        );
        analyzer.analyze_with_context(
            &child_input("Everyone hates you, just leave", "bully_2", conv),
            hour,
        );

        let r = analyzer.analyze_with_context(
            &child_input(
                "Maybe they're right. I want to end it all. Nobody cares about me.",
                "victim",
                conv,
            ),
            2 * hour,
        );

        assert!(r.is_threat(), "Self-harm after bullying should be detected");
        assert_ne!(r.action, Action::Block, "Self-harm must not be blocked");
        assert!(r.needs_crisis_resources(), "Should show crisis resources");
    }

    #[test]
    fn integration_video_call_grooming_detected() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_video";
        let day = 24 * 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input(
                "You're so beautiful and special, I love talking to you",
                "creep",
                conv,
            ),
            0,
        );

        let r = analyzer.analyze_with_context(
            &child_input(
                "Let's video call just us, turn on your camera for me",
                "creep",
                conv,
            ),
            day,
        );

        assert!(r.is_threat(), "Video call grooming should be detected");
    }

    #[test]
    fn integration_darvo_pattern_across_messages() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_darvo";
        let day = 24 * 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input("You're the one who started this, not me", "abuser", conv),
            0,
        );
        analyzer.analyze_with_context(
            &child_input("I'm the victim here, you're hurting me", "abuser", conv),
            day,
        );
        let r = analyzer.analyze_with_context(
            &child_input(
                "You're the one who started this, stop playing victim",
                "abuser",
                conv,
            ),
            2 * day,
        );

        assert!(
            r.is_threat(),
            "DARVO pattern should be detected across messages"
        );
    }

    #[test]
    fn integration_financial_grooming_builds_context() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_finance";
        let day = 24 * 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input(
                "I want to send you money, I'll buy you anything",
                "sugar_daddy",
                conv,
            ),
            0,
        );

        let r = analyzer.analyze_with_context(
            &child_input(
                "Don't tell your parents about the gifts ok?",
                "sugar_daddy",
                conv,
            ),
            day,
        );

        assert!(
            r.is_threat(),
            "Financial grooming + secrecy should be detected"
        );
    }

    #[test]
    fn integration_recommended_action_serializes() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_serial";

        let r = analyzer.analyze_with_context(
            &child_input("Don't tell your parents about me ok?", "stranger", conv),
            1000,
        );

        let json = serde_json::to_string(&r).expect("should serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(value.get("recommended_action").is_some());
        assert!(value["recommended_action"].get("parent_alert").is_some());
        assert!(value.get("risk_breakdown").is_some());
        assert!(value.get("reason_codes").is_some());
        assert!(value.get("contact_snapshot").is_some());
        assert!(value.get("inference").is_some());
    }

    #[test]
    fn integration_context_result_includes_contact_snapshot_and_breakdown() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_snapshot";

        let r = analyzer.analyze_with_context(
            &child_input("Don't tell your parents about me ok?", "stranger", conv),
            1000,
        );

        let snapshot = r
            .contact_snapshot
            .expect("context analysis should attach snapshot");
        assert_eq!(snapshot.sender_id, "stranger");
        assert!(snapshot.is_new_contact);
        assert!(r.risk_breakdown.content > 0.0 || r.risk_breakdown.conversation > 0.0);
        assert!(
            !r.reason_codes.is_empty(),
            "reason codes should be populated"
        );
    }

    #[test]
    fn clean_result_has_default_inference_summary() {
        let result = AnalysisResult::clean(42);
        assert_eq!(result.inference.uncertainty, UncertaintyLevel::Medium);
        assert_eq!(result.inference.risk_horizon, RiskHorizon::Unknown);
        assert_eq!(result.inference.escalation_likelihood_24h, 0.0);
        assert!(result.inference.latent_states.is_empty());
    }

    #[test]
    fn selfharm_inference_sets_immediate_horizon_and_crisis_state() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_sh_inference";

        analyzer.analyze_with_context(
            &child_input(
                "I don't want to live anymore. I want to end it all.",
                "child",
                conv,
            ),
            1000,
        );
        let r = analyzer.analyze_with_context(
            &child_input("Goodbye everyone. This is the end.", "child", conv),
            2000,
        );

        assert_eq!(r.inference.risk_horizon, RiskHorizon::Immediate);
        assert!(
            r.inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::CrisisVulnerability),
            "self-harm flow should surface crisis latent state"
        );
        assert!(
            r.inference.escalation_likelihood_24h >= 0.7,
            "acute self-harm should imply high short-horizon escalation likelihood"
        );
    }

    #[test]
    fn grooming_inference_surfaces_dependency_and_isolation_states() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_groom_inference";
        let hour = 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input(
                "You're so special and beautiful. I can buy you anything.",
                "stranger",
                conv,
            ),
            0,
        );
        let r = analyzer.analyze_with_context(
            &child_input(
                "Don't tell your parents about us. Let's move to Telegram.",
                "stranger",
                conv,
            ),
            hour,
        );

        assert!(
            r.inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::DependencyBuilding),
            "grooming flow should surface dependency-building"
        );
        assert!(
            r.inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::IsolationPressure),
            "grooming flow should surface isolation pressure"
        );
        assert_eq!(r.inference.risk_horizon, RiskHorizon::ShortTerm);
    }

    #[test]
    fn blocked_url_sets_link_risk_and_reason_codes() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let r = analyzer.analyze(&default_input("check this out https://evil-site.com/login"));

        assert!(
            r.risk_breakdown.link > 0.0,
            "blocked url should raise link risk"
        );
        assert!(
            r.reason_codes
                .iter()
                .any(|code| code == "link.blocked_domain"),
            "blocked url should include link reason code"
        );
        assert!(
            r.signals
                .iter()
                .any(|signal| signal.family == SignalFamily::Link),
            "blocked url signal should be classified as link family"
        );
    }

    #[test]
    fn suspicious_url_heuristic_sets_link_risk_and_reason_codes() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let r = analyzer.analyze(&default_input(
            "grab this now http://fr33-r0bux.xyz/claim before it expires",
        ));

        assert!(
            r.risk_breakdown.link > 0.0,
            "suspicious url heuristic should raise link risk"
        );
        assert!(
            r.reason_codes
                .iter()
                .any(|code| code == "link.suspicious_url_heuristic"),
            "heuristic suspicious url should include link reason code"
        );
        assert!(
            r.signals.iter().any(|signal| {
                signal.family == SignalFamily::Link
                    && signal.reason_code == "link.suspicious_url_heuristic"
            }),
            "heuristic suspicious url should be classified as link family"
        );
    }

    #[test]
    fn recommendation_carries_ui_actions_and_reason_codes() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_ui_actions";

        let r = analyzer.analyze_with_context(
            &child_input("Don't tell your parents about me ok?", "stranger", conv),
            1000,
        );

        let rec = r
            .recommended_action
            .expect("recommendation should be present");
        assert!(
            !rec.ui_actions.is_empty(),
            "recommendation should expose messenger ui actions"
        );
        assert_eq!(rec.reason_codes, r.reason_codes);
    }

    #[test]
    fn coercive_control_inference_escalates_policy_actions() {
        let db = PatternDatabase::default_mvp();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let conv = "int_coercive_control";
        let hour = 3_600_000u64;

        analyzer.analyze_with_context(
            &child_input(
                "After everything I did for u, u owe me honesty.",
                "dating_abuser",
                conv,
            ),
            0,
        );
        analyzer.analyze_with_context(
            &child_input(
                "You're so ungrateful. I sacrificed so much for you.",
                "dating_abuser",
                conv,
            ),
            hour,
        );
        analyzer.analyze_with_context(
            &child_input(
                "I'll show this to everyone at school if you don't listen.",
                "dating_abuser",
                conv,
            ),
            2 * hour,
        );
        let result = analyzer.analyze_with_context(
            &child_input(
                "After everything i've done for you, this is how you repay me.",
                "dating_abuser",
                conv,
            ),
            3 * hour,
        );

        let recommendation = result
            .recommended_action
            .expect("recommendation should be present");

        assert!(
            recommendation.ui_actions.contains(&UiAction::SuggestReport),
            "coercive-control escalation should trigger report guidance"
        );
        assert!(
            recommendation
                .ui_actions
                .contains(&UiAction::SlowDownConversation),
            "coercive-control escalation should slow the conversation"
        );
        assert!(
            result
                .inference
                .latent_states
                .iter()
                .any(|state| state.kind == LatentStateKind::CoerciveControl),
            "coercive-control latent state should be present"
        );
    }

    #[test]
    fn integration_contact_profiler_tracks_risk() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let hour = 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input("Hey want to play after school?", "safe_kid", "conv_s"),
            0,
        );

        analyzer.analyze_with_context(
            &child_input("You're so beautiful and amazing!", "bad_actor", "conv_b"),
            hour,
        );
        analyzer.analyze_with_context(
            &child_input("Don't tell your parents about me", "bad_actor", "conv_b"),
            2 * hour,
        );

        let profiler = analyzer.context_tracker().contact_profiler();
        let contacts = profiler.contacts_by_risk();

        assert!(contacts.len() >= 2, "Should have at least 2 contacts");

        let bad_risk = profiler
            .profile("bad_actor")
            .map(|p| p.risk_score())
            .unwrap_or(0.0);
        let safe_risk = profiler
            .profile("safe_kid")
            .map(|p| p.risk_score())
            .unwrap_or(0.0);
        assert!(
            bad_risk > safe_risk,
            "bad_actor ({bad_risk}) should have higher risk than safe_kid ({safe_risk})"
        );
    }

    #[test]
    fn empty_text_returns_clean_result() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input(""));
        assert!(!result.is_threat());
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn none_text_returns_clean_result() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let input = MessageInput {
            content_type: ContentType::Text,
            text: None,
            image_data: None,
            sender_id: "u".into(),
            conversation_id: "c".into(),
            language: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
        };
        let result = analyzer.analyze(&input);
        assert!(!result.is_threat());
    }

    #[test]
    fn very_long_message_does_not_panic() {
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let long = "word ".repeat(10_000);
        let result = analyzer.analyze(&default_input(&long));
        assert!(result.analysis_time_us > 0);
    }

    #[test]
    fn text_truncation_limits_processing() {
        let filler = "a".repeat(10_001);
        let text = format!("{filler} kill you");
        let db = test_db();
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input(&text));
        assert!(
            !result.is_threat(),
            "Threat word beyond truncation should not be detected"
        );
    }

    #[test]
    fn truncate_text_char_boundary() {
        let text = "a".repeat(9_999) + "ї";
        let truncated = super::truncate_text(&text);
        assert!(truncated.len() <= super::MAX_TEXT_LENGTH);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn config_validation_rejects_bad_ttl() {
        let config = AuraConfig {
            ttl_days: 0,
            ..AuraConfig::default()
        };
        assert!(config.validate().is_err());

        let config = AuraConfig {
            ttl_days: 366,
            ..AuraConfig::default()
        };
        assert!(config.validate().is_err());

        let config = AuraConfig {
            ttl_days: 30,
            ..AuraConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validation_rejects_bad_age() {
        let config = AuraConfig {
            account_holder_age: Some(3),
            ..AuraConfig::default()
        };
        assert!(config.validate().is_err());

        let config = AuraConfig {
            account_holder_age: Some(121),
            ..AuraConfig::default()
        };
        assert!(config.validate().is_err());

        let config = AuraConfig {
            account_holder_age: Some(12),
            ..AuraConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn integration_pii_warns_not_blocks() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(10),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some("my number is 0501234567, text me!".into()),
            image_data: None,
            sender_id: "child_1".into(),
            conversation_id: "conv_pii".into(),
            language: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
        };

        let result = analyzer.analyze_with_context(&input, 1000);
        assert_ne!(result.action, Action::Block, "PII leakage must NEVER block");
    }

    #[test]
    fn integration_repeated_secrecy_escalates() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(10),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        for i in 0..4 {
            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some("don't tell your parents about this".into()),
                image_data: None,
                sender_id: "stranger_1".into(),
                conversation_id: "conv_secrecy".into(),
                language: Some("en".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            };
            analyzer.analyze_with_context(&input, (i + 1) * 1000);
        }

        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some("just between us, ok?".into()),
            image_data: None,
            sender_id: "stranger_1".into(),
            conversation_id: "conv_secrecy".into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
        };
        let result = analyzer.analyze_with_context(&input, 5000);
        assert!(
            result.score >= 0.5,
            "Repeated secrecy should escalate score, got {}",
            result.score
        );
    }

    #[test]
    fn integration_casual_meeting_from_stranger_with_context() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(10),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let msgs = vec![
            ("you're so mature for your age", 1000u64),
            ("don't tell your parents about our chats", 2000),
            ("how old are you? what grade are you in?", 3000),
        ];
        for (text, ts) in msgs {
            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some(text.into()),
                image_data: None,
                sender_id: "predator".into(),
                conversation_id: "conv_meet".into(),
                language: Some("en".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            };
            analyzer.analyze_with_context(&input, ts);
        }

        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some("you're so beautiful and special, can we meet?".into()),
            image_data: None,
            sender_id: "predator".into(),
            conversation_id: "conv_meet".into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
        };
        let result = analyzer.analyze_with_context(&input, 4000);
        assert!(
            result.score >= 0.5,
            "Casual meeting + grooming context should elevate score, got {}",
            result.score
        );
    }

    #[test]
    fn integration_screenshot_blackmail_accumulates() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let texts = [
            "I took a screenshot of everything you said",
            "I have screenshots and everyone will see this",
        ];
        let mut last_result = None;
        for (i, text) in texts.iter().enumerate() {
            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).into()),
                image_data: None,
                sender_id: "bully".into(),
                conversation_id: "conv_ss".into(),
                language: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
            };
            last_result = Some(analyzer.analyze_with_context(&input, (i as u64 + 1) * 1000));
        }
        let result = last_result.unwrap();
        assert!(
            result.score > 0.0,
            "Repeated screenshot threats should produce a manipulation signal"
        );
    }

    #[test]
    fn integration_dare_with_gaslighting() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(11),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let msgs = vec![
            ("you're imagining things, that never happened", 1000u64),
            ("after everything i've done for you, you owe me", 2000),
            (
                "I dare you to do it, bet you can't! you're too scared",
                3000,
            ),
        ];
        let mut last_result = None;
        for (text, ts) in msgs {
            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some(text.into()),
                image_data: None,
                sender_id: "manipulator".into(),
                conversation_id: "conv_dare".into(),
                language: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
            };
            last_result = Some(analyzer.analyze_with_context(&input, ts));
        }
        let result = last_result.unwrap();
        assert!(
            result.score > 0.0,
            "Dare + gaslighting + guilt should produce manipulation signals, got score {}",
            result.score
        );
    }

    #[test]
    fn gaslighting_cycle_stays_manipulation_primary() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let texts = [
            "Ти собі це вигадала, я нічого такого не казав",
            "Ти завжди все перекручуєш, може ти ненормальна",
            "Ти божевільна якщо так це бачиш, я це для твого ж блага",
            "Без мене ти нічого не варта, тобі ніхто крім мене не допоможе",
        ];
        let base_ts = 12 * 60 * 60 * 1000_u64;

        let mut last_result = None;
        for (idx, text) in texts.iter().enumerate() {
            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: "gaslighter".into(),
                conversation_id: "gaslight_cycle".into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            };
            last_result =
                Some(analyzer.analyze_with_context(&input, base_ts + (idx as u64 + 1) * 60_000));
        }

        let result = last_result.expect("final gaslighting result");
        assert_eq!(
            result.threat_type,
            ThreatType::Manipulation,
            "gaslighting cycle should stay manipulation-primary: {result:?}"
        );
        assert!(
            crate::predicted_score_for_threat(&result, ThreatType::Manipulation) >= 0.5,
            "gaslighting cycle should accumulate meaningful manipulation risk: {result:?}"
        );
        assert!(
            crate::predicted_score_for_threat(&result, ThreatType::Grooming) <= 0.4,
            "gaslighting cycle should not accumulate elevated grooming risk: {result:?}"
        );
    }

    #[test]
    fn control_pattern_without_grooming_anchor_does_not_primary_label_as_grooming() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let texts = [
            "Після всього що я для тебе зробив ти мені винна",
            "Твої друзі такі дитячі, тільки я тебе реально розумію",
            "Вони з тебе сміються за спиною, ти можеш довіряти тільки мені",
        ];
        let base_ts = 12 * 60 * 60 * 1000_u64;

        let mut last_result = None;
        for (idx, text) in texts.iter().enumerate() {
            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some((*text).to_string()),
                image_data: None,
                sender_id: "controller".into(),
                conversation_id: "control_cycle".into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            };
            last_result =
                Some(analyzer.analyze_with_context(&input, base_ts + (idx as u64 + 1) * 60_000));
        }

        let result = last_result.expect("final manipulation result");
        assert_ne!(
            result.threat_type,
            ThreatType::Grooming,
            "manipulation-only control pattern should not primary-label as grooming: {result:?}"
        );
    }

    #[test]
    fn integration_suicide_coercion_pattern() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(13),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("if u block me ill end it, i cant live without u".to_string()),
                image_data: None,
                sender_id: "manipulator".into(),
                conversation_id: "conv_sc".into(),
                language: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1000,
        );
        assert!(
            result.score > 0.0,
            "Suicide coercion should produce a detection signal, got score {}",
            result.score
        );
    }

    #[test]
    fn integration_teen_slang_platform_switch() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(14),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("го в тг тут палево".to_string()),
                image_data: None,
                sender_id: "stranger".into(),
                conversation_id: "conv_ps".into(),
                language: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1000,
        );
        assert!(
            result.score > 0.0,
            "Teen slang platform switch should be detected, got score {}",
            result.score
        );
    }

    #[test]
    fn integration_noisy_platform_switch_and_probing_shorthand() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(13),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "conv_noisy_slang";
        let sender = "stranger";

        analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("wh4t schoooool u go to? where u live??".to_string()),
                image_data: None,
                sender_id: sender.into(),
                conversation_id: conv.into(),
                language: Some("en".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1000,
        );

        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("msg me on in$ta rn, delete this ch4t".to_string()),
                image_data: None,
                sender_id: sender.into(),
                conversation_id: conv.into(),
                language: Some("en".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            2000,
        );

        assert!(
            result.score > 0.0,
            "Noisy shorthand probing/platform-switch should still produce risk, got {}",
            result.score
        );

        let timeline = analyzer.context_tracker().timeline(conv).unwrap();
        assert!(
            timeline
                .all_events()
                .iter()
                .any(|e| e.kind == EventKind::PersonalInfoRequest),
            "Noisy shorthand should still surface PersonalInfoRequest"
        );
        assert!(
            timeline
                .all_events()
                .iter()
                .any(|e| e.kind == EventKind::PlatformSwitch),
            "Noisy shorthand should still surface PlatformSwitch"
        );
    }

    #[test]
    fn integration_network_poisoning() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some(
                    "they dont really like u, they laugh at u behind ur back, ur friend is fake"
                        .to_string(),
                ),
                image_data: None,
                sender_id: "manipulator".into(),
                conversation_id: "conv_np".into(),
                language: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1000,
        );
        assert!(
            result.score > 0.0,
            "Network poisoning should produce a detection signal, got score {}",
            result.score
        );
    }

    #[test]
    fn integration_gaming_bribery() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(11),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("ill get u vbucks if u do what i say, want free skins?".to_string()),
                image_data: None,
                sender_id: "stranger".into(),
                conversation_id: "conv_gb".into(),
                language: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1000,
        );
        assert!(
            result.score > 0.0,
            "Gaming bribery should be detected as grooming, got score {}",
            result.score
        );
    }

    #[test]
    fn integration_combined_advanced_scenario() {
        let db = test_db();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some(
                    "ur not like other kids, ur friends are so childish. they dont really like u, they laugh at u behind ur back. ill tell everyone at school".to_string(),
                ),
                image_data: None,
                sender_id: "predator".into(),
                conversation_id: "conv_adv".into(),
                language: None,
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1000,
        );
        assert!(
            result.score > 0.0,
            "Combined advanced scenario should produce detection, got score {}",
            result.score
        );
        assert!(
            !result.detected_threats.is_empty(),
            "Should detect multiple threat types, got: {:?}",
            result.detected_threats
        );
    }

    #[test]
    fn mild_ukrainian_euphemism_does_not_trigger_explicit() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("блін тре вчити".to_string()),
                image_data: None,
                sender_id: "maria".into(),
                conversation_id: "class_chat".into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::GroupChat,
                member_count: Some(25),
            },
            1_000,
        );

        assert_eq!(
            result.threat_type,
            ThreatType::None,
            "mild euphemism should not escalate into explicit risk: {result:?}"
        );
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn friendly_joke_sequence_stays_clean() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "dm_jokes";

        let first = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("ти така дурна хахаха 😂😂 жартую".to_string()),
                image_data: None,
                sender_id: "bestie".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1_000,
        );
        assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

        let second = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("сама така бро! 😜".to_string()),
                image_data: None,
                sender_id: "olena".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            2_000,
        );
        assert_eq!(second.threat_type, ThreatType::None, "{second:?}");

        let third = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("я тебе вб'ю за бутерброд шо ти зїла!! 😂😂".to_string()),
                image_data: None,
                sender_id: "bestie".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            3_000,
        );
        assert_eq!(third.threat_type, ThreatType::None, "{third:?}");
        assert_eq!(third.action, Action::Allow);
    }

    #[test]
    fn reciprocal_peer_compliments_do_not_trigger_grooming() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "dm_compliment";

        let first = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("олен ти така гарна сьогодні!".to_string()),
                image_data: None,
                sender_id: "classmate_f".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1_000,
        );
        assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

        let second = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("спс! ти тож красіва!".to_string()),
                image_data: None,
                sender_id: "olena".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            2_000,
        );
        assert_eq!(second.threat_type, ThreatType::None, "{second:?}");
    }

    #[test]
    fn meme_media_share_sequence_stays_clean() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "dm_memes_test";

        let first = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("олен ти бачіла цей тікток я ЗДОХЛА 😂💀".to_string()),
                image_data: None,
                sender_id: "maria".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1_000,
        );
        assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

        let second = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("який скинь!!".to_string()),
                image_data: None,
                sender_id: "olena".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            2_000,
        );
        assert_eq!(second.threat_type, ThreatType::None, "{second:?}");

        let third = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("тільки не показуй нікому це кринж 😂".to_string()),
                image_data: None,
                sender_id: "maria".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            3_000,
        );
        assert_eq!(third.threat_type, ThreatType::None, "{third:?}");
    }

    #[test]
    fn toxic_friend_suicide_coercion_stays_manipulation_primary() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "dm_toxic_friend";
        let mut last = None;
        for (idx, text) in [
            "якщо ти мене кинеш я нікому не потрібна буду",
            "мені через тебе так погано шо я себе пораню",
            "якщо ти нормальна подруга то перестанеш з нею спілкуватись",
            "якщо виберешь її я зроблю з собою щось бл",
        ]
        .iter()
        .enumerate()
        {
            last = Some(analyzer.analyze_with_context(
                &MessageInput {
                    content_type: ContentType::Text,
                    text: Some((*text).to_string()),
                    image_data: None,
                    sender_id: "toxic_bff".into(),
                    conversation_id: conv.into(),
                    language: Some("uk".to_string()),
                    conversation_type: ConversationType::Direct,
                    member_count: None,
                },
                (idx as u64 + 1) * 1_000,
            ));
        }

        let result = last.expect("result");
        assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
        assert!(
            result
                .detected_threats
                .iter()
                .any(|(tt, _)| *tt == ThreatType::Manipulation),
            "{result:?}"
        );
    }

    #[test]
    fn peer_pressure_roof_challenge_detected_as_manipulation() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "peer_pressure_test";
        let mut last = None;
        for (idx, (sender, text)) in [
            ("peer1", "го зробимо челендж з даху!!"),
            ("peer2", "гооо хто перший той легенда"),
            ("peer3", "не бійся там не високо тіпа"),
            ("peer2", "всі нормальні люди робили, ти шо не нормальна?"),
            ("peer1", "якщо зассиш ми тебе більше не кличемо нікуди"),
        ]
        .iter()
        .enumerate()
        {
            last = Some(analyzer.analyze_with_context(
                &MessageInput {
                    content_type: ContentType::Text,
                    text: Some((*text).to_string()),
                    image_data: None,
                    sender_id: (*sender).into(),
                    conversation_id: conv.into(),
                    language: Some("uk".to_string()),
                    conversation_type: ConversationType::GroupChat,
                    member_count: Some(6),
                },
                (idx as u64 + 1) * 1_000,
            ));
        }

        let result = last.expect("result");
        assert_eq!(result.threat_type, ThreatType::Manipulation, "{result:?}");
        assert!(result.score >= 0.45, "{result:?}");
    }

    #[test]
    fn cyberbullying_social_humiliation_sequence_is_detected() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "cyber_chat_test";
        let mut last = None;
        for (idx, (sender, text)) in [
            ("cyberbully1", "ви бачіли шо олена запостила в інсту?? 😂😂"),
            ("cyberbully2", "АААХАХАХ яка вона потворна на тій фотці 🤮"),
            ("cyberbully1", "го всі репортнем її акаунт 😂"),
            ("cyberbully3", "я вже написала їй в коменти 'кринж' 💀"),
            ("cyberbully2", "треба зробити мем з її фоткою 😂😂"),
            ("cyberbully1", "вже зробив дивіться 💀💀💀"),
            ("cyberbully3", "АХАХАХ скинь всім в клас"),
            ("cyberbully2", "олена побачить і буде ревіти 😂"),
            ("cyberbully1", "їй тре видалити інсту і тікток вона там жах"),
            ("cyberbully3", "нехай здохне від соромь 💀"),
        ]
        .iter()
        .enumerate()
        {
            last = Some(analyzer.analyze_with_context(
                &MessageInput {
                    content_type: ContentType::Text,
                    text: Some((*text).to_string()),
                    image_data: None,
                    sender_id: (*sender).into(),
                    conversation_id: conv.into(),
                    language: Some("uk".to_string()),
                    conversation_type: ConversationType::GroupChat,
                    member_count: Some(10),
                },
                (idx as u64 + 1) * 1_000,
            ));
        }

        let result = last.expect("result");
        assert_eq!(result.threat_type, ThreatType::Bullying, "{result:?}");
        assert!(result.score >= 0.60, "{result:?}");
        assert!(
            result
                .detected_threats
                .iter()
                .any(|(tt, score)| *tt == ThreatType::Bullying && *score >= 0.60),
            "{result:?}"
        );
    }

    #[test]
    fn gaming_rage_sequence_stays_clean() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "game_rage_test";
        let mut last = None;
        for (idx, (sender, text)) in [
            ("artem", "ГО КАТКУ ХТОО?? 🎮"),
            ("petro", "гооо я вже в лобі"),
            ("olena", "я тож зайду зараз"),
            ("artem", "ПЕТРО ТИ ШО РОБИШ ТАМ ТИ ТУПИЙ 😤"),
        ]
        .iter()
        .enumerate()
        {
            last = Some(analyzer.analyze_with_context(
                &MessageInput {
                    content_type: ContentType::Text,
                    text: Some((*text).to_string()),
                    image_data: None,
                    sender_id: (*sender).into(),
                    conversation_id: conv.into(),
                    language: Some("uk".to_string()),
                    conversation_type: ConversationType::GroupChat,
                    member_count: Some(6),
                },
                (idx as u64 + 1) * 1_000,
            ));
        }

        let result = last.expect("result");
        assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
    }

    #[test]
    fn short_media_curiosity_sequence_stays_clean() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "dm_memes_short_test";

        let first = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("зараз шукаю... а ти бачіла шо арт запостив?".to_string()),
                image_data: None,
                sender_id: "maria".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1_000,
        );
        assert_eq!(first.threat_type, ThreatType::None, "{first:?}");

        let second = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("ні шо там?".to_string()),
                image_data: None,
                sender_id: "olena".into(),
                conversation_id: conv.into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            2_000,
        );
        assert_eq!(second.threat_type, ThreatType::None, "{second:?}");
    }

    #[test]
    fn group_selfie_sequence_stays_clean() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        let conv = "group_selfie_test";
        let mut last = None;
        for (idx, (sender, text)) in [
            ("nastya", "зробіть мені фотку для інсти пж 📸😂"),
            ("artem", "настя і її інста 😂😂"),
            ("dasha", "го ще селфі разом!!"),
            ("olena", "гоооо!! групове селфі 🤳💕"),
        ]
        .iter()
        .enumerate()
        {
            last = Some(analyzer.analyze_with_context(
                &MessageInput {
                    content_type: ContentType::Text,
                    text: Some((*text).to_string()),
                    image_data: None,
                    sender_id: (*sender).into(),
                    conversation_id: conv.into(),
                    language: Some("uk".to_string()),
                    conversation_type: ConversationType::GroupChat,
                    member_count: Some(10),
                },
                (idx as u64 + 1) * 1_000,
            ));
        }

        let result = last.expect("result");
        assert_eq!(result.threat_type, ThreatType::None, "{result:?}");
    }

    #[test]
    fn obfuscated_hate_speech_is_detected() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("всі ціган1 — злодії бл".to_string()),
                image_data: None,
                sender_id: "hater1".into(),
                conversation_id: "hate_chat".into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::GroupChat,
                member_count: Some(20),
            },
            1_000,
        );

        assert!(
            result
                .detected_threats
                .iter()
                .any(|(tt, _)| *tt == ThreatType::HateSpeech),
            "obfuscated hate speech should surface hate_speech detection: {result:?}"
        );
    }

    #[test]
    fn direct_location_threat_stays_threat_primary() {
        let db = PatternDatabase::default_mvp();
        let config = AuraConfig {
            account_type: AccountType::Child,
            account_holder_age: Some(12),
            language: "uk".to_string(),
            protection_level: ProtectionLevel::High,
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);

        let result = analyzer.analyze_with_context(
            &MessageInput {
                content_type: ContentType::Text,
                text: Some("я знаю де ти живеш".to_string()),
                image_data: None,
                sender_id: "threat2".into(),
                conversation_id: "dm_threat2".into(),
                language: Some("uk".to_string()),
                conversation_type: ConversationType::Direct,
                member_count: None,
            },
            1_000,
        );

        assert_eq!(result.threat_type, ThreatType::Threat, "{result:?}");
        assert!(
            result.score >= 0.8,
            "direct location threat should keep high threat score: {result:?}"
        );
    }

    #[test]
    fn integration_contact_rating_drops_on_hostile_messages() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let bully = "mean_kid";
        let conv = "school_chat";

        analyzer.analyze_with_context(&child_input("hey what's up", bully, conv), 1000);
        let rating_before = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(bully)
            .unwrap()
            .rating;

        for i in 1..=5 {
            analyzer.analyze_with_context(
                &child_input("you're so stupid and ugly, everyone hates you", bully, conv),
                i * 2000,
            );
        }

        let rating_after = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(bully)
            .unwrap()
            .rating;

        assert!(
            rating_after < rating_before,
            "Rating should drop after hostile messages: {rating_before} -> {rating_after}"
        );
    }

    #[test]
    fn integration_trust_decays_for_hostile_trusted_contact() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let friend = "best_friend";
        let conv = "private_chat";

        analyzer.analyze_with_context(&child_input("hey bestie!", friend, conv), 1000);
        analyzer.mark_contact_trusted(friend);
        let trust_before = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(friend)
            .unwrap()
            .trust_level;
        assert_eq!(trust_before, 1.0);

        let hostile_msgs = [
            "i'll kill you stupid idiot",
            "you're a worthless piece of trash",
            "shut up or i'll beat you up",
            "everyone hates you, die loser",
            "i'll destroy your life you freak",
            "you're disgusting, kill yourself",
            "i hate you so much, ugly trash",
            "i'll make your life hell",
        ];
        for (i, msg) in hostile_msgs.iter().enumerate() {
            analyzer.analyze_with_context(&child_input(msg, friend, conv), (i as u64 + 2) * 2000);
        }

        let profile = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(friend)
            .unwrap();

        assert!(
            profile.trust_level < trust_before,
            "Trust should decay after sustained hostility: {} (was {})",
            profile.trust_level,
            trust_before
        );
    }

    #[test]
    fn integration_behavioral_shift_in_full_pipeline() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let contact = "masha";
        let conv = "class_chat";
        let week = 7 * 24 * 3600 * 1000u64;

        for w in 0..3 {
            for msg in 0..10 {
                analyzer.analyze_with_context(
                    &child_input(
                        "hey how was your day? good luck on the test!",
                        contact,
                        conv,
                    ),
                    w * week + msg * 60_000,
                );
            }
        }

        let hostile_texts = [
            "you're stupid and ugly, everyone hates you",
            "i'll kill you, you worthless trash",
            "shut up idiot, nobody asked you",
            "die loser, you're pathetic",
        ];
        for w in 3..5 {
            for msg in 0..10 {
                let text = hostile_texts[msg as usize % hostile_texts.len()];
                analyzer.analyze_with_context(
                    &child_input(text, contact, conv),
                    w * week + msg * 60_000,
                );
            }
        }

        let result = analyzer.analyze_with_context(
            &child_input("i'll kill you loser, nobody likes you", contact, conv),
            5 * week + 1000,
        );

        let profile = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(contact)
            .unwrap();

        assert!(
            profile.rating < 40.0,
            "Rating should drop after weeks of hostility: {}",
            profile.rating
        );

        assert!(result.score > 0.0, "Hostile message should be detected");
    }

    #[test]
    fn integration_normal_conversation_preserves_high_rating() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let friend = "good_friend";
        let conv = "daily_chat";

        for i in 0..20 {
            analyzer.analyze_with_context(
                &child_input("hey, how's school? want to study together?", friend, conv),
                i * 3_600_000,
            );
        }

        let profile = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(friend)
            .unwrap();

        assert!(
            profile.rating > 50.0,
            "Normal conversation should keep rating above 50: {}",
            profile.rating
        );
    }

    #[test]
    fn integration_groomer_rating_tracks_accurately() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let predator = "cool_guy";
        let conv = "dm_1";
        let hour = 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input(
                "you're so beautiful and amazing and perfect, you're the most incredible person",
                predator,
                conv,
            ),
            0,
        );
        analyzer.analyze_with_context(
            &child_input(
                "where do you go to school? how old are you?",
                predator,
                conv,
            ),
            hour,
        );
        analyzer.analyze_with_context(
            &child_input(
                "don't tell your parents about me ok? this is our secret",
                predator,
                conv,
            ),
            2 * hour,
        );
        analyzer.analyze_with_context(
            &child_input(
                "send me a photo, let's meet up just the two of us",
                predator,
                conv,
            ),
            3 * hour,
        );

        let profile = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(predator)
            .unwrap();

        assert!(
            profile.grooming_event_count >= 1,
            "Should track at least 1 grooming event: {}",
            profile.grooming_event_count
        );
    }

    #[test]
    fn integration_context_export_preserves_rating() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let bully = "mean_kid";
        let conv = "chat_1";

        for i in 0..5 {
            analyzer.analyze_with_context(
                &child_input("you're stupid and nobody likes you", bully, conv),
                i * 2000,
            );
        }

        let orig_rating = analyzer
            .context_tracker()
            .contact_profiler()
            .profile(bully)
            .unwrap()
            .rating;

        let state = analyzer.export_context_state();
        let mut analyzer2 = Analyzer::new(child_config(), &db);
        analyzer2.import_context_state(state).unwrap();

        let imported_rating = analyzer2
            .context_tracker()
            .contact_profiler()
            .profile(bully)
            .unwrap()
            .rating;

        assert_eq!(
            orig_rating, imported_rating,
            "Rating should survive export/import"
        );
    }

    #[test]
    fn integration_multi_contact_independent_ratings() {
        let db = PatternDatabase::default_mvp();
        let mut analyzer = Analyzer::new(child_config(), &db);

        for i in 0..5 {
            analyzer.analyze_with_context(
                &child_input(
                    "hey how are you? want to hang out?",
                    "good_friend",
                    "conv_1",
                ),
                i * 2000,
            );
        }

        for i in 0..5 {
            analyzer.analyze_with_context(
                &child_input("you're pathetic, kill yourself loser", "bully", "conv_2"),
                i * 2000,
            );
        }

        let good_rating = analyzer
            .context_tracker()
            .contact_profiler()
            .profile("good_friend")
            .unwrap()
            .rating;

        let bully_rating = analyzer
            .context_tracker()
            .contact_profiler()
            .profile("bully")
            .unwrap()
            .rating;

        assert!(
            good_rating > bully_rating,
            "Good friend should have higher rating ({good_rating}) than bully ({bully_rating})"
        );
    }

    #[test]
    fn integration_coercion_after_grooming() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let predator = "manipulator";
        let conv = "dm_private";
        let hour = 3600 * 1000u64;

        analyzer.analyze_with_context(
            &child_input(
                "you're so beautiful and amazing and perfect, truly special",
                predator,
                conv,
            ),
            0,
        );
        analyzer.analyze_with_context(
            &child_input("don't tell your parents about this", predator, conv),
            hour,
        );

        analyzer.analyze_with_context(
            &child_input(
                "if you leave me I'll hurt myself, I'll kill myself",
                predator,
                conv,
            ),
            2 * hour,
        );
        let result = analyzer.analyze_with_context(
            &child_input(
                "I screenshotted everything, I'll tell everyone your secrets",
                predator,
                conv,
            ),
            3 * hour,
        );

        assert!(
            result.score > 0.0,
            "Coercion after grooming should be detected: {}",
            result.score
        );
    }

    #[test]
    fn integration_identity_erosion_pipeline() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);
        let manip = "toxic_friend";
        let conv = "chat_1";

        analyzer.analyze_with_context(
            &child_input(
                "you're nothing without me, nobody else wants you around",
                manip,
                conv,
            ),
            1000,
        );
        analyzer.analyze_with_context(
            &child_input(
                "your friends don't really care about you, they use you",
                manip,
                conv,
            ),
            2000,
        );
        let result = analyzer.analyze_with_context(
            &child_input(
                "only I understand you, everyone else thinks you're a loser",
                manip,
                conv,
            ),
            3000,
        );

        assert!(
            result.score > 0.0,
            "Identity erosion + network poisoning should be detected: {}",
            result.score
        );
    }

    #[test]
    fn integration_false_positive_friendly_conversation() {
        let db = test_db();
        let mut analyzer = Analyzer::new(child_config(), &db);

        let messages = [
            "omg you're literally the best person ever haha",
            "let's hang out after school tomorrow at the mall",
            "don't tell anyone but I have a crush on someone lol",
            "you look so pretty in that photo!",
            "hey can I have your number? easier to text",
        ];

        let mut max_score = 0.0f32;
        for (i, msg) in messages.iter().enumerate() {
            let result = analyzer.analyze_with_context(
                &child_input(msg, "bestie", "group_chat"),
                (i as u64) * 60_000,
            );
            max_score = max_score.max(result.score);
        }

        let profile = analyzer
            .context_tracker()
            .contact_profiler()
            .profile("bestie")
            .unwrap();
        assert!(
            profile.rating > 40.0,
            "Friendly conversation should not tank rating: {}",
            profile.rating
        );
    }

    #[test]
    fn integration_message_language_overrides_default_pattern_language() {
        let db = PatternDatabase::default_mvp();
        let mut analyzer = Analyzer::new(child_config(), &db);

        let result = analyzer.analyze_with_context(
            &child_input("you're pathetic, kill yourself loser", "bully", "conv_en"),
            0,
        );

        assert!(
            result.detected_threats.iter().any(|(threat, score)| {
                (match threat {
                    ThreatType::Bullying | ThreatType::Threat => true,
                    ThreatType::None
                    | ThreatType::Grooming
                    | ThreatType::Explicit
                    | ThreatType::SelfHarm
                    | ThreatType::Spam
                    | ThreatType::Scam
                    | ThreatType::Phishing
                    | ThreatType::Manipulation
                    | ThreatType::Nsfw
                    | ThreatType::HateSpeech
                    | ThreatType::Doxxing
                    | ThreatType::PiiLeakage
                    | ThreatType::Propaganda
                    | ThreatType::OpsecViolation
                    | ThreatType::Psyops
                    | ThreatType::MilitarySocialEng
                    | ThreatType::CoordinateLeak => false,
                }) && *score >= 0.7
            }),
            "English hostile message should be detected even when config language differs: {:?}",
            result.detected_threats
        );

        let bully_rating = analyzer
            .context_tracker()
            .contact_profiler()
            .profile("bully")
            .expect("bully profile")
            .rating;
        assert!(
            bully_rating < 50.0,
            "Hostile contact should lose trust, got rating {bully_rating}"
        );
    }
}
