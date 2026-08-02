use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use aura_domain::MlSafetyHint;
use aura_ml::{
    IntentLabel, MlConfig, MlPipeline, MlRuntimeBackend, MlUncertaintyLevel, SafetyLabel,
    ToxicityLabel,
};
use aura_patterns::{PatternDatabase, PatternMatcher, TextNormalizer, UrlChecker};
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::action::{
    augment_recommendation_for_inference, augment_recommendation_for_reason_codes,
};
use crate::config::AuraConfig;
use crate::context::enricher::{EnricherConfig, SignalEnricher};
use crate::context::events::EventKind;
use crate::context::interpretation::ContextInterpreter;
use crate::context::observation::RawObservation;
use crate::context::timing::TimingAnalyzer;
use crate::context::tracker::{
    ConversationTracker, TrackerConfig, TrackerWireState, TRACKER_STATE_VERSION,
};
use crate::domain_runtime::{
    build_blocked_url_signal, build_domain_observations,
    confidence_from_score as score_to_confidence, decide_action_with_domain_overrides,
    detection_enabled_for_threat, map_ml_signal_to_event_kind, map_pattern_threat_subtype,
    map_rule_or_threat_to_event_kind, merge_active_domain_output_effects, parse_threat_type_label,
    should_skip_pattern_match, should_skip_pattern_rule_override, threat_priority_for_sort,
    AuraDomainRuntime,
};
use crate::ids::{ConversationId, SenderId};
use crate::product::{
    ProductRolloutMode, PRODUCT_DECISION_SURFACE_SCHEMA_VERSION, PRODUCT_POLICY_SCHEMA_VERSION,
};
use crate::runtime_capabilities::{
    RuntimeBackend, RuntimeCapabilities, RuntimeModality, RuntimeModelIdentity,
    RUNTIME_CAPABILITIES_SCHEMA_VERSION,
};
use crate::types::*;

mod stages;

struct EscalationTracker {
    recent_events: HashMap<ConversationId, Vec<(u64, SenderId)>>,
}

struct PatternScanResult {
    observations: Vec<RawObservation>,
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

    /// Returns a proportional escalation factor (0.0 or 0.20).
    ///
    /// When 5+ threat events from 2+ senders occur within one hour in
    /// the same conversation (pile-on pattern), signals are boosted by
    /// 20% of their current score. This replaces the previous flat
    /// +0.15 bonus which disproportionately affected low scores.
    fn check_bonus(&self, conversation_id: &str, now_ms: u64) -> f32 {
        let one_hour = 3600 * 1000;
        let cutoff = now_ms.saturating_sub(one_hour);

        if let Some(entries) = self.recent_events.get(conversation_id) {
            let mut recent_count = 0usize;
            let mut first_sender: Option<&SenderId> = None;
            let mut multiple_senders = false;
            for (ts, sender_id) in entries {
                if *ts < cutoff {
                    continue;
                }
                recent_count += 1;
                match first_sender {
                    Some(first) => {
                        if first != sender_id {
                            multiple_senders = true;
                        }
                    }
                    None => first_sender = Some(sender_id),
                }
                if recent_count >= 5 && multiple_senders {
                    return 0.20;
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

fn content_fingerprint_u64(text: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

fn collect_supported_pattern_languages(pattern_db: &PatternDatabase) -> HashSet<String> {
    let mut languages = HashSet::new();
    for rule in &pattern_db.rules {
        for language in &rule.languages {
            languages.insert(language.clone());
        }
    }
    languages
}

/// Performs message analysis combining pattern matching, ML inference, and context tracking.
pub struct Analyzer {
    config: AuraConfig,
    pattern_db: PatternDatabase,
    supported_pattern_languages: HashSet<String>,
    pattern_matchers: HashMap<String, PatternMatcher>,
    url_checker: UrlChecker,
    context_tracker: ConversationTracker,
    signal_enricher: SignalEnricher,
    context_interpreter: ContextInterpreter,
    timing_analyzer: TimingAnalyzer,
    ml_pipeline: MlPipeline,
    escalation_tracker: EscalationTracker,
    domain_runtime: AuraDomainRuntime,
}

impl Analyzer {
    /// Creates a new analyzer with the given configuration and pattern database.
    ///
    /// # Panics
    ///
    /// Panics when the bundled context rule packs fail validation. Release
    /// initialization should use [`Self::try_new`] to surface the typed error.
    pub fn new(config: AuraConfig, pattern_db: &PatternDatabase) -> Self {
        match Self::try_new(config, pattern_db) {
            Ok(analyzer) => analyzer,
            Err(error) => panic!("AURA analyzer initialization failed: {error}"),
        }
    }

    /// Creates an analyzer and validates all bundled context rule packs before activation.
    pub fn try_new(
        config: AuraConfig,
        pattern_db: &PatternDatabase,
    ) -> Result<Self, crate::error::AuraError> {
        config.validate()?;
        let default_pattern_language = config.language.clone();
        let pattern_matcher = PatternMatcher::from_database(pattern_db, &default_pattern_language);
        let supported_pattern_languages = collect_supported_pattern_languages(pattern_db);
        let url_checker = UrlChecker::from_database(pattern_db);
        let context_tracker = ConversationTracker::new(Self::tracker_config(&config));
        let signal_enricher = Self::signal_enricher(&config);
        let context_interpreter = ContextInterpreter::try_new()?;
        let timing_analyzer = TimingAnalyzer::new();
        let ml_pipeline = MlPipeline::new(Self::ml_config(&config));

        debug!(
            language = %config.language,
            protection = ?config.effective_protection_level(),
            rules = pattern_matcher.rule_count(),
            blocked_urls = url_checker.blocked_count(),
            inference_backend = ?ml_pipeline.runtime_backend(),
            "AURA analyzer initialized"
        );

        Ok(Self {
            config,
            pattern_db: pattern_db.clone(),
            supported_pattern_languages,
            pattern_matchers: HashMap::from([(default_pattern_language, pattern_matcher)]),
            url_checker,
            context_tracker,
            signal_enricher,
            context_interpreter,
            timing_analyzer,
            ml_pipeline,
            escalation_tracker: EscalationTracker::new(),
            domain_runtime: AuraDomainRuntime::new(),
        })
    }

    fn tracker_config(config: &AuraConfig) -> TrackerConfig {
        TrackerConfig {
            analysis_window_ms: config.ttl_days as u64 * 24 * 60 * 60 * 1000,
            is_child_account: config.account_type == AccountType::Child,
            is_teen_account: config.account_type == AccountType::Teen,
            account_holder_age: config.account_holder_age,
            protected_account_id: config.protected_account_id.clone(),
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
        // Kids mode bypasses the cascade gate so every message gets deep ML
        // inference. False negatives in child safety are unacceptable, and
        // ~10ms per message on MiniLM-L12 is acceptable on mobile.
        let kids_mode = config.effective_domain_mode() == DomainMode::Kids;

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
                    manifest_path: Some(base.join("manifest.json").to_string_lossy().into_owned()),
                    use_fallback: true,
                    language: config.language.clone(),
                    strict_manifest_validation: true,
                    safety_threshold: 0.5,
                    intent_threshold: 0.5,
                    cascade_force_bypass: kids_mode,
                    ..Default::default()
                }
            }
            None => MlConfig {
                use_fallback: true,
                language: config.language.clone(),
                cascade_force_bypass: kids_mode,
                ..Default::default()
            },
        }
    }

    fn collect_pattern_layer(
        &mut self,
        input: &MessageInput,
        text: &str,
        content_hash: Option<u64>,
    ) -> PatternScanResult {
        let matches = match input.language.as_deref() {
            Some(message_language) => {
                let matcher = self.pattern_matcher_for(Some(message_language));
                matcher.scan(text)
            }
            None => {
                let mut combined = Vec::new();
                let mut seen_rules: HashSet<String> = HashSet::new();
                let mut languages = vec![
                    self.config.language.clone(),
                    "en".to_string(),
                    "uk".to_string(),
                    "ru".to_string(),
                ];
                languages.sort();
                languages.dedup();

                for language in languages {
                    let matcher = self.pattern_matcher_for(Some(language.as_str()));
                    let results = matcher.scan(text);
                    for result in results {
                        if seen_rules.insert(result.rule_id.clone()) {
                            combined.push(result);
                        }
                    }
                }
                combined
            }
        };

        let mut matched_rule_ids: HashSet<String> = HashSet::new();
        for match_item in &matches {
            matched_rule_ids.insert(match_item.rule_id.clone());
        }

        let mut observations = Vec::with_capacity(8);

        for match_item in matches {
            let threat_type = parse_threat_type_label(&match_item.threat_type);
            if !self.is_detection_enabled(threat_type) {
                continue;
            }
            if should_skip_pattern_rule_override(&match_item.rule_id, &matched_rule_ids) {
                continue;
            }
            if should_skip_pattern_match(
                text,
                threat_type,
                &match_item.rule_id,
                match_item.matched_text.as_deref(),
            ) {
                continue;
            }

            let threat_subtype = map_pattern_threat_subtype(
                &match_item.rule_id,
                threat_type,
                match_item.matched_text.as_deref(),
            );
            let mut signal = DetectionSignal::pattern(
                threat_type,
                match_item.score,
                score_to_confidence(match_item.score),
                format!("pattern.{}", match_item.rule_id),
                match_item.explanation,
            );
            if let Some(ref threat_subtype) = threat_subtype {
                signal = signal.with_threat_subtype(threat_subtype.clone());
            }
            let observation =
                match map_rule_or_threat_to_event_kind(&match_item.rule_id, threat_type) {
                    Some(event_kind) => RawObservation::signal_with_event(
                        signal,
                        event_kind,
                        match_item.score,
                        threat_subtype,
                        content_hash,
                    ),
                    None => RawObservation::signal(signal),
                };
            observations.push(observation);
        }

        for blocked in self.url_checker.find_blocked_matches(text) {
            let blocked_signal = build_blocked_url_signal(&blocked);
            let threat_type = blocked_signal.threat_type;
            if !self.is_detection_enabled(threat_type) {
                continue;
            }

            let blocked_subtype = if blocked_signal.threat_subtype.is_empty() {
                None
            } else {
                Some(blocked_signal.threat_subtype.clone())
            };
            let observation = match map_rule_or_threat_to_event_kind(&blocked.rule_id, threat_type)
            {
                Some(event_kind) => RawObservation::signal_with_event(
                    blocked_signal,
                    event_kind,
                    blocked.score,
                    blocked_subtype,
                    content_hash,
                ),
                None => RawObservation::signal(blocked_signal),
            };
            observations.push(observation);
        }

        for finding in self.url_checker.find_suspicious_urls(text) {
            let mut signal = DetectionSignal::pattern(
                ThreatType::Phishing,
                finding.score,
                score_to_confidence(finding.score),
                "link.suspicious_url_heuristic",
                finding.explanation,
            );
            let threat_subtype = infer_suspicious_url_subtype(&signal.explanation);
            signal = signal.with_threat_subtype(threat_subtype);
            observations.push(RawObservation::signal(signal));
        }

        PatternScanResult { observations }
    }

    /// Analyzes a single message for threats without updating conversation context.
    ///
    /// Every accepted message runs through the complete local pipeline. Callers
    /// may apply admission control before invoking the analyzer, but the analyzer
    /// never turns an accepted message into a clean result because of traffic volume.
    pub fn analyze(&mut self, input: &MessageInput) -> AnalysisResult {
        self.analyze_staged(input)
    }

    /// Analyzes a message and updates conversation context with detected events at the given timestamp.
    pub fn analyze_with_context(
        &mut self,
        input: &MessageInput,
        timestamp_ms: u64,
    ) -> AnalysisResult {
        self.analyze_with_context_staged(input, timestamp_ms)
    }

    /// Clears per-run state while preserving compiled patterns, URL rules, and ML caches.
    pub fn reset_runtime_state(&mut self) {
        self.context_tracker = ConversationTracker::new(Self::tracker_config(&self.config));
        self.timing_analyzer = TimingAnalyzer::new();
        self.escalation_tracker = EscalationTracker::new();
        self.domain_runtime = AuraDomainRuntime::new();
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

        let noise_factor: f32 = match conversation_type {
            ConversationType::Direct => 1.0,
            ConversationType::Group => 0.85,
        };
        if noise_factor < 1.0 {
            for s in &mut signals {
                if s.layer != DetectionLayer::ContextAnalysis {
                    let adjusted_factor = match s.threat_type {
                        ThreatType::Grooming | ThreatType::SelfHarm | ThreatType::Manipulation => {
                            noise_factor.max(0.93)
                        }
                        ThreatType::Threat | ThreatType::Doxxing | ThreatType::HateSpeech => {
                            noise_factor.max(0.9)
                        }
                        ThreatType::None
                        | ThreatType::Bullying
                        | ThreatType::Explicit
                        | ThreatType::Spam
                        | ThreatType::Scam
                        | ThreatType::Phishing
                        | ThreatType::Nsfw
                        | ThreatType::PiiLeakage
                        | ThreatType::Propaganda
                        | ThreatType::OpsecViolation
                        | ThreatType::Psyops
                        | ThreatType::MilitarySocialEng
                        | ThreatType::CoordinateLeak => noise_factor,
                    };
                    s.score *= adjusted_factor;
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
                            if threat_priority_for_sort(s.threat_type)
                                < threat_priority_for_sort(current.threat_type)
                            {
                                anchored_priority = Some(s);
                            }
                        }
                    }
                }
                match any_priority {
                    None => any_priority = Some(s),
                    Some(current) => {
                        if threat_priority_for_sort(s.threat_type)
                            < threat_priority_for_sort(current.threat_type)
                        {
                            any_priority = Some(s);
                        }
                    }
                }
            }
        }
        let priority_signal = match (anchored_priority, any_priority) {
            (Some(anchored), Some(any)) => {
                let anchored_p = threat_priority_for_sort(anchored.threat_type);
                let any_p = threat_priority_for_sort(any.threat_type);
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

        let mut primary = priority_signal;
        let mut score = primary.score;
        for signal in &signals {
            if signal.threat_type == primary.threat_type && signal.score > score {
                score = signal.score;
                primary = signal;
            }
        }

        let (action_v2, mut recommendation) = decide_action_with_domain_overrides(
            primary.threat_type,
            score,
            protection,
            &primary.reason_code,
        );
        let mut action = action_v2;

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
        detected_threats.sort_by_key(|(tt, _)| threat_priority_for_sort(*tt));

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
            &AnalysisContextSummary::default(),
        );
        augment_recommendation_for_inference(&mut recommendation, primary.threat_type, &inference);
        if action == Action::Block
            && inference.uncertainty == UncertaintyLevel::High
            && matches!(
                primary.threat_type,
                ThreatType::Grooming | ThreatType::Manipulation | ThreatType::SelfHarm
            )
        {
            action = Action::Warn;
            recommendation.parent_alert = recommendation.parent_alert.max(AlertPriority::High);
            recommendation.ui_actions.push(UiAction::EscalateToGuardian);
            recommendation.ui_actions.push(UiAction::WarnBeforeDisplay);
            recommendation.ui_actions.sort();
            recommendation.ui_actions.dedup();
        }

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
            context_markers: Vec::new(),
            context_summary: AnalysisContextSummary::default(),
            inference,
            analysis_time_us,
        }
    }

    fn is_detection_enabled(&self, threat_type: ThreatType) -> bool {
        detection_enabled_for_threat(&self.config, threat_type)
    }

    /// Returns a reference to the internal conversation tracker.
    pub fn context_tracker(&self) -> &ConversationTracker {
        &self.context_tracker
    }

    /// Returns the effective protection level currently applied by the analyzer.
    pub fn protection_level(&self) -> ProtectionLevel {
        self.config.effective_protection_level()
    }

    /// Returns the explicitly configured product rollout.
    pub fn product_rollout_mode(&self) -> ProductRolloutMode {
        self.config.product_rollout_mode
    }

    /// Returns the account profile bound to this initialized analyzer.
    pub const fn account_type(&self) -> AccountType {
        self.config.account_type
    }

    /// Returns the effective account domain bound to this analyzer.
    pub fn effective_domain_mode(&self) -> DomainMode {
        self.config.effective_domain_mode()
    }

    /// Returns the configured canonical analysis language.
    pub fn language(&self) -> &str {
        &self.config.language
    }

    /// Returns a read-only snapshot of capabilities actually active in this analyzer.
    pub fn runtime_capabilities(&self) -> RuntimeCapabilities {
        let backend = match self.ml_pipeline.runtime_backend() {
            MlRuntimeBackend::RulesFallback => RuntimeBackend::RulesFallback,
            MlRuntimeBackend::Onnx => RuntimeBackend::Onnx,
        };
        let models = self
            .ml_pipeline
            .loaded_models()
            .iter()
            .map(|model| RuntimeModelIdentity {
                component: model.component.clone(),
                identifier: model.identifier.clone(),
                sha256: model
                    .sha256
                    .iter()
                    .any(|byte| *byte != 0)
                    .then(|| hex_digest(&model.sha256)),
            })
            .collect();

        RuntimeCapabilities {
            schema_version: RUNTIME_CAPABILITIES_SCHEMA_VERSION.to_string(),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
            backend,
            supported_modalities: vec![RuntimeModality::Text, RuntimeModality::Url],
            models,
            policy_schema_version: PRODUCT_POLICY_SCHEMA_VERSION.to_string(),
            product_schema_version: PRODUCT_DECISION_SURFACE_SCHEMA_VERSION.to_string(),
            state_schema_version: TRACKER_STATE_VERSION,
            product_rollout_mode: self.config.product_rollout_mode,
        }
    }

    /// Returns the exact validated model-manifest identity active in this runtime.
    pub fn model_manifest_digest(&self) -> [u8; 32] {
        self.ml_pipeline.model_manifest_digest()
    }

    /// Exports the conversation tracker state for persistence or transfer.
    pub fn export_context_state(&self) -> TrackerWireState {
        self.context_tracker.export_wire_state()
    }

    /// Exports kids-domain runtime memory owned by this analyzer instance.
    pub fn export_kids_memory_state(&self) -> aura_kids::pipeline::ExportedKidsMemoryState {
        self.domain_runtime.export_kids_memory()
    }

    /// Imports a previously exported tracker state, merging it with existing data.
    pub fn import_context_state(
        &mut self,
        state: TrackerWireState,
    ) -> Result<(), crate::error::AuraError> {
        self.context_tracker.import_wire_state(state)
    }

    /// Imports kids-domain runtime memory owned by this analyzer instance.
    pub fn import_kids_memory_state(
        &mut self,
        state: &aura_kids::pipeline::ExportedKidsMemoryState,
    ) -> bool {
        self.domain_runtime.import_kids_memory(state)
    }

    /// Clears kids-domain runtime memory owned by this analyzer instance.
    pub fn clear_kids_memory_state(&mut self) {
        self.domain_runtime.clear_kids_memory();
    }

    /// Returns the conversation risk score from this analyzer's kids-domain memory.
    pub fn kids_conversation_risk_score(&self, conversation_id: &str) -> f32 {
        self.domain_runtime
            .kids_conversation_risk_score(conversation_id)
    }

    /// Returns the tracked message count from this analyzer's kids-domain memory.
    pub fn kids_conversation_escalation_message_count(&self, conversation_id: &str) -> u32 {
        self.domain_runtime
            .kids_conversation_escalation_message_count(conversation_id)
    }

    /// Returns the sender risk score from this analyzer's kids-domain memory.
    pub fn kids_sender_cross_risk_score(&self, sender_id: &str) -> f32 {
        self.domain_runtime.kids_sender_cross_risk_score(sender_id)
    }

    /// Applies guardian feedback to this analyzer's live kids-domain memory.
    pub fn apply_kids_guardian_feedback(
        &mut self,
        sender_id: &str,
        conversation_id: &str,
        verdict: aura_kids::pipeline::GuardianVerdict,
    ) {
        self.domain_runtime
            .apply_kids_guardian_feedback(sender_id, conversation_id, verdict);
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

    /// Binds the stable sender ID of the protected account exactly once.
    ///
    /// Callers must derive this value from authenticated account identity. The
    /// binding is immutable for the lifetime of an analyzer so conversation
    /// context from different protected accounts cannot share one runtime.
    pub fn bind_protected_account_id(
        &mut self,
        protected_account_id: String,
    ) -> Result<(), crate::error::AuraError> {
        self.validate_protected_account_id_binding(&protected_account_id)?;
        if let Some(current) = self.config.protected_account_id.as_deref() {
            if current == protected_account_id {
                return Ok(());
            }
        }

        let mut config = self.config.clone();
        config.protected_account_id = Some(protected_account_id);
        self.context_tracker
            .update_config(Self::tracker_config(&config));
        self.config = config;
        Ok(())
    }

    /// Validates an authenticated account binding without mutating runtime state.
    pub fn validate_protected_account_id_binding(
        &self,
        protected_account_id: &str,
    ) -> Result<(), crate::error::AuraError> {
        if self
            .config
            .protected_account_id
            .as_deref()
            .is_some_and(|current| current != protected_account_id)
        {
            return Err(crate::error::AuraError::InvalidConfig(
                "protected_account_id is already bound for this runtime".to_string(),
            ));
        }
        let mut candidate = self.config.clone();
        candidate.protected_account_id = Some(protected_account_id.to_string());
        candidate.validate()
    }

    /// Replaces the analyzer configuration and rebuilds pattern matchers and ML pipeline.
    ///
    /// Validation happens before any runtime state is mutated.
    pub fn update_config(
        &mut self,
        config: AuraConfig,
        pattern_db: &PatternDatabase,
    ) -> Result<(), crate::error::AuraError> {
        if let Some(bound) = self.config.protected_account_id.as_deref() {
            if config.protected_account_id.as_deref() != Some(bound) {
                return Err(crate::error::AuraError::InvalidConfig(
                    "protected_account_id is immutable for this runtime".to_string(),
                ));
            }
        }
        config.validate()?;
        let tracker_config = Self::tracker_config(&config);
        let signal_enricher = Self::signal_enricher(&config);
        let ml_pipeline = MlPipeline::new(Self::ml_config(&config));
        self.pattern_db = pattern_db.clone();
        self.supported_pattern_languages = collect_supported_pattern_languages(pattern_db);
        self.pattern_matchers = HashMap::from([(
            config.language.clone(),
            PatternMatcher::from_database(pattern_db, &config.language),
        )]);
        self.url_checker = UrlChecker::from_database(pattern_db);
        self.context_tracker.update_config(tracker_config);
        self.signal_enricher = signal_enricher;
        self.ml_pipeline = ml_pipeline;
        self.domain_runtime = AuraDomainRuntime::new();
        self.config = config;
        Ok(())
    }

    /// Reloads pattern matchers and URL checker from an updated pattern database.
    ///
    /// **Important:** reload replaces the rule set used for *future* messages
    /// only. Events already recorded in conversation timelines retain their
    /// original `EventKind` mappings. This is intentional — re-classifying
    /// historical events would invalidate behavioral trend baselines and
    /// could cause false detection resets mid-conversation. If a rule
    /// rename changes the semantics of an `EventKind`, perform a full
    /// context export → clear → re-import cycle instead.
    pub fn reload_patterns(&mut self, pattern_db: &PatternDatabase) {
        self.pattern_db = pattern_db.clone();
        self.supported_pattern_languages = collect_supported_pattern_languages(pattern_db);
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

        if self.supported_pattern_languages.contains(language) {
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
                let (threat_type, score, explanation) = match tox.primary_label {
                    Some(ToxicityLabel::Threat) => (
                        ThreatType::Threat,
                        tox.threat.max(tox.toxicity),
                        format!("ML: threat detected (score: {:.2})", tox.threat),
                    ),
                    Some(ToxicityLabel::SexualExplicit) => (
                        ThreatType::Explicit,
                        tox.sexual_explicit.max(tox.toxicity),
                        format!(
                            "ML: sexual content detected (score: {:.2})",
                            tox.sexual_explicit
                        ),
                    ),
                    Some(ToxicityLabel::SevereToxicity) => (
                        ThreatType::Bullying,
                        tox.severe_toxicity.max(tox.toxicity),
                        format!(
                            "ML: severe toxicity detected (score: {:.2})",
                            tox.severe_toxicity
                        ),
                    ),
                    Some(ToxicityLabel::Insult) => (
                        ThreatType::Bullying,
                        tox.insult.max(tox.toxicity),
                        format!("ML: insult detected (score: {:.2})", tox.insult),
                    ),
                    Some(ToxicityLabel::IdentityAttack) => (
                        ThreatType::Bullying,
                        tox.identity_attack.max(tox.toxicity),
                        format!(
                            "ML: identity attack detected (score: {:.2})",
                            tox.identity_attack
                        ),
                    ),
                    None => (
                        ThreatType::Bullying,
                        tox.toxicity,
                        format!("ML: toxic content detected (score: {:.2})", tox.toxicity),
                    ),
                };

                if self.is_detection_enabled(threat_type) {
                    let reason_code = match threat_type {
                        ThreatType::Threat => "ml.threat",
                        ThreatType::Explicit => "ml.sexual_explicit",
                        ThreatType::Bullying => "ml.toxicity",
                        _ => "ml.generic",
                    };
                    signals.push(DetectionSignal::ml(
                        threat_type,
                        score,
                        score_to_confidence(score),
                        reason_code,
                        explanation,
                    ));
                }
            }
        }

        if let Some(ref safety) = ml_result.safety {
            let safety_threshold = self.ml_pipeline.safety_threshold();
            let (threat_type, score, reason_code, explanation) = match safety.primary_label {
                Some(SafetyLabel::Grooming) if safety.grooming >= safety_threshold => (
                    ThreatType::Grooming,
                    safety.grooming,
                    "ml.safety.grooming",
                    format!(
                        "ML safety: grooming detected (score: {:.2})",
                        safety.grooming
                    ),
                ),
                Some(SafetyLabel::Bullying) if safety.bullying >= safety_threshold => (
                    ThreatType::Bullying,
                    safety.bullying,
                    "ml.safety.bullying",
                    format!(
                        "ML safety: bullying detected (score: {:.2})",
                        safety.bullying
                    ),
                ),
                Some(SafetyLabel::SelfHarm) if safety.self_harm >= safety_threshold => (
                    ThreatType::SelfHarm,
                    safety.self_harm,
                    "ml.safety.selfharm",
                    format!(
                        "ML safety: self-harm detected (score: {:.2})",
                        safety.self_harm
                    ),
                ),
                Some(SafetyLabel::Manipulation) if safety.manipulation >= safety_threshold => (
                    ThreatType::Manipulation,
                    safety.manipulation,
                    "ml.safety.manipulation",
                    format!(
                        "ML safety: manipulation detected (score: {:.2})",
                        safety.manipulation
                    ),
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
            let intent_threshold = self.ml_pipeline.intent_threshold();
            match intent.primary_intent {
                Some(IntentLabel::RequestMeeting)
                    if intent.request_meeting >= intent_threshold
                        && self.is_detection_enabled(ThreatType::Grooming) =>
                {
                    signals.push(DetectionSignal::ml(
                        ThreatType::Grooming,
                        intent.request_meeting,
                        score_to_confidence(intent.request_meeting),
                        "ml.intent.meeting",
                        format!(
                            "ML intent: meeting request detected (score: {:.2})",
                            intent.request_meeting
                        ),
                    ));
                }
                Some(IntentLabel::RequestSecret)
                    if intent.request_secret >= intent_threshold
                        && self.is_detection_enabled(ThreatType::Grooming) =>
                {
                    signals.push(DetectionSignal::ml(
                        ThreatType::Grooming,
                        intent.request_secret,
                        score_to_confidence(intent.request_secret),
                        "ml.intent.secret",
                        format!(
                            "ML intent: secrecy request detected (score: {:.2})",
                            intent.request_secret
                        ),
                    ));
                }
                Some(IntentLabel::RequestMedia)
                    if intent.request_media >= intent_threshold
                        && self.is_detection_enabled(ThreatType::Grooming) =>
                {
                    signals.push(DetectionSignal::ml(
                        ThreatType::Grooming,
                        intent.request_media,
                        score_to_confidence(intent.request_media),
                        "ml.intent.media",
                        format!(
                            "ML intent: media request detected (score: {:.2})",
                            intent.request_media
                        ),
                    ));
                }
                _ => {}
            }
        }

        if ml_result.abstain_to_guardian {
            let uncertainty_score = match ml_result.uncertainty {
                MlUncertaintyLevel::Low => 0.35,
                MlUncertaintyLevel::Medium => 0.55,
                MlUncertaintyLevel::High => 0.72,
            };
            signals.push(DetectionSignal::context(
                ThreatType::Manipulation,
                uncertainty_score,
                Confidence::Medium,
                SignalFamily::Conversation,
                "ml.uncertainty.guardian_review",
                "ML uncertainty-aware guardrail requested guardian review before hard block",
            ));
        }

        signals
    }

    /// Extract ML safety scores from detection signals to pass as hints to domain modules.
    fn extract_ml_safety_hint(signals: &[DetectionSignal]) -> Option<MlSafetyHint> {
        let mut grooming = 0.0f32;
        let mut bullying = 0.0f32;
        let mut self_harm = 0.0f32;
        let mut manipulation = 0.0f32;
        let mut found = false;

        for signal in signals {
            if signal.layer != DetectionLayer::MlClassification {
                continue;
            }
            match signal.threat_type {
                ThreatType::Grooming => {
                    grooming = grooming.max(signal.score);
                    found = true;
                }
                ThreatType::Bullying => {
                    bullying = bullying.max(signal.score);
                    found = true;
                }
                ThreatType::SelfHarm => {
                    self_harm = self_harm.max(signal.score);
                    found = true;
                }
                ThreatType::Manipulation => {
                    manipulation = manipulation.max(signal.score);
                    found = true;
                }
                _ => {}
            }
        }

        if found {
            Some(MlSafetyHint {
                grooming,
                bullying,
                self_harm,
                manipulation,
            })
        } else {
            None
        }
    }
}

mod inference;

use inference::*;

#[cfg(test)]
mod tests;
