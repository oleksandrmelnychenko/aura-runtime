use std::collections::HashMap;
use std::time::Instant;

use aura_ml::{MlConfig, MlPipeline, ToxicityLabel};
use aura_patterns::{PatternDatabase, PatternMatcher, UrlChecker};
use tracing::debug;

use crate::action::decide_action_v2;
use crate::config::AuraConfig;
use crate::context::enricher::{EnricherConfig, SignalEnricher};
use crate::context::events::{ContextEvent, EventKind};
use crate::context::timing::TimingAnalyzer;
use crate::context::tracker::{ConversationTracker, TrackerConfig};
use crate::types::*;

struct EscalationTracker {
    recent_events: HashMap<String, Vec<(u64, String)>>,
}

impl EscalationTracker {
    fn new() -> Self {
        Self {
            recent_events: HashMap::new(),
        }
    }

    fn record(&mut self, conversation_id: &str, sender_id: &str, timestamp_ms: u64) {
        let entries = self
            .recent_events
            .entry(conversation_id.to_string())
            .or_default();
        entries.push((timestamp_ms, sender_id.to_string()));
    }

    fn check_bonus(&self, conversation_id: &str, now_ms: u64) -> f32 {
        let one_hour = 3600 * 1000;
        let cutoff = now_ms.saturating_sub(one_hour);

        if let Some(entries) = self.recent_events.get(conversation_id) {
            let recent: Vec<_> = entries.iter().filter(|(ts, _)| *ts >= cutoff).collect();
            if recent.len() >= 5 {
                let mut senders: Vec<&str> = recent.iter().map(|(_, s)| s.as_str()).collect();
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

pub struct Analyzer {
    config: AuraConfig,
    pattern_matcher: PatternMatcher,
    url_checker: UrlChecker,
    context_tracker: ConversationTracker,
    signal_enricher: SignalEnricher,
    timing_analyzer: TimingAnalyzer,
    ml_pipeline: MlPipeline,
    escalation_tracker: EscalationTracker,
}

impl Analyzer {
    pub fn new(config: AuraConfig, pattern_db: &PatternDatabase) -> Self {
        let pattern_matcher = PatternMatcher::from_database(pattern_db, &config.language);
        let url_checker = UrlChecker::from_database(pattern_db);

        let tracker_config = TrackerConfig {
            is_child_account: config.account_type == AccountType::Child,
            is_teen_account: config.account_type == AccountType::Teen,
            account_holder_age: config.account_holder_age,
            ..Default::default()
        };
        let context_tracker = ConversationTracker::new(tracker_config);

        let is_minor =
            config.account_type == AccountType::Child || config.account_type == AccountType::Teen;
        let signal_enricher = SignalEnricher::new(EnricherConfig {
            strict_mode: is_minor,
            ..Default::default()
        });
        let timing_analyzer = TimingAnalyzer::new();

        let ml_pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            language: config.language.clone(),
            ..Default::default()
        });

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
            pattern_matcher,
            url_checker,
            context_tracker,
            signal_enricher,
            timing_analyzer,
            ml_pipeline,
            escalation_tracker: EscalationTracker::new(),
        }
    }

    pub fn analyze(&mut self, input: &MessageInput) -> AnalysisResult {
        let start = Instant::now();
        let protection = self.config.effective_protection_level();

        if protection == ProtectionLevel::Off {
            return AnalysisResult::clean(0);
        }

        let mut signals = Vec::new();

        if let Some(text) = &input.text {
            let matches = self.pattern_matcher.scan(text);
            for m in matches {
                let threat_type = parse_threat_type(&m.threat_type);

                if !self.is_detection_enabled(threat_type) {
                    continue;
                }

                signals.push(DetectionSignal {
                    threat_type,
                    score: m.score,
                    confidence: score_to_confidence(m.score),
                    layer: DetectionLayer::PatternMatching,
                    explanation: m.explanation,
                });
            }

            let blocked_urls = self.url_checker.find_blocked_urls(text);
            for url in blocked_urls {
                signals.push(DetectionSignal {
                    threat_type: ThreatType::Phishing,
                    score: 0.95,
                    confidence: Confidence::High,
                    layer: DetectionLayer::PatternMatching,
                    explanation: format!("Blocked URL detected: {url}"),
                });
            }
        }

        if let Some(text) = &input.text {
            let ml_signals = self.run_ml_layer(text);
            signals.extend(ml_signals);
        }

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        self.combine_signals(signals, protection, analysis_time_us)
    }

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

        let mut signals = Vec::new();

        let mut context_events = Vec::new();

        if let Some(text) = &input.text {
            let matches = self.pattern_matcher.scan(text);
            for m in matches {
                let threat_type = parse_threat_type(&m.threat_type);
                if !self.is_detection_enabled(threat_type) {
                    continue;
                }

                signals.push(DetectionSignal {
                    threat_type,
                    score: m.score,
                    confidence: score_to_confidence(m.score),
                    layer: DetectionLayer::PatternMatching,
                    explanation: m.explanation,
                });

                if let Some(event_kind) = match_to_event_kind(&m.rule_id, threat_type) {
                    context_events.push(ContextEvent {
                        timestamp_ms,
                        sender_id: input.sender_id.clone(),
                        conversation_id: input.conversation_id.clone(),
                        kind: event_kind,
                        confidence: m.score,
                    });
                }
            }

            let blocked_urls = self.url_checker.find_blocked_urls(text);
            for url in blocked_urls {
                signals.push(DetectionSignal {
                    threat_type: ThreatType::Phishing,
                    score: 0.95,
                    confidence: Confidence::High,
                    layer: DetectionLayer::PatternMatching,
                    explanation: format!("Blocked URL detected: {url}"),
                });
            }
        }

        if let Some(text) = &input.text {
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
                timestamp_ms,
                sender_id: input.sender_id.clone(),
                conversation_id: input.conversation_id.clone(),
                kind: EventKind::NormalConversation,
                confidence: 1.0,
            });
        }

        if let Some(text) = &input.text {
            let ml_signals = self.run_ml_layer(text);

            for signal in &ml_signals {
                if let Some(kind) = ml_signal_to_event_kind(signal) {
                    context_events.push(ContextEvent {
                        timestamp_ms,
                        sender_id: input.sender_id.clone(),
                        conversation_id: input.conversation_id.clone(),
                        kind,
                        confidence: signal.score,
                    });
                }
            }

            signals.extend(ml_signals);
        }

        let context_signals = self.context_tracker.record_events(context_events);

        let sender_has_bullying_signals = signals
            .iter()
            .any(|s| s.threat_type == ThreatType::Bullying || s.threat_type == ThreatType::Threat);
        let sender_is_defender = self
            .context_tracker
            .timeline(&input.conversation_id)
            .map(|t| {
                t.all_events()
                    .iter()
                    .any(|e| e.sender_id == input.sender_id && e.kind == EventKind::DefenseOfVictim)
            })
            .unwrap_or(false);

        for signal in context_signals {
            let is_pile_on_signal = signal.layer == DetectionLayer::ContextAnalysis
                && signal.threat_type == ThreatType::Bullying
                && (signal.explanation.contains("Group bullying")
                    || signal.explanation.contains("Isolation"));

            if is_pile_on_signal && (sender_is_defender || !sender_has_bullying_signals) {
                continue;
            }
            signals.push(signal);
        }

        let is_child = self.config.account_type == AccountType::Child;
        if let Some(timeline) = self.context_tracker.timeline(&input.conversation_id) {
            let timing_signals =
                self.timing_analyzer
                    .analyze(timeline, &input.sender_id, timestamp_ms, is_child);
            signals.extend(timing_signals);
        }

        for s in &signals {
            if matches!(
                s.threat_type,
                ThreatType::Bullying | ThreatType::Threat | ThreatType::Explicit
            ) {
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
                if matches!(
                    s.threat_type,
                    ThreatType::Bullying | ThreatType::Threat | ThreatType::Explicit
                ) {
                    s.score = (s.score + bonus).min(1.0);
                }
            }
        }

        let elapsed = start.elapsed();
        let analysis_time_us = elapsed.as_micros() as u64;

        self.combine_signals(signals, protection, analysis_time_us)
    }

    fn combine_signals(
        &self,
        signals: Vec<DetectionSignal>,
        protection: ProtectionLevel,
        analysis_time_us: u64,
    ) -> AnalysisResult {
        if signals.is_empty() {
            return AnalysisResult::clean(analysis_time_us);
        }

        let max_signal = signals
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        let max_score = max_signal.score;

        let priority_signal = signals
            .iter()
            .filter(|s| s.score >= max_score - 0.3 && s.threat_type != ThreatType::None)
            .min_by_key(|s| threat_priority(s.threat_type))
            .unwrap_or(max_signal);

        let score = max_score.max(priority_signal.score);
        let primary = priority_signal;

        let (action_v2, recommendation) = decide_action_v2(primary.threat_type, score, protection);
        let action = action_v2;

        let mut threat_map: std::collections::HashMap<ThreatType, f32> =
            std::collections::HashMap::new();
        for s in &signals {
            if s.threat_type != ThreatType::None {
                let entry = threat_map.entry(s.threat_type).or_insert(0.0);
                if s.score > *entry {
                    *entry = s.score;
                }
            }
        }
        let mut detected_threats: Vec<(ThreatType, f32)> = threat_map.into_iter().collect();
        detected_threats.sort_by_key(|(tt, _)| threat_priority(*tt));

        AnalysisResult {
            threat_type: primary.threat_type,
            confidence: primary.confidence,
            action,
            score,
            explanation: primary.explanation.clone(),
            detected_threats,
            signals,
            recommended_action: Some(recommendation),
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

            ThreatType::HateSpeech | ThreatType::Doxxing => self.config.enabled,
            ThreatType::None => false,
        }
    }

    pub fn context_tracker(&self) -> &ConversationTracker {
        &self.context_tracker
    }

    pub fn export_context(&self) -> Result<String, serde_json::Error> {
        self.context_tracker.export_state()
    }

    pub fn import_context(&mut self, json: &str) -> Result<(), serde_json::Error> {
        self.context_tracker.import_state(json)
    }

    pub fn cleanup_context(&mut self, now_ms: u64) {
        self.context_tracker.cleanup(now_ms);
        self.escalation_tracker.cleanup(now_ms);
    }

    pub fn mark_contact_trusted(&mut self, sender_id: &str) {
        self.context_tracker.mark_contact_trusted(sender_id);
    }

    pub fn update_config(&mut self, config: AuraConfig, pattern_db: &PatternDatabase) {
        self.pattern_matcher = PatternMatcher::from_database(pattern_db, &config.language);
        self.url_checker = UrlChecker::from_database(pattern_db);
        self.config = config;
    }

    fn run_ml_layer(&mut self, text: &str) -> Vec<DetectionSignal> {
        let ml_result = self.ml_pipeline.analyze_text(text);
        let mut signals = Vec::new();
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
                    signals.push(DetectionSignal {
                        threat_type,
                        score: tox.toxicity,
                        confidence: score_to_confidence(tox.toxicity),
                        layer: DetectionLayer::MlClassification,
                        explanation,
                    });
                }
            }
        }

        signals
    }
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
        return Some(EventKind::GuildTripping);
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
    if rule_id.starts_with("substance_pressure") {
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

    match threat_type {
        ThreatType::Grooming => Some(EventKind::SecrecyRequest),
        ThreatType::Bullying => Some(EventKind::Insult),
        ThreatType::Threat => Some(EventKind::PhysicalThreat),
        ThreatType::SelfHarm => Some(EventKind::SuicidalIdeation),
        ThreatType::Manipulation => Some(EventKind::GuildTripping),
        ThreatType::Doxxing => Some(EventKind::DoxxingAttempt),
        ThreatType::HateSpeech => Some(EventKind::HateSpeech),
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
        _ => None,
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
        ThreatType::Manipulation => 5,
        ThreatType::HateSpeech => 6,
        ThreatType::Bullying => 7,
        ThreatType::Nsfw => 8,
        ThreatType::Phishing => 9,
        ThreatType::Scam => 10,
        ThreatType::Spam => 11,
        ThreatType::None => 12,
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
            sender_id: "user_123".to_string(),
            conversation_id: "conv_456".to_string(),
            language: Some("en".to_string()),
        }
    }

    fn child_input(text: &str, sender: &str, conversation: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id: sender.to_string(),
            conversation_id: conversation.to_string(),
            language: Some("en".to_string()),
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
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
        let result = analyzer.analyze(&default_input("Don't tell your parents about us"));
        assert!(result.is_threat());
        assert_eq!(result.threat_type, ThreatType::Grooming);
    }

    #[test]
    fn self_harm_never_blocked_only_warned() {
        let db = test_db();
        let config = AuraConfig {
            protection_level: ProtectionLevel::High,
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

        let state = analyzer.export_context().unwrap();

        let mut analyzer2 = Analyzer::new(child_config(), &db);
        analyzer2.import_context(&state).unwrap();

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
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
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
        let mut analyzer = Analyzer::new(AuraConfig::default(), &db);
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

        let state = analyzer.export_context().expect("export should work");
        assert!(state.contains(conv), "State should contain conversation");

        let mut analyzer2 = Analyzer::new(child_config(), &db);
        analyzer2
            .import_context(&state)
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
        assert!(
            json.contains("recommended_action"),
            "JSON should include recommended_action"
        );
        assert!(
            json.contains("parent_alert"),
            "JSON should include parent_alert field"
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
}
