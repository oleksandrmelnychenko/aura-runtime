use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::AuraError;
use crate::types::{ConversationType, DetectionSignal};

const TRACKER_STATE_VERSION: u32 = 2;

fn default_state_version() -> u32 {
    1
}

use super::bullying::BullyingDetector;
use super::coercion::CoercionDetector;
use super::contact::ContactProfiler;
use super::events::{ContextEvent, EventKind};
use super::grooming::GroomingDetector;
use super::manipulation::ManipulationDetector;
use super::raid::RaidDetector;
use super::selfharm::SelfHarmDetector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerConfig {
    pub max_events_per_conversation: usize,

    pub analysis_window_ms: u64,

    pub max_conversations: usize,

    pub is_child_account: bool,

    pub is_teen_account: bool,

    #[serde(default)]
    pub account_holder_age: Option<u16>,

    #[serde(default)]
    pub auto_cleanup_interval: u32,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            max_events_per_conversation: 500,
            analysis_window_ms: 30 * 24 * 60 * 60 * 1000,

            max_conversations: 200,
            is_child_account: false,
            is_teen_account: false,
            account_holder_age: None,
            auto_cleanup_interval: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTimeline {
    pub conversation_id: String,
    #[serde(default)]
    pub conversation_type: ConversationType,
    events: Vec<ContextEvent>,
    max_events: usize,
}

impl ConversationTimeline {
    pub fn new(conversation_id: String, max_events: usize) -> Self {
        Self {
            conversation_id,
            conversation_type: ConversationType::Direct,
            events: Vec::new(),
            max_events,
        }
    }

    pub fn new_with_type(
        conversation_id: String,
        max_events: usize,
        conversation_type: ConversationType,
    ) -> Self {
        Self {
            conversation_id,
            conversation_type,
            events: Vec::new(),
            max_events,
        }
    }

    pub fn push(&mut self, event: ContextEvent) {
        if self.events.len() >= self.max_events {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    pub fn events_since(&self, since_ms: u64) -> Vec<&ContextEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp_ms >= since_ms)
            .collect()
    }

    pub fn events_from_sender(&self, sender_id: &str, since_ms: u64) -> Vec<&ContextEvent> {
        self.events
            .iter()
            .filter(|e| e.sender_id == sender_id && e.timestamp_ms >= since_ms)
            .collect()
    }

    pub fn count_events(&self, sender_id: &str, kind: &EventKind, since_ms: u64) -> usize {
        self.events
            .iter()
            .filter(|e| e.sender_id == sender_id && &e.kind == kind && e.timestamp_ms >= since_ms)
            .count()
    }

    pub fn count_matching<F>(&self, since_ms: u64, predicate: F) -> usize
    where
        F: Fn(&ContextEvent) -> bool,
    {
        self.events
            .iter()
            .filter(|e| e.timestamp_ms >= since_ms && predicate(e))
            .count()
    }

    pub fn unique_senders_matching<F>(&self, since_ms: u64, predicate: F) -> Vec<String>
    where
        F: Fn(&ContextEvent) -> bool,
    {
        let mut senders: Vec<String> = self
            .events
            .iter()
            .filter(|e| e.timestamp_ms >= since_ms && predicate(e))
            .map(|e| e.sender_id.clone())
            .collect();
        senders.sort();
        senders.dedup();
        senders
    }

    pub fn all_events(&self) -> &[ContextEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

pub struct ConversationTracker {
    config: TrackerConfig,
    timelines: HashMap<String, ConversationTimeline>,
    grooming_detector: GroomingDetector,
    bullying_detector: BullyingDetector,
    manipulation_detector: ManipulationDetector,
    selfharm_detector: SelfHarmDetector,
    coercion_detector: CoercionDetector,
    raid_detector: RaidDetector,
    contact_profiler: ContactProfiler,
    call_count: u32,
}

impl ConversationTracker {
    pub fn new(config: TrackerConfig) -> Self {
        let grooming_detector =
            GroomingDetector::new(config.is_child_account || config.is_teen_account);
        let bullying_detector = BullyingDetector::new();
        let manipulation_detector = ManipulationDetector::new();
        let selfharm_detector = SelfHarmDetector::new();
        let coercion_detector = CoercionDetector::new();
        let raid_detector = RaidDetector::new();
        let contact_profiler = ContactProfiler::new();

        Self {
            config,
            timelines: HashMap::new(),
            grooming_detector,
            bullying_detector,
            manipulation_detector,
            selfharm_detector,
            coercion_detector,
            raid_detector,
            contact_profiler,
            call_count: 0,
        }
    }

    pub fn set_conversation_type(
        &mut self,
        conversation_id: &str,
        conversation_type: ConversationType,
    ) {
        if let Some(timeline) = self.timelines.get_mut(conversation_id) {
            timeline.conversation_type = conversation_type;
        }
    }

    pub fn record_event(&mut self, event: ContextEvent) -> Vec<DetectionSignal> {
        let conversation_id = event.conversation_id.clone();
        let sender_id = event.sender_id.clone();
        let now_ms = event.timestamp_ms;

        self.contact_profiler.record_event(&event);

        let timeline = self
            .timelines
            .entry(conversation_id.clone())
            .or_insert_with(|| {
                ConversationTimeline::new(
                    conversation_id.clone(),
                    self.config.max_events_per_conversation,
                )
            });

        timeline.push(event);

        if self.timelines.len() > self.config.max_conversations {
            self.evict_oldest_conversation();
        }

        let window_start = now_ms.saturating_sub(self.config.analysis_window_ms);

        let mut signals = Vec::new();

        let timeline = match self.timelines.get(&conversation_id) {
            Some(t) => t,
            None => return signals,
        };
        let grooming_signals = self.grooming_detector.analyze(
            timeline,
            &sender_id,
            window_start,
            &self.contact_profiler,
        );
        signals.extend(grooming_signals);

        let bullying_signals = self
            .bullying_detector
            .analyze(timeline, &sender_id, window_start);
        signals.extend(bullying_signals);

        let manipulation_signals =
            self.manipulation_detector
                .analyze(timeline, &sender_id, window_start);
        signals.extend(manipulation_signals);

        let selfharm_signals = self
            .selfharm_detector
            .analyze(timeline, &sender_id, window_start);
        signals.extend(selfharm_signals);

        let coercion_signals = self
            .coercion_detector
            .analyze(timeline, &sender_id, window_start);
        signals.extend(coercion_signals);

        let raid_signals = self
            .raid_detector
            .analyze(timeline, now_ms, &self.contact_profiler);
        signals.extend(raid_signals);

        let age_gap_signals = self
            .contact_profiler
            .check_age_gap(&sender_id, self.config.account_holder_age);
        signals.extend(age_gap_signals);

        let contact_signals = self
            .contact_profiler
            .check_anomalies(&sender_id, self.config.is_child_account);
        signals.extend(contact_signals);

        let shift_signals = self.contact_profiler.check_behavioral_shift(&sender_id);
        signals.extend(shift_signals);

        signals
    }

    pub fn record_events(&mut self, events: Vec<ContextEvent>) -> Vec<DetectionSignal> {
        let mut all_signals = Vec::new();
        let mut latest_ts = 0u64;
        for event in &events {
            latest_ts = latest_ts.max(event.timestamp_ms);
        }
        for event in events {
            let signals = self.record_event(event);
            all_signals.extend(signals);
        }
        if self.config.auto_cleanup_interval > 0 {
            self.call_count += 1;
            if self.call_count >= self.config.auto_cleanup_interval {
                self.call_count = 0;
                self.cleanup(latest_ts);
            }
        }
        all_signals
    }

    pub fn timeline(&self, conversation_id: &str) -> Option<&ConversationTimeline> {
        self.timelines.get(conversation_id)
    }

    pub fn conversation_ids(&self) -> Vec<&str> {
        self.timelines.keys().map(|s| s.as_str()).collect()
    }

    pub fn contact_profiler(&self) -> &ContactProfiler {
        &self.contact_profiler
    }

    pub fn contact_profiler_mut(&mut self) -> &mut ContactProfiler {
        &mut self.contact_profiler
    }

    pub fn mark_contact_trusted(&mut self, sender_id: &str) {
        self.contact_profiler.mark_trusted(sender_id);
    }

    pub fn export_state(&self) -> Result<String, serde_json::Error> {
        let state = TrackerState {
            schema_version: TRACKER_STATE_VERSION,
            timelines: self.timelines.values().cloned().collect(),
            contact_profiler: self.contact_profiler.export(),
        };
        serde_json::to_string(&state)
    }

    pub fn import_state(&mut self, json: &str) -> Result<(), AuraError> {
        let state: TrackerState = serde_json::from_str(json)?;
        if state.schema_version > TRACKER_STATE_VERSION {
            return Err(AuraError::IncompatibleStateVersion {
                found: state.schema_version,
                supported: TRACKER_STATE_VERSION,
            });
        }
        for timeline in state.timelines {
            self.timelines
                .insert(timeline.conversation_id.clone(), timeline);
        }
        self.contact_profiler.import(state.contact_profiler);
        Ok(())
    }

    pub fn cleanup(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.config.analysis_window_ms);
        self.timelines.retain(|_, timeline| {
            timeline.events.retain(|e| e.timestamp_ms >= cutoff);
            !timeline.is_empty()
        });
        self.contact_profiler.cleanup(cutoff);
    }

    fn evict_oldest_conversation(&mut self) {
        if let Some(oldest_id) = self
            .timelines
            .iter()
            .min_by_key(|(_, t)| t.all_events().last().map(|e| e.timestamp_ms).unwrap_or(0))
            .map(|(id, _)| id.clone())
        {
            self.timelines.remove(&oldest_id);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TrackerState {
    #[serde(default = "default_state_version")]
    schema_version: u32,
    timelines: Vec<ConversationTimeline>,
    contact_profiler: contact::ContactProfilerState,
}

use super::contact;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(
        conversation_id: &str,
        sender_id: &str,
        kind: EventKind,
        timestamp_ms: u64,
    ) -> ContextEvent {
        ContextEvent {
            timestamp_ms,
            sender_id: sender_id.to_string(),
            conversation_id: conversation_id.to_string(),
            kind,
            confidence: 0.8,
        }
    }

    #[test]
    fn records_events_and_creates_timeline() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        let event = make_event("conv_1", "stranger", EventKind::Flattery, 1000);
        tracker.record_event(event);

        let timeline = tracker.timeline("conv_1").unwrap();
        assert_eq!(timeline.len(), 1);
    }

    #[test]
    fn events_accumulate_per_conversation() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        tracker.record_event(make_event("conv_1", "stranger", EventKind::Flattery, 1000));
        tracker.record_event(make_event("conv_1", "stranger", EventKind::GiftOffer, 2000));
        tracker.record_event(make_event(
            "conv_1",
            "stranger",
            EventKind::SecrecyRequest,
            3000,
        ));

        let timeline = tracker.timeline("conv_1").unwrap();
        assert_eq!(timeline.len(), 3);
    }

    #[test]
    fn separate_conversations_tracked_independently() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());

        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            1000,
        ));
        tracker.record_event(make_event("conv_2", "bob", EventKind::Insult, 1000));

        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 1);
        assert_eq!(tracker.timeline("conv_2").unwrap().len(), 1);
    }

    #[test]
    fn cleanup_removes_old_events() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            analysis_window_ms: 10000,
            ..Default::default()
        });

        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 15000));

        tracker.cleanup(20000);

        let timeline = tracker.timeline("conv_1").unwrap();
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline.all_events()[0].timestamp_ms, 15000);
    }

    #[test]
    fn state_export_import_roundtrip() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event("conv_1", "alice", EventKind::Flattery, 1000));
        tracker.record_event(make_event("conv_1", "alice", EventKind::GiftOffer, 2000));

        let state = tracker.export_state().unwrap();

        let mut tracker2 = ConversationTracker::new(TrackerConfig::default());
        tracker2.import_state(&state).unwrap();

        assert_eq!(tracker2.timeline("conv_1").unwrap().len(), 2);
    }

    #[test]
    fn state_export_contains_schema_version() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event("conv_1", "alice", EventKind::Flattery, 1000));

        let state = tracker.export_state().unwrap();
        assert!(
            state.contains("\"schema_version\":2"),
            "Exported state should contain schema_version: {state}"
        );
    }

    #[test]
    fn state_import_old_json_without_version() {
        let old_json = r#"{"timelines":[],"contact_profiler":{"profiles":[]}}"#;
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        assert!(tracker.import_state(old_json).is_ok());
    }

    #[test]
    fn state_import_future_version_fails() {
        let future_json =
            r#"{"schema_version":999,"timelines":[],"contact_profiler":{"profiles":[]}}"#;
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        let result = tracker.import_state(future_json);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("incompatible state version"),
            "Error should mention incompatible version: {err}"
        );
    }

    #[test]
    fn auto_cleanup_triggers_after_interval() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            analysis_window_ms: 10_000,
            auto_cleanup_interval: 3,
            ..Default::default()
        });

        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 1);

        tracker.record_events(vec![make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_000,
        )]);
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 2);

        tracker.record_events(vec![make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_001,
        )]);
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 3);

        tracker.record_events(vec![make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_002,
        )]);
        assert_eq!(
            tracker.timeline("conv_1").unwrap().len(),
            3,
            "After auto-cleanup, old event should be removed"
        );
    }

    #[test]
    fn auto_cleanup_disabled_by_default() {
        let config = TrackerConfig::default();
        assert_eq!(config.auto_cleanup_interval, 0);
    }

    #[test]
    fn rating_updated_on_record_event() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        // Normal message first
        tracker.record_event(make_event(
            "conv_1",
            "bully",
            EventKind::NormalConversation,
            1000,
        ));
        let rating_before = tracker.contact_profiler().profile("bully").unwrap().rating;

        // Hostile message should decrease rating
        tracker.record_event(make_event("conv_1", "bully", EventKind::Insult, 2000));
        let rating_after = tracker.contact_profiler().profile("bully").unwrap().rating;

        assert!(
            rating_after < rating_before,
            "Rating should decrease after insult: {rating_before} -> {rating_after}"
        );
    }

    #[test]
    fn behavioral_shift_signal_in_output() {
        let week_ms = 7 * 24 * 60 * 60 * 1000u64;
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        // Weeks 1-3: supportive
        for week in 0..3 {
            for msg in 0..10 {
                let kind = if msg < 6 {
                    EventKind::NormalConversation
                } else {
                    EventKind::DefenseOfVictim
                };
                tracker.record_event(make_event(
                    "conv_shift",
                    "masha",
                    kind,
                    week * week_ms + msg * 1000,
                ));
            }
        }

        // Weeks 4-5: hostile
        for week in 3..5 {
            for msg in 0..10 {
                let kind = if msg < 6 {
                    EventKind::NormalConversation
                } else {
                    EventKind::Insult
                };
                tracker.record_event(make_event(
                    "conv_shift",
                    "masha",
                    kind,
                    week * week_ms + msg * 1000,
                ));
            }
        }

        // Week 6: trigger — should get behavioral shift signal
        let _signals = tracker.record_event(make_event(
            "conv_shift",
            "masha",
            EventKind::Insult,
            5 * week_ms + 1000,
        ));

        let profile = tracker.contact_profiler().profile("masha").unwrap();
        assert!(
            profile.trend == super::contact::BehavioralTrend::RoleReversal
                || profile.trend == super::contact::BehavioralTrend::RapidWorsening,
            "Expected worsening/reversal trend, got {:?}",
            profile.trend
        );
    }
}
