use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::DetectionSignal;

use super::bullying::BullyingDetector;
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTimeline {
    pub conversation_id: String,
    events: Vec<ContextEvent>,
    max_events: usize,
}

impl ConversationTimeline {
    pub fn new(conversation_id: String, max_events: usize) -> Self {
        Self {
            conversation_id,
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
    raid_detector: RaidDetector,
    contact_profiler: ContactProfiler,
}

impl ConversationTracker {
    pub fn new(config: TrackerConfig) -> Self {
        let grooming_detector =
            GroomingDetector::new(config.is_child_account || config.is_teen_account);
        let bullying_detector = BullyingDetector::new();
        let manipulation_detector = ManipulationDetector::new();
        let selfharm_detector = SelfHarmDetector::new();
        let raid_detector = RaidDetector::new();
        let contact_profiler = ContactProfiler::new();

        Self {
            config,
            timelines: HashMap::new(),
            grooming_detector,
            bullying_detector,
            manipulation_detector,
            selfharm_detector,
            raid_detector,
            contact_profiler,
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

        let timeline = self.timelines.get(&conversation_id).unwrap();
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

        signals
    }

    pub fn record_events(&mut self, events: Vec<ContextEvent>) -> Vec<DetectionSignal> {
        let mut all_signals = Vec::new();
        for event in events {
            let signals = self.record_event(event);
            all_signals.extend(signals);
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
            timelines: self.timelines.values().cloned().collect(),
            contact_profiler: self.contact_profiler.export(),
        };
        serde_json::to_string(&state)
    }

    pub fn import_state(&mut self, json: &str) -> Result<(), serde_json::Error> {
        let state: TrackerState = serde_json::from_str(json)?;
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
}
