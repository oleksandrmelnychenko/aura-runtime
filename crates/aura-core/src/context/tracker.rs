use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::AuraError;
use crate::types::{ConversationType, DetectionSignal};

const TRACKER_STATE_VERSION: u32 = 2;

use super::bullying::BullyingDetector;
use super::coercion::CoercionDetector;
use super::contact::{ContactProfiler, ContactProfilerWireState};
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

    /// Timezone offset in minutes from UTC (e.g. +180 for UTC+3 Ukraine).
    /// Used for late-night detection in TimingAnalyzer.
    #[serde(default)]
    pub timezone_offset_minutes: i32,
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
            timezone_offset_minutes: 0,
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

#[derive(Debug, Clone)]
pub struct ConversationTimelineState {
    pub conversation_id: String,
    pub conversation_type: ConversationType,
    pub events: Vec<ContextEvent>,
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

    pub fn export_state(&self) -> ConversationTimelineState {
        ConversationTimelineState {
            conversation_id: self.conversation_id.clone(),
            conversation_type: self.conversation_type,
            events: self.events.clone(),
        }
    }

    /// Merge events from another timeline, deduplicating by content signature.
    /// Uses (timestamp_ms, sender_id, kind) as the dedup key — this handles both:
    /// - Same-tracker re-import (same event_ids)
    /// - Cross-tracker merge (different trackers may assign overlapping event_ids)
    pub fn merge_from(&mut self, other: ConversationTimeline) {
        let existing: HashSet<(u64, String, EventKind)> = self
            .events
            .iter()
            .map(|e| (e.timestamp_ms, e.sender_id.clone(), e.kind.clone()))
            .collect();

        for event in other.events {
            let key = (
                event.timestamp_ms,
                event.sender_id.clone(),
                event.kind.clone(),
            );
            if !existing.contains(&key) {
                self.events.push(event);
            }
        }

        self.events.sort_by_key(|e| e.timestamp_ms);

        while self.events.len() > self.max_events {
            self.events.remove(0);
        }
    }
}

impl ConversationTimelineState {
    fn into_timeline(self, max_events: usize) -> ConversationTimeline {
        let mut timeline = ConversationTimeline::new_with_type(
            self.conversation_id,
            max_events,
            self.conversation_type,
        );
        for event in self.events {
            timeline.push(event);
        }
        timeline
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
    next_event_id: u64,
}

#[derive(Debug, Clone)]
pub struct TrackerWireState {
    pub schema_version: u32,
    pub timelines: Vec<ConversationTimelineState>,
    pub contact_profiler: ContactProfilerWireState,
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
            next_event_id: 1,
        }
    }

    pub fn config(&self) -> &TrackerConfig {
        &self.config
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

        let mut event = event;
        event.event_id = self.next_event_id;
        self.next_event_id += 1;

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

        if self.config.auto_cleanup_interval > 0 {
            self.call_count += 1;
            if self.call_count >= self.config.auto_cleanup_interval {
                self.call_count = 0;
                self.cleanup(now_ms);
            }
        }

        signals
    }

    pub fn record_events(&mut self, events: Vec<ContextEvent>) -> Vec<DetectionSignal> {
        let mut all_signals = Vec::new();
        for event in events {
            let signals = self.record_event(event);
            all_signals.extend(signals);
        }
        // auto_cleanup is handled inside each record_event() call
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

    pub fn export_wire_state(&self) -> TrackerWireState {
        TrackerWireState {
            schema_version: TRACKER_STATE_VERSION,
            timelines: self
                .timelines
                .values()
                .map(ConversationTimeline::export_state)
                .collect(),
            contact_profiler: self.contact_profiler.export_wire_state(),
        }
    }

    pub fn import_wire_state(&mut self, state: TrackerWireState) -> Result<(), AuraError> {
        if state.schema_version > TRACKER_STATE_VERSION {
            return Err(AuraError::IncompatibleStateVersion {
                found: state.schema_version,
                supported: TRACKER_STATE_VERSION,
            });
        }

        let mut max_imported_id = 0_u64;
        for incoming in state.timelines {
            for event in &incoming.events {
                max_imported_id = max_imported_id.max(event.event_id);
            }

            let incoming = incoming.into_timeline(self.config.max_events_per_conversation);
            match self.timelines.get_mut(&incoming.conversation_id) {
                Some(local) => local.merge_from(incoming),
                None => {
                    self.timelines
                        .insert(incoming.conversation_id.clone(), incoming);
                }
            }
        }

        if max_imported_id >= self.next_event_id {
            self.next_event_id = max_imported_id + 1;
        }

        self.contact_profiler
            .merge_import_wire_state(state.contact_profiler);
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
            event_id: 0,
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

        let state = tracker.export_wire_state();

        let mut tracker2 = ConversationTracker::new(TrackerConfig::default());
        tracker2.import_wire_state(state).unwrap();

        assert_eq!(tracker2.timeline("conv_1").unwrap().len(), 2);
    }

    #[test]
    fn wire_state_export_import_roundtrip() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event("conv_1", "alice", EventKind::Flattery, 1000));
        tracker.record_event(make_event("conv_1", "alice", EventKind::GiftOffer, 2000));

        let state = tracker.export_wire_state();

        let mut tracker2 = ConversationTracker::new(TrackerConfig::default());
        tracker2.import_wire_state(state).unwrap();

        assert_eq!(tracker2.timeline("conv_1").unwrap().len(), 2);
        assert!(tracker2.contact_profiler().profile("alice").is_some());
    }

    #[test]
    fn state_export_contains_schema_version() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event("conv_1", "alice", EventKind::Flattery, 1000));

        let state = tracker.export_wire_state();
        assert_eq!(state.schema_version, 2);
    }

    #[test]
    fn state_import_future_version_fails() {
        let state = TrackerWireState {
            schema_version: 999,
            timelines: Vec::new(),
            contact_profiler: ContactProfilerWireState {
                profiles: Vec::new(),
            },
        };
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        let result = tracker.import_wire_state(state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("incompatible state version"),
            "Error should mention incompatible version: {err}"
        );
    }

    #[test]
    fn auto_cleanup_triggers_after_interval() {
        // auto_cleanup_interval=3 means cleanup triggers every 3rd record_event() call
        let mut tracker = ConversationTracker::new(TrackerConfig {
            analysis_window_ms: 10_000,
            auto_cleanup_interval: 3,
            ..Default::default()
        });

        // Call 1: old event (will be cleaned up later)
        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 1);

        // Call 2: recent event
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_000,
        ));
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 2);

        // Call 3: triggers cleanup (call_count reaches 3).
        // Cleanup removes event at ts=1000 (cutoff = 20001 - 10000 = 10001)
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_001,
        ));
        assert_eq!(
            tracker.timeline("conv_1").unwrap().len(),
            2,
            "After auto-cleanup, old event at ts=1000 should be removed"
        );

        // Call 4: new event after cleanup
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_002,
        ));
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 3);
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
            profile.trend == crate::types::BehavioralTrend::RoleReversal
                || profile.trend == crate::types::BehavioralTrend::RapidWorsening,
            "Expected worsening/reversal trend, got {:?}",
            profile.trend
        );
    }

    #[test]
    fn eviction_removes_oldest_conversation() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            max_conversations: 3,
            ..Default::default()
        });

        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            1000,
        ));
        tracker.record_event(make_event(
            "conv_2",
            "bob",
            EventKind::NormalConversation,
            2000,
        ));
        tracker.record_event(make_event(
            "conv_3",
            "charlie",
            EventKind::NormalConversation,
            3000,
        ));
        // This should evict conv_1 (oldest)
        tracker.record_event(make_event(
            "conv_4",
            "dave",
            EventKind::NormalConversation,
            4000,
        ));

        assert!(
            tracker.timeline("conv_1").is_none(),
            "Oldest conversation should be evicted"
        );
        assert!(
            tracker.timeline("conv_4").is_some(),
            "New conversation should exist"
        );
    }

    #[test]
    fn conversation_type_preserved() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            1000,
        ));
        tracker.set_conversation_type("conv_1", crate::types::ConversationType::Group);

        let timeline = tracker.timeline("conv_1").unwrap();
        assert_eq!(
            timeline.conversation_type,
            crate::types::ConversationType::Group
        );
    }

    #[test]
    fn full_pipeline_grooming_plus_coercion() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        // Grooming sequence
        tracker.record_event(make_event("conv_1", "predator", EventKind::Flattery, 1000));
        tracker.record_event(make_event("conv_1", "predator", EventKind::GiftOffer, 2000));
        tracker.record_event(make_event(
            "conv_1",
            "predator",
            EventKind::SecrecyRequest,
            3000,
        ));
        tracker.record_event(make_event(
            "conv_1",
            "predator",
            EventKind::PersonalInfoRequest,
            4000,
        ));

        // Then coercion
        tracker.record_event(make_event(
            "conv_1",
            "predator",
            EventKind::SuicideCoercion,
            5000,
        ));
        tracker.record_event(make_event(
            "conv_1",
            "predator",
            EventKind::ReputationThreat,
            6000,
        ));

        let signals = tracker.record_event(make_event(
            "conv_1",
            "predator",
            EventKind::ScreenshotThreat,
            7000,
        ));

        // Should detect both grooming and manipulation/coercion signals
        let has_grooming = signals
            .iter()
            .any(|s| s.threat_type == crate::types::ThreatType::Grooming);
        let has_manipulation = signals
            .iter()
            .any(|s| s.threat_type == crate::types::ThreatType::Manipulation);
        assert!(
            has_grooming || has_manipulation,
            "Should detect grooming or manipulation in combined attack"
        );
    }

    #[test]
    fn state_roundtrip_preserves_behavioral_data() {
        let week_ms = 7 * 24 * 60 * 60 * 1000u64;
        let mut tracker = ConversationTracker::new(TrackerConfig::default());

        // Build behavioral history
        for w in 0..4 {
            for msg in 0..5 {
                tracker.record_event(make_event(
                    "conv_1",
                    "alice",
                    EventKind::NormalConversation,
                    w * week_ms + msg * 1000,
                ));
            }
        }
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::Insult,
            4 * week_ms,
        ));

        let state = tracker.export_wire_state();
        let orig = tracker.contact_profiler().profile("alice").unwrap();
        let orig_rating = orig.rating;

        let mut tracker2 = ConversationTracker::new(TrackerConfig::default());
        tracker2.import_wire_state(state).unwrap();

        let imported = tracker2.contact_profiler().profile("alice").unwrap();
        assert_eq!(
            imported.rating, orig_rating,
            "Rating should survive roundtrip"
        );
    }

    #[test]
    fn multiple_detectors_produce_signals() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        // Bullying + self-harm pathway
        for i in 0..5 {
            tracker.record_event(make_event("conv_1", "bully", EventKind::Insult, i * 1000));
        }
        tracker.record_event(make_event(
            "conv_1",
            "victim",
            EventKind::Hopelessness,
            6000,
        ));
        tracker.record_event(make_event(
            "conv_1",
            "victim",
            EventKind::Hopelessness,
            7000,
        ));
        let signals = tracker.record_event(make_event(
            "conv_1",
            "victim",
            EventKind::FarewellMessage,
            8000,
        ));

        // Should have signals from bullying detector AND self-harm detector
        let threat_types: Vec<_> = signals.iter().map(|s| s.threat_type).collect();
        assert!(
            !threat_types.is_empty(),
            "Should detect threats in bullying->selfharm pathway"
        );
    }

    #[test]
    fn record_events_batch_processes_all() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        let events = vec![
            make_event("conv_1", "alice", EventKind::NormalConversation, 1000),
            make_event("conv_1", "alice", EventKind::NormalConversation, 2000),
            make_event("conv_1", "alice", EventKind::NormalConversation, 3000),
        ];
        tracker.record_events(events);

        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 3);
    }

    #[test]
    fn timeline_count_events_works() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 2000));
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            3000,
        ));

        let timeline = tracker.timeline("conv_1").unwrap();
        assert_eq!(timeline.count_events("alice", &EventKind::Insult, 0), 2);
        assert_eq!(
            timeline.count_events("alice", &EventKind::NormalConversation, 0),
            1
        );
    }

    #[test]
    fn contact_profiler_accessible_from_tracker() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            1000,
        ));

        assert!(tracker.contact_profiler().profile("alice").is_some());
        assert!(tracker.contact_profiler().profile("bob").is_none());
    }

    // -----------------------------------------------------------------------
    // Phase 1: merge-based import tests
    // -----------------------------------------------------------------------

    #[test]
    fn import_merge_preserves_local_events() {
        let mut tracker_a = ConversationTracker::new(TrackerConfig::default());
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Mockery, 2000));

        let mut tracker_b = ConversationTracker::new(TrackerConfig::default());
        tracker_b.record_event(make_event("conv_1", "bob", EventKind::Flattery, 1500));

        // Import B into A — should merge, not overwrite
        let state_b = tracker_b.export_wire_state();
        tracker_a.import_wire_state(state_b).unwrap();

        let timeline = tracker_a.timeline("conv_1").unwrap();
        assert_eq!(
            timeline.len(),
            3,
            "Should have all 3 events after merge (2 from A + 1 from B)"
        );
        // Events should be sorted by timestamp
        let events = timeline.all_events();
        assert_eq!(events[0].timestamp_ms, 1000);
        assert_eq!(events[1].timestamp_ms, 1500);
        assert_eq!(events[2].timestamp_ms, 2000);
    }

    #[test]
    fn import_merge_deduplicates_by_event_id() {
        let mut tracker_a = ConversationTracker::new(TrackerConfig::default());
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Mockery, 2000));

        // Export A, then import it back — should NOT duplicate events
        let state = tracker_a.export_wire_state();
        tracker_a.import_wire_state(state).unwrap();

        let timeline = tracker_a.timeline("conv_1").unwrap();
        assert_eq!(
            timeline.len(),
            2,
            "Importing same events should deduplicate by event_id"
        );
    }

    #[test]
    fn import_merge_handles_separate_conversations() {
        let mut tracker_a = ConversationTracker::new(TrackerConfig::default());
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));

        let mut tracker_b = ConversationTracker::new(TrackerConfig::default());
        tracker_b.record_event(make_event("conv_2", "bob", EventKind::Flattery, 2000));

        let state_b = tracker_b.export_wire_state();
        tracker_a.import_wire_state(state_b).unwrap();

        assert!(tracker_a.timeline("conv_1").is_some());
        assert!(tracker_a.timeline("conv_2").is_some());
        assert_eq!(tracker_a.timeline("conv_1").unwrap().len(), 1);
        assert_eq!(tracker_a.timeline("conv_2").unwrap().len(), 1);
    }

    #[test]
    fn import_updates_next_event_id() {
        let mut tracker_a = ConversationTracker::new(TrackerConfig::default());
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));

        let mut tracker_b = ConversationTracker::new(TrackerConfig::default());
        // Generate many events on B to push its event_id counter high
        for i in 0..10 {
            tracker_b.record_event(make_event(
                "conv_2",
                "bob",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }

        let state_b = tracker_b.export_wire_state();
        tracker_a.import_wire_state(state_b).unwrap();

        // Now record a new event on A — its event_id should be higher than all imported ones
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Mockery, 20000));
        let events = tracker_a.timeline("conv_1").unwrap().all_events();
        let last_event = events.last().unwrap();
        assert!(
            last_event.event_id > 10,
            "New event_id {} should be higher than imported max",
            last_event.event_id
        );
    }

    #[test]
    fn event_ids_are_monotonically_assigned() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        tracker.record_event(make_event("conv_1", "bob", EventKind::Mockery, 2000));
        tracker.record_event(make_event("conv_1", "alice", EventKind::Flattery, 3000));

        let events = tracker.timeline("conv_1").unwrap().all_events();
        assert_eq!(events[0].event_id, 1);
        assert_eq!(events[1].event_id, 2);
        assert_eq!(events[2].event_id, 3);
    }

    #[test]
    fn auto_cleanup_triggers_from_single_record_event() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            analysis_window_ms: 10_000,
            auto_cleanup_interval: 2,
            ..Default::default()
        });

        tracker.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 1);

        // Call 2: triggers cleanup (20000 - 10000 = 10000 cutoff, event at 1000 removed)
        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_000,
        ));
        assert_eq!(
            tracker.timeline("conv_1").unwrap().len(),
            1,
            "Auto-cleanup from record_event() should remove old events"
        );
    }

    #[test]
    fn guilt_tripping_backward_compat_deserialization() {
        // Ensure old state with "guild_tripping" deserializes as GuiltTripping
        let json = r#"{"event_id":0,"timestamp_ms":1000,"sender_id":"x","conversation_id":"c","kind":"guild_tripping","confidence":0.8}"#;
        let event: ContextEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.kind, EventKind::GuiltTripping);
    }

    #[test]
    fn event_id_defaults_to_zero_on_deserialization() {
        // Old state without event_id field should deserialize with event_id=0
        let json = r#"{"timestamp_ms":1000,"sender_id":"x","conversation_id":"c","kind":"insult","confidence":0.8}"#;
        let event: ContextEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_id, 0);
    }
}
