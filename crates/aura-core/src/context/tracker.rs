use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::AuraError;
use crate::ids::{ConversationId, SenderId};
use crate::types::{Confidence, ConversationType, DetectionSignal, SignalFamily, ThreatType};

/// Current schema version for serialized tracker state.
pub const TRACKER_STATE_VERSION: u32 = 3;

const GROUP_PILE_ON_WINDOW_MS: u64 = 6 * 60 * 60 * 1000;

use super::coercion::CoercionDetector;
use super::contact::{ContactProfiler, ContactProfilerWireState, DEFAULT_MAX_CONTACT_PROFILES};
use super::events::{ContextEvent, EventKind};
use super::interpretation::ConfirmedEvent;
use crate::types::AnalysisMode;

use super::propaganda::PropagandaDetector;
use super::raid::RaidDetector;

/// Holds configuration parameters for the conversation tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerConfig {
    pub max_events_per_conversation: usize,

    pub analysis_window_ms: u64,

    pub max_conversations: usize,

    #[serde(default = "default_max_contact_profiles")]
    pub max_contact_profiles: usize,

    pub is_child_account: bool,

    pub is_teen_account: bool,

    #[serde(default)]
    pub account_holder_age: Option<u16>,

    /// Sender/account ID of the protected account holder.
    ///
    /// Events from this sender remain in conversation timelines but are not
    /// treated as an external contact profile.
    #[serde(default)]
    pub protected_account_id: Option<String>,

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
            max_contact_profiles: default_max_contact_profiles(),
            is_child_account: false,
            is_teen_account: false,
            account_holder_age: None,
            protected_account_id: None,
            auto_cleanup_interval: 0,
            timezone_offset_minutes: 0,
        }
    }
}

fn default_max_contact_profiles() -> usize {
    DEFAULT_MAX_CONTACT_PROFILES
}

/// Stores a bounded sequence of context events for a single conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTimeline {
    pub conversation_id: ConversationId,
    pub conversation_type: ConversationType,
    events: Vec<ContextEvent>,
    start_idx: usize,
    max_events: usize,
}

/// Represents the exportable state of a conversation timeline.
#[derive(Debug, Clone)]
pub struct ConversationTimelineState {
    pub conversation_id: ConversationId,
    pub conversation_type: ConversationType,
    pub events: Vec<ContextEvent>,
}

impl ConversationTimeline {
    /// Creates a new timeline for the given conversation with a default Direct type.
    pub fn new(conversation_id: ConversationId, max_events: usize) -> Self {
        Self {
            conversation_id,
            conversation_type: ConversationType::Direct,
            events: Vec::new(),
            start_idx: 0,
            max_events,
        }
    }

    /// Creates a new timeline with an explicit conversation type.
    pub fn new_with_type(
        conversation_id: ConversationId,
        max_events: usize,
        conversation_type: ConversationType,
    ) -> Self {
        Self {
            conversation_id,
            conversation_type,
            events: Vec::new(),
            start_idx: 0,
            max_events,
        }
    }

    /// Appends an event to the timeline, evicting the oldest if at capacity.
    pub fn push(&mut self, event: ContextEvent) {
        if self.max_events == 0 {
            return;
        }
        if self.len() >= self.max_events {
            self.start_idx += 1;
        }
        self.events.push(event);
        self.compact_if_needed();
    }

    /// Returns all events with a timestamp at or after the given time.
    pub fn events_since(&self, since_ms: u64) -> Vec<&ContextEvent> {
        let mut result = Vec::with_capacity(self.len());
        for e in self.visible_events() {
            if e.timestamp_ms >= since_ms {
                result.push(e);
            }
        }
        result
    }

    /// Returns events from a specific sender at or after the given time.
    pub fn events_from_sender(&self, sender_id: &str, since_ms: u64) -> Vec<&ContextEvent> {
        let mut result = Vec::with_capacity(self.len());
        for e in self.visible_events() {
            if e.sender_id == sender_id && e.timestamp_ms >= since_ms {
                result.push(e);
            }
        }
        result
    }

    /// Counts events matching a specific sender and event kind since the given time.
    pub fn count_events(&self, sender_id: &str, kind: &EventKind, since_ms: u64) -> usize {
        let mut count = 0usize;
        for e in self.visible_events() {
            if e.sender_id == sender_id && &e.kind == kind && e.timestamp_ms >= since_ms {
                count += 1;
            }
        }
        count
    }

    /// Counts events matching a predicate since the given time.
    pub fn count_matching<F>(&self, since_ms: u64, predicate: F) -> usize
    where
        F: Fn(&ContextEvent) -> bool,
    {
        let mut count = 0usize;
        for e in self.visible_events() {
            if e.timestamp_ms >= since_ms && predicate(e) {
                count += 1;
            }
        }
        count
    }

    /// Returns deduplicated sender IDs for events matching a predicate since the given time.
    pub fn unique_senders_matching<F>(&self, since_ms: u64, predicate: F) -> Vec<SenderId>
    where
        F: Fn(&ContextEvent) -> bool,
    {
        let mut senders: Vec<SenderId> = Vec::with_capacity(self.len());
        for e in self.visible_events() {
            if e.timestamp_ms >= since_ms && predicate(e) {
                senders.push(e.sender_id.clone());
            }
        }
        senders.sort_by(|a, b| a.0.cmp(&b.0));
        senders.dedup();
        senders
    }

    /// Returns a slice of all events in this timeline.
    pub fn all_events(&self) -> &[ContextEvent] {
        self.visible_events()
    }

    /// Returns the number of events in this timeline.
    pub fn len(&self) -> usize {
        self.events.len().saturating_sub(self.start_idx)
    }

    /// Returns true if this timeline contains no events.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Exports the timeline's state for serialization or transfer.
    pub fn export_state(&self) -> ConversationTimelineState {
        ConversationTimelineState {
            conversation_id: self.conversation_id.clone(),
            conversation_type: self.conversation_type,
            events: self.visible_events().to_vec(),
        }
    }

    /// Merge events from another timeline, deduplicating by content signature.
    /// The signature uses fields preserved by the public persisted-state wire,
    /// excluding the process-local event ID and derived context frame. It handles:
    /// - Same-tracker re-import (same event_ids)
    /// - Cross-tracker merge (different trackers may assign overlapping event_ids)
    pub fn merge_from(&mut self, other: ConversationTimeline) {
        for event in other.events.into_iter().skip(other.start_idx) {
            if !self
                .visible_events()
                .iter()
                .any(|existing| same_logical_event(existing, &event))
            {
                self.events.push(event);
            }
        }

        if self.start_idx > 0 {
            self.events.drain(0..self.start_idx);
            self.start_idx = 0;
        }
        self.events
            .sort_by_key(|event| (event.timestamp_ms, event.event_id));

        if self.max_events == 0 {
            self.events.clear();
            return;
        }
        let overflow = self.events.len().saturating_sub(self.max_events);
        self.start_idx = overflow;
        self.compact_if_needed();
    }

    fn visible_events(&self) -> &[ContextEvent] {
        let start_idx = self.start_idx.min(self.events.len());
        &self.events[start_idx..]
    }

    fn compact_if_needed(&mut self) {
        if self.start_idx == 0 {
            return;
        }
        let should_compact = self.start_idx >= self.max_events
            || self.start_idx.saturating_mul(2) >= self.events.len();
        if should_compact {
            self.events.drain(0..self.start_idx);
            self.start_idx = 0;
        }
    }
}

fn same_logical_event(left: &ContextEvent, right: &ContextEvent) -> bool {
    left.timestamp_ms == right.timestamp_ms
        && left.sender_id == right.sender_id
        && left.conversation_id == right.conversation_id
        && left.kind == right.kind
        && left.confidence.to_bits() == right.confidence.to_bits()
        && left.subtype == right.subtype
        && left.content_hash == right.content_hash
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

/// Manages per-conversation timelines and runs all threat detectors on incoming events.
pub struct ConversationTracker {
    config: TrackerConfig,
    timelines: HashMap<ConversationId, ConversationTimeline>,
    coercion_detector: CoercionDetector,
    raid_detector: RaidDetector,
    propaganda_detector: PropagandaDetector,
    contact_profiler: ContactProfiler,
    call_count: u32,
    next_event_id: u64,
}

/// Represents the serializable wire state of the entire conversation tracker.
#[derive(Debug, Clone)]
pub struct TrackerWireState {
    pub schema_version: u32,
    pub timelines: Vec<ConversationTimelineState>,
    pub contact_profiler: ContactProfilerWireState,
}

impl ConversationTracker {
    /// Creates a new tracker with the given configuration and initializes all sub-detectors.
    pub fn new(config: TrackerConfig) -> Self {
        let coercion_detector = CoercionDetector::new();
        let raid_detector = RaidDetector::new();
        let propaganda_mode = if config.is_child_account || config.is_teen_account {
            AnalysisMode::Strict
        } else {
            AnalysisMode::Standard
        };
        let propaganda_detector = PropagandaDetector::new(propaganda_mode);
        let contact_profiler = ContactProfiler::with_max_profiles(config.max_contact_profiles);

        Self {
            config,
            timelines: HashMap::new(),
            coercion_detector,
            raid_detector,
            propaganda_detector,
            contact_profiler,
            call_count: 0,
            next_event_id: 1,
        }
    }

    /// Returns a reference to the current tracker configuration.
    pub fn config(&self) -> &TrackerConfig {
        &self.config
    }

    /// Replaces the tracker configuration and adjusts timelines and limits accordingly.
    pub fn update_config(&mut self, config: TrackerConfig) {
        self.config = config;
        self.prune_protected_account_profile();
        let mode = if self.config.is_child_account || self.config.is_teen_account {
            AnalysisMode::Strict
        } else {
            AnalysisMode::Standard
        };
        self.propaganda_detector = PropagandaDetector::new(mode);

        for timeline in self.timelines.values_mut() {
            timeline.max_events = self.config.max_events_per_conversation;
            if timeline.start_idx > 0 {
                timeline.events.drain(0..timeline.start_idx);
                timeline.start_idx = 0;
            }
            if timeline.max_events == 0 {
                timeline.events.clear();
                timeline.start_idx = 0;
                continue;
            }
            if timeline.events.len() > timeline.max_events {
                let overflow = timeline.events.len() - timeline.max_events;
                timeline.events.drain(0..overflow);
            }
            timeline.start_idx = timeline.start_idx.min(timeline.events.len());
        }

        while self.timelines.len() > self.config.max_conversations {
            self.evict_oldest_conversation();
        }
        self.contact_profiler
            .update_max_profiles(self.config.max_contact_profiles);
    }

    /// Sets the conversation type for an existing timeline.
    pub fn set_conversation_type(
        &mut self,
        conversation_id: &str,
        conversation_type: ConversationType,
    ) {
        if let Some(timeline) = self.timelines.get_mut(conversation_id) {
            timeline.conversation_type = conversation_type;
        }
    }

    /// Records one interpreter-confirmed event and returns generated signals.
    ///
    /// Raw detector events cannot cross this boundary:
    ///
    /// ```compile_fail
    /// use aura_core::context::{ContextEvent, EventKind};
    /// use aura_core::context::tracker::{ConversationTracker, TrackerConfig};
    ///
    /// let mut tracker = ConversationTracker::new(TrackerConfig::default());
    /// let raw_event =
    ///     ContextEvent::new(1_000, "sender", "conversation", EventKind::Insult, 0.9);
    /// tracker.record_event(raw_event);
    /// ```
    pub fn record_event(&mut self, event: impl Into<ConfirmedEvent>) -> Vec<DetectionSignal> {
        let (conversation_id, sender_id, now_ms) = self.append_event(event.into());
        self.analyze_sender_window(&conversation_id, &sender_id, now_ms)
    }

    fn analyze_sender_window(
        &self,
        conversation_id: &ConversationId,
        sender_id: &SenderId,
        now_ms: u64,
    ) -> Vec<DetectionSignal> {
        let window_start = now_ms.saturating_sub(self.config.analysis_window_ms);
        let mut signals = Vec::new();
        let timeline = match self.timelines.get(conversation_id) {
            Some(t) => t,
            None => return signals,
        };

        if self.is_protected_account_sender(sender_id) {
            return signals;
        }

        let coercion_signals = self
            .coercion_detector
            .analyze(timeline, sender_id, window_start);
        signals.extend(coercion_signals);

        let raid_signals = self
            .raid_detector
            .analyze(timeline, now_ms, &self.contact_profiler);
        signals.extend(raid_signals);

        // Core module: propaganda detection (always active)
        let propaganda_signals =
            self.propaganda_detector
                .analyze(timeline, sender_id, now_ms, &self.contact_profiler);
        signals.extend(propaganda_signals);

        let age_gap_signals = self
            .contact_profiler
            .check_age_gap(sender_id, self.config.account_holder_age);
        signals.extend(age_gap_signals);

        let child_safety_trajectory_signals = self.contact_profiler.check_child_safety_trajectory(
            sender_id,
            self.config.is_child_account || self.config.is_teen_account,
            self.config.account_holder_age,
        );
        signals.extend(child_safety_trajectory_signals);

        let contact_signals = self.contact_profiler.check_anomalies(
            sender_id,
            self.config.is_child_account || self.config.is_teen_account,
        );
        signals.extend(contact_signals);

        if self.current_sender_event_supports_contact_shift(timeline, sender_id, now_ms) {
            let shift_signals = self.contact_profiler.check_behavioral_shift(sender_id);
            signals.extend(shift_signals);
        }
        let inferred_event_signals =
            self.infer_event_pattern_signals(timeline, sender_id, window_start, now_ms);
        signals.extend(inferred_event_signals);
        signals
    }

    fn infer_event_pattern_signals(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &SenderId,
        window_start: u64,
        now_ms: u64,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::with_capacity(2);

        let gaslighting_count = timeline.count_matching(window_start, |event| {
            event.sender_id == *sender_id
                && event.kind == EventKind::Gaslighting
                && event.supports_manipulation_inference()
        });
        if gaslighting_count > 0 {
            let score = (0.35 + gaslighting_count as f32 * 0.10).min(0.75);
            signals.push(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                Confidence::Medium,
                SignalFamily::Abuse,
                "context.gaslighting.pattern",
                "Repeated gaslighting pattern in recent sender window",
            ));
        }

        let pile_on_window_start = window_start.max(now_ms.saturating_sub(GROUP_PILE_ON_WINDOW_MS));
        let pile_on_hostile_count = timeline.count_matching(pile_on_window_start, |event| {
            event.supports_bullying_inference()
        });
        let hostile_senders = timeline.unique_senders_matching(pile_on_window_start, |event| {
            event.supports_bullying_inference()
        });
        if hostile_senders.len() >= 2 && pile_on_hostile_count >= 3 {
            let score = (0.45 + hostile_senders.len() as f32 * 0.08).min(0.75);
            signals.push(DetectionSignal::context(
                ThreatType::Bullying,
                score,
                Confidence::Medium,
                SignalFamily::Abuse,
                "context.group_bullying.pile_on",
                "Group bullying pile-on detected across multiple senders",
            ));
        }

        if let Some(signal) =
            infer_coordinate_narrowing_progression(timeline, sender_id, window_start)
        {
            signals.push(signal);
        }

        if let Some(signal) =
            infer_doxxing_aggregation_progression(timeline, sender_id, window_start)
        {
            signals.push(signal);
        }

        if let Some(signal) = infer_grooming_setup_progression(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        signals
    }

    fn append_event(&mut self, event: ConfirmedEvent) -> (ConversationId, SenderId, u64) {
        let event = event.into_event();
        let conversation_id = event.conversation_id.clone();
        let sender_id = event.sender_id.clone();
        let now_ms = event.timestamp_ms;
        let mut event = event;
        event.event_id = self.next_event_id;
        self.next_event_id += 1;
        if !self.is_protected_account_sender(&sender_id) {
            self.contact_profiler.record_event(&event);
        }
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
        if self.config.auto_cleanup_interval > 0 {
            self.call_count += 1;
            if self.call_count >= self.config.auto_cleanup_interval {
                self.call_count = 0;
                self.cleanup(now_ms);
            }
        }
        (conversation_id, sender_id, now_ms)
    }

    /// Records interpreter-confirmed events and returns all accumulated signals.
    pub fn record_events<E>(&mut self, events: impl IntoIterator<Item = E>) -> Vec<DetectionSignal>
    where
        E: Into<ConfirmedEvent>,
    {
        let mut latest_by_sender: HashMap<(ConversationId, SenderId), u64> = HashMap::new();
        for event in events {
            let (conversation_id, sender_id, now_ms) = self.append_event(event.into());
            let key = (conversation_id, sender_id);
            let entry = latest_by_sender.entry(key).or_insert(now_ms);
            if now_ms > *entry {
                *entry = now_ms;
            }
        }
        let mut all_signals = Vec::new();
        for ((conversation_id, sender_id), now_ms) in latest_by_sender {
            all_signals.extend(self.analyze_sender_window(&conversation_id, &sender_id, now_ms));
        }
        all_signals
    }

    /// Returns the timeline for the given conversation, if it exists.
    pub fn timeline(&self, conversation_id: &str) -> Option<&ConversationTimeline> {
        self.timelines.get(conversation_id)
    }

    /// Returns all tracked conversation IDs.
    pub fn conversation_ids(&self) -> Vec<&str> {
        let mut result = Vec::with_capacity(self.timelines.len());
        for s in self.timelines.keys() {
            result.push(&**s);
        }
        result
    }

    /// Returns a reference to the contact profiler.
    pub fn contact_profiler(&self) -> &ContactProfiler {
        &self.contact_profiler
    }

    /// Returns a mutable reference to the contact profiler.
    pub fn contact_profiler_mut(&mut self) -> &mut ContactProfiler {
        &mut self.contact_profiler
    }

    /// Marks a contact as trusted by sender ID.
    pub fn mark_contact_trusted(&mut self, sender_id: &str) {
        self.contact_profiler.mark_trusted(sender_id);
    }

    /// Exports the full tracker state for serialization.
    pub fn export_wire_state(&self) -> TrackerWireState {
        let mut timelines = Vec::with_capacity(self.timelines.len());
        for t in self.timelines.values() {
            timelines.push(t.export_state());
        }
        TrackerWireState {
            schema_version: TRACKER_STATE_VERSION,
            timelines,
            contact_profiler: self.contact_profiler.export_wire_state(),
        }
    }

    /// Imports a previously exported wire state, merging timelines and contact profiles.
    pub fn import_wire_state(&mut self, state: TrackerWireState) -> Result<(), AuraError> {
        if state.schema_version != TRACKER_STATE_VERSION {
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

        while self.timelines.len() > self.config.max_conversations {
            self.evict_oldest_conversation();
        }

        if max_imported_id >= self.next_event_id {
            self.next_event_id = max_imported_id + 1;
        }

        self.contact_profiler
            .merge_import_wire_state(state.contact_profiler);
        self.prune_protected_account_profile();
        Ok(())
    }

    /// Removes events and profiles older than the analysis window.
    pub fn cleanup(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.config.analysis_window_ms);
        self.timelines.retain(|_, timeline| {
            timeline.events.retain(|e| e.timestamp_ms >= cutoff);
            !timeline.is_empty()
        });
        self.contact_profiler.cleanup(cutoff);
    }

    fn evict_oldest_conversation(&mut self) {
        let mut oldest_id: Option<ConversationId> = None;
        let mut oldest_ts: u64 = u64::MAX;
        for (id, t) in &self.timelines {
            let ts = t.all_events().last().map(|e| e.timestamp_ms).unwrap_or(0);
            if oldest_id.is_none() || ts < oldest_ts {
                oldest_ts = ts;
                oldest_id = Some(id.clone());
            }
        }
        if let Some(id) = oldest_id {
            self.timelines.remove(&id);
        }
    }

    fn is_protected_account_sender(&self, sender_id: &str) -> bool {
        self.config
            .protected_account_id
            .as_deref()
            .is_some_and(|protected_id| protected_id == sender_id)
    }

    fn prune_protected_account_profile(&mut self) {
        if let Some(protected_id) = self.config.protected_account_id.as_deref() {
            self.contact_profiler.remove_profile(protected_id);
        }
    }

    fn current_sender_event_supports_contact_shift(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
    ) -> bool {
        timeline.all_events().iter().any(|event| {
            event.sender_id == sender_id
                && event.timestamp_ms == now_ms
                && !matches!(
                    event.kind,
                    EventKind::NormalConversation
                        | EventKind::TrustedContact
                        | EventKind::DefenseOfVictim
                )
        })
    }
}

fn infer_coordinate_narrowing_progression(
    timeline: &ConversationTimeline,
    sender_id: &SenderId,
    window_start: u64,
) -> Option<DetectionSignal> {
    let mut crumb_count = 0usize;
    let mut area = false;
    let mut relative = false;
    let mut site = false;
    let mut current_position = false;

    for event in timeline.events_since(window_start) {
        if event.sender_id != *sender_id || event.kind != EventKind::CoordinateMention {
            continue;
        }
        let Some(subtype) = event.subtype.as_deref() else {
            continue;
        };
        if !subtype.starts_with("coordinate_crumb.") {
            continue;
        }

        crumb_count += 1;
        match subtype {
            "coordinate_crumb.area" => area = true,
            "coordinate_crumb.relative" => relative = true,
            "coordinate_crumb.site" => site = true,
            "coordinate_crumb.current_position" => {
                site = true;
                current_position = true;
            }
            _ => {}
        }
    }

    let stage_count = [area, relative, site]
        .into_iter()
        .filter(|present| *present)
        .count();
    let has_progression =
        (crumb_count >= 3 && stage_count >= 2) || (crumb_count >= 2 && current_position);
    if !has_progression {
        return None;
    }

    let mut score = 0.50 + crumb_count as f32 * 0.04 + stage_count as f32 * 0.05;
    if current_position {
        score += 0.06;
    }
    score = score.min(0.76);

    Some(DetectionSignal::context(
        ThreatType::CoordinateLeak,
        score,
        Confidence::Medium,
        SignalFamily::Conversation,
        "context.coordinate.narrowing_progression",
        "Progressive location narrowing detected across recent military-context messages",
    ))
}

#[derive(Default)]
struct DoxxingCrumbStats {
    count: usize,
    senders: HashSet<SenderId>,
    intent: bool,
    name: bool,
    address: bool,
    city: bool,
    school: bool,
    phone: bool,
    family: bool,
    work: bool,
}

impl DoxxingCrumbStats {
    fn record(&mut self, event: &ContextEvent, subtype: &str) {
        self.count += 1;
        self.senders.insert(event.sender_id.clone());
        match subtype {
            "doxxing_crumb.intent" => self.intent = true,
            "doxxing_crumb.name" => self.name = true,
            "doxxing_crumb.address" => self.address = true,
            "doxxing_crumb.city" => self.city = true,
            "doxxing_crumb.school" => self.school = true,
            "doxxing_crumb.phone" => self.phone = true,
            "doxxing_crumb.family" => self.family = true,
            "doxxing_crumb.work" => self.work = true,
            _ => {}
        }
    }

    fn pii_type_count(&self) -> usize {
        [
            self.name,
            self.address,
            self.city,
            self.school,
            self.phone,
            self.family,
            self.work,
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
    }

    fn has_location_or_contact_anchor(&self) -> bool {
        self.address || self.phone
    }
}

fn infer_doxxing_aggregation_progression(
    timeline: &ConversationTimeline,
    sender_id: &SenderId,
    window_start: u64,
) -> Option<DetectionSignal> {
    let mut same_sender = DoxxingCrumbStats::default();
    let mut conversation = DoxxingCrumbStats::default();

    for event in timeline.events_since(window_start) {
        if event.kind != EventKind::DoxxingAttempt {
            continue;
        }
        let Some(subtype) = event.subtype.as_deref() else {
            continue;
        };
        if !subtype.starts_with("doxxing_crumb.") {
            continue;
        }

        conversation.record(event, subtype);
        if event.sender_id == *sender_id {
            same_sender.record(event, subtype);
        }
    }

    let same_sender_types = same_sender.pii_type_count();
    let conversation_types = conversation.pii_type_count();
    let same_sender_progression = same_sender.count >= 3
        && same_sender_types >= 3
        && same_sender.has_location_or_contact_anchor();
    let group_progression = conversation.count >= 5
        && conversation_types >= 4
        && conversation.has_location_or_contact_anchor()
        && (conversation.intent || conversation.senders.len() >= 2);

    let (stats, reason) = if same_sender_progression {
        (&same_sender, "sender")
    } else if group_progression {
        (&conversation, "group")
    } else {
        return None;
    };

    let pii_type_count = stats.pii_type_count();
    let mut score = 0.50 + stats.count as f32 * 0.03 + pii_type_count as f32 * 0.05;
    if stats.intent {
        score += 0.06;
    }
    if stats.address && stats.phone {
        score += 0.05;
    }
    if stats.school || stats.family {
        score += 0.04;
    }
    score = score.min(0.84);

    Some(DetectionSignal::context(
        ThreatType::Doxxing,
        score,
        if stats.intent && stats.address && stats.phone {
            Confidence::High
        } else {
            Confidence::Medium
        },
        SignalFamily::Conversation,
        "context.doxxing.aggregation_progression",
        format!(
            "Progressive doxxing aggregation detected across recent {reason} messages: {pii_type_count} PII categories"
        ),
    ))
}

fn infer_grooming_setup_progression(
    timeline: &ConversationTimeline,
    sender_id: &SenderId,
    window_start: u64,
) -> Option<DetectionSignal> {
    let mut trust_building = false;
    let mut secrecy_or_migration = false;
    let mut personal_probing = false;
    let mut media_or_sexual_pressure = false;
    let mut meeting_pressure = false;
    let mut manipulation_setup = false;
    let mut grooming_event_count = 0usize;

    for event in timeline.events_since(window_start) {
        if event.sender_id != *sender_id {
            continue;
        }
        if !event.supports_grooming_inference() {
            continue;
        }

        match event.kind {
            EventKind::Flattery
            | EventKind::LoveBombing
            | EventKind::GiftOffer
            | EventKind::MoneyOffer
            | EventKind::FinancialGrooming => {
                trust_building = true;
                grooming_event_count += 1;
            }
            EventKind::SecrecyRequest | EventKind::PlatformSwitch => {
                secrecy_or_migration = true;
                grooming_event_count += 1;
            }
            EventKind::PersonalInfoRequest | EventKind::LocationRequest => {
                personal_probing = true;
                grooming_event_count += 1;
            }
            EventKind::PhotoRequest
            | EventKind::VideoCallRequest
            | EventKind::SexualContent
            | EventKind::AgeInappropriate => {
                media_or_sexual_pressure = true;
                grooming_event_count += 1;
            }
            EventKind::MeetingRequest => {
                meeting_pressure = true;
                grooming_event_count += 1;
            }
            EventKind::CasualMeetingRequest => {
                trust_building = true;
                grooming_event_count += 1;
            }
            EventKind::IdentityErosion
            | EventKind::NetworkPoisoning
            | EventKind::FakeVulnerability
            | EventKind::FalseConsensus
            | EventKind::DebtCreation => {
                manipulation_setup = true;
                grooming_event_count += 1;
            }
            _ => {}
        }
    }

    let stage_count = [
        trust_building,
        secrecy_or_migration,
        personal_probing,
        media_or_sexual_pressure,
        meeting_pressure,
        manipulation_setup,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    let high_risk_stage_count = [
        secrecy_or_migration,
        personal_probing,
        media_or_sexual_pressure,
        meeting_pressure,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    let has_progression = high_risk_stage_count >= 2
        || (stage_count >= 3 && high_risk_stage_count >= 1 && grooming_event_count >= 3);
    if !has_progression {
        return None;
    }

    let mut score = 0.42 + stage_count as f32 * 0.07 + high_risk_stage_count as f32 * 0.06;
    if media_or_sexual_pressure {
        score += 0.06;
    }
    if meeting_pressure {
        score += 0.08;
    }
    if grooming_event_count >= 4 {
        score += 0.04;
    }
    score = score.min(0.82);

    Some(DetectionSignal::context(
        ThreatType::Grooming,
        score,
        if high_risk_stage_count >= 3 {
            Confidence::High
        } else {
            Confidence::Medium
        },
        SignalFamily::Conversation,
        "context.grooming.setup_progression",
        format!(
            "Distinct grooming setup stages detected from sender: {stage_count} stages, {high_risk_stage_count} high-risk stages"
        ),
    ))
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
            sender_id: sender_id.into(),
            conversation_id: conversation_id.into(),
            kind,
            confidence: 0.8,
            subtype: None,
            content_hash: None,
            context: Default::default(),
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
    fn protected_account_sender_is_not_profiled_or_flagged_as_contact() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            account_holder_age: Some(13),
            protected_account_id: Some("child_13".to_string()),
            ..Default::default()
        });

        let mut last_signals = Vec::new();
        for (idx, kind) in [
            EventKind::Flattery,
            EventKind::GiftOffer,
            EventKind::SecrecyRequest,
            EventKind::PlatformSwitch,
            EventKind::PhotoRequest,
        ]
        .into_iter()
        .enumerate()
        {
            last_signals = tracker.record_event(make_event(
                &format!("conv_{idx}"),
                "child_13",
                kind,
                idx as u64 * 1_000,
            ));
        }

        assert!(tracker.timeline("conv_0").is_some());
        assert!(tracker.contact_profiler().profile("child_13").is_none());
        assert!(
            last_signals
                .iter()
                .all(|signal| !signal.reason_code.starts_with("conversation.contact.")),
            "protected account must not emit contact-risk signals, got {last_signals:?}"
        );
    }

    #[test]
    fn external_sender_still_gets_multi_conversation_contact_risk() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            account_holder_age: Some(13),
            protected_account_id: Some("child_13".to_string()),
            ..Default::default()
        });

        let mut last_signals = Vec::new();
        for (idx, kind) in [
            EventKind::Flattery,
            EventKind::GiftOffer,
            EventKind::SecrecyRequest,
            EventKind::PlatformSwitch,
            EventKind::PhotoRequest,
        ]
        .into_iter()
        .enumerate()
        {
            last_signals = tracker.record_event(make_event(
                &format!("conv_{idx}"),
                "older_contact",
                kind,
                idx as u64 * 1_000,
            ));
        }

        assert!(tracker
            .contact_profiler()
            .profile("older_contact")
            .is_some());
        assert!(
            last_signals.iter().any(|signal| {
                signal.reason_code == "conversation.contact.multi_conversation_predator_pattern"
            }),
            "external sender should still emit multi-conversation contact risk, got {last_signals:?}"
        );
    }

    #[test]
    fn stale_group_pile_on_does_not_mark_later_clean_messages() {
        let day_ms = 24 * 60 * 60 * 1000u64;
        let minute_ms = 60 * 1000u64;
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            analysis_window_ms: 220 * day_ms,
            ..Default::default()
        });

        tracker.record_event(make_event("class", "bully_1", EventKind::Insult, 0));
        tracker.record_event(make_event(
            "class",
            "bully_2",
            EventKind::Denigration,
            minute_ms,
        ));
        let active_pile_on = tracker.record_event(make_event(
            "class",
            "bully_3",
            EventKind::Mockery,
            2 * minute_ms,
        ));
        assert!(
            active_pile_on
                .iter()
                .any(|signal| signal.reason_code == "context.group_bullying.pile_on"),
            "fresh hostile burst should emit pile-on signal, got {active_pile_on:?}"
        );

        let later_clean = tracker.record_event(make_event(
            "class",
            "neutral_peer",
            EventKind::NormalConversation,
            2 * day_ms,
        ));
        assert!(
            !later_clean
                .iter()
                .any(|signal| signal.reason_code == "context.group_bullying.pile_on"),
            "stale hostile burst should not mark later clean messages, got {later_clean:?}"
        );
    }

    #[test]
    fn import_prunes_protected_account_contact_profile() {
        let mut old_tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            account_holder_age: Some(13),
            ..Default::default()
        });
        old_tracker.record_event(make_event("conv_1", "child_13", EventKind::Flattery, 1_000));
        assert!(old_tracker.contact_profiler().profile("child_13").is_some());

        let state = old_tracker.export_wire_state();
        let mut restored = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            account_holder_age: Some(13),
            protected_account_id: Some("child_13".to_string()),
            ..Default::default()
        });
        restored.import_wire_state(state).unwrap();

        assert!(restored.timeline("conv_1").is_some());
        assert!(restored.contact_profiler().profile("child_13").is_none());
    }

    #[test]
    fn coordinate_crumb_progression_emits_context_signal() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());

        let mut area = make_event("conv_1", "soldier", EventKind::CoordinateMention, 0);
        area.subtype = Some("coordinate_crumb.area".to_string());
        tracker.record_event(area);

        let mut relative = make_event("conv_1", "soldier", EventKind::CoordinateMention, 30_000);
        relative.subtype = Some("coordinate_crumb.relative".to_string());
        tracker.record_event(relative);

        let mut current = make_event("conv_1", "soldier", EventKind::CoordinateMention, 60_000);
        current.subtype = Some("coordinate_crumb.current_position".to_string());
        let signals = tracker.record_event(current);

        assert!(
            signals.iter().any(|signal| {
                signal.threat_type == ThreatType::CoordinateLeak
                    && signal.reason_code == "context.coordinate.narrowing_progression"
                    && signal.score >= 0.55
            }),
            "expected coordinate narrowing context signal, got {signals:?}"
        );
    }

    #[test]
    fn doxxing_crumb_progression_emits_context_signal_for_split_pii() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());

        let mut name = make_event("conv_1", "attacker", EventKind::DoxxingAttempt, 0);
        name.subtype = Some("doxxing_crumb.name".to_string());
        tracker.record_event(name);

        let mut address = make_event("conv_1", "attacker", EventKind::DoxxingAttempt, 5_000);
        address.subtype = Some("doxxing_crumb.address".to_string());
        tracker.record_event(address);

        let mut city = make_event("conv_1", "attacker", EventKind::DoxxingAttempt, 10_000);
        city.subtype = Some("doxxing_crumb.city".to_string());
        let signals = tracker.record_event(city);

        assert!(
            signals.iter().any(|signal| {
                signal.threat_type == ThreatType::Doxxing
                    && signal.reason_code == "context.doxxing.aggregation_progression"
                    && signal.score >= 0.55
            }),
            "expected doxxing aggregation context signal, got {signals:?}"
        );
    }

    #[test]
    fn doxxing_crumb_progression_emits_context_signal_for_group_pileup() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());

        for (idx, (sender, subtype)) in [
            ("a", "doxxing_crumb.intent"),
            ("b", "doxxing_crumb.school"),
            ("c", "doxxing_crumb.name"),
            ("d", "doxxing_crumb.family"),
            ("a", "doxxing_crumb.address"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut event = make_event(
                "conv_1",
                sender,
                EventKind::DoxxingAttempt,
                idx as u64 * 5_000,
            );
            event.subtype = Some(subtype.to_string());
            let signals = tracker.record_event(event);
            if idx == 4 {
                assert!(
                    signals.iter().any(|signal| {
                        signal.threat_type == ThreatType::Doxxing
                            && signal.reason_code == "context.doxxing.aggregation_progression"
                            && signal.score >= 0.55
                    }),
                    "expected group doxxing aggregation context signal, got {signals:?}"
                );
            }
        }
    }

    #[test]
    fn timeline_push_over_capacity_keeps_latest_events() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 3);
        timeline.push(make_event("conv_1", "sender", EventKind::Flattery, 1000));
        timeline.push(make_event("conv_1", "sender", EventKind::GiftOffer, 2000));
        timeline.push(make_event(
            "conv_1",
            "sender",
            EventKind::SecrecyRequest,
            3000,
        ));
        timeline.push(make_event(
            "conv_1",
            "sender",
            EventKind::NormalConversation,
            4000,
        ));
        timeline.push(make_event("conv_1", "sender", EventKind::Insult, 5000));

        let events = timeline.all_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].timestamp_ms, 3000);
        assert_eq!(events[1].timestamp_ms, 4000);
        assert_eq!(events[2].timestamp_ms, 5000);
    }

    #[test]
    fn timeline_merge_over_capacity_keeps_latest_events() {
        let mut left = ConversationTimeline::new("conv_1".into(), 3);
        left.push(make_event("conv_1", "sender", EventKind::Flattery, 1000));
        left.push(make_event("conv_1", "sender", EventKind::GiftOffer, 2000));
        left.push(make_event(
            "conv_1",
            "sender",
            EventKind::SecrecyRequest,
            3000,
        ));

        let mut right = ConversationTimeline::new("conv_1".into(), 3);
        right.push(make_event(
            "conv_1",
            "sender",
            EventKind::NormalConversation,
            4000,
        ));
        right.push(make_event("conv_1", "sender", EventKind::Insult, 5000));

        left.merge_from(right);

        let events = left.all_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].timestamp_ms, 3000);
        assert_eq!(events[1].timestamp_ms, 4000);
        assert_eq!(events[2].timestamp_ms, 5000);
    }

    #[test]
    fn timeline_merge_preserves_distinct_same_kind_events_at_same_timestamp() {
        let mut left = ConversationTimeline::new("conv_1".into(), 10);
        let mut generic = make_event("conv_1", "sender", EventKind::SecrecyRequest, 1_000);
        generic.confidence = 0.7;
        left.push(generic);

        let mut right = ConversationTimeline::new("conv_1".into(), 10);
        let mut classified = make_event("conv_1", "sender", EventKind::SecrecyRequest, 1_000);
        classified.confidence = 0.78;
        classified.subtype = Some("grooming_secrecy".to_string());
        right.push(classified);

        left.merge_from(right);

        let events = left.all_events();
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|event| event.subtype.is_none()));
        assert!(events
            .iter()
            .any(|event| event.subtype.as_deref() == Some("grooming_secrecy")));
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
    fn state_import_reapplies_max_conversation_bound() {
        let timelines = (0..3)
            .map(|index| ConversationTimelineState {
                conversation_id: ConversationId::from(format!("conv_{index}")),
                conversation_type: ConversationType::Direct,
                events: vec![make_event(
                    &format!("conv_{index}"),
                    "alice",
                    EventKind::NormalConversation,
                    (index + 1) * 1_000,
                )],
            })
            .collect();
        let state = TrackerWireState {
            schema_version: TRACKER_STATE_VERSION,
            timelines,
            contact_profiler: ContactProfilerWireState {
                profiles: Vec::new(),
            },
        };
        let mut tracker = ConversationTracker::new(TrackerConfig {
            max_conversations: 2,
            ..TrackerConfig::default()
        });

        tracker.import_wire_state(state).unwrap();

        assert_eq!(
            (
                tracker.conversation_ids().len(),
                tracker.timeline("conv_0").is_none()
            ),
            (2, true)
        );
    }

    #[test]
    fn state_export_contains_schema_version() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(make_event("conv_1", "alice", EventKind::Flattery, 1000));

        let state = tracker.export_wire_state();
        assert_eq!(state.schema_version, TRACKER_STATE_VERSION);
    }

    #[test]
    fn state_import_mismatched_version_fails() {
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

        let older_state = TrackerWireState {
            schema_version: TRACKER_STATE_VERSION.saturating_sub(1),
            timelines: Vec::new(),
            contact_profiler: ContactProfilerWireState {
                profiles: Vec::new(),
            },
        };
        let result = tracker.import_wire_state(older_state);
        assert!(result.is_err());
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

        tracker.record_event(make_event(
            "conv_1",
            "alice",
            EventKind::NormalConversation,
            20_000,
        ));
        assert_eq!(tracker.timeline("conv_1").unwrap().len(), 2);

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

        tracker.record_event(make_event(
            "conv_1",
            "bully",
            EventKind::NormalConversation,
            1000,
        ));
        let rating_before = tracker.contact_profiler().profile("bully").unwrap().rating;

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
    fn behavioral_shift_does_not_classify_clean_current_message() {
        let week_ms = 7 * 24 * 60 * 60 * 1000u64;
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        for week in 0..3 {
            for msg in 0..10 {
                let kind = if msg < 6 {
                    EventKind::NormalConversation
                } else {
                    EventKind::DefenseOfVictim
                };
                tracker.record_event(make_event(
                    "conv_shift",
                    "peer",
                    kind,
                    week * week_ms + msg * 1000,
                ));
            }
        }

        for week in 3..5 {
            for msg in 0..10 {
                let kind = if msg < 6 {
                    EventKind::NormalConversation
                } else {
                    EventKind::Insult
                };
                tracker.record_event(make_event(
                    "conv_shift",
                    "peer",
                    kind,
                    week * week_ms + msg * 1000,
                ));
            }
        }

        let clean_signals = tracker.record_event(make_event(
            "conv_shift",
            "peer",
            EventKind::NormalConversation,
            5 * week_ms + 1_000,
        ));

        assert!(
            clean_signals.iter().all(|signal| !signal
                .reason_code
                .starts_with("conversation.contact.behavior_")),
            "clean current message should not emit behavioral shift signal, got {clean_signals:?}"
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
    fn full_pipeline_coercion_detects_manipulation() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

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

        let has_manipulation = signals
            .iter()
            .any(|s| s.threat_type == crate::types::ThreatType::Manipulation);
        assert!(
            has_manipulation,
            "Should detect coercive manipulation patterns"
        );
    }

    #[test]
    fn state_roundtrip_preserves_behavioral_data() {
        let week_ms = 7 * 24 * 60 * 60 * 1000u64;
        let mut tracker = ConversationTracker::new(TrackerConfig::default());

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
    fn core_tracker_does_not_run_domain_context_detectors() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

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

        let has_domain_context_threat = signals.iter().any(|signal| {
            signal.threat_type == crate::types::ThreatType::Grooming
                || signal.threat_type == crate::types::ThreatType::Bullying
                || signal.threat_type == crate::types::ThreatType::SelfHarm
        });
        assert!(
            !has_domain_context_threat,
            "Core tracker should not emit domain context threats"
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
    fn third_party_reported_hostility_does_not_trigger_group_patterns() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        let mut events = Vec::new();
        for i in 0..5 {
            let mut event = make_event(
                "conv_1",
                &format!("reporter_{i}"),
                EventKind::Insult,
                1_000 + i as u64 * 60_000,
            );
            event.context.speech_act = crate::context::events::EventSpeechAct::Report;
            event.context.directionality = crate::context::events::EventDirectionality::ThirdParty;
            event.context.confidence = 0.8;
            events.push(event);
        }

        let signals = tracker.record_events(events);
        assert!(
            !signals
                .iter()
                .any(|signal| signal.reason_code == "context.group_bullying.pile_on"),
            "Third-party reported hostility should not trigger pile-on patterns"
        );
        assert!(
            !signals
                .iter()
                .any(|signal| signal.reason_code.starts_with("abuse.raid.")),
            "Third-party reported hostility should not trigger raid patterns"
        );
    }

    #[test]
    fn distinct_grooming_setup_stages_emit_progression_signal() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        tracker.record_event(make_event("conv_1", "stranger", EventKind::Flattery, 1_000));
        tracker.record_event(make_event(
            "conv_1",
            "stranger",
            EventKind::SecrecyRequest,
            2_000,
        ));
        let signals = tracker.record_event(make_event(
            "conv_1",
            "stranger",
            EventKind::PhotoRequest,
            3_000,
        ));

        assert!(
            signals
                .iter()
                .any(|signal| signal.reason_code == "context.grooming.setup_progression"),
            "Distinct grooming setup stages should emit progression signal: {signals:?}"
        );
    }

    #[test]
    fn reported_grooming_setup_does_not_emit_progression_or_sender_risk() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            is_child_account: true,
            ..Default::default()
        });

        let mut events = Vec::new();
        for (idx, kind) in [
            EventKind::SecrecyRequest,
            EventKind::PhotoRequest,
            EventKind::MeetingRequest,
        ]
        .into_iter()
        .enumerate()
        {
            let mut event = make_event("conv_1", "reporter", kind, 1_000 + idx as u64 * 1_000);
            event.context.speech_act = crate::context::events::EventSpeechAct::Report;
            event.context.directionality = crate::context::events::EventDirectionality::ThirdParty;
            event.context.confidence = 0.8;
            events.push(event);
        }

        let signals = tracker.record_events(events);

        assert!(
            !signals
                .iter()
                .any(|signal| signal.reason_code == "context.grooming.setup_progression"),
            "Reported third-party grooming should not emit sender progression: {signals:?}"
        );
        let profile = tracker.contact_profiler().profile("reporter").unwrap();
        assert_eq!(
            profile.grooming_event_count, 0,
            "Reported third-party grooming should not count against the reporter"
        );
    }

    #[test]
    fn update_config_preserves_visible_window_after_shrink() {
        let mut tracker = ConversationTracker::new(TrackerConfig {
            max_events_per_conversation: 10,
            ..Default::default()
        });
        for i in 0..12 {
            tracker.record_event(make_event(
                "conv_1",
                "alice",
                EventKind::NormalConversation,
                1_000 + i * 1_000,
            ));
        }

        tracker.update_config(TrackerConfig {
            max_events_per_conversation: 5,
            ..Default::default()
        });

        let timeline = tracker.timeline("conv_1").unwrap();
        let events = timeline.all_events();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].timestamp_ms, 8_000);
        assert_eq!(events[4].timestamp_ms, 12_000);
    }

    #[test]
    fn record_events_matches_single_final_pass_for_same_sender() {
        let config = TrackerConfig {
            is_child_account: true,
            ..Default::default()
        };
        let mut batch_tracker = ConversationTracker::new(config.clone());
        let mut single_tracker = ConversationTracker::new(config);
        let events = vec![
            make_event("conv_1", "bully", EventKind::Insult, 1000),
            make_event("conv_1", "bully", EventKind::Insult, 2000),
            make_event("conv_1", "bully", EventKind::Insult, 3000),
            make_event("conv_1", "bully", EventKind::Insult, 4000),
            make_event("conv_1", "bully", EventKind::Insult, 5000),
        ];

        let batch_signals = batch_tracker.record_events(events.clone());

        for event in events.iter().take(4) {
            single_tracker.record_event(event.clone());
        }
        let single_signals = single_tracker.record_event(events[4].clone());

        assert_eq!(batch_signals.len(), single_signals.len());
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

    #[test]
    fn import_merge_preserves_local_events() {
        let mut tracker_a = ConversationTracker::new(TrackerConfig::default());
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Insult, 1000));
        tracker_a.record_event(make_event("conv_1", "alice", EventKind::Mockery, 2000));

        let mut tracker_b = ConversationTracker::new(TrackerConfig::default());
        tracker_b.record_event(make_event("conv_1", "bob", EventKind::Flattery, 1500));

        let state_b = tracker_b.export_wire_state();
        tracker_a.import_wire_state(state_b).unwrap();

        let timeline = tracker_a.timeline("conv_1").unwrap();
        assert_eq!(
            timeline.len(),
            3,
            "Should have all 3 events after merge (2 from A + 1 from B)"
        );
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
    fn guilt_tripping_alias_deserialization_is_rejected() {
        let json = r#"{"event_id":0,"timestamp_ms":1000,"sender_id":"x","conversation_id":"c","kind":"guild_tripping","confidence":0.8}"#;
        let event: Result<ContextEvent, _> = serde_json::from_str(json);
        assert!(event.is_err(), "invalid alias should not deserialize");
    }

    #[test]
    fn missing_event_id_deserialization_is_rejected() {
        let json = r#"{"timestamp_ms":1000,"sender_id":"x","conversation_id":"c","kind":"insult","confidence":0.8}"#;
        let event: Result<ContextEvent, _> = serde_json::from_str(json);
        assert!(event.is_err(), "missing event_id should not deserialize");
    }

    #[test]
    fn event_context_roundtrips_through_tracker_state() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        let mut event = make_event("conv_1", "alice", EventKind::PropagandaNarrative, 1000);
        event.context.stance = crate::context::events::EventStance::Endorse;
        event.context.repeated_by_sender = true;
        event.context.confidence = 0.8;
        tracker.record_event(event);

        let state = tracker.export_wire_state();
        let mut restored = ConversationTracker::new(TrackerConfig::default());
        restored.import_wire_state(state).unwrap();

        let restored_event = &restored.timeline("conv_1").unwrap().all_events()[0];
        assert_eq!(
            restored_event.context.stance,
            crate::context::events::EventStance::Endorse
        );
        assert!(restored_event.context.repeated_by_sender);
        assert!(restored_event.context.confidence > 0.0);
    }

    #[test]
    fn update_config_replaces_values() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());

        tracker.update_config(TrackerConfig {
            analysis_window_ms: 10_000,
            timezone_offset_minutes: 180,
            ..TrackerConfig::default()
        });

        assert_eq!(tracker.config.analysis_window_ms, 10_000);
        assert_eq!(tracker.config.timezone_offset_minutes, 180);
    }
}
