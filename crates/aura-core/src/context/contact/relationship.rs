use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::ids::{ConversationId, SenderId};
use crate::types::{
    BehavioralTrend, CircleTier, Confidence, ContactSnapshot, DetectionSignal, SignalFamily,
    ThreatType,
};

use crate::context::events::{ContextEvent, EventKind};

const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SNAPSHOTS: usize = 26;
const MAX_NARRATIVE_TIMELINE: usize = 100;
const MAX_MESSAGE_FINGERPRINTS: usize = 200;
const MAX_WEEKLY_PROPAGANDA_BUCKETS: usize = 52;
/// Default upper bound for the number of contact profiles stored.
pub const DEFAULT_MAX_CONTACT_PROFILES: usize = 1_000;

mod model;

use model::merge_weekly_snapshot;
pub use model::{AgeSource, BehavioralSnapshot, BehavioralSnapshotState, ChildSafetyTrajectory};

/// Tracks behavioral history and risk metrics for a single contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactProfile {
    pub sender_id: SenderId,
    pub(crate) conversations: Vec<ConversationId>,
    weekly_snapshots: VecDeque<BehavioralSnapshot>,
    current_snapshot: Option<BehavioralSnapshot>,
    active_days: HashSet<u32>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub total_messages: u64,
    pub conversation_count: usize,
    pub grooming_event_count: u64,
    pub bullying_event_count: u64,
    pub manipulation_event_count: u64,
    pub propaganda_event_count: u64,
    pub propaganda_source_count: u64,
    pub narrative_hits: Vec<(u8, u32)>,
    pub propaganda_score: f32,
    pub narrative_diversity: u8,
    pub first_propaganda_ms: u64,
    pub last_propaganda_ms: u64,
    pub propaganda_conversations: Vec<ConversationId>,
    pub hourly_activity: [u16; 24],
    pub message_fingerprints: VecDeque<u64>,
    pub narrative_timeline: VecDeque<(u64, u8)>,
    pub weekly_propaganda_counts: VecDeque<(u64, u16)>,
    last_fingerprint_marker: Option<(u64, u64)>,
    severity_count: u64,
    severity_sum: f32,
    pub rating: f32,
    pub trust_level: f32,
    pub inferred_age: Option<u16>,
    pub age_source: AgeSource,
    #[serde(default)]
    pub child_safety: ChildSafetyTrajectory,
    pub circle_tier: CircleTier,
    pub trend: BehavioralTrend,
    pub is_trusted: bool,
}

/// Represents the exportable state of a contact profile.
#[derive(Debug, Clone)]
pub struct ContactProfileState {
    pub sender_id: SenderId,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub total_messages: u64,
    pub conversation_count: usize,
    pub conversations: Vec<ConversationId>,
    pub grooming_event_count: u64,
    pub bullying_event_count: u64,
    pub manipulation_event_count: u64,
    pub propaganda_event_count: u64,
    pub propaganda_source_count: u64,
    pub narrative_hits: Vec<(u8, u32)>,
    pub propaganda_score: f32,
    pub narrative_diversity: u8,
    pub first_propaganda_ms: u64,
    pub last_propaganda_ms: u64,
    pub propaganda_conversations: Vec<ConversationId>,
    pub hourly_activity: [u16; 24],
    pub message_fingerprints: VecDeque<u64>,
    pub narrative_timeline: VecDeque<(u64, u8)>,
    pub weekly_propaganda_counts: VecDeque<(u64, u16)>,
    pub is_trusted: bool,
    pub severity_sum: f32,
    pub severity_count: u64,
    pub inferred_age: Option<u16>,
    pub age_source: AgeSource,
    pub child_safety: ChildSafetyTrajectory,
    pub rating: f32,
    pub trust_level: f32,
    pub circle_tier: CircleTier,
    pub trend: BehavioralTrend,
    pub weekly_snapshots: Vec<BehavioralSnapshotState>,
    pub current_snapshot: Option<BehavioralSnapshotState>,
    pub active_days: Vec<u32>,
}

impl From<&ContactProfile> for ContactProfileState {
    fn from(profile: &ContactProfile) -> Self {
        let mut active_days: Vec<u32> = Vec::with_capacity(profile.active_days.len());
        for &d in &profile.active_days {
            active_days.push(d);
        }
        active_days.sort_unstable();

        Self {
            sender_id: profile.sender_id.clone(),
            first_seen_ms: profile.first_seen_ms,
            last_seen_ms: profile.last_seen_ms,
            total_messages: profile.total_messages,
            conversation_count: profile.conversation_count,
            conversations: profile.conversations.clone(),
            grooming_event_count: profile.grooming_event_count,
            bullying_event_count: profile.bullying_event_count,
            manipulation_event_count: profile.manipulation_event_count,
            propaganda_event_count: profile.propaganda_event_count,
            propaganda_source_count: profile.propaganda_source_count,
            narrative_hits: profile.narrative_hits.clone(),
            propaganda_score: profile.propaganda_score,
            narrative_diversity: profile.narrative_diversity,
            first_propaganda_ms: profile.first_propaganda_ms,
            last_propaganda_ms: profile.last_propaganda_ms,
            propaganda_conversations: profile.propaganda_conversations.clone(),
            hourly_activity: profile.hourly_activity,
            message_fingerprints: profile.message_fingerprints.clone(),
            narrative_timeline: profile.narrative_timeline.clone(),
            weekly_propaganda_counts: profile.weekly_propaganda_counts.clone(),
            is_trusted: profile.is_trusted,
            severity_sum: profile.severity_sum,
            severity_count: profile.severity_count,
            inferred_age: profile.inferred_age,
            age_source: profile.age_source,
            child_safety: profile.child_safety,
            rating: profile.rating,
            trust_level: profile.trust_level,
            circle_tier: profile.circle_tier,
            trend: profile.trend,
            weekly_snapshots: {
                let mut snaps = Vec::with_capacity(profile.weekly_snapshots.len());
                for s in &profile.weekly_snapshots {
                    snaps.push(BehavioralSnapshotState::from(s));
                }
                snaps
            },
            current_snapshot: profile
                .current_snapshot
                .as_ref()
                .map(BehavioralSnapshotState::from),
            active_days,
        }
    }
}

impl From<ContactProfileState> for ContactProfile {
    fn from(profile: ContactProfileState) -> Self {
        Self {
            sender_id: profile.sender_id,
            first_seen_ms: profile.first_seen_ms,
            last_seen_ms: profile.last_seen_ms,
            total_messages: profile.total_messages,
            conversation_count: profile.conversation_count,
            conversations: profile.conversations,
            propaganda_event_count: profile.propaganda_event_count,
            propaganda_source_count: profile.propaganda_source_count,
            narrative_hits: profile.narrative_hits,
            propaganda_score: profile.propaganda_score,
            narrative_diversity: profile.narrative_diversity,
            first_propaganda_ms: profile.first_propaganda_ms,
            last_propaganda_ms: profile.last_propaganda_ms,
            propaganda_conversations: profile.propaganda_conversations,
            hourly_activity: profile.hourly_activity,
            message_fingerprints: profile.message_fingerprints,
            narrative_timeline: profile.narrative_timeline,
            weekly_propaganda_counts: profile.weekly_propaganda_counts,
            last_fingerprint_marker: None,
            grooming_event_count: profile.grooming_event_count,
            bullying_event_count: profile.bullying_event_count,
            manipulation_event_count: profile.manipulation_event_count,
            is_trusted: profile.is_trusted,
            severity_sum: profile.severity_sum,
            severity_count: profile.severity_count,
            inferred_age: profile.inferred_age,
            age_source: profile.age_source,
            child_safety: profile.child_safety,
            rating: profile.rating,
            trust_level: profile.trust_level,
            circle_tier: profile.circle_tier,
            trend: profile.trend,
            weekly_snapshots: {
                let mut snaps = VecDeque::with_capacity(profile.weekly_snapshots.len());
                for s in profile.weekly_snapshots {
                    snaps.push_back(BehavioralSnapshot::from(s));
                }
                snaps
            },
            current_snapshot: profile.current_snapshot.map(BehavioralSnapshot::from),
            active_days: profile.active_days.into_iter().collect(),
        }
    }
}

impl ContactProfile {
    fn new(sender_id: SenderId, first_seen_ms: u64) -> Self {
        Self {
            sender_id,
            first_seen_ms,
            last_seen_ms: first_seen_ms,
            total_messages: 0,
            conversation_count: 0,
            conversations: Vec::new(),
            grooming_event_count: 0,
            bullying_event_count: 0,
            manipulation_event_count: 0,
            propaganda_event_count: 0,
            propaganda_source_count: 0,
            narrative_hits: Vec::new(),
            propaganda_score: 0.0,
            narrative_diversity: 0,
            first_propaganda_ms: 0,
            last_propaganda_ms: 0,
            propaganda_conversations: Vec::new(),
            hourly_activity: [0u16; 24],
            message_fingerprints: VecDeque::new(),
            narrative_timeline: VecDeque::new(),
            weekly_propaganda_counts: VecDeque::new(),
            last_fingerprint_marker: None,
            is_trusted: false,
            severity_sum: 0.0,
            severity_count: 0,
            inferred_age: None,
            age_source: AgeSource::default(),
            child_safety: ChildSafetyTrajectory::default(),
            rating: 50.0,
            trust_level: 0.5,
            circle_tier: CircleTier::New,
            trend: BehavioralTrend::Stable,
            weekly_snapshots: VecDeque::new(),
            current_snapshot: None,
            active_days: HashSet::new(),
        }
    }

    /// Returns the mean severity across all recorded threat events for this contact.
    pub fn average_severity(&self) -> f32 {
        if self.severity_count == 0 {
            0.0
        } else {
            self.severity_sum / self.severity_count as f32
        }
    }

    /// Creates a lightweight snapshot of this profile for external consumption.
    pub fn snapshot(&self, is_new_contact: bool) -> ContactSnapshot {
        ContactSnapshot {
            sender_id: self.sender_id.clone(),
            rating: self.rating,
            trust_level: self.trust_level,
            circle_tier: self.circle_tier,
            trend: self.trend,
            is_trusted: self.is_trusted,
            is_new_contact,
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            conversation_count: self.conversation_count,
            grooming_event_count: self.grooming_event_count,
            bullying_event_count: self.bullying_event_count,
            manipulation_event_count: self.manipulation_event_count,
            total_threat_events: self.grooming_event_count
                + self.bullying_event_count
                + self.manipulation_event_count,
        }
    }

    /// Returns the duration in milliseconds between first and last seen timestamps.
    pub fn relationship_age_ms(&self) -> u64 {
        self.last_seen_ms - self.first_seen_ms
    }

    fn record_narrative_hit(&mut self, subtype: &str, timestamp_ms: u64) {
        use crate::context::propaganda::NarrativeId;

        let Some(nid) = NarrativeId::from_subtype(subtype) else {
            return;
        };
        let nid_u8 = nid as u8;

        let mut found = false;
        for entry in &mut self.narrative_hits {
            if entry.0 == nid_u8 {
                entry.1 += 1;
                found = true;
                break;
            }
        }
        if !found && self.narrative_hits.len() < 15 {
            self.narrative_hits.push((nid_u8, 1));
        }

        self.narrative_diversity = self.narrative_hits.len() as u8;

        if self.narrative_timeline.len() >= MAX_NARRATIVE_TIMELINE {
            self.narrative_timeline.pop_front();
        }
        self.narrative_timeline.push_back((timestamp_ms, nid_u8));
    }

    fn record_weekly_propaganda_count(&mut self, timestamp_ms: u64) {
        let week_start_ms = (timestamp_ms / WEEK_MS) * WEEK_MS;
        for bucket in &mut self.weekly_propaganda_counts {
            if bucket.0 == week_start_ms {
                bucket.1 = bucket.1.saturating_add(1);
                return;
            }
        }
        let mut insert_idx = self.weekly_propaganda_counts.len();
        for (idx, bucket) in self.weekly_propaganda_counts.iter().enumerate() {
            if week_start_ms < bucket.0 {
                insert_idx = idx;
                break;
            }
        }
        self.weekly_propaganda_counts
            .insert(insert_idx, (week_start_ms, 1));
        while self.weekly_propaganda_counts.len() > MAX_WEEKLY_PROPAGANDA_BUCKETS {
            self.weekly_propaganda_counts.pop_front();
        }
    }

    fn record_message_fingerprint(&mut self, timestamp_ms: u64, content_hash: u64) {
        if let Some((last_timestamp_ms, last_hash)) = self.last_fingerprint_marker {
            if last_timestamp_ms == timestamp_ms && last_hash == content_hash {
                return;
            }
        }
        if self.message_fingerprints.len() >= MAX_MESSAGE_FINGERPRINTS {
            self.message_fingerprints.pop_front();
        }
        self.message_fingerprints.push_back(content_hash);
        self.last_fingerprint_marker = Some((timestamp_ms, content_hash));
    }

    fn update_propaganda_score(&mut self) {
        let mut score: f32 = 0.0;

        let event_factor = (self.propaganda_event_count as f32 * 0.04).min(0.35);
        score += event_factor;

        let source_factor = (self.propaganda_source_count as f32 * 0.08).min(0.2);
        score += source_factor;

        let diversity_factor = (self.narrative_diversity as f32 * 0.06).min(0.25);
        score += diversity_factor;

        let conv_factor = (self.propaganda_conversations.len() as f32 * 0.05).min(0.2);
        score += conv_factor;

        if self.total_messages >= 10 {
            let concentration = self.propaganda_event_count as f32 / self.total_messages as f32;
            if concentration > 0.5 {
                score += 0.15;
            }
        }

        self.propaganda_score = score.min(1.0);
    }

    /// Computes a composite risk score in the range 0.0 to 1.0 based on threat event counts and trust.
    pub fn risk_score(&self) -> f32 {
        let mut score: f32 = 0.0;

        if self.grooming_event_count > 0 {
            score += (self.grooming_event_count as f32 * 0.1).min(0.4);
        }

        if self.bullying_event_count > 0 {
            score += (self.bullying_event_count as f32 * 0.08).min(0.3);
        }

        if self.manipulation_event_count > 0 {
            score += (self.manipulation_event_count as f32 * 0.1).min(0.3);
        }

        if self.propaganda_event_count > 0 {
            score += (self.propaganda_event_count as f32 * 0.06).min(0.3);
        }

        score += self.average_severity() * 0.2;

        let hours_known = self.relationship_age_ms() as f32 / (1000.0 * 3600.0);
        if hours_known < 24.0
            && (self.grooming_event_count > 0
                || self.bullying_event_count > 0
                || self.manipulation_event_count > 0)
        {
            score += 0.1;
        }

        let trust_discount = 1.0 - (self.trust_level * 0.5);
        score *= trust_discount;

        score.min(1.0)
    }

    /// Computes a child-safety trajectory risk score for persistent grooming escalation.
    pub fn child_safety_trajectory_risk(
        &self,
        is_minor_account: bool,
        account_holder_age: Option<u16>,
    ) -> f32 {
        if !is_minor_account || self.is_trusted {
            return 0.0;
        }

        let stage_count = self.child_safety.stage_count();
        let high_risk_stage_count = self.child_safety.high_risk_stage_count();
        if stage_count < 2
            || high_risk_stage_count == 0
            || self.child_safety.grooming_event_count < 2
        {
            return 0.0;
        }

        let mut score = 0.24
            + stage_count as f32 * 0.075
            + high_risk_stage_count as f32 * 0.07
            + (self.child_safety.high_risk_event_count.min(4) as f32 * 0.025);

        if high_risk_stage_count >= 2 {
            score += 0.08;
        }
        if stage_count >= 4 {
            score += 0.06;
        }
        if self.child_safety.has_rapid_escalation() {
            score += 0.08;
            if self.child_safety.rapid_escalation_ms <= 2 * 60 * 60 * 1000 {
                score += 0.04;
            }
        }
        if self.relationship_age_ms() <= 48 * 60 * 60 * 1000 {
            score += 0.07;
        }
        if self.conversation_count >= 2 && high_risk_stage_count >= 2 {
            score += 0.04;
        }

        if let (Some(holder_age), Some(sender_age)) = (account_holder_age, self.inferred_age) {
            if holder_age < 18 && sender_age >= 18 {
                let gap = sender_age.saturating_sub(holder_age);
                if gap >= 5 {
                    score +=
                        (0.08 + gap as f32 * 0.01).min(0.20) * self.age_source.confidence_factor();
                }
            }
        }

        let trust_discount = 1.0 - (self.trust_level * 0.25);
        (score * trust_discount).min(0.95)
    }

    fn dominant_contact_risk_threat(&self) -> ThreatType {
        let mut dominant = ThreatType::Grooming;
        let mut best_score = (self.grooming_event_count as f32 * 0.1).min(0.4);

        let manipulation_score = (self.manipulation_event_count as f32 * 0.1).min(0.3);
        if manipulation_score >= best_score && manipulation_score > 0.0 {
            dominant = ThreatType::Manipulation;
            best_score = manipulation_score;
        }

        let bullying_score = (self.bullying_event_count as f32 * 0.08).min(0.3);
        if bullying_score > best_score && bullying_score > 0.0 {
            dominant = ThreatType::Bullying;
            best_score = bullying_score;
        }

        let propaganda_score = (self.propaganda_event_count as f32 * 0.06).min(0.3);
        if propaganda_score > best_score && propaganda_score > 0.0 {
            dominant = ThreatType::Propaganda;
        }

        dominant
    }

    /// Updates the contact's rating, snapshot, active days, and trust based on the given event.
    pub fn update_rating(&mut self, event: &ContextEvent) {
        let delta = event.effective_rating_delta();
        self.rating = (self.rating + delta).clamp(0.0, 100.0);

        self.update_current_snapshot(event);

        let day_index = (event.timestamp_ms / DAY_MS) as u32;
        self.active_days.insert(day_index);

        self.recalculate_circle_tier();

        if event.supports_propaganda_inference() {
            self.decay_trust(event.effective_severity() * 0.5);
        } else if event.effective_is_hostile() {
            self.decay_trust(event.effective_severity());
        }
    }

    fn decay_trust(&mut self, severity: f32) {
        let decay = severity * 0.15;
        self.trust_level = (self.trust_level - decay).max(0.0);
        self.is_trusted = self.trust_level >= 0.7;
    }

    fn update_current_snapshot(&mut self, event: &ContextEvent) {
        if self.current_snapshot.is_none() {
            self.current_snapshot = Some(BehavioralSnapshot::new(event.timestamp_ms));
        }

        let needs_finalize = self
            .current_snapshot
            .as_ref()
            .is_some_and(|s| event.timestamp_ms >= s.period_start_ms.saturating_add(WEEK_MS));

        if needs_finalize {
            if let Some(mut old) = self.current_snapshot.take() {
                old.period_end_ms = old.period_start_ms.saturating_add(WEEK_MS);
                if old.total_messages > 0 {
                    self.weekly_snapshots.push_back(old);
                    if self.weekly_snapshots.len() > MAX_SNAPSHOTS {
                        self.weekly_snapshots.pop_front();
                    }
                }
            }
            self.current_snapshot = Some(BehavioralSnapshot::new(event.timestamp_ms));
            self.recalculate_trend();
        }

        let snapshot = self.current_snapshot.as_mut().unwrap();
        snapshot.total_messages += 1;
        if event.effective_is_hostile() {
            snapshot.hostile_count += 1;
        } else if event.effective_is_supportive() {
            snapshot.supportive_count += 1;
        } else {
            snapshot.neutral_count += 1;
        }
        if event.kind.is_core_grooming_indicator() && event.supports_grooming_inference() {
            snapshot.grooming_count += 1;
        }
        if event.kind.is_manipulation_indicator() {
            snapshot.manipulation_count += 1;
        }
        if event.supports_propaganda_inference() {
            snapshot.propaganda_count += 1;
        }

        let n = snapshot.total_messages as f32;
        snapshot.avg_severity =
            snapshot.avg_severity * ((n - 1.0) / n) + event.effective_severity() / n;
    }

    fn recalculate_trend(&mut self) {
        let snapshots = &self.weekly_snapshots;

        if snapshots.len() < 3 {
            self.trend = BehavioralTrend::Stable;
            return;
        }

        let baseline_count = (snapshots.len() / 2).clamp(2, 4);
        let baseline_hostile = avg_hostile_ratio(snapshots.iter().take(baseline_count));
        let baseline_supportive = avg_supportive_ratio(snapshots.iter().take(baseline_count));

        let recent_hostile = avg_hostile_ratio(snapshots.iter().rev().take(2));
        let _recent_supportive = avg_supportive_ratio(snapshots.iter().rev().take(2));

        let hostile_delta = recent_hostile - baseline_hostile;

        if baseline_supportive > 0.3 && recent_hostile > 0.3 {
            self.trend = BehavioralTrend::RoleReversal;
            return;
        }

        if hostile_delta > 0.25 {
            self.trend = BehavioralTrend::RapidWorsening;
        } else if hostile_delta > 0.10 {
            self.trend = BehavioralTrend::GradualWorsening;
        } else if hostile_delta < -0.10 {
            self.trend = BehavioralTrend::Improving;
        } else {
            self.trend = BehavioralTrend::Stable;
        }
    }

    fn recalculate_circle_tier(&mut self) {
        let age_ms = self.relationship_age_ms();

        if age_ms < 14 * DAY_MS {
            self.circle_tier = CircleTier::New;
            return;
        }

        let age_days = (age_ms / DAY_MS).max(1) as f32;
        let msgs_per_day = self.total_messages as f32 / age_days;

        let recent_active = self.count_recent_active_days(30);
        if msgs_per_day >= 5.0 || recent_active >= 20 {
            self.circle_tier = CircleTier::Inner;
            return;
        }

        if msgs_per_day >= 0.43 {
            self.circle_tier = CircleTier::Regular;
            return;
        }

        self.circle_tier = CircleTier::Occasional;
    }

    fn count_recent_active_days(&self, days: u32) -> usize {
        let now_day = (self.last_seen_ms / DAY_MS) as u32;
        let cutoff_day = now_day.saturating_sub(days);
        let mut count = 0usize;
        for &d in &self.active_days {
            if d >= cutoff_day {
                count += 1;
            }
        }
        count
    }

    /// Returns a reference to the stored weekly behavioral snapshots.
    pub fn weekly_snapshots(&self) -> &VecDeque<BehavioralSnapshot> {
        &self.weekly_snapshots
    }
}

fn avg_hostile_ratio<'a>(snapshots: impl Iterator<Item = &'a BehavioralSnapshot>) -> f32 {
    let mut sum = 0.0;
    let mut count = 0u32;
    for s in snapshots {
        if s.total_messages > 0 {
            sum += s.hostile_ratio();
            count += 1;
        }
    }
    if count == 0 {
        0.0
    } else {
        sum / count as f32
    }
}

fn avg_supportive_ratio<'a>(snapshots: impl Iterator<Item = &'a BehavioralSnapshot>) -> f32 {
    let mut sum = 0.0;
    let mut count = 0u32;
    for s in snapshots {
        if s.total_messages > 0 {
            sum += s.supportive_ratio();
            count += 1;
        }
    }
    if count == 0 {
        0.0
    } else {
        sum / count as f32
    }
}

fn merge_child_safety_trajectory(
    local: ChildSafetyTrajectory,
    incoming: ChildSafetyTrajectory,
) -> ChildSafetyTrajectory {
    let first_grooming_ms = match (local.first_grooming_ms, incoming.first_grooming_ms) {
        (0, 0) => 0,
        (0, incoming_first) => incoming_first,
        (local_first, 0) => local_first,
        (local_first, incoming_first) => local_first.min(incoming_first),
    };
    let rapid_escalation_ms = match (local.rapid_escalation_ms, incoming.rapid_escalation_ms) {
        (0, 0) => 0,
        (0, incoming_rapid) => incoming_rapid,
        (local_rapid, 0) => local_rapid,
        (local_rapid, incoming_rapid) => local_rapid.min(incoming_rapid),
    };

    ChildSafetyTrajectory {
        first_grooming_ms,
        last_grooming_ms: local.last_grooming_ms.max(incoming.last_grooming_ms),
        grooming_stage_mask: local.grooming_stage_mask | incoming.grooming_stage_mask,
        grooming_event_count: local
            .grooming_event_count
            .max(incoming.grooming_event_count),
        high_risk_event_count: local
            .high_risk_event_count
            .max(incoming.high_risk_event_count),
        rapid_escalation_ms,
    }
}

fn trend_severity(trend: &BehavioralTrend) -> u8 {
    match trend {
        BehavioralTrend::Stable => 0,
        BehavioralTrend::Improving => 0,
        BehavioralTrend::GradualWorsening => 1,
        BehavioralTrend::RapidWorsening => 2,
        BehavioralTrend::RoleReversal => 3,
    }
}

mod state;

pub use state::{ContactProfiler, ContactProfilerState, ContactProfilerWireState};

#[cfg(test)]
mod tests;
